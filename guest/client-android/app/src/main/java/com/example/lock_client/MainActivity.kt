package com.example.lock_client

import android.Manifest
import android.annotation.SuppressLint
import android.app.Application
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.ParcelUuid
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.*
import kotlinx.coroutines.NonCancellable.isActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import org.eclipse.paho.client.mqttv3.*
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence
import org.json.JSONObject
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.math.min


private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")


private val LOCK_ID_KEY = stringPreferencesKey("lock_id")
private val PHONE_MAC_KEY = stringPreferencesKey("phone_mac")
private val MQTT_BROKER_KEY = stringPreferencesKey("mqtt_broker")
private val ADVERT_INTERVAL_KEY = stringPreferencesKey("advert_interval")


private const val MANUFACTURER_ID = 0xFFFF
private const val SERVICE_UUID = "0000180D-0000-1000-8000-00805F9B34FB" // 180D
private const val TAG = "BleAdvertiser"


class AdvertiserViewModel(application: Application) : AndroidViewModel(application) {

    private val dataStore = application.dataStore

    private val _uiState = MutableStateFlow(AdvertiserUiState())
    val uiState = _uiState.asStateFlow()


    private var advertiserJob: Job? = null
    private var bleAdvertiser: BluetoothLeAdvertiser? = null
    private var sessionKey: ByteArray? = null
    private var sessionExpiry: Long = 0L


    init {
        log("ViewModel initializing...")
        viewModelScope.launch {
            val savedConfig = loadConfig()
            _uiState.update {
                it.copy(
                    lockId = savedConfig.lockId,
                    phoneMac = savedConfig.phoneMac,
                    mqttBroker = savedConfig.mqttBroker,
                    advertInterval = savedConfig.advertInterval
                )
            }
            log("Saved configuration loaded.")
        }
    }

    private suspend fun loadConfig(): SavedConfig {
        return dataStore.data.map { prefs ->
            SavedConfig(
                lockId = prefs[LOCK_ID_KEY] ?: "lock_02", // Default value
                phoneMac = prefs[PHONE_MAC_KEY] ?: "9C:2F:9D:65:CA:A6",
                mqttBroker = prefs[MQTT_BROKER_KEY] ?: "10.0.7.42",
                advertInterval = prefs[ADVERT_INTERVAL_KEY]?.toLongOrNull() ?: 30L
            )
        }.first()
    }

    private fun log(message: String) {
        Log.d(TAG, message)
        viewModelScope.launch {
            _uiState.update {
                val newLogs = (it.logs + "[${System.currentTimeMillis()}] $message")
                    .takeLast(100)
                it.copy(logs = newLogs)
            }
        }
    }

    fun onSaveConfig(
        lockId: String,
        phoneMac: String,
        mqttBroker: String,
        advertInterval: String
    ) {
        val interval = advertInterval.toLongOrNull() ?: uiState.value.advertInterval


        viewModelScope.launch(Dispatchers.IO) {
            dataStore.edit { prefs ->
                prefs[LOCK_ID_KEY] = lockId
                prefs[PHONE_MAC_KEY] = phoneMac
                prefs[MQTT_BROKER_KEY] = mqttBroker
                prefs[ADVERT_INTERVAL_KEY] = interval.toString()
            }
        }

        _uiState.update {
            it.copy(
                lockId = lockId,
                phoneMac = phoneMac,
                mqttBroker = mqttBroker,
                advertInterval = interval
            )
        }
        log("Configuration saved.")
    }

    fun getSessionKey(context: Context) {

        viewModelScope.launch(Dispatchers.IO) { // Already on a background thread
            _uiState.update { it.copy(isGettingKey = true, hasSessionKey = false) }
            log("Requesting session key...")

            val config = uiState.value

            try {

                val (key, expiry) = fetchKeyViaMqtt(config)

                sessionKey = key
                sessionExpiry = expiry
                log("Session key received. Expires: $expiry")
                log("Key (Base64): ${Base64.getEncoder().encodeToString(key)}")
                _uiState.update { it.copy(hasSessionKey = true) }

            } catch (e: Exception) {
                if (e is CancellationException) {
                    log("Key request cancelled.")
                } else {
                    log("Error getting key: ${e.message}")
                    e.printStackTrace()
                }
                _uiState.update { it.copy(hasSessionKey = false) }
            } finally {
                // This block executes on success, failure, or cancellation
                log("[MQTT] getSessionKey job finished.")
                _uiState.update { it.copy(isGettingKey = false) }
            }
        }
    }

    private suspend fun fetchKeyViaMqtt(
        config: AdvertiserUiState
    ): Pair<ByteArray, Long> = withTimeout(10_000L) { // 10-second timeout
        suspendCancellableCoroutine { continuation ->
            var client: MqttClient? = null
            try {
                val clientId = MqttClient.generateClientId()
                val serverUri = "tcp://${config.mqttBroker}:1883"
                val guestTopic = "guests/${config.lockId}/session"
                val requestTopic = "backend/session_requests"
                val requestPayload = JSONObject().apply {
                    put("lock_id", config.lockId)
                    put("curr_time", Instant.now().epochSecond)
                }.toString()


                client = MqttClient(serverUri, clientId, MemoryPersistence())

                client.setCallback(object : MqttCallback {
                    override fun connectionLost(cause: Throwable?) {
                        log("[MQTT] Connection lost: ${cause?.message}")
                        if (continuation.isActive)
                            continuation.resumeWithException(cause ?: Exception("MQTT Connection Lost"))
                    }

                    override fun messageArrived(topic: String?, message: MqttMessage?) {
                        if (topic == guestTopic && message != null) {
                            log("[MQTT] Received session key data.")
                            try {
                                val data = JSONObject(message.payload.decodeToString())
                                val keyB64 = data.getString("session_key")
                                val expiry = data.optLong("expiry", 0L)
                                val keyBytes = Base64.getDecoder().decode(keyB64)


                                if (continuation.isActive)
                                    continuation.resume(keyBytes to expiry)
                            } catch (e: Exception) {
                                if (continuation.isActive)
                                    continuation.resumeWithException(Exception("Failed to parse key", e))
                            }
                        }
                    }

                    override fun deliveryComplete(token: IMqttDeliveryToken?) {}
                })


                val options = MqttConnectOptions()
                options.isCleanSession = true
                log("[MQTT] Connecting to $serverUri...")
                client.connect(options)
                log("[MQTT] Connected.")

                log("[MQTT] Subscribing to $guestTopic...")
                client.subscribe(guestTopic, 1)
                log("[MQTT] Subscribed.")

                val msg = MqttMessage(requestPayload.toByteArray())
                msg.qos = 1
                log("[MQTT] Publishing to $requestTopic...")
                client.publish(requestTopic, msg)
                log("[MQTT] Published. Waiting for key...")

            } catch (e: Exception) {
                if (continuation.isActive)
                    continuation.resumeWithException(e)
            }


            continuation.invokeOnCancellation {
                viewModelScope.launch(Dispatchers.IO) {
                    try {
                        log("[MQTT] Cleaning up and disconnecting...")
                        client?.disconnect()
                    } catch (e: Exception) {
                        log("[MQTT] Error during disconnect: ${e.message}")
                    }
                }
            }
        }
    }



    fun startAdvertisingLoop(context: Context) {
        if (uiState.value.isAdvertising) {
            log("Already advertising.")
            return
        }
        if (sessionKey == null) {
            log("Error: Must get session key before advertising.")
            return
        }
        if (!isBleAdapterEnabled(context)) {
            log("Error: Bluetooth is not enabled.")
            return
        }

        _uiState.update { it.copy(isAdvertising = true) }
        log("Starting advertising loop...")

        advertiserJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                // advertisingLoop is a suspend function
                advertisingLoopInternal(context, uiState.value)
            } catch (e: CancellationException) {
                log("Advertising stopped by user.")
            } catch (e: Exception) {
                log("Advertising loop error: ${e.message}")
            } finally {
                // This finally block cleans up the advertising *loop*
                log("Cleaning up advertising...")
                stopBleAdvertising()
                _uiState.update { it.copy(isAdvertising = false, hasSessionKey = false) }
                sessionKey = null // Invalidate key on stop
                sessionExpiry = 0L
            }
        }
    }

    fun stopAdvertisingLoop() {
        advertiserJob?.cancel()
    }

    @SuppressLint("MissingPermission")
    private suspend fun advertisingLoopInternal(context: Context, config: AdvertiserUiState) {
        val btManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bleAdvertiser = btManager.adapter.bluetoothLeAdvertiser
        if (bleAdvertiser == null) {
            log("Error: Failed to get BluetoothLeAdvertiser. Is BLE supported?")
            return
        }

        while (isActive) {
            val currentTime = System.currentTimeMillis() / 1000L
            val remaining = sessionExpiry - currentTime
            if (sessionExpiry != 0L && remaining <= 0) {
                log("Session key expired. Stopping.")
                break
            }

            val token = generateToken(config.phoneMac, config.advertInterval)
            log("[ADV] Updating token: ${token.toHex()}")

            stopBleAdvertising()
            startBleAdvertising(token)

            val sleepTime = if (sessionExpiry == 0L) {
                config.advertInterval * 1000L
            } else {
                min(config.advertInterval * 1000L, remaining * 1000L)
            }

            if (sleepTime <= 0) break
            delay(sleepTime)
        }
    }
    
    private fun generateToken(phoneMac: String, advertInterval: Long): ByteArray {
        val key = sessionKey ?: throw IllegalStateException("Session key is null")
        val ts = (System.currentTimeMillis() / 1000L) / advertInterval
        val msg = (phoneMac + ts).toByteArray(Charsets.UTF_8)

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg).copyOfRange(0, 16) // Truncate to 16 bytes
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            log("[BLE] Advertising started successfully.")
        }
        override fun onStartFailure(errorCode: Int) {
            log("[BLE] Advertising failed to start: ${bleErrorToString(errorCode)}")

            stopAdvertisingLoop()
        }
    }

    @SuppressLint("MissingPermission")
    private fun startBleAdvertising(token: ByteArray) {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(false)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid.fromString(SERVICE_UUID))
            .addManufacturerData(MANUFACTURER_ID, token)
            .build()

        bleAdvertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    @SuppressLint("MissingPermission")
    private fun stopBleAdvertising() {
        try {
            bleAdvertiser?.stopAdvertising(advertiseCallback)
        } catch (e: Exception) {
            log("[BLE] Error stopping advertising: ${e.message}")
        }
    }

    private fun isBleAdapterEnabled(context: Context): Boolean {
        val btManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        return btManager?.adapter?.isEnabled == true
    }

    private fun bleErrorToString(errorCode: Int): String = when (errorCode) {
        AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED -> "ALREADY_STARTED"
        AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE -> "DATA_TOO_LARGE"
        AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> "FEATURE_UNSUPPORTED"
        AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR -> "INTERNAL_ERROR"
        AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> "TOO_MANY_ADVERTISERS"
        else -> "UNKNOWN_ERROR ($errorCode)"
    }

    private fun ByteArray.toHex(): String =
        joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
}


data class AdvertiserUiState(
    // Config
    val lockId: String = "loading...",
    val phoneMac: String = "loading...",
    val mqttBroker: String = "loading...",
    val advertInterval: Long = 30,
    // Activity State
    val isGettingKey: Boolean = false,
    val isAdvertising: Boolean = false,
    val hasSessionKey: Boolean = false,
    // Logs
    val logs: List<String> = emptyList()
)

private data class SavedConfig(
    val lockId: String,
    val phoneMac: String,
    val mqttBroker: String,
    val advertInterval: Long
)


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    PermissionGatedScreen()
                }
            }
        }
    }
}


@Composable
fun PermissionGatedScreen() {
    var hasPermissions by remember { mutableStateOf(false) }
    var showRationale by remember { mutableStateOf(false) }

    val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        listOf(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
        )
    } else {
        listOf(
            Manifest.permission.BLUETOOTH,
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    }

    val launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions(),
        onResult = { permissionsMap ->
            if (permissionsMap.values.all { it }) {
                hasPermissions = true
            } else {
                showRationale = true
            }
        }
    )

    LaunchedEffect(Unit) {
        launcher.launch(permissions.toTypedArray())
    }

    if (hasPermissions) {

        BleAdvertiserScreen(
            viewModel = viewModel(
                factory = AdvertiserViewModelFactory(
                    LocalContext.current.applicationContext as Application
                )
            )
        )
    } else {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                "Requesting Bluetooth & Location permissions...",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(Modifier.height(16.dp))
            Button(onClick = { launcher.launch(permissions.toTypedArray()) }) {
                Text("Retry Permissions")
            }
        }
    }

    if (showRationale) {
        RationaleDialog(
            onDismiss = { showRationale = false },
            onConfirm = {
                showRationale = false
                launcher.launch(permissions.toTypedArray())
            }
        )
    }
}


class AdvertiserViewModelFactory(private val application: Application) :
    ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(AdvertiserViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return AdvertiserViewModel(application) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}

@Composable
fun RationaleDialog(onDismiss: () -> Unit, onConfirm: () -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        Card {
            Column(Modifier.padding(16.dp)) {
                Text("Permissions Required", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                Text(
                    "This app requires Bluetooth permissions to advertise. " +
                            "On older Android versions, Location is also required for BLE."
                )
                Spacer(Modifier.height(16.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onDismiss) { Text("Cancel") }
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = onConfirm) { Text("Grant") }
                }
            }
        }
    }
}


@Composable
fun BleAdvertiserScreen(viewModel: AdvertiserViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val logListState = rememberLazyListState()

    LaunchedEffect(uiState.logs.size) {
        if (uiState.logs.isNotEmpty()) {
            logListState.animateScrollToItem(uiState.logs.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {

        ConfigEditor(
            uiState = uiState,
            onSave = { lockId, mac, broker, interval ->
                viewModel.onSaveConfig(lockId, mac, broker, interval)
            }
        )

        Spacer(Modifier.height(16.dp))
        Divider()
        Spacer(Modifier.height(16.dp))


        ControlPanel(
            uiState = uiState,
            onGetKey = { viewModel.getSessionKey(context) },
            onStart = { viewModel.startAdvertisingLoop(context) },
            onStop = { viewModel.stopAdvertisingLoop() }
        )

        Spacer(Modifier.height(16.dp))

        Text("Logs", style = MaterialTheme.typography.headlineSmall)
        Card(
            modifier = Modifier
                .fillMaxSize()
                .padding(top = 8.dp),
            elevation = CardDefaults.cardElevation(2.dp)
        ) {
            LazyColumn(
                state = logListState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(8.dp)
            ) {
                items(uiState.logs) { log ->
                    Text(
                        log,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(vertical = 2.dp)
                    )
                }
            }
        }
    }
}


@Composable
fun ConfigEditor(
    uiState: AdvertiserUiState,
    onSave: (String, String, String, String) -> Unit
) {


    var draftLockId by remember(uiState.lockId) { mutableStateOf(uiState.lockId) }
    var draftPhoneMac by remember(uiState.phoneMac) { mutableStateOf(uiState.phoneMac) }
    var draftMqttBroker by remember(uiState.mqttBroker) { mutableStateOf(uiState.mqttBroker) }
    var draftAdvertInterval by remember(uiState.advertInterval) {
        mutableStateOf(uiState.advertInterval.toString())
    }

    val isEnabled = !uiState.isAdvertising && !uiState.isGettingKey

    Column {
        Text("Configuration", style = MaterialTheme. typography.headlineSmall)
        Spacer(Modifier.height(8.dp))

        ConfigTextField(
            label = "Lock ID",
            value = draftLockId,
            onValueChange = { draftLockId = it },
            enabled = isEnabled
        )
        ConfigTextField(
            label = "Phone MAC",
            value = draftPhoneMac,
            onValueChange = { draftPhoneMac = it },
            enabled = isEnabled
        )
        ConfigTextField(
            label = "MQTT Broker (IP or Hostname)",
            value = draftMqttBroker,
            onValueChange = { draftMqttBroker = it },
            enabled = isEnabled
        )
        ConfigTextField(
            label = "Advert Interval (seconds)",
            value = draftAdvertInterval,
            onValueChange = { draftAdvertInterval = it },
            enabled = isEnabled
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { onSave(draftLockId, draftPhoneMac, draftMqttBroker, draftAdvertInterval) },
            enabled = isEnabled,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Save Config")
        }
    }
}


@Composable
fun ControlPanel(
    uiState: AdvertiserUiState,
    onGetKey: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit
) {
    val isBusy = uiState.isAdvertising || uiState.isGettingKey

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(contentAlignment = Alignment.Center) {
            Button(
                onClick = onGetKey,
                enabled = !isBusy
            ) {
                Text("Get Session Key")
            }
            if (uiState.isGettingKey) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            }
        }


        Button(
            onClick = onStart,
            enabled = !isBusy && uiState.hasSessionKey
        ) {
            Text("Start Advert")
        }

        Button(
            onClick = onStop,
            enabled = uiState.isAdvertising,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error
            )
        ) {
            Text("Stop Advert")
        }
    }
}


@Composable
fun ConfigTextField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        singleLine = true,
        enabled = enabled
    )
}
