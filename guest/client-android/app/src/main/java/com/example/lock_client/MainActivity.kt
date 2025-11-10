package com.example.lock_client

import android.Manifest
import android.annotation.SuppressLint
import android.app.Application
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.ParcelUuid
import android.util.Log
import androidx.activity.ComponentActivity
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
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import org.json.JSONObject
import java.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.math.min

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

private val LOCK_ID_KEY = stringPreferencesKey("lock_id")
private val ISSUER_BEACON_NAME_KEY = stringPreferencesKey("issuer_beacon_name")
private val ISSUER_BEACON_ADDRESS_KEY = stringPreferencesKey("issuer_beacon_address")
private val ADVERT_INTERVAL_KEY = stringPreferencesKey("advert_interval")

private const val MANUFACTURER_ID = 0xFFFF
private const val SERVICE_UUID = "0000180D-0000-1000-8000-00805F9B34FB"
private const val PROVISIONING_SERVICE_UUID = "c0de0001-0000-1000-8000-00805f9b34fb"
private const val PROVISIONING_CHARACTERISTIC_UUID = "c0de0002-0000-1000-8000-00805f9b34fb"
private const val TAG = "BleAdvertiser"

class AdvertiserViewModel(application: Application) : AndroidViewModel(application) {

    private val dataStore = application.dataStore
    private val _uiState = MutableStateFlow(AdvertiserUiState())
    val uiState = _uiState.asStateFlow()

    private var advertiserJob: Job? = null
    private var bleAdvertiser: BluetoothLeAdvertiser? = null
    private var bleScanner: BluetoothLeScanner? = null
    private var sessionKey: ByteArray? = null
    private var sessionExpiry: Long = 0L
    private var nonce: String? = null

    init {
        log("ViewModel initializing...")
        viewModelScope.launch {
            val savedConfig = loadConfig()
            _uiState.update {
                it.copy(
                    lockId = savedConfig.lockId,
                    issuerBeaconName = savedConfig.issuerBeaconName,
                    issuerBeaconAddress = savedConfig.issuerBeaconAddress,
                    advertInterval = savedConfig.advertInterval
                )
            }
            log("Saved configuration loaded.")
        }
    }

    private suspend fun loadConfig(): SavedConfig {
        return dataStore.data.map { prefs ->
            SavedConfig(
                lockId = prefs[LOCK_ID_KEY] ?: "lock_02",
                issuerBeaconName = prefs[ISSUER_BEACON_NAME_KEY] ?: "IssuerBeacon",
                issuerBeaconAddress = prefs[ISSUER_BEACON_ADDRESS_KEY] ?: "",
                advertInterval = prefs[ADVERT_INTERVAL_KEY]?.toLongOrNull() ?: 5L
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
        issuerBeaconName: String,
        issuerBeaconAddress: String,
        advertInterval: String
    ) {
        val interval = advertInterval.toLongOrNull() ?: uiState.value.advertInterval

        viewModelScope.launch(Dispatchers.IO) {
            dataStore.edit { prefs ->
                prefs[LOCK_ID_KEY] = lockId
                prefs[ISSUER_BEACON_NAME_KEY] = issuerBeaconName
                prefs[ISSUER_BEACON_ADDRESS_KEY] = issuerBeaconAddress
                prefs[ADVERT_INTERVAL_KEY] = interval.toString()
            }
        }

        _uiState.update {
            it.copy(
                lockId = lockId,
                issuerBeaconName = issuerBeaconName,
                issuerBeaconAddress = issuerBeaconAddress,
                advertInterval = interval
            )
        }
        log("Configuration saved.")
    }

    fun getSessionKey(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            _uiState.update { it.copy(isGettingKey = true, hasSessionKey = false, sessionExpiryTime = 0L) }
            log("Scanning for issuer beacon...")

            val config = uiState.value

            try {
                val (key, expiry, nonce) = scanAndProvision(context, config)

                sessionKey = key
                sessionExpiry = expiry
                this@AdvertiserViewModel.nonce = nonce
                log("Session key received. Expires: $expiry")
                log("Key (Base64): ${Base64.getEncoder().encodeToString(key)}")
                if (nonce != null) {
                    log("Nonce: $nonce")
                }
                // *** MODIFIED: Update UI state with expiry time ***
                _uiState.update { it.copy(hasSessionKey = true, sessionExpiryTime = expiry) }

            } catch (e: Exception) {
                if (e is CancellationException) {
                    log("Key request cancelled.")
                } else {
                    log("Error getting key: ${e.message}")
                    e.printStackTrace()
                }
                _uiState.update { it.copy(hasSessionKey = false) }
            } finally {
                log("getSessionKey job finished.")
                _uiState.update { it.copy(isGettingKey = false) }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun scanAndProvision(
        context: Context,
        config: AdvertiserUiState
    ): Triple<ByteArray, Long, String?> = withTimeout(30_000L) {
        suspendCancellableCoroutine { continuation ->
            val btManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            bleScanner = btManager.adapter.bluetoothLeScanner

            if (bleScanner == null) {
                continuation.resumeWithException(Exception("BLE Scanner not available"))
                return@suspendCancellableCoroutine
            }

            val scanCallback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult?) {
                    result?.let { scanResult ->
                        val device = scanResult.device
                        val scanRecord = scanResult.scanRecord

                        // Check if this matches our issuer beacon
                        val nameMatch = if (config.issuerBeaconName.isNotEmpty()) {
                            device.name == config.issuerBeaconName ||
                                    scanRecord?.deviceName == config.issuerBeaconName
                        } else false

                        val addressMatch = if (config.issuerBeaconAddress.isNotEmpty()) {
                            device.address.equals(config.issuerBeaconAddress, ignoreCase = true)
                        } else false

                        val manufacturerMatch = scanRecord?.manufacturerSpecificData?.get(MANUFACTURER_ID) != null

                        if (nameMatch || addressMatch || manufacturerMatch) {
                            log("Found issuer beacon: ${device.name ?: "unknown"} (${device.address})")
                            bleScanner?.stopScan(this)

                            // Connect and provision
                            viewModelScope.launch(Dispatchers.IO) {
                                try {
                                    val result = connectAndProvision(context, device, config.lockId)
                                    if (continuation.isActive) {
                                        continuation.resume(result)
                                    }
                                } catch (e: Exception) {
                                    if (continuation.isActive) {
                                        continuation.resumeWithException(e)
                                    }
                                }
                            }
                        }
                    }
                }

                override fun onScanFailed(errorCode: Int) {
                    log("Scan failed with error: $errorCode")
                    if (continuation.isActive) {
                        continuation.resumeWithException(Exception("BLE scan failed: $errorCode"))
                    }
                }
            }

            val scanSettings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build()

            val filters = mutableListOf<ScanFilter>()
            
            // Add manufacturer data filter
            filters.add(
                ScanFilter.Builder()
                    .setManufacturerData(MANUFACTURER_ID, ByteArray(0))
                    .build()
            )

            try {
                log("Starting BLE scan...")
                bleScanner?.startScan(filters, scanSettings, scanCallback)
            } catch (e: Exception) {
                continuation.resumeWithException(Exception("Failed to start scan: ${e.message}"))
                return@suspendCancellableCoroutine
            }

            continuation.invokeOnCancellation {
                viewModelScope.launch(Dispatchers.IO) {
                    try {
                        log("Stopping BLE scan...")
                        bleScanner?.stopScan(scanCallback)
                    } catch (e: Exception) {
                        log("Error stopping scan: ${e.message}")
                    }
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun connectAndProvision(
        context: Context,
        device: android.bluetooth.BluetoothDevice,
        lockId: String
    ): Triple<ByteArray, Long, String?> = suspendCancellableCoroutine { continuation ->
        val responseChannel = Channel<ByteArray>(Channel.CONFLATED)
        var gatt: BluetoothGatt? = null

        val gattCallback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt?, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        log("Connected to issuer beacon, discovering services...")
                        gatt?.discoverServices()
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        log("Disconnected from issuer beacon")
                    }
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt?, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    log("Services discovered")
                    val service = gatt?.getService(UUID.fromString(PROVISIONING_SERVICE_UUID))
                    val characteristic = service?.getCharacteristic(
                        UUID.fromString(PROVISIONING_CHARACTERISTIC_UUID)
                    )

                    if (characteristic != null) {
                        // Enable notifications
                        gatt?.setCharacteristicNotification(characteristic, true)
                        
                        // Write descriptor to enable notifications
                        val descriptor = characteristic.getDescriptor(
                            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
                        )
                        descriptor?.let {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                gatt?.writeDescriptor(it, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                            } else {
                                @Suppress("DEPRECATION")
                                it.value = BluetoothGattDescriptor
                                    .ENABLE_NOTIFICATION_VALUE
                                @Suppress("DEPRECATION")
                                gatt?.writeDescriptor(it)
                            }
                        }

                        // Send provisioning request
                        viewModelScope.launch {
                            delay(500) // Give time for notifications to be enabled
                            
                            val request = JSONObject().apply {
                                put("lock_id", lockId)
                                put("client_time", System.currentTimeMillis() / 1000)
                            }
                            val requestBytes = request.toString().toByteArray()

                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                gatt?.writeCharacteristic(
                                    characteristic,
                                    requestBytes,
                                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                                )
                            } else {
                                @Suppress("DEPRECATION")
                                characteristic.value = requestBytes
                                @Suppress("DEPRECATION")
                                gatt?.writeCharacteristic(characteristic)
                            }
                            log("Sent provisioning request")
                        }
                    } else {
                        if (continuation.isActive) {
                            continuation.resumeWithException(
                                Exception("Provisioning characteristic not found")
                            )
                        }
                        gatt?.disconnect()
                    }
                } else {
                    if (continuation.isActive) {
                        continuation.resumeWithException(
                            Exception("Service discovery failed: $status")
                        )
                    }
                    gatt?.disconnect()
                }
            }

            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray
            ) {
                viewModelScope.launch {
                    responseChannel.send(value)
                }
            }

            @Deprecated("Deprecated in API 33")
            override fun onCharacteristicChanged(
                gatt: BluetoothGatt?,
                characteristic: BluetoothGattCharacteristic?
            ) {
                 characteristic?.value?.let { data ->
                    viewModelScope.launch {
                        responseChannel.send(data)
                    }
                }
            }
        }

        try {
            log("Connecting to issuer beacon...")
            gatt = device.connectGatt(context, false, gattCallback)

            // Wait for response with timeout
            viewModelScope.launch {
                try {
                    withTimeout(15_000L) {
                        val responseData = responseChannel.receive()
                        val response = JSONObject(String(responseData))

                        if (response.optString("status") == "ok") {
                            val keyB64 = response.getString("session_key")
                            val key = Base64.getDecoder().decode(keyB64)
                            val expiry = response.optLong("expiry", 0L)
                            val nonce = response.optString("nonce", null)
                            
                            val clockOffset = response.optInt("clock_offset", 0)
                            if (clockOffset != 0) {
                                log("Issuer reported clock offset: $clockOffset")
                            }

                            if (continuation.isActive) {
                                continuation.resume(Triple(key, expiry, nonce))
                            }
                        } else {
                            val errorMsg = response.optString("message", "Unknown error")
                            if (continuation.isActive) {
                                continuation.resumeWithException(Exception("Provisioning failed: $errorMsg"))
                            }
                        }
                        
                        gatt?.disconnect()
                    }
                } catch (e: TimeoutCancellationException) {
                    if (continuation.isActive) {
                        continuation.resumeWithException(Exception("Timeout waiting for provisioning response"))
                    }
                    gatt?.disconnect()
                } catch (e: Exception) {
                    if (continuation.isActive) {
                        continuation.resumeWithException(e)
                    }
                    gatt?.disconnect()
                }
            }

        } catch (e: Exception) {
            if (continuation.isActive) {
                continuation.resumeWithException(Exception("Failed to connect: ${e.message}"))
            }
        }

        continuation.invokeOnCancellation {
            viewModelScope.launch(Dispatchers.IO) {
                try {
                    log("Disconnecting from issuer beacon...")
                    gatt?.disconnect()
                    gatt?.close()
                } catch (e: Exception) {
                    log("Error during disconnect: ${e.message}")
                }
            }
        }
    }

    // *** MODIFIED: Reworked start/stop logic ***
    fun startAdvertisingLoop(context: Context) {
        if (uiState.value.isAdvertising) {
            log("Already advertising.")
            return
        }
        if (sessionKey == null) {
            log("Error: Must get session key before advertising.")
            return
        }
        // Check for expiry *before* starting
        val currentTime = System.currentTimeMillis() / 1000L
        val remaining = sessionExpiry - currentTime
        if (sessionExpiry != 0L && remaining <= 0) {
            log("Error: Session key has already expired. Get a new key.")
            // Clear the expired key
            _uiState.update { it.copy(hasSessionKey = false, sessionExpiryTime = 0L) }
            sessionKey = null
            sessionExpiry = 0L
            nonce = null
            return
        }

        if (!isBleAdapterEnabled(context)) {
            log("Error: Bluetooth is not enabled.")
            return
        }

        _uiState.update { it.copy(isAdvertising = true) }
        log("Starting advertising loop...")

        advertiserJob = viewModelScope.launch(Dispatchers.IO) {
            var keyExpired = false
            try {
                // Pass a lambda to be called if the key expires during the loop
                advertisingLoopInternal(context, uiState.value) {
                    keyExpired = true
                }

                // This code runs if the loop finishes *without* cancellation
                if (keyExpired) {
                    log("Session expired. Clearing key.")
                    _uiState.update { it.copy(isAdvertising = false, hasSessionKey = false, sessionExpiryTime = 0L) }
                    sessionKey = null
                    sessionExpiry = 0L
                    nonce = null
                } else {
                    // This shouldn't happen unless loop is changed, but good to handle
                    log("Advertising loop finished unexpectedly.")
                    _uiState.update { it.copy(isAdvertising = false) }
                }

            } catch (e: CancellationException) {
                // This runs when stopAdvertisingLoop() is called
                log("Advertising stopped by user.")
                // Update advertising state, but *keep* the session key
                _uiState.update { it.copy(isAdvertising = false) }
            } catch (e: Exception) {
                // This runs on any other error
                log("Advertising loop error: ${e.message}")
                // An error occurred, clear the key
                _uiState.update { it.copy(isAdvertising = false, hasSessionKey = false, sessionExpiryTime = 0L) }
                sessionKey = null
                sessionExpiry = 0L
                nonce = null
            } finally {
                // This *always* runs to ensure BLE advertising is stopped
                log("Cleaning up advertising hardware...")
                stopBleAdvertising()
            }
        }
    }

    fun stopAdvertisingLoop() {
        advertiserJob?.cancel()
    }

    @SuppressLint("MissingPermission")
    private suspend fun advertisingLoopInternal(
        context: Context,
        config: AdvertiserUiState,
        onKeyExpired: () -> Unit // *** MODIFIED: Added lambda ***
    ) {
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
                onKeyExpired() // *** MODIFIED: Call lambda ***
                break
            }

            val token = generateToken(config.advertInterval)
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

    private fun generateToken(advertInterval: Long): ByteArray {
        val key = sessionKey ?: throw IllegalStateException("Session key is null")
        val ts = (System.currentTimeMillis() / 1000L) / advertInterval
        
        val components = mutableListOf<ByteArray>()
        nonce?.let { components.add(it.toByteArray(Charsets.UTF_8)) }
        components.add(ts.toString().toByteArray(Charsets.UTF_8))
        
        val msg = components.reduce { acc, bytes -> acc + bytes }

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg).copyOfRange(0, 16)
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

// *** MODIFIED: Added sessionExpiryTime ***
data class AdvertiserUiState(
    val lockId: String = "loading...",
    val issuerBeaconName: String = "loading...",
    val issuerBeaconAddress: String = "loading...",
    val advertInterval: Long = 5,
    val isGettingKey: Boolean = false,
    val isAdvertising: Boolean = false,
    val hasSessionKey: Boolean = false,
    val sessionExpiryTime: Long = 0L, // Timestamp of expiry
    val logs: List<String> = emptyList()
)

private data class SavedConfig(
    val lockId: String,
    val issuerBeaconName: String,
    val issuerBeaconAddress: String,
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
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.ACCESS_FINE_LOCATION
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
                    "This app requires Bluetooth permissions to scan for and communicate " +
                            "with the issuer beacon, and to advertise your unlock token."
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
            onSave = { lockId, beaconName, beaconAddr, interval ->
                viewModel.onSaveConfig(lockId, beaconName, beaconAddr, interval)
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
    var draftBeaconName by remember(uiState.issuerBeaconName) {
        mutableStateOf(uiState.issuerBeaconName)
    }
    var draftBeaconAddress by remember(uiState.issuerBeaconAddress) {
        mutableStateOf(uiState.issuerBeaconAddress)
    }
    var draftAdvertInterval by remember(uiState.advertInterval) {
        mutableStateOf(uiState.advertInterval.toString())
    }

    val isEnabled = !uiState.isAdvertising && !uiState.isGettingKey

    Column {
        Text("Configuration", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))

        ConfigTextField(
            label = "Lock ID",
            value = draftLockId,
            onValueChange = { draftLockId = it },
            enabled = isEnabled
        )
        ConfigTextField(
            label = "Issuer Beacon Name",
            value = draftBeaconName,
            onValueChange = { draftBeaconName = it },
            enabled = isEnabled
        )
        ConfigTextField(
            label = "Issuer Beacon Address (optional)",
            value = draftBeaconAddress,
            onValueChange = { draftBeaconAddress = it },
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
            onClick = { 
                onSave(draftLockId, draftBeaconName, draftBeaconAddress, draftAdvertInterval) 
            },
            enabled = isEnabled,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Save Config")
        }
    }
}

// *** MODIFIED: Reworked ControlPanel to show expiry time ***
@Composable
fun ControlPanel(
    uiState: AdvertiserUiState,
    onGetKey: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit
) {
    val isBusy = uiState.isAdvertising || uiState.isGettingKey
    val expiryTime = uiState.sessionExpiryTime
    var remainingTime by remember { mutableStateOf<Long?>(null) }

    // This effect runs when expiryTime changes. It updates the
    // remaining time every second.
    LaunchedEffect(expiryTime) {
        if (expiryTime == 0L) {
            remainingTime = null
            return@LaunchedEffect
        }

        while (isActive) {
            val current = System.currentTimeMillis() / 1000L
            val remaining = expiryTime - current
            remainingTime = if (remaining > 0) remaining else 0L

            if (remaining <= 0) {
                // Stop the countdown, the ViewModel will handle the
                // actual expiry logic and reset expiryTime to 0.
                break
            }
            delay(1000L)
        }
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
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

        // Show the remaining time
        remainingTime?.let {
            if (it > 0 || uiState.isAdvertising) { // Show "00:00" briefly if still advertising
                Spacer(Modifier.height(12.dp))
                val timeColor = if (it < 60 && it > 0) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f)
                }
                Text(
                    text = "Key expires in: ${formatRemainingTime(it)}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = timeColor
                )
            }
        }
    }
}

/**
 * Formats a duration in seconds into MM:SS string.
 */
private fun formatRemainingTime(totalSeconds: Long): String {
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    return "%02d:%02d".format(minutes, seconds)
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
