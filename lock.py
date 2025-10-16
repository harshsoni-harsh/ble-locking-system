import asyncio
import paho.mqtt.client as mqtt
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
import hmac, hashlib, time
from bleak.backends.scanner import AdvertisementData

MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_TOPIC = "locks/status"
LOCK_ID = "lock_01"
SHARED_SECRETS = {
	"AA:BB:CC:DD:EE:FF": b"supersecretkey1",
	"11:22:33:44:55:66": b"supersecretkey2",  # Example multiple authorized phones
}
RSSI_THRESHOLD = -70
TOKEN_WINDOW = 30			# seconds
DEVICE_TIMEOUT = 10			# seconds to auto-lock if device disappears

lock_state = {"locked": True, "battery": 100, "proximity": False}
last_seen = {}  # mac -> timestamp of last seen advertisement

# ---------------- MQTT ----------------
client = mqtt.Client()

def on_connect(client, userdata, flags, rc):
	if rc == 0:
		print("MQTT connected successfully")
	else:
		print(f"MQTT connection failed: {rc}")

client.on_connect = on_connect
client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.loop_start()

def publish_status():
	payload = str({
		"lock_id": LOCK_ID,
		"locked": lock_state["locked"],
		"battery": lock_state["battery"],
		"proximity": lock_state["proximity"]
	})
	client.publish(MQTT_TOPIC, payload)

# ---------------- TOKEN VALIDATION ----------------
def validate_token(mac: str, token: bytes) -> bool:
	"""Check rolling token using HMAC with shared secret and timestamp."""
	secret = SHARED_SECRETS.get(mac.upper())
	if not secret:
		return False
	ts = int(time.time() // TOKEN_WINDOW)
	expected = hmac.new(secret, mac.encode() + str(ts).encode(), hashlib.sha256).digest()[:16]
	return hmac.compare_digest(expected, token)

def parse_manufacturer_data(adv_data: dict) -> bytes:
	"""Extract the first manufacturer data blob as token."""
	if adv_data:
		return next(iter(adv_data.values()))
	return b""

# ---------------- BLE SCANNER ----------------
def handle_detection(device: BLEDevice, advertisement_data: AdvertisementData):
	mac = device.address.upper()
	token = parse_manufacturer_data(advertisement_data.manufacturer_data)
	rssi = advertisement_data.rssi
	is_valid = token and validate_token(mac, token)
	is_nearby = rssi > RSSI_THRESHOLD
	
	if mac in SHARED_SECRETS.keys():
		print(f"[SCAN] Detected {mac} RSSI={rssi} Token={token.hex()} Valid={'✅' if is_valid else '❌'} Nearby={'✅' if is_nearby else '❌'}")

	if is_valid and is_nearby:
		last_seen[mac] = time.time()

	if is_valid and is_nearby:
		if lock_state["locked"]:
			lock_state["locked"] = False
			print(f"[UNLOCK] Device {mac} nearby, RSSI {rssi}")
			publish_status()
		if not lock_state["proximity"]:
			lock_state["proximity"] = True
			publish_status()
	else:
		if lock_state["proximity"]:
			lock_state["proximity"] = False
			publish_status()

# ---------------- AUTO-LOCK WATCHDOG ----------------
async def watchdog_loop():
	while True:
		now = time.time()
		unlocked = not lock_state["locked"]
		proximity_changed = False

		for mac, ts in list(last_seen.items()):
			if now - ts > DEVICE_TIMEOUT:
				print(f"[TIMEOUT] Device {mac} not seen for {DEVICE_TIMEOUT}s → locking")
				last_seen.pop(mac)
				lock_state["locked"] = True
				lock_state["proximity"] = False
				proximity_changed = True

		if proximity_changed or unlocked != lock_state["locked"]:
			publish_status()
		await asyncio.sleep(1)

# ---------------- MAIN LOOP ----------------
async def main_loop():
	print("Starting BLE scanner (Bleak)...")
	scanner = BleakScanner(detection_callback=handle_detection)
	await scanner.start()
	print(f"Scanning for authorized devices: {list(SHARED_SECRETS.keys())}")
	try:
		await watchdog_loop()
	finally:
		await scanner.stop()
		print("BLE scanner stopped.")

if __name__ == "__main__":
	try:
		asyncio.run(main_loop())
	except KeyboardInterrupt:
		print("Stopping lock application...")
	finally:
		client.loop_stop()
		client.disconnect()
		print("MQTT disconnected.")
