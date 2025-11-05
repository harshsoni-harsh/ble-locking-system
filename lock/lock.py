import asyncio
import base64
import json
import logging
import time

import paho.mqtt.client as mqtt
from bleak import BleakScanner
from paho.mqtt.enums import CallbackAPIVersion

from .auth_service import register_auth_service, unregister_auth_service
from .constants import MANUFACTURER_ID
from .core import SessionError, extract_session, load_keys
from .hybrid import HybridAuthenticator
from .utils import normalize_mac

MQTT_BROKER = "0.0.0.0"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
RSSI_THRESHOLD = -70

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY = load_keys(LOCK_ID)
AUTHENTICATOR = HybridAuthenticator(LOCK_ID)


def _log_unlock(mac: str, _session) -> None:
	logger.info("Unlock granted to %s", mac)


AUTHENTICATOR.on_unlock = _log_unlock


def on_message(client, _userdata, msg):
	logger.info("Received MQTT message on %s", msg.topic)
	try:
		payload = json.loads(msg.payload.decode())
	except json.JSONDecodeError:
		logger.error("Malformed JSON payload; ignoring")
		return

	try:
		session = extract_session(payload, LOCK_ID, BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY)
	except SessionError as exc:
		logger.error("Invalid session payload: %s", exc)
		return

	try:
		AUTHENTICATOR.register_session(session)
	except ValueError as exc:
		logger.error("Session rejected: %s", exc)
		return

	key_b64 = base64.b64encode(session.key).decode()
	logger.info(
		"Stored session for %s exp=%s nonce=%s key=%s",
		session.phone_mac,
		session.expiry,
		session.nonce,
		key_b64,
	)


def detection_callback(device, advertisement_data):
	payload_map = advertisement_data.manufacturer_data or {}
	payload = payload_map.get(MANUFACTURER_ID)
	if not payload:
		return

	rssi = advertisement_data.rssi
	if rssi is not None and rssi <= RSSI_THRESHOLD:
		logger.debug("Device %s below RSSI threshold (%s <= %s)", device.address, rssi, RSSI_THRESHOLD)
		return

	verification = AUTHENTICATOR.handle_advertisement(
		device.address,
		bytes(payload),
		rssi,
		now=time.time(),
	)
	if verification:
		mac = normalize_mac(device.address)
		logger.info(
			"Accepted advertisement from %s (step=0x%02X, rssi=%s)",
			mac,
			verification.frame.time_step,
			rssi,
		)


async def setup_mqtt() -> mqtt.Client:
	client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
	client.on_message = on_message
	client.connect(MQTT_BROKER, MQTT_PORT, 60)
	topic = f"locks/{LOCK_ID}/session"
	client.subscribe(topic)
	client.loop_start()
	logger.info("Subscribed to %s for session keys", topic)
	return client


async def main():
	client = await setup_mqtt()

	try:
		service, bus, adapter = await register_auth_service(AUTHENTICATOR)
	except RuntimeError as exc:
		logger.error("Unable to register BLE GATT service: %s", exc)
		client.loop_stop()
		client.disconnect()
		return

	scanner = BleakScanner(detection_callback=detection_callback)
	try:
		await scanner.start()
	except Exception as exc:
		logger.error("Failed to start BLE scanner: %s", exc)
		await unregister_auth_service(service, bus, adapter)
		client.loop_stop()
		client.disconnect()
		return

	logger.info("BLE scanner started (watching manufacturer 0x%04X)", MANUFACTURER_ID)

	try:
		while True:
			AUTHENTICATOR.purge()
			await asyncio.sleep(1)
	except KeyboardInterrupt:
		logger.info("Stopping...")
	finally:
		client.loop_stop()
		client.disconnect()
		await scanner.stop()
		await unregister_auth_service(service, bus, adapter)


if __name__ == "__main__":
	asyncio.run(main())
