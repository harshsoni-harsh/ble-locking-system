import asyncio
import base64
import json
import logging
from typing import Optional

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from bleak import BleakScanner

from lock.core import (
	MANUFACTURER_ID,
	SessionError,
	SessionRecord,
	extract_session,
	has_expired,
	load_keys,
	matches_mac,
	normalize_mac,
	validate_token,
)

MQTT_BROKER = "127.0.0.1"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
RSSI_THRESHOLD = -70

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY = load_keys(LOCK_ID)

SESSION: Optional[SessionRecord] = None

def on_message(client, userdata, msg):
	global SESSION
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

	SESSION = session
	key_b64 = base64.b64encode(session.key).decode()
	logger.info(
		"Decrypted session key: %s (expires %s, nonce %s)",
		key_b64,
		session.expiry,
		session.nonce,
	)
	
def detection_callback(device, advertisement_data):
	session = SESSION
	if session is None:
		return

	token_map = advertisement_data.manufacturer_data or {}
	if MANUFACTURER_ID not in token_map:
		return

	token = token_map[MANUFACTURER_ID]
	rssi = advertisement_data.rssi
	logger.debug("RSSI %s, threshold %s", rssi, RSSI_THRESHOLD)
	if rssi is not None and rssi <= RSSI_THRESHOLD:
		logger.info("Device %s below RSSI threshold; ignoring", device.address)
		return

	device_mac = normalize_mac(device.address)
	if not matches_mac(session, device_mac):
		logger.info("Ignoring advertisement from unexpected device %s", device_mac)
		return

	if has_expired(session):
		logger.warning("Session key expired at %s; rejecting token", session.expiry)
		return

	if validate_token(token, session):
		logger.info("Token valid for %s; unlocking", device_mac)
	else:
		logger.warning("Invalid token from %s: %s", device_mac, token.hex())

async def main():
	client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
	client.on_message = on_message
	client.connect(MQTT_BROKER, MQTT_PORT, 60)
	topic = f"locks/{LOCK_ID}/session"
	client.subscribe(topic)
	client.loop_start()
	logger.info("Subscribed to %s for session keys", topic)

	scanner = BleakScanner(detection_callback=detection_callback)
	await scanner.start()
	logger.info("BLE scanner started")

	try:
		while True:
			await asyncio.sleep(1)
	except KeyboardInterrupt:
		logger.info("Stopping...")
	finally:
		client.loop_stop()
		client.disconnect()
		await scanner.stop()

if __name__ == "__main__":
	asyncio.run(main())
