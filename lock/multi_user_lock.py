import asyncio
import base64
import json
import logging
from typing import List, Optional

import paho.mqtt.client as mqtt
from bleak import BleakScanner
from paho.mqtt.enums import CallbackAPIVersion

from lock.core import (
	MANUFACTURER_ID,
	SessionError,
	SessionRecord,
	extract_session,
	has_expired,
	load_keys,
	normalize_mac,
	validate_token,
)

MQTT_BROKER = "10.0.10.142"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
RSSI_THRESHOLD = -70

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SESSIONS: List[SessionRecord] = []

BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY = load_keys(LOCK_ID)

def on_message(client, userdata, msg):
	global SESSIONS
	logger.info("Received request on %s", msg.topic)
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

	SESSIONS.append(session)
	key_b64 = base64.b64encode(session.key).decode()
	logger.info(
		"Added session: key=%s expires=%s nonce=%s mac=%s",
		key_b64,
		session.expiry,
		session.nonce,
		session.phone_mac,
	)

	SESSIONS = [s for s in SESSIONS if not has_expired(s)]
	logger.info("Active sessions: %d", len(SESSIONS))

def detection_callback(device, advertisement_data):
	token_sources = advertisement_data.manufacturer_data or {}
	token = token_sources.get(MANUFACTURER_ID)
	if not token:
		return

	rssi = advertisement_data.rssi
	logger.debug("RSSI %s, threshold %s", rssi, RSSI_THRESHOLD)
	if rssi is not None and rssi <= RSSI_THRESHOLD:
		logger.info("Device %s below RSSI threshold; RSSI=%s; ignoring", device.address, rssi)
		return

	device_mac = normalize_mac(device.address)
	
	for session in SESSIONS:
		if has_expired(session):
			continue
			
		if validate_token(token, session):
			logger.info(
				"Token valid for session (mac=%s, rssi=%s); unlocking",
				device_mac,
				rssi,
			)
			return
	
	logger.debug("No matching session for device %s with token %s", device_mac, token.hex()[:16])

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
