import asyncio
import base64
import json
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

MQTT_BROKER = "10.0.15.108"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
RSSI_THRESHOLD = -70

BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY = load_keys(LOCK_ID)

SESSION: Optional[SessionRecord] = None


def on_message(client, userdata, msg):
	global SESSION
	print(f"Received MQTT message on {msg.topic}")

	try:
		payload = json.loads(msg.payload.decode())
	except json.JSONDecodeError:
		print("Malformed JSON payload; ignoring")
		return

	try:
		session = extract_session(payload, LOCK_ID, BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY)
	except SessionError as exc:
		print(f"Invalid session payload: {exc}")
		return

	SESSION = session
	key_b64 = base64.b64encode(session.key).decode()
	print(
		f"Decrypted session key: {key_b64} (expires {session.expiry}, nonce {session.nonce})"
	)
	if session.offset:
		print(
			f"Applied clock offset {session.offset} seconds for session; phone={session.phone_mac}"
		)
	else:
		print(f"Session registered for phone={session.phone_mac}")


def detection_callback(device, advertisement_data):
	session = SESSION
	if session is None:
		return

	token_map = advertisement_data.manufacturer_data or {}
	if MANUFACTURER_ID not in token_map:
		return

	token = token_map[MANUFACTURER_ID]
	rssi = advertisement_data.rssi
	print(f"RSSI: {rssi}, Threshold: {RSSI_THRESHOLD}")
	if rssi is not None and rssi <= RSSI_THRESHOLD:
		print("Device too far; ignoring")
		return

	device_mac = normalize_mac(device.address)
	if not matches_mac(session, device_mac):
		print(f"Ignoring advertisement from unexpected device {device_mac}")
		return

	if has_expired(session):
		print(f"Session key expired at {session.expiry}; rejecting token")
		return

	if validate_token(token, session):
		print("Token valid! Unlocking...")
	else:
		print(f"Invalid token: {token.hex()}")


async def main():
	client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
	client.on_message = on_message
	client.connect(MQTT_BROKER, MQTT_PORT, 60)
	topic = f"locks/{LOCK_ID}/session"
	client.subscribe(topic)
	client.loop_start()
	print(f"Subscribed to {topic} for session keys")

	scanner = BleakScanner(detection_callback=detection_callback)
	await scanner.start()
	print("BLE scanner started")

	try:
		while True:
			await asyncio.sleep(1)
	except KeyboardInterrupt:
		print("Stopping...")
	finally:
		client.loop_stop()
		client.disconnect()
		await scanner.stop()


if __name__ == "__main__":
	asyncio.run(main())
