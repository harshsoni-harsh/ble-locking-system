import base64
import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, Optional, cast

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
	load_pem_private_key,
	load_pem_public_key,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT_DIR / "keys"

MQTT_BROKER = "10.0.10.142"
MQTT_PORT = 1883

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

with open(KEYS_DIR / "backend_private.pem", "rb") as handle:
	BACKEND_PRIVATE_KEY = cast(
		rsa.RSAPrivateKey,
		load_pem_private_key(handle.read(), password=None, backend=default_backend()),
	)

LOCK_PUBLIC_KEYS: Dict[str, Path] = {
    p.stem.replace("_public", ""): p
    for p in KEYS_DIR.glob("*_public.pem")
}

def generate_session_key() -> bytes:
	return os.urandom(32)

def load_lock_public_key(device_id: str) -> rsa.RSAPublicKey:
	key_path = LOCK_PUBLIC_KEYS.get(device_id)
	if key_path is None or not key_path.exists():
		raise ValueError(f"Unknown lock id {device_id}")
	with open(key_path, "rb") as handle:
		return cast(
			rsa.RSAPublicKey,
			load_pem_public_key(handle.read(), backend=default_backend()),
		)

def encrypt_for_lock(session_key: bytes, device_id: str) -> bytes:
	pubkey = load_lock_public_key(device_id)
	return pubkey.encrypt(
		session_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None,
		),
	)

def sign_payload(payload: bytes) -> str:
	signature = BACKEND_PRIVATE_KEY.sign(
		payload,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH,
		),
		hashes.SHA256(),
	)
	return base64.b64encode(signature).decode()

def issue_session_key(
	device_id: str,
	expiry: int = 300,
	clock_offset: Optional[int] = None,
):
	session_key = generate_session_key()
	encrypted_key = encrypt_for_lock(session_key, device_id)
	expiry_ts = int(time.time()) + expiry
	nonce = base64.urlsafe_b64encode(os.urandom(8)).decode()

	payload_dict = {
		"device_id": device_id,
		"session_key": base64.b64encode(encrypted_key).decode(),
		"expiry": expiry_ts,
		"nonce": nonce,
	}
	if clock_offset is not None:
		payload_dict["clock_offset"] = clock_offset
	payload_json = json.dumps(payload_dict, separators=(",", ":"))
	payload_dict["signature"] = sign_payload(payload_json.encode())
	final_payload = json.dumps(payload_dict, separators=(",", ":"))

	client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
	client.connect(MQTT_BROKER, MQTT_PORT, 60)
	client.loop_start()
	try:
		topic = f"locks/{device_id}/session"
		client.publish(topic, final_payload, qos=1).wait_for_publish()
		logger.info("Published encrypted session key for %s to %s", device_id, topic)

		guest_payload = {
			"session_key": base64.b64encode(session_key).decode(),
			"expiry": expiry_ts,
			"nonce": nonce,
		}
		if clock_offset is not None:
			guest_payload["clock_offset"] = clock_offset
		guest_topic = f"guests/{device_id}/session"
		client.publish(guest_topic, json.dumps(guest_payload), qos=1).wait_for_publish()
		logger.info("Published plain session key for %s to %s", device_id, guest_topic)
	finally:
		client.loop_stop()
		client.disconnect()
	return session_key, expiry_ts, nonce

def on_message(client, userdata, msg):
	logger.info("Received request on %s", msg.topic)
	try:
		payload = json.loads(msg.payload.decode())
	except json.JSONDecodeError:
		logger.error("Invalid request payload")
		return

	device_id = payload.get("lock_id")
	client_time = payload.get("curr_time")
	server_time = int(time.time())
	clock_offset = 0
	if isinstance(client_time, (int, float)):
		clock_offset = int(client_time) - server_time
		logger.info(
			"Clock offset for request: client=%s server=%s offset=%s",
			int(client_time),
			server_time,
			clock_offset,
		)
	if device_id and device_id in LOCK_PUBLIC_KEYS:
		issue_session_key(
			device_id,
			clock_offset=clock_offset,
		)
	else:
		logger.error("Invalid request")

def main():
	client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
	client.on_message = on_message
	try:
		client.connect(MQTT_BROKER, MQTT_PORT, 60)
		request_topic = "backend/session_requests"
		client.subscribe(request_topic)
		logger.info("Backend listening for session requests on %s", request_topic)
		client.loop_forever()
	except ConnectionRefusedError:
		logger.error(
			"Failed to connect to MQTT broker. Make sure the broker is running on %s:%s",
			MQTT_BROKER,
			MQTT_PORT,
		)
	except KeyboardInterrupt:
		logger.info("Script stopped by user.")
	except Exception as exc:
		logger.exception("Unhandled error in backend issuer: %s", exc)

if __name__ == "__main__":
	main()
