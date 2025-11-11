import base64
import json
import logging
import os
import time
from typing import Any, Dict, Optional

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from cryptography.hazmat.primitives.asymmetric import rsa

from . import config
from .ble_utils import normalize_mac
from .keystore import KeyStore

logger = logging.getLogger(__name__)

def generate_session_key() -> bytes:
	return os.urandom(32)

class SessionIssuer:
	def __init__(
		self,
		keystore: KeyStore,
		broker: str = config.MQTT_BROKER,
		port: int = config.MQTT_PORT,
		expiry_seconds: int = config.SESSION_EXPIRY_SECONDS,
	):
		self._keystore = keystore
		self._broker = broker
		self._port = port
		self._expiry_seconds = expiry_seconds

	def issue_session(
		self,
		lock_id: str,
		*,
		phone_mac: Optional[str] = None,
		client_id: Optional[str] = None,
		client_time: Optional[float] = None,
		unlocker_public_key: Optional[rsa.RSAPublicKey] = None,
	) -> Dict[str, Any]:
		if not self._keystore.has_lock(lock_id):
			raise ValueError(f"Unknown lock id {lock_id}")

		resolved_client_id = client_id
		resolved_unlocker_key = unlocker_public_key
		if resolved_unlocker_key is None:
			if not resolved_client_id:
				raise ValueError("missing client identifier")
			resolved_unlocker_key = self._keystore.load_unlocker_public_key(resolved_client_id)
		else:
			if not resolved_client_id:
				resolved_client_id = self._keystore.fingerprint_public_key(resolved_unlocker_key)

		session_key = generate_session_key()
		encrypted_key = self._keystore.encrypt_for_lock(session_key, lock_id)
		server_time = int(time.time())
		expiry_ts = server_time + self._expiry_seconds
		nonce = base64.urlsafe_b64encode(os.urandom(8)).decode()
		normalized_mac = normalize_mac(phone_mac)
		clock_offset = 0
		if isinstance(client_time, (int, float)):
			clock_offset = int(client_time) - server_time

		payload_dict: Dict[str, Any] = {
			"device_id": lock_id,
			"session_key": base64.b64encode(encrypted_key).decode(),
			"expiry": expiry_ts,
			"nonce": nonce,
		}
		if normalized_mac:
			payload_dict["phone_mac"] = normalized_mac
		if isinstance(client_time, (int, float)):
			payload_dict["clock_offset"] = clock_offset

		payload_json = json.dumps(payload_dict, separators=(",", ":"))
		payload_dict["signature"] = self._keystore.sign_payload(payload_json.encode())
		final_payload = json.dumps(payload_dict, separators=(",", ":"))

		topic = f"locks/{lock_id}/session"
		logger.info("Publishing session payload for %s to %s", lock_id, topic)
		self._publish(topic, final_payload)

		guest_payload: Dict[str, Any] = {
			"session_key": base64.b64encode(session_key).decode(),
			"expiry": expiry_ts,
			"nonce": nonce,
		}
		if normalized_mac:
			guest_payload["phone_mac"] = normalized_mac
		if isinstance(client_time, (int, float)):
			guest_payload["clock_offset"] = clock_offset
		guest_payload_json = json.dumps(guest_payload, separators=(",", ":")).encode()
		encrypted_guest_payload = self._keystore.encrypt_for_unlocker(
			guest_payload_json,
			client_id=resolved_client_id if unlocker_public_key is None else None,
			public_key=resolved_unlocker_key,
		)
		guest_signature = self._keystore.sign_payload(guest_payload_json)

		logger.info(
			"Issued session for %s (expires %s, offset %s) to %s",
			lock_id,
			expiry_ts,
			clock_offset,
			resolved_client_id,
		)
		return {
			"payload": base64.b64encode(encrypted_guest_payload).decode(),
			"signature": guest_signature,
			"encryption": {
				"algorithm": "RSA-OAEP",
				"hash": "SHA256",
			},
		}

	def _publish(self, topic: str, payload: str) -> None:
		client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
		client.connect(self._broker, self._port, 60)
		client.loop_start()
		try:
			client.publish(topic, payload, qos=1).wait_for_publish()
		finally:
			client.loop_stop()
			client.disconnect()
