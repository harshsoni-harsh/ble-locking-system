import asyncio
import base64
import json
import logging
import os
import threading
import time
from pathlib import Path
from contextlib import suppress
from typing import Dict, Optional, cast

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.util import Adapter, get_message_bus
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
	load_pem_private_key,
	load_pem_public_key,
)
from dbus_next.constants import MessageType, PropertyAccess
from dbus_next.errors import DBusError
from dbus_next.message import Message
from dbus_next.signature import Variant
from dbus_next.service import dbus_property

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

ISSUER_BEACON_NAME = os.getenv("ISSUER_BEACON_NAME", "IssuerBeacon")
ISSUER_SERVICE_UUIDS = os.getenv("ISSUER_SERVICE_UUIDS", "180D").split(",")
ISSUER_MANUFACTURER_ID = int(os.getenv("ISSUER_MANUFACTURER_ID", str(0xFFFF)))
ISSUER_MANUFACTURER_PAYLOAD = os.getenv("ISSUER_MANUFACTURER_PAYLOAD", "issuer").encode()
ISSUER_ADVERT_PATH = "/com/ble_lock/issuer/advert0"
ISSUER_ADVERT_TIMEOUT = 0


async def get_first_adapter(bus) -> Adapter:
	message = Message(
		destination="org.bluez",
		path="/",
		interface="org.freedesktop.DBus.ObjectManager",
		member="GetManagedObjects",
	)
	reply = await bus.call(message)
	if reply.message_type == MessageType.ERROR:
		raise RuntimeError(
			f"GetManagedObjects failed: {reply.error_name} {reply.body}"
		)

	objects = reply.body[0]
	for path, interfaces in objects.items():
		if "org.bluez.Adapter1" in interfaces:
			introspection = await bus.introspect("org.bluez", path)
			proxy = bus.get_proxy_object("org.bluez", path, introspection)
			return Adapter(proxy)

	raise ValueError("No bluetooth adapters could be found.")


class IssuerBeaconAdvertisement(Advertisement):
	def __init__(self):
		super().__init__(
			localName=ISSUER_BEACON_NAME,
			serviceUUIDs=[uuid.strip() for uuid in ISSUER_SERVICE_UUIDS if uuid.strip()],
			appearance=0x0340,
			timeout=ISSUER_ADVERT_TIMEOUT,
			manufacturerData={ISSUER_MANUFACTURER_ID: ISSUER_MANUFACTURER_PAYLOAD},
		)
		self._manufacturerData[ISSUER_MANUFACTURER_ID] = Variant("ay", ISSUER_MANUFACTURER_PAYLOAD)
		self._advert_path = ISSUER_ADVERT_PATH

	async def start(self, bus, adapter):
		await super().register(bus, adapter, self._advert_path)

	async def stop(self, adapter):
		interface = adapter._proxy.get_interface(self._MANAGER_INTERFACE)
		try:
			await interface.call_unregister_advertisement(self._advert_path)
		except DBusError as exc:
			if getattr(exc, "name", None) != "org.freedesktop.DBus.Error.DoesNotExist":
				raise
	
	@dbus_property(PropertyAccess.READWRITE)
	def TxPower(self) -> "n":  # type: ignore[override]
		return 0

	@TxPower.setter
	def TxPower(self, value: "n") -> None:  # type: ignore[override]
		return


class IssuerBeaconAdvertiser(threading.Thread):
	def __init__(self):
		super().__init__(name="IssuerBeaconAdvertiser", daemon=True)
		self._stop_event = threading.Event()
		self._loop: Optional[asyncio.AbstractEventLoop] = None

	def run(self):
		asyncio.run(self._run())

	async def _run(self):
		try:
			bus = await get_message_bus()
			adapter = await get_first_adapter(bus)
		except Exception as exc:  # pragma: no cover - hardware dependent
			logger.error("Issuer beacon setup failed: %s", exc)
			return

		self._loop = asyncio.get_running_loop()
		advert = IssuerBeaconAdvertisement()
		try:
			await advert.start(bus, adapter)
			try:
				adapter_name = await adapter.get_name()
			except Exception:
				adapter_name = "unknown"
			logger.info(
				"Issuer beacon advertising started on adapter %s", adapter_name
			)
			run_log_once = True
			while not self._stop_event.is_set():
				if run_log_once:
					logger.debug("Issuer beacon advertising loop active")
					run_log_once = False
				await asyncio.sleep(1)
		except Exception as exc:  # pragma: no cover - hardware dependent
			logger.error("Issuer beacon advertising error: %s", exc)
		finally:
			with suppress(Exception):
				await advert.stop(adapter)
			logger.info("Issuer beacon advertising stopped")

	def stop(self, timeout: float = 5.0):
		self._stop_event.set()
		loop = self._loop
		if loop is not None:
			try:
				loop.call_soon_threadsafe(lambda: None)
			except RuntimeError:
				pass
		if self.is_alive():
			self.join(timeout=timeout)

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
	beacon_thread = IssuerBeaconAdvertiser()
	beacon_thread.start()
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
	finally:
		beacon_thread.stop()

if __name__ == "__main__":
	main()
