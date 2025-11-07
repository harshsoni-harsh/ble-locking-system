import asyncio
import base64
import json
import logging
import os
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, Optional, cast

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.gatt.characteristic import (
	CharacteristicFlags,
	CharacteristicReadOptions,
	CharacteristicWriteOptions,
	characteristic,
)
from bluez_peripheral.gatt.service import Service, ServiceCollection
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
SESSION_EXPIRY_SECONDS = int(os.getenv("SESSION_EXPIRY_SECONDS", "300"))
PROVISIONING_SERVICE_UUID = os.getenv(
	"PROVISIONING_SERVICE_UUID",
	"c0de0001-0000-1000-8000-00805f9b34fb",
)
PROVISIONING_CHARACTERISTIC_UUID = os.getenv(
	"PROVISIONING_CHARACTERISTIC_UUID",
	"c0de0002-0000-1000-8000-00805f9b34fb",
)

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
_SERVICE_UUIDS_ENV = os.getenv("ISSUER_SERVICE_UUIDS", "180D")
ISSUER_SERVICE_UUIDS = [uuid.strip() for uuid in _SERVICE_UUIDS_ENV.split(",") if uuid.strip()]
if PROVISIONING_SERVICE_UUID not in ISSUER_SERVICE_UUIDS:
	ISSUER_SERVICE_UUIDS.append(PROVISIONING_SERVICE_UUID)
ISSUER_MANUFACTURER_ID = int(os.getenv("ISSUER_MANUFACTURER_ID", str(0xFFFF)))
ISSUER_MANUFACTURER_PAYLOAD = os.getenv("ISSUER_MANUFACTURER_PAYLOAD", "issuer").encode()
ISSUER_ADVERT_PATH = "/com/ble_lock/issuer/advert0"
ISSUER_ADVERT_TIMEOUT = 0

def normalize_mac(value: Optional[str]) -> Optional[str]:
	if not value:
		return None
	return value.replace("-", ":").upper()

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

class SessionIssuer:
	def __init__(self, broker: str, port: int, expiry_seconds: int = SESSION_EXPIRY_SECONDS):
		self._broker = broker
		self._port = port
		self._expiry_seconds = expiry_seconds

	def issue_session(
		self,
		lock_id: str,
		*,
		phone_mac: Optional[str] = None,
		client_time: Optional[float] = None,
	) -> Dict[str, Any]:
		if lock_id not in LOCK_PUBLIC_KEYS:
			raise ValueError(f"Unknown lock id {lock_id}")

		session_key = generate_session_key()
		encrypted_key = encrypt_for_lock(session_key, lock_id)
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
		payload_dict["signature"] = sign_payload(payload_json.encode())
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

		logger.info(
			"Issued session for %s (expires %s, offset %s)",
			lock_id,
			expiry_ts,
			clock_offset,
		)
		return guest_payload

	def _publish(self, topic: str, payload: str) -> None:
		client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
		client.connect(self._broker, self._port, 60)
		client.loop_start()
		try:
			client.publish(topic, payload, qos=1).wait_for_publish()
		finally:
			client.loop_stop()
			client.disconnect()


class ProvisioningService(Service):
	exchange_char = characteristic(
		PROVISIONING_CHARACTERISTIC_UUID,
		CharacteristicFlags.READ
		| CharacteristicFlags.WRITE
		| CharacteristicFlags.NOTIFY,
	)

	def __init__(self, issuer: SessionIssuer):
		self._issuer = issuer
		self._response: bytes = b""
		super().__init__(PROVISIONING_SERVICE_UUID)

	@exchange_char
	def _read_exchange(self, options: CharacteristicReadOptions) -> bytes:
		return self._response

	@exchange_char.setter  # type: ignore[misc]
	async def _write_exchange(self, data: bytes, options: CharacteristicWriteOptions) -> None:
		try:
			payload = json.loads(bytes(data).decode())
		except (UnicodeDecodeError, json.JSONDecodeError):
			logger.error("Received malformed provisioning request")
			response = {"status": "error", "message": "invalid_request"}
		else:
			response = await self._handle_request(payload)
		self._response = json.dumps(response, separators=(",", ":")).encode()
		self.exchange_char.changed(self._response)

	async def _handle_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		lock_id = payload.get("lock_id")
		if not isinstance(lock_id, str) or not lock_id:
			return {"status": "error", "message": "missing_lock_id"}

		phone_mac = payload.get("phone_mac")
		client_time = payload.get("client_time")

		try:
			result = await asyncio.to_thread(
				self._issuer.issue_session,
				lock_id,
				phone_mac=phone_mac,
				client_time=client_time,
			)
		except ValueError as exc:
			logger.warning("Provisioning request rejected for %s: %s", lock_id, exc)
			return {"status": "error", "message": str(exc)}
		except Exception:
			logger.exception("Provisioning request failed for %s", lock_id)
			return {"status": "error", "message": "internal_error"}

		return {"status": "ok", **result}


class IssuerBeaconAdvertiser(threading.Thread):
	def __init__(self, issuer: SessionIssuer):
		super().__init__(name="IssuerBeaconAdvertiser", daemon=True)
		self._stop_event = threading.Event()
		self._loop: Optional[asyncio.AbstractEventLoop] = None
		self._issuer = issuer
		self._service_collection: Optional[ServiceCollection] = None

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
		service = ProvisioningService(self._issuer)
		collection = ServiceCollection([service])
		self._service_collection = collection
		try:
			await advert.start(bus, adapter)
			await collection.register(bus, adapter=adapter)
			try:
				adapter_name = await adapter.get_name()
			except Exception:
				adapter_name = "unknown"
			logger.info(
				"Issuer beacon advertising started on adapter %s", adapter_name
			)
			logger.info("Provisioning GATT service registered")
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
			with suppress(Exception):
				if self._service_collection is not None:
					await self._service_collection.unregister()
			self._service_collection = None
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
def main():
	session_issuer = SessionIssuer(MQTT_BROKER, MQTT_PORT)
	beacon_thread = IssuerBeaconAdvertiser(session_issuer)
	beacon_thread.start()
	logger.info("Issuer beacon ready; press Ctrl+C to stop")
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		logger.info("Script stopped by user.")
	except Exception as exc:
		logger.exception("Unhandled error in backend issuer: %s", exc)
	finally:
		beacon_thread.stop()

if __name__ == "__main__":
	main()
