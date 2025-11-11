import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import time
from contextlib import suppress
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, cast

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakError, BleakDBusError
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.util import Adapter, get_message_bus
from dbus_next.constants import MessageType, PropertyAccess
from dbus_next.errors import DBusError
from dbus_next.message import Message
from dbus_next.signature import Variant
from dbus_next.service import dbus_property

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
	Encoding,
	PublicFormat,
	load_pem_private_key,
	load_pem_public_key,
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = Path(os.getenv("KEYS_DIR", str(ROOT_DIR / "keys")))
UNLOCKER_PRIVATE_KEY_PATH = Path(
	os.getenv("UNLOCKER_PRIVATE_KEY", str(KEYS_DIR / "unlocker_private.pem"))
)
_BACKEND_PUBLIC_KEY_ENV = os.getenv("BACKEND_PUBLIC_KEY")
_BACKEND_PUBLIC_KEY_DEFAULT = KEYS_DIR / "backend_public.pem"
if _BACKEND_PUBLIC_KEY_ENV:
	BACKEND_PUBLIC_KEY_PATH: Optional[Path] = Path(_BACKEND_PUBLIC_KEY_ENV)
elif _BACKEND_PUBLIC_KEY_DEFAULT.exists():
	BACKEND_PUBLIC_KEY_PATH = _BACKEND_PUBLIC_KEY_DEFAULT
else:
	BACKEND_PUBLIC_KEY_PATH = None
CLIENT_ID = os.getenv("CLIENT_ID", "default")

LOCK_ID = os.getenv("LOCK_ID", "lock_01")
MANUFACTURER_ID = 0xFFFF
ADVERT_INTERVAL = 3  # Token update interval in seconds
BLE_MIN_INTERVAL = int(os.getenv("BLE_MIN_INTERVAL", "100")) # in ms
BLE_MAX_INTERVAL = int(os.getenv("BLE_MAX_INTERVAL", "200")) # in ms
ADVERT_TIMEOUT = 0  # Continuous advertising
ISSUER_BEACON_NAME = os.getenv("ISSUER_BEACON_NAME", "IssuerBeacon")
ISSUER_BEACON_ADDRESS = os.getenv("ISSUER_BEACON_ADDRESS")
ISSUER_SCAN_TIMEOUT = float(os.getenv("ISSUER_SCAN_TIMEOUT", "10.0"))
ISSUER_CONNECT_TIMEOUT = float(os.getenv("ISSUER_CONNECT_TIMEOUT", "10.0"))
ISSUER_RESPONSE_TIMEOUT = float(os.getenv("ISSUER_RESPONSE_TIMEOUT", "10.0"))
PROVISIONING_SERVICE_UUID = os.getenv(
	"PROVISIONING_SERVICE_UUID",
	"c0de0001-0000-1000-8000-00805f9b34fb",
)
PROVISIONING_CHARACTERISTIC_UUID = os.getenv(
	"PROVISIONING_CHARACTERISTIC_UUID",
	"c0de0002-0000-1000-8000-00805f9b34fb",
)

def generate_token(session_key: bytes, nonce: Optional[str]) -> bytes:
	"""Generate rolling HMAC token using session key, nonce, and timestamp."""
	ts = int(time.time() // ADVERT_INTERVAL)
	components = []
	if nonce:
		components.append(nonce.encode())
	components.append(str(ts).encode())
	msg = b"".join(components)
	return hmac.new(session_key, msg, hashlib.sha256).digest()[:16]


@lru_cache()
def _load_unlocker_private_key() -> rsa.RSAPrivateKey:
	if not UNLOCKER_PRIVATE_KEY_PATH.exists():
		raise RuntimeError(
			f"Unlocker private key not found at {UNLOCKER_PRIVATE_KEY_PATH}"
		)
	with open(UNLOCKER_PRIVATE_KEY_PATH, "rb") as handle:
		return cast(
			rsa.RSAPrivateKey,
			load_pem_private_key(handle.read(), password=None, backend=default_backend()),
		)

@lru_cache()
def _load_backend_public_key_from_file() -> rsa.RSAPublicKey:
	"""Load backend public key from file (hardcoded key path)."""
	path = BACKEND_PUBLIC_KEY_PATH
	if path is None:
		raise RuntimeError(
			"Backend public key path not configured. "
			"Set BACKEND_PUBLIC_KEY env var or place key at keys/backend_public.pem"
		)
	if not path.exists():
		raise RuntimeError(f"Backend public key not found at {path}")
	with open(path, "rb") as handle:
		key = cast(
			rsa.RSAPublicKey,
			load_pem_public_key(handle.read(), backend=default_backend()),
		)
	logger.info("Loaded backend public key from %s", path)
	return key

@lru_cache()
def _load_unlocker_public_key_bytes() -> bytes:
	private_key = _load_unlocker_private_key()
	return private_key.public_key().public_bytes(
		encoding=Encoding.PEM,
		format=PublicFormat.SubjectPublicKeyInfo,
	)

def _decrypt_guest_payload(payload_b64: str, signature_b64: Optional[str]) -> Dict[str, Any]:
	try:
		encrypted_payload = base64.b64decode(payload_b64)
	except (binascii.Error, TypeError) as exc:
		raise RuntimeError("Issuer payload decoding failed") from exc

	private_key = _load_unlocker_private_key()
	plaintext = private_key.decrypt(
		encrypted_payload,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None,
		),
	)

	if signature_b64:
		try:
			signature = base64.b64decode(signature_b64)
		except (binascii.Error, TypeError) as exc:
			raise RuntimeError("Issuer signature decoding failed") from exc
		backend_public = _load_backend_public_key_from_file()
		try:
			backend_public.verify(
				signature,
				plaintext,
				padding.PSS(
					mgf=padding.MGF1(hashes.SHA256()),
					salt_length=padding.PSS.MAX_LENGTH,
				),
				hashes.SHA256(),
			)
		except InvalidSignature as exc:
			raise RuntimeError("Issuer response signature invalid") from exc

	try:
		return json.loads(plaintext.decode())
	except json.JSONDecodeError as exc:
		raise RuntimeError("Issuer response payload malformed") from exc

def _decode_session_response(response: Dict[str, Any]) -> Dict[str, Any]:
	if response.get("status") != "ok":
		return response

	payload_b64 = response.get("payload")
	if not isinstance(payload_b64, str):
		return response

	signature_b64 = response.get("signature")
	if signature_b64 is not None and not isinstance(signature_b64, str):
		signature_b64 = None

	decrypted = _decrypt_guest_payload(payload_b64, signature_b64)
	result: Dict[str, Any] = {
		key: value
		for key, value in response.items()
		if key not in {"payload", "signature", "encryption"}
	}
	result.update(decrypted)
	return result

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

	objects: Dict[str, Dict[str, Any]] = reply.body[0]
	for path, interfaces in objects.items():
		if "org.bluez.Adapter1" in interfaces:
			introspection = await bus.introspect("org.bluez", path)
			proxy = bus.get_proxy_object("org.bluez", path, introspection)
			return Adapter(proxy)

	raise ValueError("No bluetooth adapters could be found.")

def _matches_issuer(device: BLEDevice, advertisement: Optional[AdvertisementData] = None) -> bool:
	"""Check if device matches the issuer beacon by address, name, or manufacturer data."""
	if ISSUER_BEACON_ADDRESS:
		if device.address.lower() == ISSUER_BEACON_ADDRESS.lower().replace("-", ":"):
			return True

	if ISSUER_BEACON_NAME:
		adv_name = advertisement.local_name if advertisement else None
		if device.name == ISSUER_BEACON_NAME or adv_name == ISSUER_BEACON_NAME:
			return True

	manufacturer_data = None
	if advertisement:
		manufacturer_data = advertisement.manufacturer_data
	else:
		metadata = getattr(device, "metadata", {})
		if metadata:
			manufacturer_data = metadata.get("manufacturer_data")
	
	return bool(manufacturer_data and MANUFACTURER_ID in manufacturer_data)

async def find_issuer_beacon(
	scan_timeout: float = ISSUER_SCAN_TIMEOUT,
) -> BLEDevice:
	"""Scan for the issuer beacon using optional name/address hints."""
	logger.info("Scanning for issuer beacon (timeout %.1fs)", scan_timeout)
	found_device: Optional[BLEDevice] = None
	found_event = asyncio.Event()

	def detection_callback(device: BLEDevice, advertisement: AdvertisementData) -> None:
		nonlocal found_device
		if not _matches_issuer(device, advertisement):
			return
		
		if found_device is None:
			found_device = device
			logger.info("Found issuer beacon: %s (%s)", device.name or "unknown", device.address)
			found_event.set()

	scanner = BleakScanner(detection_callback=detection_callback)
	try:
		await scanner.start()
	except BleakError as exc:
		raise RuntimeError("BLE scan failed for issuer beacon") from exc
	
	try:
		# Check already-known devices immediately.
		for device in list(scanner.discovered_devices):
			if _matches_issuer(device):
				found_device = device
				logger.info("Found issuer beacon: %s (%s)", device.name or "unknown", device.address)
				found_event.set()
				break

		# Wait for beacon if not already found
		if not found_event.is_set():
			try:
				await asyncio.wait_for(found_event.wait(), timeout=scan_timeout)
			except asyncio.TimeoutError:
				pass
	finally:
		with suppress(Exception):
			await scanner.stop()

	if not found_device:
		raise RuntimeError("Issuer beacon not found during scan")
	
	logger.info(
		"Issuer beacon found: %s (%s)",
		found_device.name or "unknown",
		found_device.address,
	)
	return found_device

async def request_session_from_issuer(lock_id: str) -> tuple[bytes, int, Optional[str]]:
	"""Request a session key from the issuer beacon."""
	device = await find_issuer_beacon()
	response_event = asyncio.Event()
	result: Dict[str, Any] = {}
	# Buffer for chunked notifications
	pending_notifications: Dict[str, Any] = {"total": 0, "parts": {}}

	def handle_notification(_: Any, data: bytearray) -> None:
		nonlocal result
		if response_event.is_set():
			return
		rb = bytes(data)
		text: Optional[str] = None
		try:
			text = rb.decode()
			obj = json.loads(text)
		except Exception:
			logger.error(
				"Received malformed provisioning response from issuer: not-json (hex=%s, b64=%s)",
				rb.hex(),
				base64.b64encode(rb).decode(),
			)
			return

		if isinstance(obj, dict) and {"chunk_index", "total_chunks", "data"}.issubset(obj.keys()):
			pending = pending_notifications
			idx = int(obj["chunk_index"])
			total = int(obj["total_chunks"])
			if pending["total"] == 0:
				pending["total"] = total
			try:
				part = base64.b64decode(obj["data"])
			except (binascii.Error, TypeError):
				logger.error("Received invalid base64 chunk in notification")
				return
			pending["parts"][idx] = part
			if len(pending["parts"]) < pending["total"]:
				return
			assembled = b"".join(pending["parts"][i] for i in range(pending["total"]))
			pending_notifications["total"] = 0
			pending_notifications["parts"] = {}
			try:
				payload = json.loads(assembled.decode())
			except Exception:
				logger.error("Reassembled provisioning response malformed (hex=%s)", assembled.hex())
				return
		else:
			payload = obj
		
		result = payload
		response_event.set()

	try:
		async with BleakClient(device, timeout=ISSUER_CONNECT_TIMEOUT) as client:
			if not client.is_connected:
				raise RuntimeError("Failed to establish BLE connection to issuer beacon")
			logger.info(
				"Connected to issuer beacon %s (%s)",
				device.name or "unknown",
				device.address,
			)
			await client.start_notify(PROVISIONING_CHARACTERISTIC_UUID, handle_notification)
			
			request_plain: Dict[str, Any] = {
				"lock_id": lock_id,
				"client_time": int(time.time()),
				"unlocker_public_key": base64.b64encode(_load_unlocker_public_key_bytes()).decode(),
			}
			if CLIENT_ID:
				request_plain["client_id"] = CLIENT_ID
			
			payload_bytes = json.dumps(request_plain, separators=(",", ":")).encode()
			# BLE GATT writes may have limits; chunk the payload if it's large.
			DEFAULT_CHUNK = int(os.getenv("PROVISION_CHUNK_SIZE", "120"))

			async def _send_chunks(chunk_size: int) -> None:
				if len(payload_bytes) <= chunk_size:
					await client.write_gatt_char(
						PROVISIONING_CHARACTERISTIC_UUID,
						payload_bytes,
						response=True,
					)
					return
				total = (len(payload_bytes) + chunk_size - 1) // chunk_size
				for idx in range(total):
					start = idx * chunk_size
					chunk = payload_bytes[start : start + chunk_size]
					chunk_obj = {
						"chunk_index": idx,
						"total_chunks": total,
						"data": base64.b64encode(chunk).decode(),
					}
					await client.write_gatt_char(
						PROVISIONING_CHARACTERISTIC_UUID,
						json.dumps(chunk_obj, separators=(",", ":")).encode(),
						response=True,
					)
					# small delay to avoid overwhelming the BLE stack
					await asyncio.sleep(0.03)

			# Try sending with default chunk; on Invalid Length, retry with smaller chunk
			try:
				await _send_chunks(DEFAULT_CHUNK)
			except BleakDBusError as exc:
				# BlueZ may reject larger writes with InvalidArguments/Invalid Length.
				name = getattr(exc, "error_name", "")
				msg = str(exc)
				if "InvalidArguments" in name or "Invalid Length" in msg:
					SMALL = max(64, DEFAULT_CHUNK // 2)
					logger.info("Write rejected for chunk size %d, retrying with %d", DEFAULT_CHUNK, SMALL)
					await _send_chunks(SMALL)
				else:
					raise
			try:
				await asyncio.wait_for(response_event.wait(), timeout=ISSUER_RESPONSE_TIMEOUT)
			except asyncio.TimeoutError as exc:
				raise TimeoutError("Timed out waiting for provisioning response from issuer") from exc
			finally:
				with suppress(Exception):
					await client.stop_notify(PROVISIONING_CHARACTERISTIC_UUID)
	except BleakError as exc:
		raise RuntimeError("BLE interaction with issuer beacon failed") from exc

	if not result:
		raise RuntimeError("Issuer beacon returned no response")
	result = _decode_session_response(result)
	if result.get("status") != "ok":
		raise RuntimeError(result.get("message", "Issuer reported an error"))

	session_key_b64 = result.get("session_key")
	if not isinstance(session_key_b64, str):
		raise RuntimeError("Session key missing from issuer response")
	session_key = base64.b64decode(session_key_b64)
	expiry_raw = result.get("expiry")
	try:
		expiry = int(expiry_raw) if expiry_raw is not None else 0
	except (TypeError, ValueError):
		expiry = 0
	nonce = result.get("nonce")
	if nonce is not None and not isinstance(nonce, str):
		nonce = None
	clock_offset = result.get("clock_offset")
	if clock_offset is not None:
		logger.info("Issuer reported clock offset %s", clock_offset)
	return session_key, expiry + (clock_offset or 0), nonce

class LockAdvertisement(Advertisement):
	def __init__(self, session_key: bytes, nonce: Optional[str]):
		self.session_key = session_key
		self.nonce = nonce
		token = generate_token(self.session_key, self.nonce)
		logger.debug("Generated advertisement token: %s", token.hex())
		super().__init__(
			localName="Unlocker",
			serviceUUIDs=["180D"],
			appearance=0x0340,
			timeout=ADVERT_TIMEOUT,
			manufacturerData={MANUFACTURER_ID: token},
		)
		self._manufacturerData[MANUFACTURER_ID] = Variant("ay", token)
		self._advert_path = "/com/ble_lock/unlocker/advert0"

	async def start(self, bus, adapter):
		await super().register(bus, adapter, self._advert_path)

	async def stop(self, adapter):
		interface = adapter._proxy.get_interface(self._MANAGER_INTERFACE)
		try:
			await interface.call_unregister_advertisement(self._advert_path)
		except DBusError as exc:
			name = getattr(exc, "name", "") or ""
			if name not in {
				"org.freedesktop.DBus.Error.DoesNotExist",
				"org.freedesktop.DBus.Error.UnknownObject",
				"org.bluez.Error.DoesNotExist",
			}:
				raise

	def update_token(self):
		token = generate_token(self.session_key, self.nonce)
		self._manufacturerData[MANUFACTURER_ID] = Variant("ay", token)
		logger.debug("Updated advertisement token: %s", token.hex())

	@dbus_property(PropertyAccess.READ)
	def MinInterval(self) -> "q":  # type: ignore[override]
		"""Minimum BLE advertisement interval in milliseconds."""
		return BLE_MIN_INTERVAL

	@dbus_property(PropertyAccess.READ)
	def MaxInterval(self) -> "q":  # type: ignore[override]
		"""Maximum BLE advertisement interval in milliseconds."""
		return BLE_MAX_INTERVAL

	@dbus_property(PropertyAccess.READWRITE)
	def TxPower(self) -> "n":  # type: ignore[override]
		return 0

	@TxPower.setter
	def TxPower(self, value: "n") -> None:  # type: ignore[override]
		return

async def advertise_loop(session_key: bytes, expiry: int | float, nonce: Optional[str]):
	"""Main async advertising loop."""
	bus = await get_message_bus()
	try:
		adapter = await get_first_adapter(bus)
		adapter_name = await adapter.get_name()
		advertiser = LockAdvertisement(session_key, nonce)
		await advertiser.start(bus, adapter)
	except Exception as exc:
		logger.error("Failed to start advertising: %s", exc)
		return
	logger.info("Advertising started on adapter %s", adapter_name)

	try:
		while True:
			remaining = expiry - time.time()
			if remaining <= 0:
				logger.info("Session key expired; stopping advertising")
				break

			await asyncio.sleep(min(ADVERT_INTERVAL, max(0.5, remaining)))
			advertiser.update_token()
			await advertiser.stop(adapter)
			await advertiser.start(bus, adapter)
	except asyncio.CancelledError:
		pass
	finally:
		logger.info("Stopping advertising")
		try:
			await advertiser.stop(adapter)
		except Exception:
			pass

async def main() -> None:
	logger.info("Requesting session key from issuer beacon for %s", LOCK_ID)
	session_key, expiry, nonce = await request_session_from_issuer(LOCK_ID)
	logger.info("Session key (base64): %s", base64.b64encode(session_key).decode())
	if not expiry:
		expiry = int(time.time()) + ADVERT_INTERVAL
	await advertise_loop(session_key, expiry, nonce)

if __name__ == "__main__":
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		logger.info("Script stopped by user")
	except Exception as exc:
		logger.exception("Guest unlocker encountered an error: %s", exc)
