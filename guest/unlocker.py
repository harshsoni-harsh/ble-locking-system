import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from contextlib import suppress
from typing import Any, Dict, Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.util import Adapter, get_message_bus
from dbus_next.constants import MessageType, PropertyAccess
from dbus_next.errors import DBusError
from dbus_next.message import Message
from dbus_next.signature import Variant
from dbus_next.service import dbus_property

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PHONE_MAC_OVERRIDE: Optional[str] = os.getenv("PHONE_MAC_OVERRIDE")

LOCK_ID = os.getenv("LOCK_ID", "lock_01")
MANUFACTURER_ID = 0xFFFF
ADVERT_INTERVAL = 30
ADVERT_TIMEOUT = 0  # Continuous advertising
ISSUER_BEACON_NAME = os.getenv("ISSUER_BEACON_NAME", "IssuerBeacon")
ISSUER_BEACON_ADDRESS = os.getenv("ISSUER_BEACON_ADDRESS")
ISSUER_SCAN_TIMEOUT = float(os.getenv("ISSUER_SCAN_TIMEOUT", "8.0"))
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

async def find_issuer_beacon(scan_timeout: float = ISSUER_SCAN_TIMEOUT) -> BLEDevice:
	"""Scan for the issuer beacon using optional name/address hints."""
	try:
		logger.info("Scanning for issuer beacon (timeout %.1fs)", scan_timeout)
		devices = await BleakScanner.discover(timeout=scan_timeout)
	except BleakError as exc:
		raise RuntimeError("BLE scan failed for issuer beacon") from exc

	selected: Optional[BLEDevice] = None
	if ISSUER_BEACON_ADDRESS:
		address = ISSUER_BEACON_ADDRESS.lower().replace("-", ":")
		for device in devices:
			if device.address.lower() == address:
				selected = device
				break
			if device.name is not None and device.name == ISSUER_BEACON_NAME:
				selected = device
				break
	if selected is None:
		for device in devices:
			metadata = getattr(device, "metadata", {}) or {}
			manufacturer_data = metadata.get("manufacturer_data") if isinstance(metadata, dict) else None
			if manufacturer_data and MANUFACTURER_ID in manufacturer_data:
				selected = device
				break

	if selected is None:
		raise RuntimeError("Issuer beacon not found during scan")
	logger.info("Issuer beacon candidate: %s (%s)", selected.name or "unknown", selected.address)
	return selected

async def request_session_from_issuer(lock_id: str) -> tuple[bytes, int, Optional[str]]:
	device = await find_issuer_beacon()
	response_event = asyncio.Event()
	result: Dict[str, Any] = {}

	def handle_notification(_: Any, data: bytearray) -> None:
		nonlocal result
		if response_event.is_set():
			return
		try:
			payload = json.loads(bytes(data).decode())
		except (UnicodeDecodeError, json.JSONDecodeError):
			logger.error("Received malformed provisioning response from issuer")
			return
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
			request_payload: Dict[str, Any] = {
				"lock_id": lock_id,
				"client_time": int(time.time()),
			}
			if PHONE_MAC_OVERRIDE:
				request_payload["phone_mac"] = PHONE_MAC_OVERRIDE
			payload_bytes = json.dumps(request_payload, separators=(",", ":")).encode()
			await client.write_gatt_char(
				PROVISIONING_CHARACTERISTIC_UUID,
				payload_bytes,
				response=True,
			)
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
	return session_key, expiry, nonce

class LockAdvertisement(Advertisement):
	def __init__(self, session_key: bytes, nonce: Optional[str]):
		self.session_key = session_key
		self.nonce = nonce
		token = generate_token(self.session_key, self.nonce)
		logger.debug("Generated advertisement token: %s", token.hex())
		super().__init__(
			localName="BLELock",
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
			if getattr(exc, "name", None) != "org.freedesktop.DBus.Error.DoesNotExist":
				raise

	def update_token(self):
		token = generate_token(self.session_key, self.nonce)
		self._manufacturerData[MANUFACTURER_ID] = Variant("ay", token)
		logger.debug("Updated advertisement token: %s", token.hex())

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
