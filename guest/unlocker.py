import asyncio
import base64
import json
import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import paho.mqtt.client as mqtt
from bleak import BleakClient
from paho.mqtt.enums import CallbackAPIVersion
from bluez_peripheral.advert import Advertisement, AdvertisingIncludes, PacketType
from bluez_peripheral.util import get_message_bus, Adapter
from dbus_next.constants import MessageType, PropertyAccess
from dbus_next.errors import DBusError, InterfaceNotFoundError
from dbus_next.message import Message
from dbus_next.signature import Variant
from dbus_next.service import dbus_property

if __package__ is None or __package__ == "":  # pragma: no cover - script execution support
	sys.path.append(str(Path(__file__).resolve().parent.parent))

from lock.auth_service import CHALLENGE_CHAR_UUID, RESPONSE_CHAR_UUID
from lock.constants import MANUFACTURER_ID
from lock.protocol import (
	TOTP_STEP_SECONDS,
	build_advertisement_frame,
	build_response_packet,
	verify_challenge_packet,
)
from lock.utils import derive_phone_hash

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PHONE_MAC_OVERRIDE: Optional[str] = None

LOCK_ID = "lock_01"
LOCK_ADDRESS: Optional[str] = None  # Set to lock BLE MAC to attempt unlock automatically
MQTT_BROKER = "0.0.0.0"
MQTT_PORT = 1883
ADVERT_TIMEOUT = 60  # seconds; BlueZ rejects 0 with Invalid Parameters
ADVERT_LOCAL_NAME = "BLELock"
ADVERT_SERVICE_UUIDS = ["180D"]  # arbitrary 16-bit; provides compatibility with some stacks
ADVERT_APPEARANCE = 0x0340

session_key_data = None

def on_message(client, userdata, msg):
	"""Handles incoming MQTT messages (session key responses)."""
	global session_key_data
	logger.info("Received session key on %s", msg.topic)
	data = json.loads(msg.payload.decode())
	session_key_data = data

def get_session_key(lock_id: str, phone_mac: str):
	"""Requests a session key from the backend via MQTT."""
	global session_key_data
	session_key_data = None
	client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
	client.on_message = on_message

	try:
		client.connect(MQTT_BROKER, MQTT_PORT, 60)
	except OSError as exc:
		raise ConnectionError(
			f"Failed to connect to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}: {exc}"
		) from exc

	guest_topic = f"guests/{lock_id}/session"
	request_topic = "backend/session_requests"
	request_payload = json.dumps({"lock_id": lock_id, "phone_mac": phone_mac})

	client.loop_start()
	try:
		client.subscribe(guest_topic, qos=1)
		publish_result = client.publish(request_topic, request_payload, qos=1)
		publish_result.wait_for_publish()
		logger.info("Requested session key for %s", lock_id)

		start = time.time()
		timeout = 10  # seconds

		while session_key_data is None and time.time() - start < timeout:
			time.sleep(0.1)
	finally:
		client.loop_stop()
		client.disconnect()

		if session_key_data:
			phone_mac_received = session_key_data.get("phone_mac")
			if phone_mac_received:
				logger.info("Backend included phone MAC in guest payload; ignoring per policy.")
			session_key = base64.b64decode(session_key_data["session_key"])
			expiry = session_key_data.get("expiry")
			nonce = session_key_data.get("nonce")
			logger.info("Session key received. Expires: %s, nonce: %s", expiry, nonce)
			return session_key, expiry, nonce
		raise TimeoutError("No session key received from backend within timeout")

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

async def _detect_phone_mac() -> str:
	bus = await get_message_bus()
	try:
		adapter = await get_first_adapter(bus)
		address = await adapter.get_address()
		return address.upper()
	finally:
		try:
			bus.disconnect()
		except Exception:
			pass


async def resolve_phone_mac() -> str:
	if PHONE_MAC_OVERRIDE:
		return PHONE_MAC_OVERRIDE.upper()
	mac = await _detect_phone_mac()
	logger.info("Detected adapter MAC: %s", mac)
	return mac


def _ensure_le_advertising_support(adapter: Adapter) -> None:
	try:
		adapter._proxy.get_interface("org.bluez.LEAdvertisingManager1")
	except InterfaceNotFoundError as exc:
		raise RuntimeError(
			"Adapter does not expose LEAdvertisingManager1; start bluetoothd with --experimental or use hardware that supports advertising."
		) from exc


async def _set_adapter_property(adapter: Adapter, name: str, value: bool) -> None:
	try:
		props = adapter._proxy.get_interface("org.freedesktop.DBus.Properties")
		await props.call_set("org.bluez.Adapter1", name, Variant("b", value))  # type: ignore[attr-defined]
	except (InterfaceNotFoundError, AttributeError):
		return
	except DBusError as exc:
		err_name = getattr(exc, "name", "")
		if err_name not in {
			"org.freedesktop.DBus.Error.PropertyReadOnly",
			"org.bluez.Error.NotPermitted",
			"org.bluez.Error.NotSupported",
		}:
			logger.debug("Unable to set adapter property %s: %s", name, exc)


async def _stop_discovery(adapter: Adapter) -> None:
	try:
		await adapter.stop_discovery()  # type: ignore[attr-defined]
		return
	except AttributeError:
		pass
	except DBusError:
		return
	try:
		iface = adapter._proxy.get_interface("org.bluez.Adapter1")
		await iface.call_stop_discovery()  # type: ignore[attr-defined]
	except Exception:
		pass


async def _prepare_adapter_for_advertising(adapter: Adapter) -> None:
	_ensure_le_advertising_support(adapter)
	await _set_adapter_property(adapter, "Powered", True)
	await _stop_discovery(adapter)


def _describe_advertising_error(exc: Exception, adapter_name: str) -> str:
	if isinstance(exc, RuntimeError):
		return str(exc)
	if isinstance(exc, DBusError):
		err_name = getattr(exc, "type", "") or getattr(exc, "name", "")
		err_text = getattr(exc, "text", "") or str(exc)
		if err_name == "org.bluez.Error.NotSupported":
			return (
				f"Adapter {adapter_name} rejected LE advertising (NotSupported); ensure bluetoothd is running with --experimental and the adapter firmware allows advertising."
			)
		if err_name == "org.bluez.Error.AlreadyExists":
			return (
				"An advertisement with the same path is still registered. Restart bluetoothd or wait for the previous session to expire."
			)
		if err_name == "org.bluez.Error.NotAuthorized":
			return (
				"DBus reported NotAuthorized; run under a user in the bluetooth group or adjust policy to allow advertising."
			)
		if err_name in {
			"org.bluez.Error.InvalidArguments",
			"org.bluez.Error.Failed",
			"org.freedesktop.DBus.Error.AccessDenied",
		}:
			return f"{err_name}: {err_text}"
		return f"{err_name or 'DBusError'}: {err_text}"
	return str(exc)


class LockAdvertisement(Advertisement):
	def __init__(
		self,
		shared_key: bytes,
		lock_id: str,
		phone_identifier: str,
		packet_type: PacketType = PacketType.PERIPHERAL,
	):
		self.shared_key = shared_key
		self.lock_id = lock_id
		self.phone_identifier = phone_identifier
		self.packet_type = packet_type
		self.current_frame = build_advertisement_frame(shared_key, lock_id, phone_identifier)
		payload = self.current_frame.encode()
		logger.debug(
			"Generated advertisement payload (step=%s): %s",
			self.current_frame.time_step,
			payload.hex(),
		)
		computed_length = 3 + (3 if payload else 0) + len(payload)
		logger.debug("Advertising payload total after manufacturer data: %d bytes", computed_length)
		super().__init__(
			localName=ADVERT_LOCAL_NAME if packet_type == PacketType.PERIPHERAL else "",
			serviceUUIDs=ADVERT_SERVICE_UUIDS if packet_type == PacketType.PERIPHERAL else [],
			appearance=ADVERT_APPEARANCE,
			timeout=ADVERT_TIMEOUT,
			discoverable=(packet_type == PacketType.PERIPHERAL),
			packet_type=packet_type,
			manufacturerData={MANUFACTURER_ID: payload},
			includes=AdvertisingIncludes.NONE,
		)
		self._manufacturerData[MANUFACTURER_ID] = Variant("ay", payload)
		self._advert_path = f"/com/ble_lock/unlocker/advert_{uuid.uuid4().hex}"

	async def start(self, bus, adapter):
		await super().register(bus, adapter, self._advert_path)

	async def stop(self, adapter):
		interface = adapter._proxy.get_interface(self._MANAGER_INTERFACE)
		try:
			await interface.call_unregister_advertisement(self._advert_path)
		except DBusError as exc:
			if getattr(exc, "name", None) != "org.freedesktop.DBus.Error.DoesNotExist":
				raise

	def refresh(self):
		self.current_frame = build_advertisement_frame(
			self.shared_key,
			self.lock_id,
			self.phone_identifier,
		)
		payload = self.current_frame.encode()
		self._manufacturerData[MANUFACTURER_ID] = Variant("ay", payload)
		logger.debug(
			"Updated advertisement payload (step=%s): %s",
			self.current_frame.time_step,
			payload.hex(),
		)

	@property
	def counter(self) -> int:
		return self.current_frame.time_counter

	@dbus_property(PropertyAccess.READWRITE)
	def TxPower(self) -> "n":  # type: ignore[override]
		return 0

	@TxPower.setter
	def TxPower(self, value: "n") -> None:  # type: ignore[override]
		return

async def advertise_loop(
	shared_key: bytes,
	expiry: int | float,
	phone_identifier: str,
	ready_future: Optional[asyncio.Future] = None,
):
	"""Main async advertising loop."""
	bus = await get_message_bus()
	adapter = None
	adapter_name = "<unknown>"
	advertiser: Optional[LockAdvertisement] = None
	try:
		adapter = await get_first_adapter(bus)
		adapter_name = await adapter.get_name()
		await _prepare_adapter_for_advertising(adapter)
		last_exc: Optional[Exception] = None
		for packet_type in (PacketType.PERIPHERAL, PacketType.BROADCAST):
			candidate = LockAdvertisement(
				shared_key,
				LOCK_ID,
				phone_identifier,
				packet_type=packet_type,
			)
			try:
				await candidate.start(bus, adapter)
			except Exception as exc:
				reason = _describe_advertising_error(exc, adapter_name)
				logger.warning(
					"Advertising registration failed using %s mode: %s",
					packet_type.name.lower(),
					reason,
				)
				last_exc = RuntimeError(reason)
				continue
			advertiser = candidate
			logger.info("Advertising registered using %s mode", packet_type.name.lower())
			break
		if advertiser is None:
			raise last_exc or RuntimeError("Unable to register advertisement with BlueZ")
		if ready_future and not ready_future.done():
			ready_future.set_result(advertiser)
	except Exception as exc:
		reason = _describe_advertising_error(exc, adapter_name)
		logger.error("Failed to start advertising: %s", reason)
		if ready_future and not ready_future.done():
			ready_future.set_exception(RuntimeError(reason))
		return
	logger.info("Advertising started on adapter %s", adapter_name)

	try:
		while True:
			remaining = expiry - time.time()
			if remaining <= 0:
				logger.info("Session key expired; stopping advertising")
				break

			await asyncio.sleep(min(TOTP_STEP_SECONDS, max(0.5, remaining)))
			advertiser.refresh()
			await advertiser.stop(adapter)
			await advertiser.start(bus, adapter)
	except asyncio.CancelledError:
		pass
	finally:
		logger.info("Stopping advertising")
		try:
			if advertiser and adapter:
				await advertiser.stop(adapter)
		except Exception:
			pass
		try:
			bus.disconnect()
		except Exception:
			pass


async def perform_unlock(
	lock_address: str,
	shared_key: bytes,
	phone_identifier: str,
	advertiser: LockAdvertisement,
):
	"""Connect to the lock and complete the challenge-response exchange."""
	logger.info("Connecting to lock %s for challenge-response", lock_address)
	phone_hash = derive_phone_hash(phone_identifier)
	async with BleakClient(lock_address) as client:
		challenge_payload = await client.read_gatt_char(CHALLENGE_CHAR_UUID)
		challenge = verify_challenge_packet(
			challenge_payload,
			shared_key,
			LOCK_ID,
			phone_identifier,
		)
		response_packet = build_response_packet(
			shared_key,
			LOCK_ID,
			phone_hash,
			challenge,
			advertiser.counter,
		)
		await client.write_gatt_char(
			RESPONSE_CHAR_UUID,
			response_packet.encode(),
			response=False,
		)
		logger.info(
			"Challenge-response sent (step=0x%02X)", response_packet.time_step
		)

async def main():
	phone_mac = await resolve_phone_mac()
	logger.info("Using phone MAC %s", phone_mac)
	logger.info("Requesting session key from backend...")
	try:
		session_key, expiry_raw, nonce = get_session_key(LOCK_ID, phone_mac)
	except ConnectionError as exc:
		logger.error("Unable to obtain session key: %s", exc)
		return
	except TimeoutError as exc:
		logger.error("Session key request timed out: %s", exc)
		return
	logger.info("Session key (base64): %s", base64.b64encode(session_key).decode())
	if nonce:
		logger.info("Backend nonce retained for audit: %s", nonce)
	expiry = float(expiry_raw or (time.time() + 300))
	ready_future: asyncio.Future = asyncio.get_running_loop().create_future()
	advert_task = asyncio.create_task(
		advertise_loop(session_key, expiry, phone_mac, ready_future=ready_future)
	)
	try:
		advertiser = await ready_future
	except Exception as exc:
		logger.error("Unable to start advertising: %s", exc)
		if not advert_task.done():
			advert_task.cancel()
			try:
				await advert_task
			except asyncio.CancelledError:
				pass
		return
	try:
		if LOCK_ADDRESS:
			await asyncio.sleep(1.0)
			await perform_unlock(LOCK_ADDRESS, session_key, phone_mac, advertiser)
		else:
			logger.info("LOCK_ADDRESS not configured; skipping challenge-response phase.")
		await advert_task
	except asyncio.CancelledError:
		pass
	finally:
		if not advert_task.done():
			advert_task.cancel()
			try:
				await advert_task
			except asyncio.CancelledError:
				pass


if __name__ == "__main__":
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		logger.info("Script stopped by user")
	except Exception as exc:
		logger.exception("Guest unlocker encountered an error: %s", exc)
