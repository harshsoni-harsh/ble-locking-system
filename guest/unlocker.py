import asyncio
import base64
import json
import logging
import hmac
import hashlib
import time
from typing import Any, Dict, Optional

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.util import get_message_bus, Adapter
from dbus_next.constants import MessageType, PropertyAccess
from dbus_next.errors import DBusError
from dbus_next.message import Message
from dbus_next.signature import Variant
from dbus_next.service import dbus_property

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PHONE_MAC_OVERRIDE: Optional[str] = None

LOCK_ID = "lock_01"
MQTT_BROKER = "10.0.15.108"
MQTT_PORT = 1883
MANUFACTURER_ID = 0xFFFF
ADVERT_INTERVAL = 30
ADVERT_TIMEOUT = 0  # Continuous advertising

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
	except ConnectionRefusedError as exc:
		raise ConnectionError(f"Failed to connect to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}") from exc

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

def resolve_phone_mac() -> str:
	if PHONE_MAC_OVERRIDE:
		return PHONE_MAC_OVERRIDE.upper()
	mac = asyncio.run(_detect_phone_mac())
	logger.info("Detected adapter MAC: %s", mac)
	return mac

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

if __name__ == "__main__":
	try:
		phone_mac = resolve_phone_mac()
		logger.info("Using phone MAC %s", phone_mac)
		logger.info("Requesting session key from backend...")
		session_key, expiry, nonce = get_session_key(LOCK_ID, phone_mac)
		logger.info("Session key (base64): %s", base64.b64encode(session_key).decode())
		asyncio.run(advertise_loop(session_key, expiry or 0, nonce))
	except KeyboardInterrupt:
		logger.info("Script stopped by user")
	except Exception as exc:
		logger.exception("Guest unlocker encountered an error: %s", exc)
