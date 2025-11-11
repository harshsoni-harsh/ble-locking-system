import asyncio
import logging
import threading
from contextlib import suppress
from typing import Optional

from bluez_peripheral.advert import Advertisement
from bluez_peripheral.gatt.service import ServiceCollection
from bluez_peripheral.util import get_message_bus
from dbus_next.constants import PropertyAccess
from dbus_next.errors import DBusError
from dbus_next.service import dbus_property
from dbus_next.signature import Variant

from . import config
from .ble_utils import get_first_adapter
from .keystore import KeyStore
from .provisioning_service import ProvisioningService
from .session import SessionIssuer

logger = logging.getLogger(__name__)

class IssuerBeaconAdvertisement(Advertisement):
	def __init__(self, keystore: KeyStore):
		self._keystore = keystore
		static_payload = b"\x01\x00"
		self._manufacturer_payload = {config.ISSUER_MANUFACTURER_ID: static_payload}
		super().__init__(
			localName=config.ISSUER_BEACON_NAME,
			serviceUUIDs=[uuid for uuid in config.ISSUER_SERVICE_UUIDS if uuid],
			appearance=config.ISSUER_BEACON_APPEARANCE,
			timeout=config.ISSUER_ADVERT_TIMEOUT,
			manufacturerData=self._manufacturer_payload,
		)
		self._manufacturerData[config.ISSUER_MANUFACTURER_ID] = Variant("ay", static_payload)
		self._advert_path = config.ISSUER_ADVERT_PATH

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
	def __init__(self, issuer: SessionIssuer, keystore: KeyStore):
		super().__init__(name="IssuerBeaconAdvertiser", daemon=True)
		self._issuer = issuer
		self._keystore = keystore
		self._stop_event = threading.Event()
		self._loop: Optional[asyncio.AbstractEventLoop] = None
		self._service_collection: Optional[ServiceCollection] = None

	def run(self) -> None:
		asyncio.run(self._run())

	async def _run(self) -> None:
		try:
			bus = await get_message_bus()
			adapter = await get_first_adapter(bus)
		except Exception as exc:  # pragma: no cover - hardware dependent
			logger.error("Issuer beacon setup failed: %s", exc)
			return

		self._loop = asyncio.get_running_loop()
		advert = IssuerBeaconAdvertisement(self._keystore)
		service = ProvisioningService(self._issuer, self._keystore)
		service.attach_bus(bus)
		collection = ServiceCollection([service])
		self._service_collection = collection
		try:
			await advert.start(bus, adapter)
			await collection.register(bus, adapter=adapter)
			try:
				adapter_name = await adapter.get_name()
			except Exception:
				adapter_name = "unknown"
			logger.info("Issuer beacon advertising started on adapter %s", adapter_name)
			logger.info("Provisioning GATT service registered")
			while not self._stop_event.is_set():
				await asyncio.sleep(1.0)
		except Exception as exc:  # pragma: no cover - hardware dependent
			logger.error("Issuer beacon advertising error: %s", exc)
		finally:
			with suppress(Exception):
				await advert.stop(adapter)
				if self._service_collection is not None:
					await self._service_collection.unregister()
			self._service_collection = None
			logger.info("Issuer beacon advertising stopped")

	def stop(self, timeout: float = 5.0) -> None:
		self._stop_event.set()
		loop = self._loop
		if loop is not None:
			try:
				loop.call_soon_threadsafe(lambda: None)
			except RuntimeError:
				pass
		if self.is_alive():
			self.join(timeout=timeout)
