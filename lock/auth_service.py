import logging
from typing import Optional, Tuple

from bluez_peripheral.gatt.characteristic import CharacteristicFlags, characteristic
from bluez_peripheral.gatt.service import Service
from bluez_peripheral.util import Adapter, get_message_bus, is_bluez_available
from dbus_next.aio.proxy_object import ProxyObject
from dbus_next.errors import DBusError, InterfaceNotFoundError
from dbus_next.aio.message_bus import MessageBus

from .hybrid import HybridAuthenticator
from .utils import normalize_mac

LOGGER = logging.getLogger(__name__)

SERVICE_UUID = "e7add780-b042-4876-aae1-112855353cc1"
CHALLENGE_CHAR_UUID = "e7add781-b042-4876-aae1-112855353cc1"
RESPONSE_CHAR_UUID = "e7add782-b042-4876-aae1-112855353cc1"


def _path_to_mac(device_path: Optional[str]) -> str:
    if not device_path or "/dev_" not in device_path:
        raise ValueError("device path missing")
    encoded = device_path.split("/dev_")[-1]
    mac = encoded.replace("_", ":")
    normalized = normalize_mac(mac)
    if normalized is None:
        raise ValueError("invalid MAC derived from device path")
    return normalized


class LockAuthService(Service):
    def __init__(self, authenticator: HybridAuthenticator):
        super().__init__(SERVICE_UUID)
        self._auth = authenticator

    @characteristic(CHALLENGE_CHAR_UUID, flags=CharacteristicFlags.READ)
    def challenge(self, options):
        device = options.device
        try:
            mac = _path_to_mac(device)
            packet = self._auth.issue_challenge(mac)
            LOGGER.debug("Issued challenge for %s", mac)
            return packet.encode()
        except ValueError as exc:
            LOGGER.warning("Challenge request rejected: %s", exc)
            raise DBusError("org.bluez.Error.NotAuthorized", str(exc)) from exc

    @characteristic(
        RESPONSE_CHAR_UUID,
        flags=CharacteristicFlags.WRITE | CharacteristicFlags.WRITE_WITHOUT_RESPONSE,
    )
    def response_value(self, options):
        return b""

    @response_value.setter
    def write_response(self, value, options):
        device = options.device
        try:
            mac = _path_to_mac(device)
            self._auth.verify_response(mac, bytes(value))
            LOGGER.info("Unlock verified for %s", mac)
        except ValueError as exc:
            LOGGER.warning("Response verification failed: %s", exc)
            raise DBusError("org.bluez.Error.AuthenticationFailed", str(exc)) from exc
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.exception("Unexpected error handling response: %s", exc)
            raise DBusError("org.bluez.Error.Failed", str(exc)) from exc


async def register_auth_service(
    authenticator: HybridAuthenticator,
) -> Tuple[LockAuthService, MessageBus, Adapter]:
    bus = await get_message_bus()

    if not await is_bluez_available(bus):
        raise RuntimeError(
            "BlueZ service not available on DBus; ensure bluetoothd is running and the adapter is enabled."
        )

    adapter = await _resolve_adapter(bus)
    service = LockAuthService(authenticator)
    await service.register(bus, adapter=adapter)
    LOGGER.info("Lock authentication service registered on %s", await adapter.get_address())
    return service, bus, adapter


async def unregister_auth_service(
    service: LockAuthService,
    bus: MessageBus,
    _adapter: Adapter,
) -> None:
    try:
        await service.unregister()
    finally:
        try:
            bus.disconnect()
        except Exception:
            pass
        LOGGER.info("Lock authentication service unregistered")


async def _resolve_adapter(bus: MessageBus) -> Adapter:
    try:
        return await Adapter.get_first(bus)
    except (ValueError, InterfaceNotFoundError, DBusError) as exc:
        LOGGER.debug("Adapter.get_first failed: %s", exc)

    root = await bus.introspect("org.bluez", "/org/bluez")
    for node in root.nodes:
        path = f"/org/bluez/{node.name}"
        try:
            introspection = await bus.introspect("org.bluez", path)
        except DBusError as exc:
            LOGGER.debug("Failed to introspect %s: %s", path, exc)
            continue

        if not any(iface.name == "org.bluez.Adapter1" for iface in introspection.interfaces):
            continue

        proxy: ProxyObject = bus.get_proxy_object("org.bluez", path, introspection)
        try:
            adapter = Adapter(proxy)
            # Touch a property to ensure permissions are sufficient.
            await adapter.get_address()
            return adapter
        except (DBusError, InterfaceNotFoundError) as exc:
            LOGGER.debug("Adapter candidate %s rejected: %s", path, exc)
            continue

    raise RuntimeError(
        "No Bluetooth adapter exposing org.bluez.Adapter1 was found; check hardware and permissions."
    )
