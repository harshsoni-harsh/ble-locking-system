from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method

from ble.core.service import GATTService

class GATTCharacteristic(ServiceInterface):
    def __init__(self, path, uuid, flags, service: GATTService, initial_value=b"", on_read=None, on_write=None):
        super().__init__('org.bluez.GattCharacteristic1')
        self._path = path
        self._uuid = uuid
        self._flags = flags
        self._service = service
        self._value = initial_value
        self._on_read = on_read
        self._on_write = on_write

    @property
    def path(self):
        return self._path

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> 's':
        return self._uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> 'o':
        return self._service._path

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> 'as':
        return self._flags

    @dbus_property(access=PropertyAccess.READ)
    def Notifying(self) -> 'b':
        return False

    @dbus_property(access=PropertyAccess.READ)
    def Descriptors(self) -> 'ao':
        return []

    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        print(f"[READ] Returning: {self._value}")
        return self._value
