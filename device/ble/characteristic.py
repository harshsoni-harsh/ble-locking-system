from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, method, dbus_property

class GATTCharacteristic(ServiceInterface):
    def __init__(self, path, uuid, flags, service):
        super().__init__('org.bluez.GattCharacteristic1')
        self.path = path
        self.uuid = uuid
        self.flags = flags
        self.service = service
        self.value = b'Hello D-Bus!'

    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        print(f"Read request received. Returning: {bytes(self.value).decode()}")
        return self.value

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> 's':
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> 'as':
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> 'o':
        return self.service.path
    
    @dbus_property(access=PropertyAccess.READ)
    def Notifying(self) -> 'b':
        return False

    @dbus_property(access=PropertyAccess.READ)
    def Descriptors(self) -> 'ao':
        return []