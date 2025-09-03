from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, method, dbus_property

# types
from ble.core.characteristic import GATTCharacteristic

class GATTDescriptor(ServiceInterface):
    def __init__(self, path, uuid, flags, characteristic: GATTCharacteristic, initial_value=b""):
        super().__init__('org.bluez.GattDescriptor1')
        self.path = path
        self.uuid = uuid
        self.flags = flags
        self.value = initial_value
        self.characteristic = characteristic

    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        print(f"[READ] Descriptor read: {self.value}")
        return list(self.value)

    @method()
    def WriteValue(self, value: 'ay', options: 'a{sv}') -> None:
        print(f"[WRITE] Descriptor updated: {value}")
        self.value = bytes(value)

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> 's':
        return self.uuid
    
    @dbus_property(access=PropertyAccess.READ)
    def Characteristic(self) -> 'o':
        return self.characteristic.path

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> 'as':
        return self.flags
