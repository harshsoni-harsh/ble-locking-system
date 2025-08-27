from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property
import os

# local imports
from .characteristic import GATTCharacteristic

CHARACTERISTIC_UUID = '12345678-1234-5678-1234-56789abcdef1'

class GATTService(ServiceInterface):
    def __init__(self, path, uuid):
        super().__init__('org.bluez.GattService1')
        self.path = path
        self.uuid = uuid
        self.characteristics = [
            GATTCharacteristic(
                os.path.join(path, f'char{i}'),
                CHARACTERISTIC_UUID,
                ['read'],
                self
            ) for i in range(1)
        ]

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> 's':
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> 'b':
        return True

    @dbus_property(access=PropertyAccess.READ)
    def Characteristics(self) -> 'ao':
        return [c.path for c in self.characteristics]
