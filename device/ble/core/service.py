from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property

class GATTService(ServiceInterface):
    def __init__(self, path: str, uuid: str, characteristics: list):
        super().__init__('org.bluez.GattService1')
        self.path = path
        self.uuid = uuid
        self.characteristics = characteristics

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> 's':
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> 'b':
        return True

    @dbus_property(access=PropertyAccess.READ)
    def Characteristics(self) -> 'ao':
        return [c.path for c in self.characteristics]
