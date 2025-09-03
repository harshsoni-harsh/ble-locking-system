from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, method, dbus_property
from dbus_next.signature import Variant


class Advertisement(ServiceInterface):
    def __init__(self, path, local_name, service_uuids):
        super().__init__('org.bluez.LEAdvertisement1')
        self.path = path
        self.local_name = local_name
        self.service_uuids = service_uuids

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> 's':
        return 'peripheral'

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> 's':
        return self.local_name

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> 'as':
        return self.service_uuids
    
    @dbus_property(access=PropertyAccess.READ)
    def Includes(self) -> 'as':
        return []
    
    @dbus_property(access=PropertyAccess.READ)
    def Appearance(self) -> 'q':
        return 128

    @dbus_property(access=PropertyAccess.READ)
    def ManufacturerData(self) -> 'a{qv}':
        return {0xFFFF: Variant('ay', bytes([0x01]))}
