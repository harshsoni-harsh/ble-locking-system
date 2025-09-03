from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method

# types
from ble.core.service import GATTService

class GATTCharacteristic(ServiceInterface):
    def __init__(self, path, uuid, flags, service: GATTService, initial_value=b"", on_read=None, on_write=None, descriptors=[]):
        super().__init__('org.bluez.GattCharacteristic1')
        self.path = path
        self.uuid = uuid
        self.flags = flags
        self.service = service
        self.value = initial_value
        self.on_read = on_read
        self.on_write = on_write
        self.notifying = False
        self.descriptors = descriptors

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> 's':
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> 'o':
        return self.service.path

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> 'as':
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Notifying(self) -> 'b':
        return self.notifying

    @dbus_property(access=PropertyAccess.READ)
    def Descriptors(self) -> 'ao':
        return [d.path for d in self.descriptors]

    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        print(f"[READ] Returning: {self.value}")
        return self.value

    @method()
    def StartNotify(self):
        if not self.notifying:
            self.notifying = True
            print("[CCCD] Notifications enabled")

    @method()
    def StopNotify(self):
        if self.notifying:
            self.notifying = False
            print("[CCCD] Notifications disabled")
    
    def notify(self, value):
        self.value = value

        if self.notifying:
            self.emit_properties_changed({"Value": value})
            print(f"[NOTIFY] Sent notification: {value}")
        else:
            print("[NOTIFY] Skipped (no client subscribed)")

