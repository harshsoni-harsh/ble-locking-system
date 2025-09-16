from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method

# types
from ble.core.service import GATTService

class GATTCharacteristic(ServiceInterface):
    def __init__(self, path, uuid, flags, service: GATTService, initial_value=b"", on_read=None, on_write=None):
        super().__init__('org.bluez.GattCharacteristic1')
        self.path = path
        self.uuid = uuid
        self.flags = flags
        self.service = service
        self._value = initial_value
        self.on_read = on_read
        self.on_write = on_write
        self.notifying = False
        self.descriptors = []

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> 'ay':
        return self._value

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
    
    def add_descriptor(self, descriptor):
        self.descriptors.append(descriptor)

    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        print(f"[READ] Returning: {self._value}")
        return self._value

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
        self._value = value

        if self.notifying:
            self.emit_properties_changed({"Value": value})
            print(f"[NOTIFY] Sent notification: {value}")
        else:
            print("[NOTIFY] Skipped (no client subscribed)")

