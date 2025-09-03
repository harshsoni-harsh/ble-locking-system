import os
from ble.core.service import GATTService
from ble.core.characteristic import GATTCharacteristic, method
from ble.core.descriptor import GATTDescriptor

class LCService(GATTService):
    def __init__(self, path):
        self.locked = False
        self.battery_level = 100
        self.tamper = False
        self.uptime = 0
        self.locked_char = LockedCharacteristic(os.path.join(path, "locked"), self)
        self.battery_level_char = BatteryLevelCharacteristic(os.path.join(path, "battery_level"), self)
        self.tamper_char = TamperCharacteristic(os.path.join(path, "tamper"), self)
        self.uptime_char = UptimeCharacteristic(os.path.join(path, "uptime"), self)
        characteristics = [self.locked_char, self.battery_level_char, self.tamper_char, self.uptime_char]
        super().__init__(path, "84bedf55-c9b2-4927-bd28-86cd93f91cfd", characteristics)

    def toggle_locked(self, locked):
        self.locked = locked
        self.locked_char.notify(bytes([1 if self.locked else 0]))

    def update_battery_level(self, battery_level):
        self.battery_level = battery_level
        self.battery_level_char.notify(bytes([self.battery_level]))

    def toggle_tamper(self, tamper):
        self.tamper = tamper
        self.tamper_char.notify(bytes([1 if self.tamper else 0]))

    def update_uptime(self, uptime):
        self.uptime = uptime
        self.uptime_char.notify(self.uptime.to_bytes(4, 'little'))

class LockedCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        super().__init__(path, "2a137f90-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify"], service, initial_value=b"\x00")
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return bytes([1 if self.service.locked else 0])

class BatteryLevelCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        d = GATTDescriptor(
            os.path.join(path, "cud"),
            "00002901-0000-1000-8000-00805f9b34fb",
            ["read"],
            self,
            initial_value="Battery Level sss".encode("utf-8")
        )
        super().__init__(path, "fe11bc92-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify"], service, initial_value=b"\x64", descriptors=[d])
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return bytes([self.service.battery_level])


class TamperCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        super().__init__(path, "bc008b7a-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify"], service, initial_value=b"\x00")
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return bytes([1 if self.service.tamper else 0])

class UptimeCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        super().__init__(path, "9f8b83a2-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify"], service, initial_value=b"\x00\x00\x00\x00")
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return self.service.uptime.to_bytes(4, 'little')
