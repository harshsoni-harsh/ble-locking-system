import os
from ble.core.service import GATTService
from ble.core.characteristic import GATTCharacteristic

class BatteryService(GATTService):
    def __init__(self, path):
        characteristics = [
            BatteryLevelCharacteristic(os.path.join(path, "battery_level"), self)
        ]
        super().__init__(path, "0001180f-0000-1000-8000-00805f9b34fb", characteristics)


class BatteryLevelCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        super().__init__(path, "00002a19-0000-1000-8000-00805f9b34fb", ["read"], service, initial_value=bytes([100]))
