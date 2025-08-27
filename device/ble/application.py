from dbus_next.service import ServiceInterface

class GATTApplication(ServiceInterface):
    def __init__(self, path, services):
        super().__init__('org.bluez.GattApplication1')
        self.path = path
        self.services = services