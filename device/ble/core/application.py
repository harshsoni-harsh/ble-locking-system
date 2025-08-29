from dbus_next.service import ServiceInterface, method


class GATTApplication(ServiceInterface):
    """
    Implements org.freedesktop.DBus.ObjectManager at APP_PATH.
    BlueZ calls GetManagedObjects() to discover all services/characteristics/descriptors.
    """
    def __init__(self, path, services):
        super().__init__('org.freedesktop.DBus.ObjectManager')
        self.path = path
        self.services = services

    @method()
    def GetManagedObjects(self) -> 'a{oa{sa{sv}}}':
        """
        Return a dict:
        {
          object_path: {
            interface_name: {
              prop_name: VariantValue,
              ...
            }
          },
          ...
        }
        """
        managed = {}

        for svc in self.services:
            # Service node
            managed[svc._path] = {
                'org.bluez.GattService1': {
                    'UUID': svc._uuid,
                    'Primary': True,
                    'Includes': [],
                }
            }

            # Characteristic nodes
            for ch in getattr(svc, 'characteristics', []):
                managed[ch.path] = {
                    'org.bluez.GattCharacteristic1': {
                        'UUID': ch._uuid,
                        'Service': svc._path,
                        'Flags': ch._flags,
                        'Descriptors': [d._path for d in getattr(ch, 'descriptors', [])],
                        'Notifying': getattr(ch, 'notifying', False),
                    }
                }

                # Descriptor nodes (if any)
                for d in getattr(ch, 'descriptors', []):
                    managed[d._path] = {
                        'org.bluez.GattDescriptor1': {
                            'UUID': d._uuid,
                            'Characteristic': ch._path,
                            'Flags': d._flags,
                        }
                    }

        return managed
