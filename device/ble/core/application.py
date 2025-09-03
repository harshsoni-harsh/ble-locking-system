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
            managed[svc.path] = {
                'org.bluez.GattService1': {
                    'UUID': svc.uuid,
                    'Primary': True,
                    'Includes': [],
                }
            }

            # Characteristic nodes
            for ch in getattr(svc, 'characteristics', []):
                managed[ch.path] = {
                    'org.bluez.GattCharacteristic1': {
                        'UUID': ch.uuid,
                        'Service': svc.path,
                        'Flags': ch.flags,
                        'Descriptors': [d.path for d in getattr(ch, 'descriptors', [])],
                        'Notifying': getattr(ch, 'notifying', False),
                    }
                }

                # Descriptor nodes (if any)
                for d in getattr(ch, 'descriptors', []):
                    managed[d.path] = {
                        'org.bluez.GattDescriptor1': {
                            'UUID': d.uuid,
                            'Characteristic': ch.path,
                            'Flags': d.flags,
                            'Value': d.value,
                        }
                    }

        return managed
