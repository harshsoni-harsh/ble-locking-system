import asyncio
from dbus_next.aio import MessageBus
from dbus_next.constants import BusType
from dbus_next.errors import DBusError
import logging

# local imports
from ble.application import GATTApplication
from ble.service import GATTService
from ble.advertisement import Advertisement

logging.getLogger("dbus_next.message_bus").setLevel(logging.CRITICAL)

BLUEZ = 'org.bluez'

ADAPTER_PATH = '/org/bluez/hci0'
APP_PATH = '/org/bluez/example'
GATT_SERVICE_PATH = '/org/bluez/example/service0'
LE_ADVERTISEMENT_PATH = '/org/bluez/example/advertisement0'

SERVICE_UUID = '12345678-1234-5678-1234-56789abcdef0'
CHARACTERISTIC_UUID = '12345678-1234-5678-1234-56789abcdef1'

async def main():
    """Main function to create and register the GATT server and advertisement."""
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    service = GATTService(GATT_SERVICE_PATH, SERVICE_UUID)
    advertisement = Advertisement(LE_ADVERTISEMENT_PATH, "Starlink", [SERVICE_UUID])
    app = GATTApplication(APP_PATH, [service])

    # Get proxies for the BlueZ GATT and Advertisement managers
    intro = await bus.introspect(BLUEZ, ADAPTER_PATH)
    adapter = bus.get_proxy_object(BLUEZ, ADAPTER_PATH, intro)
    gatt_mgr = adapter.get_interface('org.bluez.GattManager1')
    adv_mgr  = adapter.get_interface('org.bluez.LEAdvertisingManager1')

    try:
        print("Registering Application")
        bus.export(APP_PATH, app)

        print("Registering GATT Service...")
        bus.export(GATT_SERVICE_PATH, service)
        for characteristic in service.characteristics:
            bus.export(characteristic.path, characteristic)

        await gatt_mgr.call_register_application(APP_PATH, {})
        
        bus.export(advertisement.path, advertisement)
        print("Registering Advertisement...")
        await adv_mgr.call_register_advertisement(advertisement.path, {})
        
        print("\nDevice is now advertising and GATT server is running.")
        print("Press Ctrl+C to stop.")
        
        # Keep the event loop running to listen for D-Bus signals
        await asyncio.get_event_loop().create_future()
    
    except DBusError as e:
        print(f"D-Bus error: {e}")
    
    except asyncio.CancelledError:
        # Raised when Ctrl+C stops the loop
        pass
    
    finally:
        print("Unregistering service and advertisement...")
        try:
            await gatt_mgr.call_unregister_application(APP_PATH)
        except Exception as e:
            pass

        try:
            await adv_mgr.call_unregister_advertisement(advertisement.path)
        except Exception as e:
            pass

        print("Shutdown complete.")
            
if __name__ == '__main__':
    asyncio.run(main())