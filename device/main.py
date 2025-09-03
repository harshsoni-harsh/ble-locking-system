import asyncio
from dbus_next.aio import MessageBus
from dbus_next.constants import BusType
from dbus_next.errors import DBusError
import logging

from ble.core.application import GATTApplication
from ble.core.advertisement import Advertisement
from ble.services import LCService

logging.getLogger("dbus_next.message_bus").setLevel(logging.CRITICAL)

BLUEZ = 'org.bluez'
ADAPTER_PATH = '/org/bluez/hci0'
APP_PATH = '/org/bluez/example'
LE_ADVERTISEMENT_PATH = '/org/bluez/example/advertisement0'


async def main():
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    services = [
        LCService("/org/bluez/example/service0"),
    ]

    app = GATTApplication(APP_PATH, services)
    advertisement = Advertisement(
        LE_ADVERTISEMENT_PATH,
        "Starlink",
        [s.uuid for s in services]
    )

    intro = await bus.introspect(BLUEZ, ADAPTER_PATH)
    adapter = bus.get_proxy_object(BLUEZ, ADAPTER_PATH, intro)
    gatt_mgr = adapter.get_interface('org.bluez.GattManager1')
    adv_mgr  = adapter.get_interface('org.bluez.LEAdvertisingManager1')

    try:
        print("Registering GATT Application...")
        bus.export(APP_PATH, app)

        for service in services:
            bus.export(service.path, service)
            for char in service.characteristics:
                bus.export(char.path, char)
                print("Registered char:", char.path)
                for desc in getattr(char, "descriptors", []):
                    print("Registered desc:", desc.path)
                    bus.export(desc.path, desc)

        await gatt_mgr.call_register_application(APP_PATH, {})

        print("Registering Advertisement...")
        bus.export(advertisement.path, advertisement)
        await adv_mgr.call_register_advertisement(advertisement.path, {})

        print("\n✅ Device is now advertising and GATT server is running.")
        print("Press Ctrl+C to stop.")

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
        except Exception:
            pass

        try:
            await adv_mgr.call_unregister_advertisement(advertisement.path)
        except Exception:
            pass

        print("Shutdown complete.")


if __name__ == '__main__':
    asyncio.run(main())
