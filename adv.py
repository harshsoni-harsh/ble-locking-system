import asyncio
import hmac, hashlib, time
from bluez_peripheral.advert import Advertisement, AdvertisingIncludes
from bluez_peripheral.util import get_message_bus, Adapter
from dbus_fast import Variant

# TODO: share secrets on first pair and store securely (per device)
SHARED_SECRET = b"supersecretkey1"
ADVERT_INTERVAL = 30
PHONE_MAC = "AA:BB:CC:DD:EE:FF" # Example

# A constant Manufacturer ID (replace 0xFFFF with your assigned company ID)
MANUFACTURER_ID = 0xFFFF
ADVERT_TIMEOUT = 0  # 0 means advertising continues indefinitely (or until stopped)

def generate_token(mac: str) -> bytes:
    ts = int(time.time() // ADVERT_INTERVAL)
    return hmac.new(SHARED_SECRET, mac.encode() + str(ts).encode(), hashlib.sha256).digest()[:16]

class LockAdvertisement(Advertisement):
    def __init__(self):
        super().__init__(
            localName="BLELock", 
            serviceUUIDs=["180D"], 
            appearance=0x0340, 
            timeout=ADVERT_TIMEOUT, 
            manufacturerData={MANUFACTURER_ID: generate_token(PHONE_MAC)},
            # includes=AdvertisingIncludes.TX_POWER   # not supported in some adapters
		)

    def update_token(self):
        token = generate_token(PHONE_MAC)
        self._manufacturerData[MANUFACTURER_ID] = Variant("ay", token)
        print(f"[ADV] Advertising token: {token.hex()}")

async def advertise_loop():
    bus = await get_message_bus()
    adapter = await Adapter.get_first(bus)
    adapter_name = await adapter.get_name()
    advertiser = LockAdvertisement()

    await advertiser.register(bus, adapter)

    print(f"Starting BLE Advertising on adapter {adapter_name}...")
    
    try:
        while True:
            advertiser.update_token()
            
            await advertiser.unregister()
            await advertiser.register(bus, adapter)
            
            await asyncio.sleep(ADVERT_INTERVAL)

    except asyncio.CancelledError:
        pass
    finally:
        print("Stopping BLE Advertising...")
        await advertiser.unregister()


if __name__ == "__main__":
    try:
        asyncio.run(advertise_loop())
    except KeyboardInterrupt:
        print("\nScript stopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
