import asyncio
import sys
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

async def main():
    def callback(d: BLEDevice, advt: AdvertisementData):
        if len(sys.argv) > 1:
            name = sys.argv[1]
            if d.name and name in d.name:
                print(d.address)
        else:
            print(d)
    async with BleakScanner(callback):
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
