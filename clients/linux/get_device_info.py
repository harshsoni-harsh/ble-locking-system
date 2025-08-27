import asyncio
import sys
from bleak import BleakClient


async def main(address):
    async with BleakClient(address) as client:
        if client.is_connected:
            for service in client.services:
                print("\nservice", service.handle, service.uuid, service.description)

                characteristics = service.characteristics

                for char in characteristics:
                    print(
                        "  characteristic",
                        char.handle,
                        char.uuid,
                        char.description,
                        char.properties,
                    )

                    descriptors = char.descriptors

                    for desc in descriptors:
                        print("    descriptor", desc)


if __name__ == "__main__":
    address = sys.argv[1]
    print("address:", address)
    asyncio.run(main(address))
