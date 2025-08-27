from bleak import BleakClient

address = "AA:AA:AA:AA:AA:AA"
char_uuid = "0000180a-0000-0000-8000-00805f9b34fb"

async def read_watch_data():
    async with BleakClient(address) as client:
        if client.is_connected:
            value = await client.read_gatt_char(char_uuid)
            print("Raw bytes:", value)
            print("Decoded:", value.decode('utf-8', errors='ignore'))

import asyncio
asyncio.run(read_watch_data())
