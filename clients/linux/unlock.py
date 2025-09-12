import asyncio
import hmac
import hashlib
from bleak import BleakClient

AUTH_UUID   = "3a2ac7f1-5ca0-4d93-93a0-9b1e3aee0a10"
LOCKED_UUID = "2a137f90-c9b2-4927-bd28-86cd93f91cfd"
PSK = b"dev-psk-change-me"

auth_data = {}
nonce_event = asyncio.Event()

def auth_notify_handler(sender, data: bytearray):
    if len(data) == 20:
        nonce = data[:16]
        counter = data[16:]
        msg = b"AUTH" + nonce + counter
        mac = hmac.new(PSK, msg, hashlib.sha256).digest()
        auth_data["mac"] = mac
        nonce_event.set()
    elif len(data) == 1:
        print("Auth result:", "✅ success" if data[0] == 1 else "❌ failed")

async def run(address: str):
    async with BleakClient(address) as client:
        print("Connected:", client.is_connected)
        await client.start_notify(AUTH_UUID, auth_notify_handler)

        # Wait for nonce/counter notification
        await nonce_event.wait()

        # Send HMAC response
        print("Sending HMAC response...")
        await client.write_gatt_char(AUTH_UUID, auth_data["mac"], response=True)

        # Wait for server's result notification
        await asyncio.sleep(1.0)

        # Try toggling locked state
        print("Toggling lock...")
        await client.write_gatt_char(LOCKED_UUID, bytearray([1]), response=True)
        await asyncio.sleep(1.0)

if __name__ == "__main__":
    asyncio.run(run("AA:BB:CC:DD:EE:FF")) # replace with actual MAC
