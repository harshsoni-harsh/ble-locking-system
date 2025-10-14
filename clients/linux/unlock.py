import sys
import asyncio
import hmac
import hashlib
import time
from bleak import BleakClient, BleakScanner

AUTH_UUID   = "3a2ac7f1-5ca0-4d93-93a0-9b1e3aee0a10"
LOCKED_UUID = "2a137f90-c9b2-4927-bd28-86cd93f91cfd"
PSK = b"dev-psk-change-me"
MAX_ATTEMPTS = 3

def log(message):
	"""Prints a message with a millisecond-precision timestamp."""
	timestamp = f"{time.time():.3f}"
	print(f"[{timestamp}] {message}")

auth_data = {}
nonce_event = asyncio.Event()
auth_event = asyncio.Event()

def auth_notify_handler(sender, data: bytearray):
	"""Notification handler for the auth characteristic."""
	payload = bytes(data)

	if len(payload) == 20:
		nonce = payload[:16]
		counter = payload[16:]
		msg = b"AUTH" + nonce + counter
		mac = hmac.new(PSK, msg, hashlib.sha256).digest()
		auth_data["mac"] = mac
		log("[CLIENT] Received nonce+counter -> prepared HMAC")
		if not nonce_event.is_set():
			nonce_event.set()

	elif len(payload) == 1:
		ok = payload[0] == 1
		auth_data["ok"] = ok
		log(f"[CLIENT] Auth result: {'✅ success' if ok else '❌ failed'}")
		if not auth_event.is_set():
			auth_event.set()
	else:
		log(f"[CLIENT] Unexpected auth notify (len={len(payload)}): {payload.hex()}")


async def run(address: str, adapter: str | None = None):
	client_kwargs = {}
	if adapter:
		client_kwargs["adapter"] = adapter

	log(f"Discovering device {address}...")
	device = await BleakScanner.find_device_by_address(address, timeout=15.0)

	if not device:
		log(f"[ERROR] Device with address {address} not found.")
		return

	log(f"Device found. Attempting to connect...")
	async with BleakClient(device, **client_kwargs) as client:
		log(f"[CLIENT] Connected: {client.is_connected}")

		await client.start_notify(AUTH_UUID, auth_notify_handler)
		log("[CLIENT] Subscribed to AUTH notifications")

		auth_succeeded = False
		for attempt in range(1, MAX_ATTEMPTS + 1):
			log(f"--- Starting handshake attempt {attempt}/{MAX_ATTEMPTS} ---")
			
			nonce_event.clear()
			auth_event.clear()
			auth_data.clear()

			try:
				# 1) Trigger handshake
				log("[CLIENT] Triggering handshake (initial write)...")
				await client.write_gatt_char(AUTH_UUID, b"\x00", response=True)

				# 2) Wait for nonce+counter
				await asyncio.wait_for(nonce_event.wait(), timeout=3.0)

				# 3) Send computed HMAC
				mac = auth_data.get("mac")
				if not mac:
					raise ValueError("Internal error: HMAC not prepared")
				log("[CLIENT] Sending HMAC response...")
				await client.write_gatt_char(AUTH_UUID, mac, response=True)

				# 4) Wait for auth result
				await asyncio.wait_for(auth_event.wait(), timeout=3.0)

				if auth_data.get("ok"):
					log("--- Handshake attempt successful ---")
					auth_succeeded = True
					break # Exit the retry loop on success
				else:
					log("--- Handshake attempt failed (server rejected auth) ---")

			except asyncio.TimeoutError:
				log(f"--- Handshake attempt {attempt} failed: Timeout ---")
			except Exception as e:
				log(f"--- Handshake attempt {attempt} failed: {e} ---")
			
			if attempt < MAX_ATTEMPTS:
				await asyncio.sleep(0.5)

		if not auth_succeeded:
			log("[CLIENT] Authentication failed after all attempts, aborting.")
			return

		# 5) Auth succeeded — now attempt toggling lock
		log("[CLIENT] Toggling lock (write to LOCKED_UUID)...")
		try:
			await client.write_gatt_char(LOCKED_UUID, bytearray([1]), response=True)
			log("[CLIENT] Write to lock characteristic successful.")
			await asyncio.sleep(0.5)
		except Exception as e:
			log(f"[CLIENT] Failed to write lock char: {e}")

		log("[CLIENT] Done.")
		try:
			await client.stop_notify(AUTH_UUID)
			log("[CLIENT] Unsubscribed from AUTH notifications.")
		except Exception:
			pass


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: python unlock.py <MAC> [adapter]")
		sys.exit(1)

	address = sys.argv[1]
	adapter = sys.argv[2] if len(sys.argv) > 2 else None

	try:
		asyncio.run(run(address, adapter))
	except Exception as e:
		print(f"An error occurred: {e}")
