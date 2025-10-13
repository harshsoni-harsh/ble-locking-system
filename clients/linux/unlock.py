"""
unlock.py

Usage:
	python unlock.py <MAC> [adapter]

Example:
	python unlock.py AA:BB:CC:DD:EE:FF hci0
"""

import sys
import asyncio
import hmac
import hashlib
from bleak import BleakClient

AUTH_UUID   = "3a2ac7f1-5ca0-4d93-93a0-9b1e3aee0a10"
LOCKED_UUID = "2a137f90-c9b2-4927-bd28-86cd93f91cfd"
PSK = b"dev-psk-change-me"

# Shared state between handler and task
auth_data = {}
nonce_event = asyncio.Event()
auth_event = asyncio.Event()

def auth_notify_handler(sender, data: bytearray):
	"""Notification handler for the auth characteristic.

	- 20 bytes => nonce(16) + counter(4)
	- 1 byte  => auth result (0x01 success / 0x00 fail)
	"""
	# Convert to immutable bytes for safety
	payload = bytes(data)

	if len(payload) == 20:
		nonce = payload[:16]
		counter = payload[16:]
		# Compute HMAC exactly as server expects
		msg = b"AUTH" + nonce + counter
		mac = hmac.new(PSK, msg, hashlib.sha256).digest()
		auth_data["mac"] = mac
		print("[CLIENT] Received nonce+counter -> prepared HMAC")
		# signal waiting coroutine
		if not nonce_event.is_set():
			nonce_event.set()

	elif len(payload) == 1:
		ok = payload[0] == 1
		auth_data["ok"] = ok
		print("[CLIENT] Auth result:", "✅ success" if ok else "❌ failed")
		if not auth_event.is_set():
			auth_event.set()
	else:
		# Unexpected payload length — print for debugging
		print(f"[CLIENT] Unexpected auth notify (len={len(payload)}): {payload.hex()}")


async def run(address: str, adapter: str | None = None):
	client_kwargs = {}
	if adapter:
		# Bleak accepts adapter parameter on Linux backends
		client_kwargs["adapter"] = adapter

	async with BleakClient(address, **client_kwargs) as client:
		print("[CLIENT] Connected:", client.is_connected)

		# subscribe to auth notifications
		await client.start_notify(AUTH_UUID, auth_notify_handler)
		print("[CLIENT] Subscribed to AUTH notifications")

		# 1) Trigger handshake: do an initial write to auth char so server generates nonce
		# Server's WriteValue handler starts handshake on first write and notifies
		print("[CLIENT] Triggering handshake (initial write)...")
		try:
			await client.write_gatt_char(AUTH_UUID, b"\x00", response=True)
		except Exception as e:
			print("[CLIENT] Trigger write failed:", e)
			return

		# 2) Wait for nonce+counter (20 bytes) from server
		try:
			await asyncio.wait_for(nonce_event.wait(), timeout=5.0)
		except asyncio.TimeoutError:
			print("[CLIENT] Timeout waiting for nonce from server")
			return

		# 3) Send computed HMAC back to server
		mac = auth_data.get("mac")
		if not mac:
			print("[CLIENT] Internal error: HMAC not prepared")
			return

		print("[CLIENT] Sending HMAC response...")
		try:
			await client.write_gatt_char(AUTH_UUID, mac, response=True)
		except Exception as e:
			print("[CLIENT] HMAC write failed:", e)
			return

		# 4) Wait for 1-byte auth result
		try:
			await asyncio.wait_for(auth_event.wait(), timeout=5.0)
		except asyncio.TimeoutError:
			print("[CLIENT] Timeout waiting for auth result")
			return

		if not auth_data.get("ok"):
			print("[CLIENT] Authentication failed, aborting")
			return

		# 5) Auth succeeded — now attempt toggling lock (note: server may still block on proximity)
		print("[CLIENT] Toggling lock (write to LOCKED_UUID)...")
		try:
			await client.write_gatt_char(LOCKED_UUID, bytearray([1]), response=True)
			# give server a moment to emit notification for locked state (if it does)
			await asyncio.sleep(0.5)
		except Exception as e:
			print("[CLIENT] Failed to write lock char:", e)
			return

		print("[CLIENT] Done.")

		# cleanup: stop notify
		try:
			await client.stop_notify(AUTH_UUID)
		except Exception:
			pass


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: python unlock.py <MAC> [adapter]")
		sys.exit(1)

	address = sys.argv[1]
	adapter = sys.argv[2] if len(sys.argv) > 2 else None

	asyncio.run(run(address, adapter))
