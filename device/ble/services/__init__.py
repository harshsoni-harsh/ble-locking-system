import os
import time
import hmac
import hashlib
import secrets
import threading
import subprocess

from ble.core.service import GATTService
from ble.core.characteristic import GATTCharacteristic, method
from ble.core.descriptor import GATTDescriptor
from ble.constants import AUTH_PSK_ENV, SESSION_TIMEOUT, TX_POWER_DEFAULT

def path_to_mac(device_path: str) -> str | None:
	last = device_path.split("/")[-1]
	if last.startswith("dev_"):
		return last[4:].replace("_", ":")
	return None

class LCService(GATTService):
	def __init__(self, path):
		# basic state
		self.session_start_time = None
		self.locked = False
		self.battery_level = 100
		self.tamper = False
		self.uptime = 0

		# session/auth state (single active device)
		self.active_device = None
		self.session_auth = False
		self.conn_counter = 0
		self.last_nonce = None

		# proximity state
		self.tx_power = TX_POWER_DEFAULT
		self.last_rssi = None
		self.proximity_ok = False

		# PSK for HMAC (bytes)
		psk = os.getenv(AUTH_PSK_ENV, "dev-psk-change-me").encode("utf-8")
		self.psk = psk

		# Characteristics
		self.auth_char = AuthCharacteristic(os.path.join(path, "auth"), self)
		self.locked_char = LockedCharacteristic(os.path.join(path, "locked"), self)
		self.battery_level_char = BatteryLevelCharacteristic(os.path.join(path, "battery_level"), self)
		self.tamper_char = TamperCharacteristic(os.path.join(path, "tamper"), self)
		self.uptime_char = UptimeCharacteristic(os.path.join(path, "uptime"), self)
		self.proximity_char = ProximityCharacteristic(os.path.join(path, "proximity"), self)

		characteristics = [
			self.auth_char,
			self.locked_char,
			self.battery_level_char,
			self.tamper_char,
			self.uptime_char,
			self.proximity_char,
		]

		super().__init__(path, "84bedf55-c9b2-4927-bd28-86cd93f91cfd", characteristics)
		
		threading.Thread(target=self._poll_rssi, daemon=True).start()
		
	def _poll_rssi(self):
		"""Periodically fetch RSSI using hcitool for the active BLE device."""
		while True:
			try:
				print("[RSSI POLLER] Active device:", self.active_device)
				if not self.active_device:
					time.sleep(0.5)
					continue

				r = subprocess.check_output(
					["hcitool", "con"],
					stderr=subprocess.STDOUT
				).decode()

				print("[RSSI POLLER] hcitool con output:", r.strip())

				# Run hcitool to fetch RSSI for the connected device
				result = subprocess.check_output(
					["hcitool", "rssi", self.active_device],
					stderr=subprocess.STDOUT
				).decode()

				print("[RSSI POLLER] hcitool output:", result.strip())

				# Parse the output like: "RSSI return value: -65"
				if "RSSI return value:" in result:
					rssi = int(result.strip().split(":")[-1])
					self.last_rssi = rssi
					self.proximity_ok = rssi > -70  # adjust threshold as needed

					print(f"[RSSI] {self.active_device} → {rssi} dBm, proximity_ok={self.proximity_ok}")

					# Notify BLE clients of proximity change
					if hasattr(self, "proximity_char"):
						self.proximity_char.notify(bytes([1 if self.proximity_ok else 0]))

				# time.sleep(3)  # poll interval (seconds)

			except subprocess.CalledProcessError as e:
				# hcitool fails if not connected
				if b"Not connected" in e.output:
					self.last_rssi = None
					self.proximity_ok = False
				print("[RSSI POLLER] hcitool error:", e.output.decode().strip())
				time.sleep(0.5)
			except Exception as e:
				print("[RSSI POLLER ERROR]", e)
				time.sleep(0.5)

	# ---------------- Lock state updates ----------------
	def toggle_locked(self, locked):
		self.locked = locked
		self.locked_char.notify(bytes([1 if self.locked else 0]))

	def update_battery_level(self, battery_level):
		self.battery_level = battery_level
		self.battery_level_char.notify(bytes([self.battery_level]))

	def toggle_tamper(self, tamper):
		self.tamper = tamper
		self.tamper_char.notify(bytes([1 if self.tamper else 0]))

	def update_uptime(self, uptime):
		self.uptime = uptime
		self.uptime_char.notify(self.uptime.to_bytes(4, 'little'))

	# ---------------- Auth helpers ----------------
	def start_auth_handshake(self, device_mac: str):
		"""Start a new handshake for a device, replacing previous session."""
		self.active_device = device_mac
		self.conn_counter = (self.conn_counter + 1) & 0xFFFFFFFF
		self.session_auth = False
		self.last_nonce = secrets.token_bytes(16)
		self.session_start_time = time.time()

		payload = self.last_nonce + self.conn_counter.to_bytes(4, 'little')
		if hasattr(self, 'auth_char'):
			self.auth_char.notify(payload)
	
	def is_session_valid(self, device_mac: str) -> bool:
		"""Check if session is still valid (correct device + timeout not exceeded)."""
		if device_mac != self.active_device:
			return False
		if not self.session_auth:
			return False
		if not self.session_start_time:
			return False
		if time.time() - self.session_start_time > SESSION_TIMEOUT:
			print("[AUTH] Session expired")
			self.session_auth = False
			self.active_device = None
			return False
		return True

	async def validate_auth(self, client_mac: bytes, device_mac: str) -> bool:
		"""Validate client HMAC only if from active device."""
		if device_mac != self.active_device:
			print("[AUTH] Denied: not active session device")
			return False
		if not self.last_nonce:
			return False

		msg = b"AUTH" + self.last_nonce + self.conn_counter.to_bytes(4, 'little')
		expected = hmac.new(self.psk, msg, hashlib.sha256).digest()
		ok = hmac.compare_digest(expected, client_mac)

		self.session_auth = ok
		if ok:
			self.session_start_time = time.time()
		return ok

# ---------------- Characteristics ----------------

class AuthCharacteristic(GATTCharacteristic):
	def __init__(self, path, service: LCService):
		super().__init__(path, "3a2ac7f1-5ca0-4d93-93a0-9b1e3aee0a10",
						 ["notify", "write"], service, initial_value=b"")

	@method()
	def StopNotify(self):
		try:
			super().StopNotify()
		finally:
			self.service.session_auth = False
			self.service.active_device = None

	@method()
	async def WriteValue(self, value: 'ay', options: 'a{sv}'):
		value = bytes(value)
		if not options.get("device", None):
			print("[AUTH] Missing device path in options")
			self.notify(b"\x00")
			return
		device_path = options.get("device", None).value
		device_mac = path_to_mac(device_path)		
		print("[AUTH] Write from device:", device_mac)

		# first time we see this device → start handshake
		if self.service.active_device != device_mac or not self.service.last_nonce:
			print("[AUTH] Starting new handshake")
			self.service.start_auth_handshake(device_mac)
			return

		ok = await self.service.validate_auth(value, device_mac)
		self.notify(b"\x01" if ok else b"\x00")


class LockedCharacteristic(GATTCharacteristic):
	def __init__(self, path, service):
		super().__init__(path, "2a137f90-c9b2-4927-bd28-86cd93f91cfd",
						 ["read", "notify", "write"], service, initial_value=b"\x00")

	@method()
	def ReadValue(self, options: 'a{sv}') -> 'ay':
		return bytes([1 if self.service.locked else 0])

	@method()
	def WriteValue(self, value: 'ay', options: 'a{sv}'):
		if not options.get("device", None):
			print("[LOCK] Missing device path in options")
			self.notify(b"\x00")
			return
		device_path = options.get("device", None).value
		device_mac = path_to_mac(device_path)		
		print("[LOCK] Write from device:", device_mac)

		if not self.service.is_session_valid(device_mac):
			print("[LOCK] Write denied: invalid or expired session")
			return
		# if not getattr(self.service, "proximity_ok", False):
		#	 print("[LOCK] Write denied: device not in proximity")
		#	 return
		try:
			new_state = bool(int(bytes(value)[0]))
			self.service.toggle_locked(new_state)
		except Exception:
			print("[LOCK] Invalid payload for locked state")


class BatteryLevelCharacteristic(GATTCharacteristic):
	def __init__(self, path, service):
		super().__init__(path, "180f0002-0000-1000-8000-00805f9b34fb", ["read", "notify"], service, bytes([100]))

		cud = GATTDescriptor(
			os.path.join(path, "cud"),
			"2901",
			["read"],
			self,
			initial_value="Battery Level".encode("utf-8"),
		)

		self.add_descriptor(cud)

	@method()
	def ReadValue(self, options: 'a{sv}') -> 'ay':
		return bytes([self.service.battery_level])


class TamperCharacteristic(GATTCharacteristic):
	def __init__(self, path, service):
		super().__init__(path, "bc008b7a-c9b2-4927-bd28-86cd93f91cfd",
						 ["read", "notify"], service, initial_value=b"\x00")

	@method()
	def ReadValue(self, options: 'a{sv}') -> 'ay':
		return bytes([1 if self.service.tamper else 0])


class UptimeCharacteristic(GATTCharacteristic):
	def __init__(self, path, service):
		super().__init__(path, "9f8b83a2-c9b2-4927-bd28-86cd93f91cfd",
						 ["read", "notify"], service, initial_value=b"\x00\x00\x00\x00")

	@method()
	def ReadValue(self, options: 'a{sv}') -> 'ay':
		return self.service.uptime.to_bytes(4, 'little')


class ProximityCharacteristic(GATTCharacteristic):
	def __init__(self, path, service):
		super().__init__(path, "cf238b13-6f89-4a6e-9e3d-42f0d8e4b1a5",
						 ["read", "notify"], service, initial_value=b"\x00")

	@method()
	def ReadValue(self, options: 'a{sv}') -> 'ay':
		return bytes([1 if self.service.proximity_ok else 0])
