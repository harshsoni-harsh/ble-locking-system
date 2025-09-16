import os
import time
import hmac
import hashlib
import secrets
from dbus_next.aio import MessageBus

from ble.core.service import GATTService
from ble.core.characteristic import GATTCharacteristic, method
from ble.core.descriptor import GATTDescriptor

AUTH_PSK_ENV = "BLE_PSK"  # Pre-Shared Key env var name


class LCService(GATTService):
    def __init__(self, path):
        # basic state
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
        self.tx_power = -59  # calibrated at 1m
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
    def start_auth_handshake(self, device_path: str):
        """Start a new handshake for a device, replacing previous session."""
        self.active_device = device_path
        self.conn_counter = (self.conn_counter + 1) & 0xFFFFFFFF
        self.session_auth = False
        self.last_nonce = secrets.token_bytes(16)

        payload = self.last_nonce + self.conn_counter.to_bytes(4, 'little')
        if hasattr(self, 'auth_char'):
            self.auth_char.notify(payload)

    async def validate_auth(self, client_mac: bytes, device_path: str) -> bool:
        """Validate client HMAC only if from active device."""
        if device_path != self.active_device:
            print("[AUTH] Denied: not active session device")
            return False
        if not self.last_nonce:
            return False

        msg = b"AUTH" + self.last_nonce + self.conn_counter.to_bytes(4, 'little')
        expected = hmac.new(self.psk, msg, hashlib.sha256).digest()
        ok = hmac.compare_digest(expected, client_mac)

        self.session_auth = ok
        if ok:
            await self.update_rssi_from_bluez(device_path)
        return ok

    # ---------------- Proximity helpers ----------------
    def update_rssi(self, rssi: int):
        """Update RSSI, recompute proximity."""
        self.last_rssi = rssi
        self.check_proximity()

    def check_proximity(self):
        """Decide if device is near enough based on RSSI + TxPower."""
        if self.last_rssi is None:
            return
        # Distance approximation using path-loss model
        distance = 10 ** ((self.tx_power - self.last_rssi) / (10 * 2))  # n≈2
        self.proximity_ok = distance < 2.0  # threshold = 2m
        self.proximity_char.notify(bytes([1 if self.proximity_ok else 0]))

    async def update_rssi_from_bluez(self, device_path: str):
        """Fetch RSSI from BlueZ for the authenticated device."""
        try:
            bus = await MessageBus().connect()
            obj = bus.get_proxy_object("org.bluez", device_path, [
                "org.freedesktop.DBus.Properties"
            ])
            props_iface = obj.get_interface("org.freedesktop.DBus.Properties")
            rssi = await props_iface.call_get("org.bluez.Device1", "RSSI")
            self.update_rssi(rssi)
            print(f"[PROXIMITY] RSSI={rssi}, proximity_ok={self.proximity_ok}")
        except Exception as e:
            print(f"[PROXIMITY] Could not read RSSI: {e}")



# ---------------- Characteristics ----------------

class AuthCharacteristic(GATTCharacteristic):
    def __init__(self, path, service: LCService):
        super().__init__(path, "3a2ac7f1-5ca0-4d93-93a0-9b1e3aee0a10",
                         ["notify", "write"], service, initial_value=b"")

    @method()
    def StartNotify(self):
        try:
            super().StartNotify()
        except Exception:
            pass
        # device path should be provided in options during WriteValue
        # we can't know it here until a write occurs

    @method()
    def StopNotify(self):
        try:
            super().StopNotify()
        finally:
            self.service.session_auth = False
            self.service.active_device = None

    @method()
    async def WriteValue(self, value: 'ay', options: 'a{sv}'):
        mac = bytes(value)
        device_path = options.get("device", None)
        print("[AUTH] Write from device:", device_path)
        if not device_path:
            print("[AUTH] Missing device path in options")
            self.notify(b"\x00")
            return

        # first time we see this device → start handshake
        if self.service.active_device != device_path:
            self.service.start_auth_handshake(device_path)

        ok = await self.service.validate_auth(mac, device_path)
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
        device_path = options.get("device", None)
        if device_path != self.service.active_device:
            print("[AUTH] Write denied: not active session device")
            return
        if not self.service.session_auth:
            print("[AUTH] Write denied: not authenticated")
            return
        if not getattr(self.service, "proximity_ok", False):
            print("[AUTH] Write denied: device not in proximity")
            return
        try:
            new_state = bool(int(bytes(value)[0]))
            self.service.toggle_locked(new_state)
        except Exception:
            print("[WRITE] Invalid payload for locked state")


class BatteryLevelCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        d = GATTDescriptor(
            os.path.join(path, "cud"),
            "00002901-0000-1000-8000-00805f9b34fb",
            ["read"],
            self,
            initial_value="Battery Level".encode("utf-8")
        )
        super().__init__(path, "fe11bc92-c9b2-4927-bd28-86cd93f91cfd",
                         ["read", "notify"], service, initial_value=b"\x64", descriptors=[d])

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
