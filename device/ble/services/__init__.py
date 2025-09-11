import os
from ble.core.service import GATTService
from ble.core.characteristic import GATTCharacteristic, method
from ble.core.descriptor import GATTDescriptor
import hmac
import hashlib
import secrets


AUTH_PSK_ENV = "BLE_PSK"  # Pre-Shared Key env var name

class LCService(GATTService):
    def __init__(self, path):
        # basic state
        self.locked = False
        self.battery_level = 100
        self.tamper = False
        self.uptime = 0

        # session/auth state
        self.session_auth = False
        self.conn_counter = 0
        # PSK for HMAC (bytes)
        psk = os.getenv(AUTH_PSK_ENV, "dev-psk-change-me").encode("utf-8")
        self.psk = psk

        # Characteristics
        self.auth_char = AuthCharacteristic(os.path.join(path, "auth"), self)
        self.locked_char = LockedCharacteristic(os.path.join(path, "locked"), self)
        self.battery_level_char = BatteryLevelCharacteristic(os.path.join(path, "battery_level"), self)
        self.tamper_char = TamperCharacteristic(os.path.join(path, "tamper"), self)
        self.uptime_char = UptimeCharacteristic(os.path.join(path, "uptime"), self)

        characteristics = [
            self.auth_char,
            self.locked_char,
            self.battery_level_char,
            self.tamper_char,
            self.uptime_char,
        ]

        super().__init__(path, "84bedf55-c9b2-4927-bd28-86cd93f91cfd", characteristics)

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

    # -- auth helpers --
    def start_auth_handshake(self):
        """Start a new handshake: bump counter, generate nonce, clear session auth, notify nonce+counter."""
        self.conn_counter = (self.conn_counter + 1) & 0xFFFFFFFF
        self.session_auth = False
        self.last_nonce = secrets.token_bytes(16)
        # notify client with nonce and conn_counter (nonce||counter_le)
        if hasattr(self, 'auth_char'):
            payload = self.last_nonce + self.conn_counter.to_bytes(4, 'little')
            self.auth_char.notify(payload)

    def validate_auth(self, client_mac: bytes) -> bool:
        """Validate client MAC (HMAC) over b"AUTH"||nonce||connCounter."""
        if not hasattr(self, 'last_nonce'):
            return False
        msg = b"AUTH" + self.last_nonce + self.conn_counter.to_bytes(4, 'little')
        expected = hmac.new(self.psk, msg, hashlib.sha256).digest()
        ok = hmac.compare_digest(expected, client_mac)
        self.session_auth = ok
        return ok


class AuthCharacteristic(GATTCharacteristic):
    def __init__(self, path, service: LCService):
        # notify + write without response
        super().__init__(path, "3a2ac7f1-5ca0-4d93-93a0-9b1e3aee0a10", ["notify", "write"], service, initial_value=b"")

    @method()
    def StartNotify(self):
        # enable notifications and kick off handshake
        try:
            super().StartNotify()
        except Exception:
            # ignore if already enabled
            pass
        self.service.start_auth_handshake()

    @method()
    def StopNotify(self):
        try:
            super().StopNotify()
        finally:
            # reset session on stop notify
            self.service.session_auth = False

    @method()
    def WriteValue(self, value: 'ay', options: 'a{sv}'):
        # value should be 32-byte HMAC-SHA256
        mac = bytes(value)
        ok = self.service.validate_auth(mac)
        # Optionally notify result (1 byte)
        self.notify(b"\x01" if ok else b"\x00")

class LockedCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        # make it writeable to allow control when authenticated
        super().__init__(path, "2a137f90-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify", "write"], service, initial_value=b"\x00")
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return bytes([1 if self.service.locked else 0])

    @method()
    def WriteValue(self, value: 'ay', options: 'a{sv}'):
        # require authenticated session
        if not getattr(self.service, 'session_auth', False):
            print("[AUTH] Write denied: session not authenticated")
            return
        try:
            new_state = bool(int(bytes(value)[0]))
        except Exception:
            print("[WRITE] Invalid payload for locked state")
            return
        self.service.toggle_locked(new_state)

class BatteryLevelCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        d = GATTDescriptor(
            os.path.join(path, "cud"),
            "00002901-0000-1000-8000-00805f9b34fb",
            ["read"],
            self,
            initial_value="Battery Level sss".encode("utf-8")
        )
        super().__init__(path, "fe11bc92-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify"], service, initial_value=b"\x64", descriptors=[d])
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return bytes([self.service.battery_level])


class TamperCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        super().__init__(path, "bc008b7a-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify"], service, initial_value=b"\x00")
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return bytes([1 if self.service.tamper else 0])

class UptimeCharacteristic(GATTCharacteristic):
    def __init__(self, path, service):
        super().__init__(path, "9f8b83a2-c9b2-4927-bd28-86cd93f91cfd", ["read", "notify"], service, initial_value=b"\x00\x00\x00\x00")
        
    @method()
    def ReadValue(self, options: 'a{sv}') -> 'ay':
        return self.service.uptime.to_bytes(4, 'little')
