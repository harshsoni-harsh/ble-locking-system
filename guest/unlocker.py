import asyncio
import base64
import json
import hmac, hashlib, time
from bluez_peripheral.advert import Advertisement
from bluez_peripheral.util import get_message_bus, Adapter
from dbus_fast import Variant
import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

LOCK_ID = "lock_01"
PHONE_MAC = "B4:8C:9D:8D:83:90"
MQTT_BROKER = "10.0.15.108"
MQTT_PORT = 1883
MANUFACTURER_ID = 0xFFFF
ADVERT_INTERVAL = 30
ADVERT_TIMEOUT = 0  # Continuous advertising

session_key_data = None

def on_message(client, userdata, msg):
    """Handles incoming MQTT messages (session key responses)."""
    global session_key_data
    print(f"[MQTT] Received session key on {msg.topic}")
    data = json.loads(msg.payload.decode())
    session_key_data = data

def get_session_key(lock_id: str):
    """Requests a session key from the backend via MQTT."""
    global session_key_data
    session_key_data = None
    client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
    client.on_message = on_message

    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
    except ConnectionRefusedError:
        raise ConnectionError(f"Failed to connect to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}")

    guest_topic = f"guests/{lock_id}/session"
    request_topic = "backend/session_requests"
    request_payload = json.dumps({"lock_id": lock_id})

    client.loop_start()
    try:
        client.subscribe(guest_topic, qos=1)
        publish_result = client.publish(request_topic, request_payload, qos=1)
        publish_result.wait_for_publish()
        print(f"[MQTT] Requested session key for {lock_id}")

        start = time.time()
        timeout = 10  # seconds

        while session_key_data is None and time.time() - start < timeout:
            time.sleep(0.1)
    finally:
        client.loop_stop()
        client.disconnect()

    if session_key_data:
        session_key = base64.b64decode(session_key_data["session_key"])
        expiry = session_key_data.get("expiry")
        nonce = session_key_data.get("nonce")
        print(f"[MQTT] Session key received. Expires: {expiry}, Nonce: {nonce}")
        return session_key, expiry
    raise TimeoutError("No session key received from backend within timeout")

def generate_token(session_key: bytes, mac: str) -> bytes:
    """Generate rolling HMAC token using session key + timestamp."""
    ts = int(time.time() // ADVERT_INTERVAL)
    msg = mac.encode() + str(ts).encode()
    return hmac.new(session_key, msg, hashlib.sha256).digest()[:16]

class LockAdvertisement(Advertisement):
    def __init__(self, session_key: bytes):
        super().__init__(
            localName="BLELock",
            serviceUUIDs=["180D"],
            appearance=0x0340,
            timeout=ADVERT_TIMEOUT,
            manufacturerData={MANUFACTURER_ID: generate_token(session_key, PHONE_MAC)},
        )
        self.session_key = session_key

    def update_token(self):
        """Update the manufacturer data with a new rolling token."""
        token = generate_token(self.session_key, PHONE_MAC)
        self._manufacturerData[MANUFACTURER_ID] = Variant("ay", token)
        print(f"[ADV] Updated token: {token.hex()}")

async def advertise_loop(session_key: bytes, expiry: int | float):
    """Main async advertising loop."""
    bus = await get_message_bus()
    adapter = await Adapter.get_first(bus)
    adapter_name = await adapter.get_name()
    lock_advertiser = LockAdvertisement(session_key)
    advertiser: Advertisement = lock_advertiser

    await advertiser.register(bus, adapter)
    print(f"[BLE] Advertising started on adapter {adapter_name}...")

    try:
        while True:
            remaining = expiry - time.time()
            if remaining <= 0:
                print("[BLE] Session key expired; stopping advertising.")
                break

            lock_advertiser.update_token()
            await advertiser.unregister()  # type: ignore[attr-defined]
            await advertiser.register(bus, adapter)

            sleep_for = min(ADVERT_INTERVAL, max(0.5, remaining))
            await asyncio.sleep(sleep_for)
    except asyncio.CancelledError:
        pass
    finally:
        print("[BLE] Stopping advertising...")
        try:
            await advertiser.unregister()  # type: ignore[attr-defined]
        except Exception:
            pass

if __name__ == "__main__":
    try:
        print("[SYS] Requesting session key from backend...")
        session_key, expiry = get_session_key(LOCK_ID)
        print(f"[SYS] Session key (base64): {base64.b64encode(session_key).decode()}")
        asyncio.run(advertise_loop(session_key, expiry or 0))
    except KeyboardInterrupt:
        print("\n[SYS] Script stopped by user.")
    except Exception as e:
        print(f"\n[ERR] {e}")
