import asyncio
import base64
import binascii
import hmac
import hashlib
import json
import time
from pathlib import Path
from typing import cast

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from bleak import BleakScanner
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT_DIR / "keys"

MQTT_BROKER = "10.0.15.108"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
SESSION_KEY = None
SESSION_EXPIRY = 0

EXPECTED_PHONE_MAC = "B4:8C:9D:8D:83:90"
ADVERT_INTERVAL = 30  # seconds; must stay in sync with unlocker
ROLLING_WINDOW = 1  # accept current and previous slot to absorb small clock drift

with open(KEYS_DIR / "backend_public.pem", "rb") as handle:
    BACKEND_PUBLIC_KEY = cast(
        rsa.RSAPublicKey,
        load_pem_public_key(handle.read(), backend=default_backend()),
    )

with open(KEYS_DIR / f"{LOCK_ID}_private.pem", "rb") as handle:
    LOCK_PRIVATE_KEY = cast(
        rsa.RSAPrivateKey,
        load_pem_private_key(handle.read(), password=None, backend=default_backend()),
    )


def on_message(client, userdata, msg):
    global SESSION_KEY, SESSION_EXPIRY
    print(f"Received MQTT message on {msg.topic}")

    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        print("Malformed JSON payload; ignoring")
        return

    signature_b64 = payload.pop("signature", None)
    if not signature_b64:
        print("Payload missing signature; ignoring")
        return

    try:
        signature = base64.b64decode(signature_b64)
    except (ValueError, binascii.Error):
        print("Malformed signature encoding; ignoring payload")
        return

    signed_payload = {
        key: payload.get(key)
        for key in ("device_id", "session_key", "expiry", "nonce")
        if key in payload
    }

    if signed_payload.get("device_id") != LOCK_ID:
        print("Payload target mismatch; ignoring")
        return

    if not all(k in signed_payload for k in ("session_key", "expiry", "nonce")):
        print("Payload missing required fields; ignoring")
        return

    canonical = json.dumps(signed_payload, separators=(",", ":")).encode()
    try:
        BACKEND_PUBLIC_KEY.verify(
            signature,
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        print("Signature verification failed; ignoring payload")
        return

    try:
        encrypted_key = base64.b64decode(payload["session_key"])
    except (KeyError, binascii.Error, ValueError):
        print("Invalid encrypted session key; ignoring")
        return

    session_key = LOCK_PRIVATE_KEY.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    try:
        expiry = int(payload["expiry"])
    except (KeyError, ValueError, TypeError):
        print("Invalid expiry in payload; ignoring")
        return

    nonce = payload.get("nonce")
    print(
        f"Decrypted session key: {base64.b64encode(session_key).decode()} (expires {expiry}, nonce {nonce})"
    )
    SESSION_KEY = session_key
    SESSION_EXPIRY = expiry


def _expected_token(session_key, slot):
    message = EXPECTED_PHONE_MAC.encode() + str(slot).encode()
    return hmac.new(session_key, message, hashlib.sha256).digest()[:16]


def validate_token(token, session_key):
    if not session_key:
        return False
    if time.time() >= SESSION_EXPIRY:
        return False

    current_slot = int(time.time() // ADVERT_INTERVAL)
    for offset in range(ROLLING_WINDOW + 1):
        slot = current_slot - offset
        if slot < 0:
            continue
        expected = _expected_token(session_key, slot)
        if hmac.compare_digest(token, expected):
            return True
    return False


def detection_callback(device, advertisement_data):
    if SESSION_KEY is None:
        return

    print(f"Detected device: {device.name}, address: {device.address}")
    if advertisement_data.manufacturer_data:
        company_id = 0xFFFF
        if company_id in advertisement_data.manufacturer_data:
            token = advertisement_data.manufacturer_data[company_id]
            if validate_token(token, SESSION_KEY):
                print("Token valid! Unlocking...")
            else:
                print("Invalid token")
        else:
            print("No token in manufacturing data")
    else:
        print("No manufacturing data")


async def main():
    client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    topic = f"locks/{LOCK_ID}/session"
    client.subscribe(topic)
    client.loop_start()
    print(f"Subscribed to {topic} for session keys")

    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    print("BLE scanner started")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        client.loop_stop()
        client.disconnect()
        await scanner.stop()


if __name__ == "__main__":
    asyncio.run(main())
