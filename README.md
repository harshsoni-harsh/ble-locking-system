# BLE Locking System

## Overview
This project prototypes a secure BLE locking system where phones obtain short-lived unlock credentials over Bluetooth Low Energy and present rolling advertisements that locks can verify. A backend service issues the credentials, advertises itself as a provisioning beacon, and pushes encrypted session material to locks over MQTT so they can validate guest beacons.

The repository contains three runnable roles plus supporting utilities:

- **Backend issuer** (`backend/issuer.py`): Advertises a BLE provisioning service and issues session keys.
- **Guest unlocker** (`guest/unlocker.py`): Scans for the issuer beacon, provisions a session over GATT, and advertises rolling tokens.
- **Lock scanners** (`lock/lock.py` and `lock/multi_user_lock.py`): Subscribe to encrypted sessions via MQTT and verify BLE advertisements from provisioned phones.

## Architecture

### Backend (`backend/issuer.py`)
- Hosts an always-on BLE advertisement so guests can discover the provisioning beacon.
- Exposes a GATT characteristic; guests write a JSON request containing `lock_id` (and optionally time/MAC).
- Issues a fresh 32-byte session key, encrypts and signs a payload for the lock, and publishes it to `locks/{lock_id}/session` via MQTT.
- Returns the plaintext session key, expiry, nonce, and optional clock offset to the guest over the notification channel.
- Resolves the guest’s Bluetooth MAC through D-Bus when available so locks can bind sessions to devices.

### Guest (`guest/unlocker.py`)
- Scans continuously until it discovers the issuer beacon (matching by address, name, or manufacturer data).
- Connects to the provisioning characteristic, writes a request, and waits for the session response.
- Generates time-based HMAC tokens (rolling every `ADVERT_INTERVAL` seconds) and advertises them in manufacturer data (company ID `0xFFFF`).
- Refreshes the advertisement payload periodically until the server-declared expiry is reached.

### Lock (`lock/lock.py`)
- Subscribes to `locks/{lock_id}/session`, decrypts the RSA-encrypted session key, and caches the active session.
- Uses `bleak` to scan for advertisements containing the expected manufacturer data.
- Checks RSSI thresholds, optional phone MAC binding, session expiry, and HMAC validity before reporting an unlock event.

### Multi-User Lock (`lock/multi_user_lock.py`)
- Variation that manages multiple simultaneous sessions keyed by phone MAC addresses.
- Allows per-phone RSSI thresholds via the `AUTHORIZED_PHONES` dictionary.

## Security Features
- **RSA-OAEP + RSA-PSS** protect and authenticate session payloads sent toward locks.
- **HMAC-SHA256** rolling tokens with nonce + time resist replay attacks.
- **Short-lived sessions** (default 5 minutes) limit exposure.
- **Optional MAC binding** lets the backend tie sessions to the phone that provisioned them.

## Prerequisites
- Linux host with BLE adapter and BlueZ (version supporting LE Peripheral).
- Python 3.10+ (tested with 3.13 on Ubuntu).
- An MQTT broker (Mosquitto works well).

## Installation
1. Clone and install requirements:
   ```bash
   git clone https://github.com/harshsoni-harsh/ble-locking-system.git
   cd ble-locking-system
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Ensure the broker is running and reachable. For local testing:
   ```bash
   sudo apt install mosquitto
   sudo systemctl enable --now mosquitto
   ```
3. Confirm RSA key material exists in `keys/`. Generate replacements as needed (2048-bit minimum) for backend and each lock ID.

## End-to-End Flow
1. **Start backend issuer**:
   ```bash
   python backend/issuer.py
   ```
   Logs should note the advertising adapter and provisioning service registration.
2. **Start lock** on the device near the door:
   ```bash
   python lock/lock.py
   ```
   It subscribes to the MQTT session topic and begins scanning.
3. **Run guest unlocker** (phone simulator):
   ```bash
   python guest/unlocker.py
   ```
   The guest discovers the issuer beacon, negotiates a session, and starts advertising tokens.
4. The lock receives the encrypted session from MQTT, validates advertisements, and logs successful unlocks when tokens match.

For multi-user setups, run `python lock/multi_user_lock.py` instead and populate `AUTHORIZED_PHONES` with allowed MAC addresses and thresholds.

## Testing Tips
- Use `bluetoothctl show` and `bluetoothctl scan on` to confirm adapters are powered and visible.
- `sudo btmon` is helpful to inspect raw BLE traffic when debugging advertisement payloads.
- If the guest cannot register its advert, check BlueZ experimental mode and ensure payload size ≤ 31 bytes.
- When provisioning fails, verify the provisioning characteristic UUIDs match between backend and guest.

## Troubleshooting
- **MQTT timeouts**: confirm broker reachability, check credentials/firewall, and verify `MQTT_BROKER` values.
- **BLE scan finds no issuer**: confirm backend advert is live (`sudo btmon`), adjust `ISSUER_SCAN_TIMEOUT`, or supply the beacon’s MAC via `ISSUER_BEACON_ADDRESS`.
- **Provisioning GATT write errors**: BlueZ must run with `--experimental`; also ensure only one process is advertising on the adapter.
- **Clock skew errors**: the backend returns `clock_offset`; use it to adjust token generation logic if needed.

## Future Improvements
- Persist sessions and audit logs on the backend.
- Evaluate distance estimation by embedding calibrated Tx power in adverts.
- Harden MQTT transport with TLS and credentials.

