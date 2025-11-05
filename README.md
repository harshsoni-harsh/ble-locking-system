# BLE Locking System - Architecture and Flow Documentation

## Overview
This project implements a secure BLE-based locking system using MQTT for session key delivery, RSA encryption for key security, and a **hybrid BLE authentication protocol** that combines connectionless TOTP beacons with a GATT challenge–response exchange. The system consists of three main components: Backend (session key issuer), Lock (scanner + GATT peripheral), and Guest (advertiser + central). Communication flows over BLE and MQTT.

## Architecture Components

### 1. Backend (session_key_issuer.py)
- **Role**: Issues session keys on demand via MQTT
- **Responsibilities**:
  - Listens for session key requests on MQTT topic `backend/session_requests`
  - Generates random 32-byte session keys
  - Encrypts session key for lock using RSA-OAEP
  - Signs the payload with backend RSA private key
  - Publishes encrypted key to `locks/{lock_id}/session`
  - Publishes plain key to `guests/{lock_id}/session`

### 2. Lock (lock.py)
- **Role**: BLE scanner and GATT peripheral executing hybrid authentication
- **Responsibilities**:
   - Subscribes to MQTT topic `locks/{lock_id}/session` for encrypted session keys
   - Decrypts session keys using the lock's RSA private key
   - Scans for connectionless BLE advertisements from phones
   - Verifies the TOTP-based manufacturer payload, RSSI, and replay cache
   - Exposes a custom GATT service that issues per-connection challenges
   - Validates the phone's HMAC response within strict timing windows
   - Triggers unlock only after successful challenge–response verification

### 3. Guest (guest/unlocker.py)
- **Role**: App that requests session key, advertises TOTP frames, and completes the challenge–response
- **Responsibilities**:
   - Publishes request to `backend/session_requests` with lock_id and phone identifier
   - Subscribes to `guests/{lock_id}/session` for the symmetric session key
   - Continuously emits manufacturer data beacons containing protocol metadata, TOTP, and CMAC
   - Connects to the lock, reads the challenge, verifies the lock MAC, and writes the HMAC response
   - Observes token lifetime and latency constraints to mitigate relay attempts
   - Configure `LOCK_ADDRESS` in `guest/unlocker.py` to match the target lock's BLE MAC before attempting unlocks

### 4. MQTT Broker
- **Role**: Message broker for secure key delivery
- **Configuration**: Mosquitto with anonymous access enabled

## Security Features
- **RSA + Signatures**: Session keys encrypted with RSA-OAEP and signed with PSS
- **Hybrid BLE auth**: TOTP advertisements bound to a follow-up challenge–response exchange
- **AES-CMAC + HMAC**: Manufacturer payload and responses protected with independent MAC keys
- **Replay protection**: Time-step windows, nonce-based challenges, and per-session replay cache
- **Timing & proximity**: RSSI thresholds, connection latency deadlines, and token lifetimes limit relay attacks

### Detailed Flow Steps:
1. **Session Key Request**:
   - Guest publishes `{"lock_id": "lock_01"}` to `backend/session_requests`

2. **Key Generation**:
   - Backend generates 32-byte random session key
   - Encrypts with lock's RSA public key
   - Signs payload with backend private key
   - Publishes encrypted payload to `locks/lock_01/session`
   - Publishes plain session key to `guests/lock_01/session`

3. **Key Reception**:
   - Lock receives encrypted key, decrypts with private key
   - Guest receives plain key

4. **Hybrid BLE Unlock**:
   - Guest advertises manufacturer data `[proto|lock_short|phone_hash|step|totp|cmac]`
   - Lock scans, validates CMAC + TOTP within ±1 step and RSSI threshold, caches pending auth
   - Phone connects to lock, reads challenge `{nonce|lock_ts|session_id|cmac}`
   - Phone verifies lock authenticity, computes `HMAC(shared_key, context || nonce || lock_ts || session_id || phone_ts || step)`
   - Phone writes `{phone_ts|step|resp_mac}`
   - Lock recomputes HMAC, enforces timing budgets, and unlocks on success

## Setup Instructions

### Prerequisites
- Linux with BlueZ (BLE support)
- Python 3.8+
- MQTT broker (Mosquitto)

### Installation
1. **Clone repository**:
   ```bash
   git clone <repo-url>
   cd ble-locking-system
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install and configure MQTT broker**:
   ```bash
   sudo apt install mosquitto
   sudo nano /etc/mosquitto/mosquitto.conf
   ```
   Add:
   ```
   listener 1883 0.0.0.0
   allow_anonymous true
   ```
   ```bash
   sudo systemctl restart mosquitto
   ```

4. **Configure network**:
   - Update `MQTT_BROKER` in all scripts to the broker's IP address
   - Ensure firewall allows port 1883

### Key Generation
RSA keys are pre-generated in the code. For production:
- Generate new RSA keypairs for backend and each lock
- Update `DEVICE_REGISTRY` in `session_key_issuer.py`
- Update `LOCK_PRIVATE_KEY_PEM` in `lock.py`

## Testing Instructions

### Single Machine Test
1. **Start MQTT broker**:
   ```bash
   mosquitto
   ```

2. **Start backend**:
   ```bash
   python session_key_issuer.py
   ```

3. **Start lock**:
   ```bash
   python lock.py
   ```
   (Requires BLE hardware/adapter for scanning)

4. **Run guest app**:
   ```bash
   python ble_unlock_app.py
   ```
   (Requires BLE hardware/adapter for advertising)

### Multi-Machine Test
- Run backend and MQTT broker on server
- Run lock on device with BLE for scanning
- Run guest on device with BLE for advertising

### Expected Output
- Backend: "Backend listening for session requests on backend/session_requests"
- Lock: subscription message, advertisement acceptance logs, challenge/response success
- Guest: session key acquisition, advertising updates, handshake success logs

## Troubleshooting

### MQTT Connection Issues
- Check broker IP and port
- Verify `mosquitto` is running: `sudo systemctl status mosquitto`
- Test connection: `mosquitto_sub -h <broker_ip> -t test`

### BLE Issues
- Check BlueZ: `bluetoothctl show`
- Ensure BLE adapter: `hciconfig`
- Permissions: Run with sudo if needed
- For advertising (guest): Ensure bluez-peripheral can access BLE
- For scanning (lock): Ensure bleak can access BLE

### Key / Authentication Errors
- Verify RSA keys are correct format
- Check session expiry and local clock skew
- Ensure the lock and phone share the same manufacturer ID constant
- Confirm the phone connects within the allowed time window and RSSI threshold

## Security Considerations
- Use strong RSA keys (2048+ bits)
- Implement proper authentication for guest requests
- Rotate session keys frequently
- Monitor MQTT traffic
- Use TLS for MQTT in production

## Future Enhancements
- Add user authentication and provisioning UX
- Publish lock status and audit events over MQTT
- Expand to multiple locks with key derivation per device
- Integrate with native mobile stacks (Android/iOS)
- Support secure key rotation and revocation workflows
