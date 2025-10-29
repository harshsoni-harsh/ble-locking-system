# BLE Locking System - Architecture and Flow Documentation

## Overview
This project implements a secure BLE-based locking system using MQTT for session key delivery and RSA encryption for key security. The system consists of three main components: Backend (session key issuer), Lock (BLE scanner), and Guest (advertiser app). Communication is limited to BLE advertisements and MQTT protocols.

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
- **Role**: BLE scanner that detects and validates guest advertisements
- **Responsibilities**:
  - Subscribes to MQTT topic `locks/{lock_id}/session` for encrypted session keys
  - Decrypts session keys using lock's RSA private key
  - Scans for BLE advertisements from guests
  - Validates HMAC token in advertisement local name
  - Triggers unlock if token is valid
  - Validates session key expiry

### 3. Guest (ble_unlock_app.py)
- **Role**: App that requests session key and advertises unlock token
- **Responsibilities**:
  - Publishes request to `backend/session_requests` with lock_id
  - Subscribes to `guests/{lock_id}/session` for session key
  - Generates HMAC token using session key
  - Advertises with token in manufacturer data (company ID 0xFFFF)
  - Validates session key expiry

### 4. MQTT Broker
- **Role**: Message broker for secure key delivery
- **Configuration**: Mosquitto with anonymous access enabled

## Security Features
- **RSA Encryption**: Session keys encrypted for lock using RSA-OAEP
- **Digital Signatures**: Payloads signed with PSS padding
- **HMAC Tokens**: Advertisement tokens use HMAC-SHA256
- **Session Key Expiry**: Keys valid for 5 minutes
- **Nonce**: Prevents replay attacks

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

4. **BLE Unlock**:
   - Guest generates HMAC-SHA256(session_key, "unlock")[:16]
   - Guest advertises with manufacturer data containing the token (company ID 0xFFFF)
   - Lock scans for advertisements
   - Lock extracts token from manufacturer data
   - Lock verifies token matches expected HMAC
   - If valid, unlock successful

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
- Lock: "Subscribed to locks/lock_01/session for session keys" + BLE scan messages
- Guest: "Requested session key", "Received session key", then "Advertising with token"

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

### Key Errors
- Verify RSA keys are correct format
- Check expiry times
- Ensure cryptography library installed

## Security Considerations
- Use strong RSA keys (2048+ bits)
- Implement proper authentication for guest requests
- Rotate session keys frequently
- Monitor MQTT traffic
- Use TLS for MQTT in production

## Future Enhancements
- Add user authentication
- Implement lock status publishing
- Add multiple lock support
- Integrate with mobile apps
- Add audit logging
