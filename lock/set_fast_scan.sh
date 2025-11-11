#!/bin/bash
# Script to configure BlueZ for aggressive BLE scanning
# Run this before starting the lock for fastest detection

# Set scan interval and window using hcitool
# Interval: 40ms (0x0040 in hex = 64 * 0.625ms = 40ms)
# Window: 40ms (same as interval = 100% duty cycle)
sudo hcitool -i hci0 cmd 0x08 0x000b 0x01 0x40 0x00 0x40 0x00 0x00 0x00

echo "BLE scan parameters set to aggressive mode:"
echo "  Interval: 40ms"
echo "  Window: 40ms (100% duty cycle)"
echo "  This gives ~25 scan opportunities per second"
echo ""
echo "Now run: python -m lock.lock"
