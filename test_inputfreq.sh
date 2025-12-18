#!/bin/bash
# Test script for inputfreq

echo "Testing inputfreq program..."
echo

"This script will read from /dev/input/event3 to generate input events."
echo "In another terminal, move your mouse or press keys to see events detected."
echo

# Find an available input device
INPUT_DEV="/dev/input/event3"

if [ ! -r "$INPUT_DEV" ]; then
    echo "Cannot read $INPUT_DEV - trying to find accessible device..."
    for dev in /dev/input/event*; do
        if [ -r "$dev" ]; then
            INPUT_DEV="$dev"
            break
        fi
    done
fi

echo "Using device: $INPUT_DEV"
echo

# Start inputfreq in background
echo "Starting inputfreq..."
sudo ./inputfreq &
INPUTFREQ_PID=$!

sleep 2

# Read some events from the input device to trigger our BPF program
echo "Reading from $INPUT_DEV for 5 seconds..."
echo "Move your mouse or press keys NOW!"
timeout 5 sudo hexdump -C $INPUT_DEV > /dev/null 2>&1 &

sleep 6

# Stop inputfreq
echo
echo "Stopping inputfreq..."
sudo kill $INPUTFREQ_PID 2>/dev/null

echo
echo "Test complete. Check the output above for detected events."
echo
echo "To see BPF debug output, run: sudo cat /sys/kernel/debug/tracing/trace_pipe"
