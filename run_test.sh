#!/bin/bash

echo "Starting Instacap-Rs Network Packet Analyzer..."
echo "This will run for 10 seconds to demonstrate the functionality."
echo ""

# Run the application in the background and capture its PID
sudo ./target/release/instacap-rs -i en0 -v &
PID=$!

# Wait for 10 seconds
sleep 10

# Send SIGINT (Ctrl+C) to gracefully shutdown
sudo kill -INT $PID

# Wait a moment for cleanup
sleep 2

echo ""
echo "Packet analyzer test completed!"
