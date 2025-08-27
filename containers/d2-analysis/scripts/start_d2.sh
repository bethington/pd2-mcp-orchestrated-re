#!/bin/bash

# D2 Game Starter - Launch Diablo 2
set -e

echo "🎮 Starting Diablo 2..."

# Wait for setup-wine to complete
echo "⏳ Waiting for Wine setup to complete..."
while ! [ -f "/var/log/setup-wine-complete.flag" ]; do
    echo "Waiting for setup-wine process..."
    sleep 2
done
echo "✅ Wine setup completed"

# Cleanup on exit
cleanup() {
    echo "🧹 Cleaning up..."
    pkill -f "Game.exe" || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Start Project Diablo 2 in full screen windowed mode
echo "Launching Project Diablo 2 in full screen windowed mode..."
cd /game/pd2/ProjectD2
wine Game.exe -ns -3dfx &
GAME_PID=$!

echo "✅ Diablo 2 started with PID: $GAME_PID"

# Give Diablo 2 time to load and check if it's still running
echo "⏳ Waiting for Diablo 2 to load..."
sleep 10

# Check if the game process is still running
if kill -0 $GAME_PID 2>/dev/null; then
    echo "✅ Diablo 2 is running successfully"
    # Keep the script alive to maintain the process
    wait $GAME_PID
else
    echo "❌ Diablo 2 process exited unexpectedly"
    exit 1
fi
