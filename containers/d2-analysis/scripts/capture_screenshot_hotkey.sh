#!/bin/bash
# Screenshot hotkey script for VNC session
# This script can be bound to a keyboard shortcut in Fluxbox

DISPLAY=:1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="hotkey_screenshot_${TIMESTAMP}.png"
SCREENSHOT_DIR="/screenshots"

# Capture screenshot
scrot "${SCREENSHOT_DIR}/${FILENAME}"

# Create metadata
python3 << EOF
import json
import datetime

metadata = {
    "timestamp": datetime.datetime.now().isoformat(),
    "description": "Screenshot captured via VNC hotkey",
    "capture_method": "hotkey_trigger",
    "filename": "${FILENAME}",
    "source": "vnc_session"
}

with open("${SCREENSHOT_DIR}/${FILENAME%.png}.json", "w") as f:
    json.dump(metadata, f, indent=2)
EOF

# Show notification (if available)
if command -v xmessage >/dev/null 2>&1; then
    xmessage -timeout 3 "Screenshot saved: ${FILENAME}" &
fi
