#!/bin/bash

# D2 Game Debug Script
echo "🔍 Debugging Diablo 2 environment..."

# Environment check
echo "📋 Environment Variables:"
echo "  WINEPREFIX: $WINEPREFIX"
echo "  WINEARCH: $WINEARCH" 
echo "  DISPLAY: $DISPLAY"

# Path verification
echo "🗂️ Path Verification:"
echo "  Game directory exists: $([ -d "$WINEPREFIX/drive_c/pd2/ProjectD2" ] && echo "✅ YES" || echo "❌ NO")"
echo "  Game.exe exists: $([ -f "$WINEPREFIX/drive_c/pd2/ProjectD2/Game.exe" ] && echo "✅ YES" || echo "❌ NO")"

# Display check
echo "🖥️ Display Check:"
echo "  X server running: $(pgrep Xvfb >/dev/null && echo "✅ YES" || echo "❌ NO")"

# Wine check
echo "🍷 Wine Check:"
cd "$WINEPREFIX/drive_c/pd2/ProjectD2"
echo "  Current directory: $(pwd)"

# Try to get more info about why the game exits
echo "🚀 Attempting to run Game.exe with verbose output..."
WINEDEBUG=+all wine Game.exe -ns -window 2>&1 | head -50

echo "🏁 Debug script completed"
