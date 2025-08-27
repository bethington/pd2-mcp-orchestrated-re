#!/bin/bash
# setup_wine.sh - One-time Wine and game setup

# Configure Wine for Project Diablo 2
echo "📁 Configuring Wine drive mapping..."
cd /root/.wine/drive_c
if [ ! -L "pd2" ] && [ -d "/game/pd2" ]; then
    ln -sf /game/pd2 ./pd2
    echo "✅ Created symlink: /root/.wine/drive_c/pd2 -> /game/pd2"
fi

# Install DirectX and required components for Project Diablo 2
echo "📦 Installing DirectX and Windows components..."
winetricks -q directx9 vcrun2019 d3dx9

# Verify game files exist
if [ -f "/game/pd2/ProjectD2/Game.exe" ]; then
    echo "✅ Game.exe found at /game/pd2/ProjectD2/Game.exe"
else
    echo "⚠️ Game.exe not found - container will start but game won't launch"
fi

echo "🎉 Wine setup completed successfully!"

# Create completion flag for other processes to check
touch /var/log/setup-wine-complete.flag
echo "✅ Setup-wine completion flag created"
