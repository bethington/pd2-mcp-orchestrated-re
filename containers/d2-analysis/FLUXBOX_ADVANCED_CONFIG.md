# Advanced Fluxbox Customization for Diablo 2 Analysis

## Configuration Files Overview

### 1. **fluxbox-init** - Main Configuration
- **Purpose**: Core Fluxbox behavior settings optimized for gaming
- **Key Features**:
  - Single workspace for focused analysis
  - ClickToFocus for precise control
  - Minimal decorations for better game performance
  - Hidden toolbar to maximize screen real estate
  - Optimized window placement and focus behavior

**Key Gaming Optimizations**:
```ini
session.screen0.focusModel: ClickToFocus          # Prevents accidental focus loss
session.screen0.fullMaximization: true            # True fullscreen for games
session.screen0.toolbar.visible: false            # Hidden UI for maximum space
session.screen0.workspacewarping: false           # Prevents accidental workspace switching
```

### 2. **fluxbox-menu** - Context Menu System
- **Purpose**: Quick access to D2 analysis tools and functions
- **Key Features**:
  - Direct game launch options (fullscreen and windowed)
  - Analysis tools submenu (htop, memory monitoring, Wine tools)
  - Display resolution switching for testing
  - Debugging utilities (Wine console, logs, process monitoring)
  - Window management tools

**Analysis-Specific Features**:
```bash
[exec] (Diablo 2) {wine /root/.wine/drive_c/pd2/ProjectD2/Game.exe -ns -3dfx}
[exec] (Process Monitor) {htop}
[exec] (Memory Usage) {free -h}
[exec] (Wine Debug) {wineconsole cmd}
```

### 3. **fluxbox-keys** - Keyboard Shortcuts
- **Purpose**: Rapid access to analysis functions without interrupting gameplay
- **Key Features**:
  - Emergency shortcuts (Ctrl+Shift+Q/R/C)
  - Game launching shortcuts (Mod4+D for fullscreen, Mod4+W for windowed)
  - Window management without mouse
  - Display resolution hotkeys (F1/F2/F3)
  - Screenshot and debugging shortcuts

**Advanced Shortcuts**:
```bash
Mod4 d :Exec wine /root/.wine/drive_c/pd2/ProjectD2/Game.exe -ns -3dfx  # Launch D2
Control Shift x :Exec xkill                                             # Kill hanging windows
Print :Exec scrot -s /tmp/screenshot.png                               # Screenshot selection
```

### 4. **fluxbox-windowmenu** - Per-Window Options
- **Purpose**: Advanced window manipulation for analysis scenarios
- **Key Features**:
  - Window size presets for testing different resolutions
  - Analysis mode toggles (always on top, transparency)
  - Window monitoring and logging capabilities
  - Game-specific window operations

**Analysis Features**:
```bash
[exec] (Monitor This Window) {echo "Starting monitoring..." >> /tmp/analysis.log}
[exec] (Make Transparent 50%) {transset-df -i :ACTIVE: 0.5}
[exec] (Screenshot Window) {scrot -u /tmp/window_$(date +%s).png}
```

### 5. **fluxbox-startup** - Environment Initialization
- **Purpose**: Set up complete analysis environment on Fluxbox start
- **Key Features**:
  - Wine environment optimization
  - Performance monitoring startup
  - Network packet capture initialization
  - File system monitoring for game file changes
  - X11 gaming optimizations

**Performance Optimizations**:
```bash
xset -dpms              # Disable power management
xset s off              # Disable screensaver
export __GL_SYNC_TO_VBLANK=0    # GPU optimization
iostat -x 5 > /tmp/analysis_logs/io_stats.log &    # I/O monitoring
```

### 6. **fluxbox-d2analysis-style** - Visual Theme
- **Purpose**: Dark theme optimized for long analysis sessions
- **Key Features**:
  - Dark color scheme to reduce eye strain
  - Minimal borders for gaming
  - High contrast for readability
  - Consistent color coding for different window states

## Integration Instructions

### Step 1: Update supervisord.conf
```ini
[program:fluxbox]
command=/root/.fluxbox/startup
environment=DISPLAY=:1
autostart=true
autorestart=true
priority=300
stdout_logfile=/var/log/fluxbox.log
stderr_logfile=/var/log/fluxbox_error.log
```

### Step 2: Dockerfile Integration
```dockerfile
# Copy Fluxbox configuration files
RUN mkdir -p /root/.fluxbox /root/.fluxbox/styles
COPY containers/d2-analysis/fluxbox-init /root/.fluxbox/init
COPY containers/d2-analysis/fluxbox-menu /root/.fluxbox/menu  
COPY containers/d2-analysis/fluxbox-keys /root/.fluxbox/keys
COPY containers/d2-analysis/fluxbox-windowmenu /root/.fluxbox/windowmenu
COPY containers/d2-analysis/fluxbox-startup /root/.fluxbox/startup
COPY containers/d2-analysis/fluxbox-d2analysis-style /root/.fluxbox/styles/D2Analysis

# Set permissions
RUN chmod +x /root/.fluxbox/startup

# Install additional tools for advanced window management
RUN apt-get install -y wmctrl xbindkeys transset-df unclutter clipit scrot inotify-tools sysstat
```

### Step 3: Runtime Usage

**Via VNC Menu Access**:
- Right-click on desktop → Full Fluxbox menu
- Right-click on window title → Window-specific menu

**Keyboard Shortcuts**:
- `Mod4 + D`: Launch Diablo 2 fullscreen
- `Mod4 + W`: Launch Diablo 2 windowed  
- `F1/F2/F3`: Switch display resolutions
- `Print`: Take screenshot selection
- `Ctrl+Shift+X`: Kill window tool

**Analysis Features**:
- Automatic process monitoring logs
- Network packet capture
- File system change monitoring
- Performance statistics collection

## Advanced Customization Options

### Dynamic Window Rules
Add to startup script:
```bash
# Auto-position Diablo 2 window
wmctrl -c "Diablo II" -e 0,0,0,800,600 &

# Set game window always on top
wmctrl -r "Diablo II" -b add,above &
```

### Custom Key Bindings
Add to keys file:
```bash
# Analysis shortcuts
Control Mod1 m :Exec echo "Memory snapshot $(date)" >> /tmp/analysis.log
Control Mod1 n :Exec netstat -tulpn > /tmp/network_$(date +%s).log
Control Mod1 p :Exec ps aux | grep -i diablo > /tmp/processes_$(date +%s).log
```

### Environment Variables
Add to startup script:
```bash
# Wine performance tweaks
export WINEDEBUG=+loaddll,+module,+dll
export WINE_RT_POLICY=FF
export WINE_RT_PRIORITY=90
```

This configuration provides a complete, production-ready Fluxbox environment optimized for Diablo 2 reverse engineering analysis within your containerized MCP platform.
