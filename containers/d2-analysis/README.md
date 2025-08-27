# D2 Analysis Container

This container provides Diablo 2 game analysis capabilities using Wine emulation with VNC access and MCP server integration.

## Architecture

```
d2-analysis/
├── src/                    # Source code
│   ├── diablo2_monitor.py     # Main game monitoring
│   ├── simple_mcp_server.py  # MCP server implementation  
│   ├── game_state_api.py      # API endpoints
│   └── game_state_api_fixed.py # Enhanced API
├── config/                 # Configuration files
│   ├── supervisord.conf       # Process management
│   ├── fluxbox-*             # Window manager config
│   └── wine.conf             # Wine settings
├── scripts/               # Utility scripts
│   ├── setup_wine.sh         # Wine environment setup
│   ├── start_d2.sh           # Game launcher
│   └── debug_d2.sh           # Debug utilities
├── tests/                # Container-specific tests
└── Dockerfile            # Container image definition
```

## Features

- **Wine Environment**: 32-bit Windows emulation for Diablo 2
- **VNC Access**: Remote desktop on port 5900 (direct) and 5901 (noVNC web)
- **Game Monitoring**: Real-time character and game state tracking
- **MCP Server**: Model Context Protocol server for AI integration
- **Memory Analysis**: Game memory inspection and analysis
- **API Endpoints**: REST API for game data access

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DISPLAY` | `:1` | X11 display for GUI applications |
| `WINEPREFIX` | `/root/.wine` | Wine installation directory |
| `WINEARCH` | `win32` | Wine architecture (32-bit) |
| `WINEDEBUG` | `-all` | Wine debug verbosity |
| `SESSION_ID` | `default` | Analysis session identifier |

## API Endpoints

### Health & Status
- `GET /health` - Container health check
- `GET /processes` - Running processes
- `GET /system/info` - System information

### Game Analysis  
- `GET /game/status` - Overall game status
- `GET /game/processes` - Game processes
- `GET /game/character` - Character information
- `GET /game/inventory` - Inventory state
- `GET /game/state` - Complete game state
- `POST /game/action/{action}` - Execute game actions

### Memory Analysis
- `GET /memory/info` - Memory analysis information

## Usage

### Development
```bash
# Build development image
docker-compose -f docker-compose.dev.yml build d2-analysis

# Run with debug
docker-compose -f docker-compose.dev.yml run --rm d2-analysis bash
```

### Production
```bash
# Start container
docker-compose up -d d2-analysis

# Access via VNC
vncviewer localhost:5900

# Access via web VNC  
curl http://localhost:8080

# Monitor game state
curl http://localhost:3000/game/status
```

### Testing
```bash
# Run container tests
docker-compose run --rm d2-analysis python -m pytest tests/ -v

# Health check
curl -f http://localhost:3000/health
```

## Troubleshooting

### Wine Issues
```bash
# Check Wine environment
docker-compose exec d2-analysis wine --version
docker-compose exec d2-analysis ls -la $WINEPREFIX

# Reinitialize Wine
docker-compose exec d2-analysis rm -rf $WINEPREFIX
docker-compose exec d2-analysis winecfg
```

### VNC Issues  
```bash
# Check VNC process
docker-compose exec d2-analysis ps aux | grep vnc

# Restart VNC server
docker-compose exec d2-analysis supervisorctl restart x11vnc
```

### Game Launch Issues
```bash
# Enable Wine debugging
# In .env: WINEDEBUG=+all,+dll,+registry

# Manual game launch
docker-compose exec d2-analysis bash
cd /data/pd2 && wine Game.exe -w -ns
```

## Security

- Runs with SYS_PTRACE capability for memory access
- Uses privileged mode for system debugging
- Isolated on re-platform Docker network
- VNC access should be secured with SSH tunneling in production

## Dependencies

- Wine (32-bit Windows emulation)
- X11 + Fluxbox (GUI environment)  
- VNC server (remote access)
- Python 3.10+ (monitoring and API)
- Supervisor (process management)