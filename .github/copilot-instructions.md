# Instructions: PD2-MCP Orchestrated Reverse Engineering Platform

This is a container-focused platform for reverse engineering and analysis applications, with specialized support for Project Diablo 2. The platform uses the Model Context Protocol (MCP) with Claude AI intelligence for orchestrated analysis.

You are an intelligent reverse engineering orchestrator using the Model Context Protocol (MCP) to coordinate multiple containerized analysis tools.

## Table of Contents
1. [Quick Start](#quick-start)
2. [Environment Variables & Configuration](#environment-variables--configuration)
3. [Available Service Endpoints](#available-service-endpoints)
4. [Troubleshooting Guide](#troubleshooting-guide)
5. [Tech Stack & Standards](#tech-stack--standards)
6. [Container-Focused Architecture](#container-focused-architecture)
7. [MCP Protocol Integration](#model-context-protocol-mcp-integration)
8. [Data Flow Architecture](#data-flow-architecture)
9. [Security Guidelines](#security-guidelines)
10. [Development Workflow](#development-workflow)
11. [Monitoring and Observability](#monitoring-and-observability)
12. [Performance Considerations](#performance-considerations)
13. [Development Patterns](#key-development-patterns)
14. [Developer Experience](#developer-experience)
15. [Operational Information](#operational-information)
16. [API Usage Examples](#api-usage-examples)

## Quick Start

### Prerequisites
- Docker & Docker Compose installed
- 8GB+ RAM, 4+ CPU cores
- 20GB+ free disk space

### 30-Second Setup
```bash
# Clone and setup
git clone <repo-url> && cd pd2-mcp-orchestrated-re
cp .env.example .env

# Start platform (builds automatically)
docker-compose up -d
# OR use quickstart scripts:
# Windows: setup.bat quickstart or setup.ps1 quickstart
# Cross-platform: python quickstart.py

# Verify services
make health
```

### Access Points
- **Game Desktop**: `vnc://localhost:5900` (VNC client) or `http://localhost:5901` (noVNC browser)
- **Analysis Dashboard**: `http://localhost:80`  
- **MCP Coordinator**: `http://localhost:8000` (API and orchestration hub)
- **Dgraph Database UI**: `http://localhost:8081`
- **Jupyter Lab**: `http://localhost:8888` (Analysis notebooks)

### Development vs Production

#### Development Setup
```bash
# Hot reload enabled, debug ports exposed
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
make dev
```

#### Production Setup  
```bash
# Optimized images, security hardened, load balanced
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
make prod
```

#### Testing Setup
```bash
# Run comprehensive tests
make test
docker-compose run --rm analysis-engine python -m pytest tests/ -v
```

## Environment Variables & Configuration

### Core Environment Variables (.env)

#### Required Variables
```bash
# .env - Required configuration
# Session Management
SESSION_ID=default                          # Unique analysis session identifier

# Database Configuration  
DGRAPH_ENDPOINT=http://dgraph-alpha:8080    # Dgraph database connection
REDIS_URL=redis://redis:6379                # Redis cache connection

# Service URLs (Internal Container Communication)
MCP_COORDINATOR_URL=http://mcp-coordinator:8080  # MCP orchestration hub
D2_ANALYSIS_URL=http://d2-analysis:8765          # Game analysis service

# Wine/Game Configuration (Required for D2 Analysis)
WINEPREFIX=/root/.wine                      # Wine installation directory
WINEARCH=win32                              # Wine architecture (32-bit for D2)
WINEDEBUG=-all                              # Wine debug verbosity (production: -all)
DISPLAY=:1                                  # X11 display for GUI applications
```

#### Optional Variables  
```bash
# .env - Optional configuration
# Performance Tuning
WORKER_PROCESSES=4                          # Number of worker processes
MAX_MEMORY_USAGE=4G                         # Container memory limits
CPU_LIMIT=2.0                               # CPU usage limit per container

# Security Settings
ENABLE_TLS=false                            # Enable HTTPS/TLS (production: true)
JWT_SECRET_KEY=your-secret-key-here         # JWT authentication secret
API_RATE_LIMIT=100                          # Requests per minute per IP

# Development Options
DEBUG_MODE=false                            # Enable debug logging
HOT_RELOAD=false                            # Enable hot reload for development
ENABLE_PROFILING=false                      # Enable performance profiling

# Storage Configuration
BACKUP_RETENTION_DAYS=30                    # Backup retention period
LOG_LEVEL=INFO                              # Logging verbosity (DEBUG/INFO/WARN/ERROR)
```

### Deployment-Specific Configurations

#### Development Environment (.env.dev)
```bash
# .env.dev - Development overrides
DEBUG_MODE=true
HOT_RELOAD=true
LOG_LEVEL=DEBUG
WINEDEBUG=+all                              # Verbose Wine debugging
ENABLE_PROFILING=true

# Development-specific ports (to avoid conflicts)
D2_VNC_PORT=5901
MCP_COORDINATOR_PORT=8010
ANALYSIS_ENGINE_PORT=8011
WEB_DASHBOARD_PORT=81

# Development database settings
REDIS_URL=redis://localhost:6380           # Separate Redis for dev
DGRAPH_ENDPOINT=http://localhost:8082      # Separate Dgraph for dev
```

#### Production Environment (.env.prod)  
```bash
# .env.prod - Production overrides
DEBUG_MODE=false
LOG_LEVEL=WARN
WINEDEBUG=-all

# Security hardening
ENABLE_TLS=true
JWT_SECRET_KEY=${JWT_SECRET_KEY}            # From secure secret management
API_RATE_LIMIT=50                           # Lower rate limit for production

# Performance optimization
WORKER_PROCESSES=8
MAX_MEMORY_USAGE=8G
CPU_LIMIT=4.0

# Production database settings (external)
REDIS_URL=redis://redis.production.internal:6379
DGRAPH_ENDPOINT=https://dgraph.production.internal:8080
```

#### Testing Environment (.env.test)
```bash
# .env.test - Testing overrides
SESSION_ID=test-${CI_PIPELINE_ID}
DEBUG_MODE=true
LOG_LEVEL=DEBUG

# Use in-memory/ephemeral storage for tests
REDIS_URL=redis://localhost:6381
DGRAPH_ENDPOINT=http://localhost:8083

# Disable external dependencies
ENABLE_WINE=false                           # Mock Wine environment for tests
MOCK_GAME_DATA=true                         # Use mock game data
```

### Configuration Validation

#### Environment Check Script
```bash
#!/bin/bash
# scripts/check-env.sh - Validate environment configuration

echo "=== Environment Configuration Check ==="

# Required variables check
required_vars=(
    "SESSION_ID" 
    "DGRAPH_ENDPOINT" 
    "REDIS_URL" 
    "MCP_COORDINATOR_URL"
    "WINEPREFIX"
    "WINEARCH"
)

missing_vars=()
for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        missing_vars+=("$var")
    fi
done

if [[ ${#missing_vars[@]} -gt 0 ]]; then
    echo "❌ Missing required environment variables:"
    printf '  - %s\n' "${missing_vars[@]}"
    exit 1
else
    echo "✅ All required environment variables are set"
fi

# Service connectivity check
echo "Checking service connectivity..."
services=(
    "$DGRAPH_ENDPOINT/health"
    "${REDIS_URL%/*}/ping"
    "$MCP_COORDINATOR_URL/health"
)

for service in "${services[@]}"; do
    if timeout 5 curl -f -s "$service" >/dev/null 2>&1; then
        echo "✅ $service"
    else
        echo "❌ $service (unreachable)"
    fi
done
```

#### Configuration Templates
```bash
# Generate environment files from templates
cp .env.example .env                        # Base configuration
cp .env.dev.example .env.dev               # Development overrides  
cp .env.prod.example .env.prod             # Production overrides

# Validate configuration
make check-env                             # Run environment validation
```

## Available Service Endpoints

### Core Platform Services
- **Web Dashboard**: `http://localhost:80` - Main analysis interface
- **Web Dashboard (HTTPS)**: `https://localhost:443` - Secure analysis interface  
- **MCP Coordinator**: `http://localhost:8000` - API and orchestration hub
- **MCP WebSocket**: `ws://localhost:9000` - Real-time communication
- **Nginx Proxy**: `http://localhost:8090` - Load balancer and reverse proxy

### Game Analysis Services
- **VNC Access**: `vnc://localhost:5900` - Direct desktop access to game
- **Web VNC**: `http://localhost:5901` - Browser-based VNC client
- **Game Health Check**: `http://localhost:3000` - D2 analysis health status
- **Game State API**: `http://localhost:8765` - MCP server for game analysis

### Database & Storage Services
- **Dgraph Alpha**: `http://localhost:8081` - Graph database UI
- **Dgraph Zero**: `http://localhost:5080` - Dgraph cluster management
- **Redis**: `redis://localhost:6379` - Session and cache storage

### API Endpoints by Service

#### D2 Analysis Container (localhost:8765, localhost:3000)
- `GET /health` - Service health status
- `GET /game/processes` - Running game processes
- `GET /game/character` - Character information  
- `GET /game/inventory` - Current inventory state
- `GET /game/state` - Overall game state
- `POST /game/action/{action}` - Execute game actions
- `GET /memory/info` - Memory analysis information
- `GET /game/status` - Game status overview
- `GET /processes` - System process information
- `GET /system/info` - System information

#### Analysis Engine Container (localhost:8001)
- `GET /` - Service root
- `GET /health` - Health check endpoint
- `POST /analyze` - Submit analysis requests
- `GET /status` - Analysis status

#### Web Dashboard Container (localhost:80)
- `GET /` - Dashboard home page
- `GET /api/status` - Platform status API
- `GET /api/character` - Character data API
- `GET /api/network` - Network analysis API
- `GET /api/security` - Security analysis API
- `GET /health` - Dashboard health check

#### MCP Coordinator (localhost:8000)
- `GET /health` - Coordinator health status
- `POST /mcp/execute` - Execute MCP tool requests
- `GET /mcp/servers` - List registered MCP servers
- `GET /mcp/tools` - Available analysis tools
- `GET /mcp/resources` - Available data resources
- `WS /mcp/ws` - WebSocket connection for real-time updates

#### Network Monitor Container (shares d2-analysis network)
- **Note**: Network monitor uses `network_mode: "container:d2-analysis"` sharing the same network namespace
- Accessible through d2-analysis container at localhost:3000 or localhost:8765
- `GET /health` - Network monitor health (via d2-analysis)
- `GET /capture/status` - Packet capture status  
- `POST /capture/start` - Start packet capture
- `POST /capture/stop` - Stop packet capture
- `GET /analysis/protocols` - Protocol analysis results
- `GET /analysis/traffic` - Traffic pattern analysis

### Authentication & Security
- **No Authentication Required**: Development mode (localhost access only)
- **Production Security**: JWT tokens, API keys, IP whitelisting
- **Container Isolation**: Network segmentation, privilege separation
- **Data Encryption**: TLS for external access, encrypted storage

## Troubleshooting Guide

### Common Container Startup Issues

#### Container Fails to Start
```bash
# Check container status and logs
docker-compose ps
docker-compose logs <container-name> --tail=50

# Common fixes:
# 1. Port conflicts
docker-compose down && docker-compose up -d
netstat -tulpn | grep <port>                # Check what's using the port
killall -9 <process-name>                   # Kill conflicting process

# 2. Volume permission issues  
sudo chown -R $USER:$USER ./data/outputs
chmod -R 755 ./data/outputs

# 3. Out of disk space
docker system prune -f                      # Clean up unused containers
docker volume prune -f                      # Clean up unused volumes
```

#### Database Connection Issues
```bash
# Dgraph connection problems
docker-compose logs dgraph-alpha dgraph-zero
docker-compose exec dgraph-alpha curl -s localhost:8080/health

# Redis connection problems  
docker-compose logs redis
docker-compose exec redis redis-cli ping

# Fix: Reset database containers
docker-compose stop dgraph-alpha dgraph-zero redis
docker volume rm dgraph_data redis_data
docker-compose up -d dgraph-alpha dgraph-zero redis
```

### Network Connectivity Problems

#### Container-to-Container Communication
```bash
# Test internal network connectivity
docker-compose exec d2-analysis curl -f http://mcp-coordinator:8080/health
docker-compose exec mcp-coordinator curl -f http://dgraph-alpha:8080/health

# Check Docker network
docker network ls
docker network inspect pd2-mcp-orchestrated-re_re-platform

# Fix network issues
docker-compose down
docker network prune
docker-compose up -d
```

#### External Access Issues
```bash
# Check if ports are properly mapped
docker-compose ps
docker port <container-name>

# Test external connectivity
curl -f http://localhost:8000/health        # MCP Coordinator
curl -f http://localhost:80/health          # Web Dashboard  
curl -f http://localhost:8081/health        # Dgraph

# Fix port mapping issues
# Check docker-compose.yml port mappings
# Ensure no firewall blocking ports
sudo ufw status                             # Check firewall (Linux)
```

### Wine/D2 Game Launch Failures

#### Wine Environment Issues
```bash
# Check Wine installation in container
docker-compose exec d2-analysis wine --version
docker-compose exec d2-analysis ls -la $WINEPREFIX

# Reinitialize Wine environment
docker-compose exec d2-analysis rm -rf $WINEPREFIX
docker-compose exec d2-analysis winecfg
docker-compose restart d2-analysis

# Check X11/Display issues
docker-compose exec d2-analysis echo $DISPLAY
docker-compose exec d2-analysis xwininfo -root -tree
```

#### VNC Connection Problems
```bash
# Check VNC server status
docker-compose exec d2-analysis ps aux | grep vnc
docker-compose logs d2-analysis | grep vnc

# Test VNC connectivity
vncviewer localhost:5900                   # Desktop VNC client
curl -f http://localhost:5901              # Web VNC interface

# Restart VNC server
docker-compose exec d2-analysis supervisorctl restart x11vnc
```

#### Game Launch Debugging
```bash
# Enable Wine debugging for game issues
# In .env file:
WINEDEBUG=+all,+dll,+registry

# Check game files
docker-compose exec d2-analysis ls -la /data/pd2/
docker-compose exec d2-analysis file /data/pd2/Game.exe

# Manual game launch for debugging
docker-compose exec d2-analysis bash
cd /data/pd2 && wine Game.exe -w -ns
```

### Port Conflicts Resolution

#### Identify Port Conflicts
```bash
# Check which process is using a port
sudo lsof -i :8000                         # Check specific port
sudo netstat -tulpn | grep :8000           # Alternative check

# Check all platform ports
ports=(80 443 3000 3001 5080 5900 5901 6080 6379 8000 8001 8002 8003 8004 8005 8081 8090 8765 8888 9000 9080 27042)
for port in "${ports[@]}"; do
    echo "Port $port:"
    sudo lsof -i :$port || echo "  Available"
done
```

#### Resolve Port Conflicts
```bash
# Option 1: Kill conflicting process
sudo kill -9 $(sudo lsof -ti :8000)

# Option 2: Change platform ports
# Edit docker-compose.yml or use environment overrides
echo "MCP_COORDINATOR_PORT=8001" >> .env.local
docker-compose --env-file .env.local up -d

# Option 3: Use alternative port ranges
# For development, use docker-compose.dev.yml with different ports
```

### Memory and Performance Issues

#### High Memory Usage
```bash
# Monitor container memory usage
docker stats --format "table {{.Container}}\t{{.MemUsage}}\t{{.MemPerc}}"

# Check for memory leaks
docker-compose exec d2-analysis ps aux --sort=-%mem | head -10
docker-compose exec mcp-coordinator python -c "import psutil; print(psutil.virtual_memory())"

# Limit container memory usage
# In docker-compose.yml:
services:
  d2-analysis:
    mem_limit: 4g
    mem_reservation: 2g
```

#### Performance Optimization  
```bash
# Check system resources
df -h                                       # Disk usage
free -h                                     # Memory usage
top -p $(pgrep -f docker)                   # Docker process usage

# Optimize Docker performance
# Add to /etc/docker/daemon.json:
{
  "storage-driver": "overlay2",
  "log-opts": {"max-size": "100m", "max-file": "5"}
}

sudo systemctl restart docker
```

### Log Analysis and Debugging

#### Container Log Analysis
```bash
# Real-time log monitoring
docker-compose logs -f --tail=100

# Container-specific debugging
docker-compose logs d2-analysis | grep ERROR
docker-compose logs mcp-coordinator | grep -i "connection\|timeout"

# Export logs for analysis
docker-compose logs --no-color > platform-logs-$(date +%Y%m%d).log
```

#### Application-Level Debugging
```bash
# Enable debug mode
echo "DEBUG_MODE=true" >> .env
echo "LOG_LEVEL=DEBUG" >> .env
docker-compose restart

# Python debugging in containers
docker-compose exec mcp-coordinator python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
"

# Wine debugging
docker-compose exec d2-analysis bash -c "
WINEDEBUG=+all wine /data/pd2/Game.exe -w 2>&1 | tee wine-debug.log
"
```

## Tech Stack & Standards
- **Containerization**: Docker + Docker Compose orchestration
- **Languages**: Python 3.10+, Shell scripting, JavaScript/Node.js
- **Architecture**: Container-first microservices with MCP communication
- **Game Environment**: Project Diablo 2 via Wine with VNC access
- **VNC Access**: Remote desktop on port 5900, web VNC on port 5901
- **Data Storage**: Dgraph graph database + Redis caching + file-based outputs
- **Security**: Multi-tier networks, container sandboxing, encrypted storage
- **Development Tools**: Hot reload, comprehensive testing, mock data systems

## Container-Focused Architecture

Each container is self-contained with its own configs, scripts, and dependencies:

```
pd2-mcp-orchestrated-re/
├── docker-compose.yml           # Main orchestration
├── .env.example                 # Environment configuration template
│
├── containers/                  # Container-specific implementations
│   ├── d2-analysis/            # 🎮 Game analysis container
│   │   ├── Dockerfile          # Wine + D2 + Python environment
│   │   ├── requirements.txt    # Python dependencies
│   │   ├── supervisord.conf    # Process management (X11, VNC, etc.)
│   │   ├── setup_wine.sh       # Wine environment setup
│   │   ├── diablo2_monitor.py  # Game state monitoring
│   │   ├── simple_mcp_server.py # MCP server for D2 analysis
│   │   └── health_check.py     # Container health monitoring
│   │
│   ├── mcp-coordinator/        # 🧠 MCP orchestration hub
│   │   ├── Dockerfile          # FastAPI + MCP coordination
│   │   ├── requirements.txt    # MCP + FastAPI dependencies
│   │   ├── coordinator.py      # Main MCP coordination logic
│   │   └── config/            # MCP server configurations
│   │
│   ├── analysis-engine/        # ⚙️ Core analysis processing
│   │   ├── Dockerfile          # Analysis tools + algorithms
│   │   ├── requirements.txt    # Analysis dependencies
│   │   └── engines/           # Analysis implementations
│   │
│   ├── network-monitor/        # 🌐 Network packet analysis
│   │   ├── Dockerfile          # Network capture + analysis tools
│   │   ├── requirements.txt    # Network analysis dependencies
│   │   └── monitors/          # Packet capture & analysis
│   │
│   └── web-dashboard/          # 📊 Web UI and reporting
│       ├── Dockerfile          # React/Vue frontend + backend
│       ├── package.json        # Node.js dependencies
│       └── src/               # Dashboard implementation
│
├── shared/                     # Shared libraries and utilities
│   ├── mcp/                   # MCP protocol implementations
│   ├── analysis/              # Common analysis utilities  
│   ├── game/                  # D2-specific game logic
│   ├── data/                  # Data models and storage
│   └── claude/                # AI orchestration logic
│
├── data/                       # Runtime data and outputs
│   ├── pd2/                   # Project Diablo 2 game files
│   │   ├── Game.exe           # Main game executable
│   │   ├── *.dll              # Game libraries (D2Client.dll, etc.)
│   │   ├── *.mpq              # Game data archives
│   │   └── *.json/*.ini       # Game configuration files
│   │
│   ├── reference/             # Structure definitions and discovered offsets
│   │   ├── D2Structs.h        # C structure definitions (ground truth)
│   │   ├── live_memory_offsets.json # Discovered static offsets
│   │   ├── D2Ptrs.h           # Memory pointers and addresses
│   │   └── Constants.h        # Game constants and enums
│   │
│   └── outputs/               # Analysis results
│       ├── sessions/          # Analysis session data
│       ├── reports/           # Generated reports
│       ├── logs/              # Container and analysis logs
│       └── memory_dumps/      # Memory analysis dumps (400+ snapshots)
│
├── tools/                     # Production and development utilities
│   ├── memory_hunters/        # Production memory analysis tools
│   │   ├── rosterunit_hunter.py        # RosterUnit structure hunting
│   │   ├── current_player_unit_demo.py  # UnitAny extraction demo
│   │   ├── store_memory_data_dgraph.py  # Database integration
│   │   ├── extract_from_container.py    # Container-based extraction
│   │   └── README.md                    # Production tools documentation
│   │
│   ├── development/           # Development helpers
│   │   ├── setup_dev_env.py   # Development environment setup
│   │   └── validate_setup.py  # Setup validation
│   │
│   └── scripts/               # Build and deployment scripts
│       ├── build.bat/.ps1     # Cross-platform build scripts
│       └── validate_*.py      # Validation utilities
│
├── examples/                  # Educational examples and demonstrations
│   ├── memory_analysis/       # Memory analysis examples
│   │   ├── demo_playerdata_hunt.py     # PlayerData hunting demo
│   │   ├── live_memory_extractor.py    # Live memory extraction
│   │   ├── playerdata_hunter_live.py   # Live PlayerData analysis
│   │   └── README.md                   # Examples documentation
│   │
│   └── [other examples]/     # Additional analysis examples
│
└── docs/                     # Complete documentation system
    └── memory_analysis/      # Memory analysis documentation
        ├── README.md         # Overview and quick start
        ├── api_reference.md  # Complete API documentation (671 lines)
        ├── memory_structures.md # Structure layouts and offsets (239 lines)
        ├── usage_guide.md    # Step-by-step instructions (316 lines)
        ├── development_guide.md # Extension guide (528 lines)
        └── troubleshooting.md   # Debugging guide (442 lines)
```

## Model Context Protocol (MCP) Integration

### MCP Protocol Overview
The Model Context Protocol (MCP) enables standardized communication between AI assistants and external systems. In this platform:

- **MCP Servers**: Each analysis container runs an MCP server exposing tools and resources
- **MCP Coordinator**: Central hub orchestrating multiple MCP servers and routing requests
- **Tool Registration**: Analysis capabilities exposed as MCP tools (memory analysis, game state, etc.)
- **Resource Management**: Game data, memory dumps, and analysis results as MCP resources

### MCP Usage Patterns
```python
# Example MCP tool registration
@mcp_server.tool("analyze_memory")
async def analyze_memory(process_id: int, address: str) -> dict:
    """Analyze memory at specific address for given process"""
    return await memory_analyzer.analyze(process_id, address)

# Example MCP resource
@mcp_server.resource("game_state")
async def get_game_state() -> dict:
    """Current Diablo 2 game state including character, inventory, etc."""
    return await game_monitor.get_current_state()
```

### MCP Server Endpoints
- **d2-analysis**: `http://d2-analysis:8765/mcp` - Game analysis tools
- **analysis-engine**: `http://analysis-engine:8766/mcp` - Static/dynamic analysis
- **network-monitor**: `http://network-monitor:8768/mcp` - Network analysis tools

## Memory Analysis System

### Overview
The platform includes a comprehensive memory analysis system for reverse engineering Project Diablo 2, with production-ready tools, educational examples, and complete documentation.

### Key Capabilities
- **Live Memory Reading**: Direct extraction from running Game.exe processes via `/proc/PID/mem`
- **Structure Discovery**: Automated hunting for game structures (RosterUnit, UnitAny, PlayerData)
- **Static Offset Discovery**: Finding stable memory offsets like `D2Client.dll+0x11BBFC`
- **Graph Database Storage**: Complete relationship modeling in Dgraph with full schema
- **Real-time Validation**: Field-by-field verification of extracted structures
- **Container Integration**: Memory access through d2-analysis container

### Discovered Memory Structures

#### Static Memory Offsets (Verified)
| Structure | Size | Offset | Description |
|-----------|------|--------|-------------|
| **Current Player Unit** | 236 bytes | D2Client.dll+0x11BBFC | Main UnitAny player structure |
| **RosterUnit List** | 132 bytes | D2Client.dll+0x11BC14 | Party/roster information |
| **PlayerData** | 40 bytes | Via UnitAny+0x14 | Character name, quests, waypoints |

#### Structure Field Layouts

**UnitAny Structure (Current Player Unit - 236 bytes)**
```c
struct UnitAny {
    DWORD dwType;              // 0x00 - Unit type (0=Player)
    DWORD dwTxtFileNo;         // 0x04 - Character class ID (0-6)
    DWORD _1;                  // 0x08 - Unknown
    DWORD dwUnitId;            // 0x0C - Unique unit identifier
    DWORD dwMode;              // 0x10 - Current unit mode/state
    PlayerData* pPlayerData;   // 0x14 - Player data pointer
    DWORD dwAct;               // 0x18 - Current act number (0-4)
    // ... additional fields ...
    StatList* pStats;          // 0x5C - Character statistics
    WORD wX;                   // 0x8C - World X coordinate
    WORD wY;                   // 0x8E - World Y coordinate
    DWORD dwFlags;             // 0xC4 - Primary unit flags
    DWORD dwFlags2;            // 0xC8 - Extended unit flags
    UnitAny* pNext;            // 0xE8 - Next unit in list
};
```

**RosterUnit Structure (Party Data - 132 bytes)**
```c
struct RosterUnit {
    char szName[16];           // 0x00 - Player name (null-terminated)
    DWORD dwUnitId;            // 0x10 - Unit ID (matches UnitAny.dwUnitId)
    DWORD dwPartyLife;         // 0x14 - Party life percentage (0-100)
    DWORD dwClassId;           // 0x1C - Character class ID
    WORD wLevel;               // 0x20 - Character level
    WORD wPartyId;             // 0x22 - Party identifier
    DWORD dwLevelId;           // 0x24 - Current area/level ID
    DWORD Xpos;                // 0x28 - X position
    DWORD Ypos;                // 0x2C - Y position
    DWORD dwPartyFlags;        // 0x30 - Party status flags
    // ... additional fields ...
    RosterUnit* pNext;         // 0x80 - Next RosterUnit pointer
};
```

### Memory Analysis Tools

#### Production Tools (`tools/memory_hunters/`)
- **`rosterunit_hunter.py`**: Hunt for RosterUnit structures using known live values
- **`current_player_unit_demo.py`**: Extract UnitAny (Current Player Unit) structures
- **`current_player_unit_full.py`**: Complete UnitAny field breakdown (all 61 fields)
- **`store_memory_data_dgraph.py`**: Store discoveries in Dgraph with full relationships
- **`extract_from_container.py`**: Container-native memory analysis execution
- **`real_live_memory.py`**: Realistic memory data representation

#### Educational Examples (`examples/memory_analysis/`)
- **`demo_playerdata_hunt.py`**: PlayerData structure hunting demonstration
- **`live_memory_extractor.py`**: Live memory extraction via container API
- **`playerdata_hunter_live.py`**: Live PlayerData analysis and validation

### Usage Examples

#### Hunt for RosterUnit Structure
```bash
# Using known live values: szName="Xerzes", dwPartyLife=40, wLevel=1
python tools/memory_hunters/rosterunit_hunter.py
```

#### Extract Current Player Data
```bash
# Get complete UnitAny structure with all fields
python tools/memory_hunters/current_player_unit_demo.py
```

#### Store in Graph Database
```bash
# Store discoveries with relationships in Dgraph
python tools/memory_hunters/store_memory_data_dgraph.py
```

#### Container-Based Analysis
```bash
# Execute analysis inside d2-analysis container for direct access
python tools/memory_hunters/extract_from_container.py
```

### Live Memory Access Methods

#### Direct Process Memory Reading
```python
# Read from /proc/PID/mem inside d2-analysis container
with open('/proc/14/mem', 'rb') as mem:
    mem.seek(address)
    data = mem.read(size)
    value = struct.unpack('<L', data)[0]
```

#### Base Address Discovery
```python
# Find D2Client.dll base address using gdb
d2client_base = 0x6FAB0000  # Wine environment
player_unit_addr = d2client_base + 0x11BBFC  # Static offset
```

#### Structure Validation
```python
# Validate extracted structures against known values
def validate_roster_unit(data):
    return (
        data['szName'] == "Xerzes" and
        data['dwPartyLife'] == 40 and
        data['wLevel'] == 1
    )
```

### Database Integration

#### Dgraph Schema
Complete graph database schema with types:
- **Modules**: D2 DLL information and base addresses
- **MemoryOffsets**: Static memory offsets with relationships
- **MemoryStructures**: Structure layouts and field definitions
- **Characters**: Live character data with stats and positions
- **AnalysisSessions**: Analysis tracking with timestamps

#### Sample Queries
```graphql
# Query all characters with their stats
{
  characters(func: type(Character)) {
    char.name
    char.class
    char.level
    char.memory_address
    char.stats {
      stats.strength
      stats.energy
      stats.dexterity
      stats.vitality
    }
  }
}
```

### Memory Analysis API Endpoints

#### D2 Analysis Container Memory APIs
- **GET** `/memory/info` - Memory analysis information and process details
- **GET** `/memory/structures` - Available structure definitions
- **POST** `/memory/hunt` - Hunt for specific structures with known values
- **GET** `/memory/offsets` - Current static memory offsets
- **POST** `/memory/validate` - Validate extracted structure data

#### MCP Memory Analysis Tools
- **`hunt_roster_unit`**: Hunt for RosterUnit structures in live memory
- **`extract_player_unit`**: Extract Current Player UnitAny structure
- **`analyze_memory_region`**: Analyze specific memory regions
- **`validate_structure`**: Validate extracted structure data
- **`store_discovery`**: Store discoveries in graph database

### Security and Safety

#### Read-Only Memory Access
- All memory operations are read-only (never write to process memory)
- Proper error handling for permission denied and invalid addresses
- Memory access confined to d2-analysis container for security

#### Ethical Guidelines
- **✅ Defensive Security Research**: Game security analysis and cheat detection
- **✅ Educational Purposes**: Learning reverse engineering techniques
- **✅ Game Mechanics Study**: Understanding D2 internals and structures
- **❌ Cheat Development**: Creating game cheats or hacks
- **❌ Online Exploitation**: Circumventing anti-cheat systems

### Documentation System

#### Complete Documentation (`docs/memory_analysis/`)
- **README.md**: Overview, architecture, and quick start guide
- **api_reference.md**: Complete API documentation with examples (671 lines)
- **memory_structures.md**: Detailed structure layouts and verified offsets (239 lines)
- **usage_guide.md**: Step-by-step instructions and workflows (316 lines)
- **development_guide.md**: Guide for extending the system (528 lines)
- **troubleshooting.md**: Common issues and debugging solutions (442 lines)

#### Reference Data (`data/reference/`)
- **D2Structs.h**: C structure definitions (ground truth from reverse engineering)
- **live_memory_offsets.json**: Complete discovered offsets with live examples
- **D2Ptrs.h**: Memory pointers and function addresses
- **Constants.h**: Game constants and enumeration values

### Verified Live Data Examples

#### Level 1 Sorceress "Xerzes"
- **Memory Address**: 0x0E45AB00
- **Stats**: STR=10, ENE=35, DEX=25, VIT=10
- **HP/Mana**: 45/45 HP, 50/50 Mana
- **Position**: (5726, 4539) in Act 1

#### Level 99 Druid "Druid"
- **Memory Address**: 0x0E447D00
- **Stats**: STR=27, ENE=20, DEX=28, VIT=25
- **HP/Mana**: 262/262 HP, 216/216 Mana
- **Position**: (5113, 5068) in Act 4
- **Experience**: 3,520,485,254

### Development Workflow

#### Adding New Structure Hunters
1. Define structure in `data/reference/D2Structs.h`
2. Create hunter class extending `MemoryHunter` base
3. Implement pattern generation and validation
4. Add Dgraph schema and storage methods
5. Create comprehensive tests and documentation

#### Testing and Validation
- Unit tests for all structure parsers
- Integration tests with live memory data
- Performance benchmarks for memory operations
- Security validation for memory access patterns

## Security Guidelines

### Container Security Best Practices

#### Container Hardening
```bash
# Run containers with minimal privileges
# In docker-compose.yml:
services:
  d2-analysis:
    user: "1000:1000"                        # Non-root user
    read_only: true                          # Read-only root filesystem
    tmpfs:
      - /tmp:exec,nosuid,nodev,size=1g       # Temporary filesystem
    cap_drop:
      - ALL                                  # Drop all capabilities
    cap_add:
      - SYS_PTRACE                          # Only required capabilities
      - NET_RAW
    security_opt:
      - no-new-privileges:true              # Prevent privilege escalation
      - seccomp=./security/seccomp.json     # Syscall filtering
```

#### Network Security & Isolation
```yaml
# Network segmentation in docker-compose.yml
networks:
  frontend:                                 # Web-facing services
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  backend:                                  # Database and internal services  
    driver: bridge
    internal: true                          # No external access
    ipam:
      config:
        - subnet: 172.21.0.0/24
  analysis:                                 # Game analysis isolated network
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.22.0.0/24
```

#### Production Security Configuration
```bash
# .env.prod - Security hardening
ENABLE_TLS=true
FORCE_HTTPS=true
HSTS_MAX_AGE=31536000
X_FRAME_OPTIONS=DENY
X_CONTENT_TYPE_OPTIONS=nosniff

# JWT Configuration
JWT_SECRET_KEY=${VAULT_JWT_SECRET}          # From secret management system
JWT_EXPIRY_HOURS=24
JWT_REFRESH_ENABLED=true

# API Security
API_RATE_LIMIT=50                           # Requests per minute
API_BURST_LIMIT=100                         # Burst capacity
CORS_ALLOWED_ORIGINS=https://yourdomain.com
```

### Data Handling Protocols

#### Memory Dump Security
```bash
# Secure memory dump handling
#!/bin/bash
# scripts/secure-memory-dump.sh

DUMP_FILE="$1"
if [[ ! -f "$DUMP_FILE" ]]; then
    echo "Error: Dump file not found"
    exit 1
fi

# 1. Encrypt memory dumps at rest
gpg --symmetric --cipher-algo AES256 "$DUMP_FILE"
rm "$DUMP_FILE"                             # Remove unencrypted original

# 2. Set restrictive permissions
chmod 600 "${DUMP_FILE}.gpg"
chown analysis-user:analysis-group "${DUMP_FILE}.gpg"

# 3. Move to secure storage location
mv "${DUMP_FILE}.gpg" "/secure/memory-dumps/"

# 4. Log access
echo "$(date): Memory dump $DUMP_FILE encrypted and secured" >> /var/log/security.log
```

#### Sensitive Data Handling
```python
# Python code for handling sensitive game data
import secrets
from cryptography.fernet import Fernet
import logging

class SecureDataHandler:
    def __init__(self):
        self.cipher_key = self._get_encryption_key()
        self.cipher = Fernet(self.cipher_key)
        
    def encrypt_sensitive_data(self, data: dict) -> bytes:
        """Encrypt sensitive game data before storage"""
        # Remove sensitive fields that shouldn't be stored
        cleaned_data = self._sanitize_data(data)
        
        json_data = json.dumps(cleaned_data)
        encrypted = self.cipher.encrypt(json_data.encode())
        
        # Log access without sensitive details
        logging.info(f"Data encrypted for storage: {len(data)} fields")
        return encrypted
    
    def _sanitize_data(self, data: dict) -> dict:
        """Remove passwords, keys, and other sensitive information"""
        sensitive_keys = {'password', 'api_key', 'token', 'secret'}
        return {k: v for k, v in data.items() 
                if k.lower() not in sensitive_keys}
```

### Secrets Management

#### Development Secrets
```bash
# Use Docker secrets for sensitive data (production)
echo "your-jwt-secret" | docker secret create jwt_secret -
echo "your-db-password" | docker secret create db_password -

# Reference in docker-compose.yml:
services:
  mcp-coordinator:
    secrets:
      - jwt_secret
      - db_password
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - DB_PASSWORD_FILE=/run/secrets/db_password

secrets:
  jwt_secret:
    external: true
  db_password:
    external: true
```

#### Environment-Specific Secrets
```bash
# Development - Use .env.local (never commit)
echo "JWT_SECRET_KEY=dev-secret-key-$(openssl rand -hex 32)" > .env.local
echo ".env.local" >> .gitignore

# Production - Use external secret management
# AWS Secrets Manager, HashiCorp Vault, etc.
export JWT_SECRET_KEY=$(aws secretsmanager get-secret-value \
    --secret-id prod/mcp-platform/jwt \
    --query SecretString --output text)
```

#### Secret Rotation
```bash
#!/bin/bash
# scripts/rotate-secrets.sh - Automated secret rotation

rotate_jwt_secret() {
    NEW_SECRET=$(openssl rand -hex 64)
    
    # Update secret in secret manager
    aws secretsmanager update-secret \
        --secret-id prod/mcp-platform/jwt \
        --secret-string "$NEW_SECRET"
    
    # Graceful restart of services
    docker-compose restart mcp-coordinator web-dashboard
    
    echo "JWT secret rotated successfully"
}

# Run weekly via cron
0 2 * * 0 /opt/platform/scripts/rotate-secrets.sh
```

### Access Control & Authentication

#### Production Authentication
```python
# JWT-based authentication for production APIs
from functools import wraps
import jwt
from flask import request, jsonify

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
            
        try:
            # Remove 'Bearer ' prefix
            token = token.replace('Bearer ', '')
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            request.user_id = payload['user_id']
            request.permissions = payload.get('permissions', [])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    return decorated

@app.route('/api/memory/analyze', methods=['POST'])
@require_auth
def analyze_memory():
    # Verify user has memory analysis permissions
    if 'memory:analyze' not in request.permissions:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    # Proceed with analysis...
```

#### API Rate Limiting & Protection
```python
# Rate limiting and DDoS protection
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per minute", "1000 per hour"]
)

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")  # Stricter limit for analysis
@require_auth
def analyze_endpoint():
    # Analysis logic here
    pass
```

### Security Monitoring & Auditing

#### Security Event Logging
```python
# Security event logging
import logging
from datetime import datetime

security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
handler = logging.FileHandler('/var/log/security-events.log')
formatter = logging.Formatter(
    '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
security_logger.addHandler(handler)

def log_security_event(event_type: str, user_id: str, details: dict):
    """Log security-relevant events"""
    security_logger.info(
        f"Event: {event_type} | User: {user_id} | "
        f"IP: {request.remote_addr} | Details: {details}"
    )

# Usage examples:
log_security_event("AUTH_FAILURE", "anonymous", {"reason": "invalid_token"})
log_security_event("MEMORY_ACCESS", user_id, {"process_id": 1234, "address": "0x7FF123"})
log_security_event("DATA_EXPORT", user_id, {"file": "analysis_report.json", "size": 1024})
```

#### Intrusion Detection
```bash
# Monitor for suspicious activity
#!/bin/bash
# scripts/security-monitor.sh

# Monitor failed authentication attempts
tail -f /var/log/security-events.log | grep "AUTH_FAILURE" | \
while read line; do
    ip=$(echo "$line" | grep -o 'IP: [0-9.]*' | cut -d' ' -f2)
    count=$(grep "$ip" /var/log/security-events.log | grep "AUTH_FAILURE" | wc -l)
    
    if [[ $count -gt 5 ]]; then
        echo "ALERT: Multiple auth failures from $ip"
        # Block IP or send alert
    fi
done

# Monitor unusual memory access patterns
docker-compose exec d2-analysis python -c "
import psutil
for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
    if proc.info['memory_percent'] > 80:
        print(f'HIGH MEMORY: {proc.info}')
"
```

### Compliance & Data Protection

#### Data Retention Policies
```bash
# Automated data cleanup based on retention policies
#!/bin/bash
# scripts/data-retention.sh

# Remove old memory dumps (30 days retention)
find /data/outputs/memory_dumps -name "*.dump" -mtime +30 -delete

# Archive old analysis sessions (90 days retention)
find /data/outputs/sessions -name "*.json" -mtime +90 \
    -exec gzip {} \; -exec mv {}.gz /archives/ \;

# Clean old logs (7 days retention for debug logs)
find /data/outputs/logs -name "debug-*.log" -mtime +7 -delete
```

#### Privacy Protection
```python
# Personally Identifiable Information (PII) scrubbing
import re

class PIIScubber:
    def __init__(self):
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'username': r'(?i)user[name]*[:=]\s*[a-zA-Z0-9_]+',
        }
    
    def scrub_data(self, data: str) -> str:
        """Remove or mask PII from data before logging/storage"""
        scrubbed = data
        for pii_type, pattern in self.patterns.items():
            scrubbed = re.sub(pattern, f'[REDACTED_{pii_type.upper()}]', scrubbed)
        return scrubbed
```

## Development Workflow

### Enhanced Hot Reload Setup
```bash
# Development environment with hot reload
# docker-compose.dev.yml
version: '3.8'
services:
  mcp-coordinator:
    volumes:
      - ./containers/mcp-coordinator:/app:ro
      - /app/node_modules                   # Preserve node_modules
    environment:
      - NODE_ENV=development
      - FLASK_ENV=development
    command: ["python", "-m", "flask", "run", "--host=0.0.0.0", "--reload"]

  d2-analysis:
    volumes:
      - ./containers/d2-analysis:/app:ro
      - ./shared:/app/shared:ro
    environment:
      - PYTHONPATH=/app:/app/shared
      - FLASK_DEBUG=1
```

### Individual Container Debugging
```bash
# Debug single containers in isolation
#!/bin/bash
# scripts/debug-container.sh

CONTAINER_NAME=$1
if [[ -z "$CONTAINER_NAME" ]]; then
    echo "Usage: $0 <container-name>"
    exit 1
fi

echo "Starting debugging session for $CONTAINER_NAME"

# Start dependencies only
case $CONTAINER_NAME in
    "d2-analysis")
        docker-compose up -d dgraph-alpha redis
        ;;
    "mcp-coordinator")
        docker-compose up -d dgraph-alpha redis d2-analysis
        ;;
    "analysis-engine")
        docker-compose up -d dgraph-alpha redis mcp-coordinator
        ;;
esac

# Run container in debug mode
docker-compose run --rm \
    -p 5678:5678 \
    -e DEBUG_MODE=true \
    -e LOG_LEVEL=DEBUG \
    "$CONTAINER_NAME" bash

echo "Debugging session ended for $CONTAINER_NAME"
```

### Comprehensive Testing Procedures
```bash
# Multi-level testing strategy
#!/bin/bash
# scripts/run-tests.sh

echo "=== Running Comprehensive Test Suite ==="

# 1. Unit tests per container
containers=("d2-analysis" "mcp-coordinator" "analysis-engine" "web-dashboard")
for container in "${containers[@]}"; do
    echo "Running unit tests for $container..."
    docker-compose run --rm "$container" python -m pytest tests/unit/ -v \
        --cov=src --cov-report=html --cov-report=term
done

# 2. Integration tests
echo "Running integration tests..."
docker-compose run --rm test-runner python -m pytest tests/integration/ -v \
    --tb=short

# 3. API tests
echo "Running API tests..."
docker-compose run --rm test-runner python -m pytest tests/api/ -v \
    --html=reports/api-test-report.html

# 4. Load tests  
echo "Running load tests..."
docker-compose run --rm load-tester python -m locust \
    --host=http://mcp-coordinator:8000 \
    --users=10 --spawn-rate=2 --run-time=60s \
    --html reports/load-test-report.html

# 5. Security tests
echo "Running security tests..."
docker-compose run --rm security-scanner python -m bandit -r src/
docker-compose run --rm security-scanner safety check

# 6. End-to-end tests
echo "Running end-to-end tests..."
docker-compose run --rm e2e-tester python -m pytest tests/e2e/ -v \
    --browser=chrome --headless
```

### Advanced Code Formatting & Linting
```bash
# Comprehensive code quality pipeline
#!/bin/bash
# scripts/code-quality.sh

echo "=== Code Quality Pipeline ==="

# 1. Python formatting and imports
containers=("d2-analysis" "mcp-coordinator" "analysis-engine")
for container in "${containers[@]}"; do
    echo "Formatting Python code in $container..."
    docker-compose run --rm "$container" black src/ tests/ --line-length=88
    docker-compose run --rm "$container" isort src/ tests/ --profile=black
done

# 2. Linting
for container in "${containers[@]}"; do
    echo "Linting Python code in $container..."
    docker-compose run --rm "$container" flake8 src/ --max-line-length=88
    docker-compose run --rm "$container" pylint src/ --rcfile=.pylintrc
done

# 3. Type checking
for container in "${containers[@]}"; do
    echo "Type checking Python code in $container..."
    docker-compose run --rm "$container" mypy src/ --strict --ignore-missing-imports
done

# 4. Security linting
echo "Running security analysis..."
docker-compose run --rm security-scanner bandit -r src/ -f json -o reports/security-report.json

# 5. Documentation linting
echo "Checking documentation..."
docker-compose run --rm docs-checker pydocstyle src/
docker-compose run --rm docs-checker doc8 docs/

# 6. Shell script linting
echo "Linting shell scripts..."
find . -name "*.sh" -exec shellcheck {} \;

# 7. Docker linting
echo "Linting Dockerfiles..."
find . -name "Dockerfile*" -exec hadolint {} \;

# 8. YAML linting  
echo "Linting YAML files..."
find . -name "*.yml" -o -name "*.yaml" | xargs yamllint

echo "Code quality checks completed!"
```

### Pre-commit Hooks Setup
```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/psf/black
    rev: 22.10.0
    hooks:
      - id: black
        language_version: python3.10

  - repo: https://github.com/pycqa/isort
    rev: 5.10.1
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/pycqa/flake8
    rev: 5.0.4
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v0.991
    hooks:
      - id: mypy

# Install pre-commit hooks
docker-compose run --rm d2-analysis pre-commit install
```

## Data Flow Architecture

### Container Communication Flow
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Claude AI     │───▶│  MCP Coordinator │───▶│   D2 Analysis   │
│   Assistant     │    │    (Port 8000)   │    │  (Port 8765)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Analysis Engine  │    │ Network Monitor │
                       │  (Port 8766)     │    │  (Port 8768)    │
                       └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────────────────────────────┐
                       │         Dgraph + Redis Storage          │
                       │     (Ports 8081, 9080, 6379)            │
                       └─────────────────────────────────────────┘
                                         │
                                         ▼
                       ┌─────────────────────────────────────────┐
                       │        Memory Analysis System          │
                       │  tools/memory_hunters/ (Production)    │
                       │  examples/memory_analysis/ (Educational)│
                       │  docs/memory_analysis/ (Documentation) │
                       └─────────────────────────────────────────┘
```

### Data Processing Pipeline
1. **Game State Capture**: D2 analysis container monitors game memory and processes
2. **Memory Structure Discovery**: Hunt for game structures using known values and patterns
3. **MCP Tool Invocation**: Coordinator receives AI requests and routes to appropriate containers
4. **Analysis Processing**: Containers execute analysis and return structured data
5. **Structure Validation**: Field-by-field verification of extracted memory structures
6. **Data Storage**: Results stored in Dgraph (graph relationships) and Redis (session cache)
7. **Memory Offset Storage**: Static offsets and structure definitions stored for reuse
8. **Result Aggregation**: Coordinator combines results from multiple sources
9. **Response Delivery**: Structured analysis delivered back to Claude AI

### Volume Mounting Strategy
```yaml
# Shared data volumes across containers
- ./data/outputs/sessions:/sessions:rw      # Cross-container session data
- ./data/outputs/memory_dumps:/dumps:rw    # Memory analysis artifacts  
- ./data/outputs/reports:/reports:rw       # Generated analysis reports
- ./shared:/app/shared:ro                  # Common libraries and utilities
```

## Monitoring and Observability

### Health Check Endpoints
```bash
# Container health status
curl http://localhost:3000/health          # D2 Analysis
curl http://localhost:8000/health          # MCP Coordinator  
curl http://localhost:80/health            # Web Dashboard
curl http://localhost:8081/health          # Dgraph Alpha
```

### Logging Architecture
```bash
# Centralized logging via Docker Compose
docker-compose logs -f --tail=100                    # All containers
docker-compose logs -f d2-analysis                   # Game analysis only
docker-compose logs -f mcp-coordinator               # MCP coordination
docker-compose logs -f analysis-engine               # Analysis processing

# Log aggregation locations
./data/outputs/logs/d2-analysis/game_monitor.log     # Game state monitoring
./data/outputs/logs/mcp-coordinator/requests.log     # MCP request/response
./data/outputs/logs/analysis-engine/processing.log   # Analysis operations
```

### Metrics Collection
- **Container Resource Usage**: CPU, memory, network via Docker stats
- **MCP Request Metrics**: Request count, latency, error rates
- **Game Analysis Metrics**: Process monitoring, memory access patterns
- **Database Performance**: Dgraph query performance, Redis hit rates

### Alerting and Notifications
```bash
# Service health monitoring
make health                                 # Check all services
docker-compose ps                          # Container status overview
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

## Performance Considerations

### Resource Requirements
```yaml
# Minimum system requirements
CPU: 4+ cores (Wine + D2 + multiple analysis containers)
RAM: 8GB+ (4GB for Wine/D2, 4GB+ for analysis containers)  
Storage: 20GB+ (Game files, analysis outputs, container images)
Network: Low latency for real-time game monitoring
```

### Optimization Strategies

#### Container Performance
- **Resource Limits**: Set appropriate CPU/memory limits per container
- **Image Optimization**: Multi-stage builds, minimal base images
- **Volume Performance**: Use bind mounts for frequently accessed data
- **Network Optimization**: Container networking on same Docker bridge

#### Game Analysis Performance  
- **Memory Access Patterns**: Batch memory reads, cache frequently accessed data
- **Process Monitoring**: Efficient polling intervals, selective process tracking
- **Wine Performance**: Optimized Wine prefix, minimal Windows emulation overhead

#### Database Performance
```bash
# Dgraph optimization
- Index frequently queried fields
- Batch write operations
- Connection pooling for multiple containers

# Redis optimization  
- Appropriate eviction policies
- Connection pooling
- Memory usage monitoring
```

#### Scaling Considerations
- **Horizontal Scaling**: Multiple analysis-engine containers for load distribution
- **Container Orchestration**: Production deployment with Kubernetes/Docker Swarm
- **Load Balancing**: Nginx reverse proxy for request distribution
- **Data Partitioning**: Session-based data isolation for concurrent analysis

### Performance Monitoring Commands
```bash
# Container resource monitoring
docker stats --no-stream                    # Current resource usage
docker system df                            # Docker disk usage
docker system events                        # Real-time Docker events

# Application performance
curl -w "@curl-format.txt" http://localhost:8000/health  # Response times
redis-cli --latency-history                 # Redis latency monitoring
```

## Key Development Patterns

### Container Communication
- **MCP Protocol**: All inter-container communication uses MCP
- **Port Mapping**: d2-analysis (5900:VNC), mcp-coordinator (8000:API)
- **Shared Volumes**: `/data/outputs` for analysis results

### File Organization Rules
1. **Container-Specific**: Each container owns its configs/scripts in `containers/<name>/`
2. **Shared Code**: Common utilities go in `shared/` directory
3. **Runtime Data**: All outputs and game files in `data/` directory
4. **No Config Mixing**: Container configs stay with their respective containers

### Build and Run Commands
```bash
# Environment setup
cp .env.example .env

# Build all containers
docker-compose build --no-cache

# Start platform
docker-compose up -d

# Access game environment
# VNC: vnc://localhost:5900
# Web Dashboard: http://localhost:8000

# View logs
docker-compose logs <container-name> --tail=50
```

## Developer Experience

### IDE Setup Recommendations

#### VS Code Extensions
```json
// .vscode/extensions.json
{
  "recommendations": [
    "ms-python.python",              // Python language support
    "ms-vscode.docker",              // Docker integration
    "ms-azuretools.vscode-docker",   // Docker compose support
    "ms-python.black-formatter",     // Code formatting
    "ms-python.pylint",              // Python linting
    "hashicorp.terraform",           // Infrastructure as code
    "redhat.vscode-yaml",            // YAML support
    "ms-vscode.makefile-tools"       // Makefile support
  ]
}
```

#### VS Code Settings
```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "./containers/*/venv/bin/python",
  "docker.defaultRegistryPath": "",
  "files.associations": {
    "docker-compose*.yml": "yaml",
    "Dockerfile*": "dockerfile"
  },
  "python.linting.enabled": true,
  "python.formatting.provider": "black"
}
```

### Debugging Configuration

#### Container Debugging
```yaml
# .vscode/launch.json - Remote debugging
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug D2 Analysis",
      "type": "python",
      "request": "attach",
      "connect": {"host": "localhost", "port": 5678},
      "pathMappings": [{"localRoot": "${workspaceFolder}", "remoteRoot": "/app"}]
    },
    {
      "name": "Debug MCP Coordinator", 
      "type": "python",
      "request": "attach",
      "connect": {"host": "localhost", "port": 5679},
      "pathMappings": [{"localRoot": "${workspaceFolder}", "remoteRoot": "/app"}]
    }
  ]
}
```

#### Local Development Setup
```bash
# Run individual containers for debugging
docker-compose up dgraph-alpha redis                    # Start dependencies
docker-compose run --rm -p 5678:5678 d2-analysis bash  # Debug container
python -m debugpy --listen 0.0.0.0:5678 --wait-for-client analysis_server.py
```

### Development Workflow

#### Hot Reload Development
```bash
# Development with volume mounts for live editing
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Watch for changes and restart specific services
docker-compose restart mcp-coordinator  # After coordinator changes
docker-compose restart d2-analysis      # After analysis changes
```

#### Testing Procedures
```bash
# Container-specific tests
docker-compose run --rm d2-analysis python -m pytest tests/ -v
docker-compose run --rm analysis-engine python -m pytest tests/ -v
docker-compose run --rm mcp-coordinator python -m pytest tests/ -v

# Integration tests
docker-compose run --rm test-runner python -m pytest integration_tests/ -v

# Load testing
docker-compose run --rm load-tester python load_test.py --endpoint http://mcp-coordinator:8000
```

### Code Quality & Standards
```bash
# Code formatting
docker-compose run --rm d2-analysis black . --check
docker-compose run --rm d2-analysis isort . --check-only

# Linting
docker-compose run --rm d2-analysis flake8 .
docker-compose run --rm d2-analysis pylint src/

# Type checking  
docker-compose run --rm d2-analysis mypy src/ --strict
```

## Operational Information

### Backup and Recovery

#### Data Backup Strategy
```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup Dgraph data
docker-compose exec dgraph-alpha dgraph export -f "$BACKUP_DIR/dgraph_export"

# Backup Redis data  
docker-compose exec redis redis-cli BGSAVE
docker cp redis:/data/dump.rdb "$BACKUP_DIR/redis_dump.rdb"

# Backup analysis outputs
cp -r ./data/outputs "$BACKUP_DIR/analysis_outputs"

# Backup configurations
cp -r ./config "$BACKUP_DIR/config"
cp .env "$BACKUP_DIR/.env"
```

#### Disaster Recovery
```bash
# Stop services
docker-compose down -v

# Restore data volumes
docker volume create dgraph_data
docker volume create redis_data

# Restore from backup
docker run --rm -v dgraph_data:/dgraph -v "$BACKUP_DIR":/backup alpine \
  cp -r /backup/dgraph_export /dgraph/

docker run --rm -v redis_data:/data -v "$BACKUP_DIR":/backup alpine \
  cp /backup/redis_dump.rdb /data/dump.rdb

# Restart services
docker-compose up -d
```

### Health Check Procedures
```bash
# Comprehensive health check script
#!/bin/bash
echo "=== Platform Health Check ==="

# Container status
echo "Container Status:"
docker-compose ps

# Service health endpoints
services=("localhost:3000" "localhost:8000" "localhost:80" "localhost:8081")
for service in "${services[@]}"; do
    echo "Checking $service/health..."
    curl -f -s "http://$service/health" > /dev/null && echo "✅ $service" || echo "❌ $service"
done

# Resource usage
echo "Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Disk usage
echo "Disk Usage:"
docker system df
```

### Log Aggregation Setup
```bash
# ELK Stack integration (optional)
# Add to docker-compose.yml:
filebeat:
  image: docker.elastic.co/beats/filebeat:7.15.0
  volumes:
    - ./data/outputs/logs:/logs:ro
    - ./config/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
  environment:
    - ELASTICSEARCH_HOST=elasticsearch:9200

# Centralized logging with rsyslog
logger:
  image: rsyslog/syslog_appliance_alpine:latest  
  ports:
    - "514:514/udp"
  volumes:
    - ./data/outputs/logs:/logs
```

### Scaling Considerations

#### Horizontal Scaling
```yaml
# docker-compose.override.yml for scaling
version: '3.8'
services:
  analysis-engine:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
  
  nginx:
    depends_on:
      - analysis-engine
    volumes:
      - ./config/nginx-scaled.conf:/etc/nginx/nginx.conf:ro
```

#### Load Balancing Configuration
```nginx
# config/nginx-scaled.conf
upstream analysis_backend {
    server analysis-engine_1:8766;
    server analysis-engine_2:8766;  
    server analysis-engine_3:8766;
}

upstream coordinator_backend {
    server mcp-coordinator:8000;
}
```

## API Usage Examples

### Game State Monitoring
```bash
# Get current character information
curl -X GET "http://localhost:8765/game/character" \
  -H "Content-Type: application/json" | jq '.'

# Response example:
{
  "character": {
    "name": "TestChar",
    "class": "Necromancer", 
    "level": 45,
    "experience": 892847,
    "health": {"current": 180, "maximum": 180},
    "mana": {"current": 165, "maximum": 165},
    "stats": {
      "strength": 85,
      "dexterity": 75, 
      "vitality": 120,
      "energy": 95
    }
  },
  "timestamp": "2025-01-26T10:30:15Z"
}
```

### Memory Analysis
```bash
# Hunt for RosterUnit structure with known values
curl -X POST "http://localhost:8000/mcp/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "hunt_roster_unit",
    "arguments": {
      "known_values": {
        "szName": "Xerzes",
        "dwPartyLife": 40,
        "wLevel": 1
      }
    }
  }' | jq '.'

# Response example:
{
  "result": {
    "structure": "RosterUnit",
    "size": 132,
    "memory_address": "0x0E45AB00",
    "fields": {
      "szName": {"offset": "0x00", "value": "Xerzes", "type": "char[16]"},
      "dwUnitId": {"offset": "0x10", "value": 3, "type": "DWORD"},
      "dwPartyLife": {"offset": "0x14", "value": 40, "type": "DWORD"},
      "wLevel": {"offset": "0x20", "value": 1, "type": "WORD"},
      "dwClassId": {"offset": "0x1C", "value": 1, "type": "DWORD"}
    },
    "validation": {
      "is_valid": true,
      "confidence": "high",
      "checks_passed": ["name_match", "party_life_match", "level_match"]
    }
  },
  "execution_time": 0.125,
  "timestamp": "2025-01-26T10:30:15Z"
}

# Extract Current Player Unit structure
curl -X POST "http://localhost:8000/mcp/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "extract_player_unit",
    "arguments": {
      "include_stats": true,
      "include_position": true
    }
  }' | jq '.'

# Response example:
{
  "result": {
    "structure": "UnitAny",
    "size": 236,
    "memory_address": "0x0E45AB00",
    "fields": {
      "dwType": {"offset": "0x00", "value": 0, "type": "DWORD"},
      "dwTxtFileNo": {"offset": "0x04", "value": 1, "type": "DWORD"},
      "dwUnitId": {"offset": "0x0C", "value": 3, "type": "DWORD"},
      "wX": {"offset": "0x8C", "value": 5726, "type": "WORD"},
      "wY": {"offset": "0x8E", "value": 4539, "type": "WORD"}
    },
    "character_data": {
      "name": "Xerzes",
      "class": "Sorceress",
      "level": 1,
      "stats": {
        "strength": 10,
        "energy": 35,
        "dexterity": 25,
        "vitality": 10
      },
      "position": {"x": 5726, "y": 4539, "act": 0}
    }
  },
  "execution_time": 0.087,
  "timestamp": "2025-01-26T10:30:15Z"
}
```

### Network Traffic Analysis
```bash
# Start packet capture
curl -X POST "http://localhost:3000/capture/start" \
  -H "Content-Type: application/json" \
  -d '{"filter": "port 4000 or port 6112", "duration": 60}'

# Get traffic analysis
curl -X GET "http://localhost:3000/analysis/traffic" | jq '.'

# Response example:
{
  "analysis": {
    "total_packets": 1247,
    "protocols": {
      "tcp": 1100,
      "udp": 147
    },
    "endpoints": [
      {"ip": "198.51.100.10", "port": 4000, "packets": 856},
      {"ip": "198.51.100.11", "port": 6112, "packets": 391}
    ],
    "suspicious_activity": []
  },
  "capture_period": "60s",
  "timestamp": "2025-01-26T10:30:15Z"
}
```

### MCP Orchestration
```bash
# List available analysis tools
curl -X GET "http://localhost:8000/mcp/tools" | jq '.'

# Execute complex analysis workflow
curl -X POST "http://localhost:8000/mcp/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow": [
      {"tool": "capture_game_state", "arguments": {}},
      {"tool": "analyze_memory_patterns", "arguments": {"pattern": "inventory"}},
      {"tool": "detect_anomalies", "arguments": {"threshold": 0.8}}
    ]
  }' | jq '.'
```

### WebSocket Real-time Updates
```javascript
// JavaScript WebSocket client example
const ws = new WebSocket('ws://localhost:9000/mcp/ws');

ws.onopen = function() {
    console.log('Connected to MCP WebSocket');
    ws.send(JSON.stringify({
        type: 'subscribe',
        topics: ['game_state', 'memory_analysis', 'network_events']
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Real-time update:', data);
    
    switch(data.type) {
        case 'game_state':
            updateGameStateUI(data.payload);
            break;
        case 'memory_analysis':
            displayMemoryAnalysis(data.payload);
            break;
        case 'network_events':
            logNetworkEvent(data.payload);
            break;
    }
};
```

## Coding Conventions
- **Python**: Type hints, docstrings, error handling, Python 3.10+
- **Shell Scripts**: Executable, error checking, logging
- **Docker**: Multi-stage builds, minimal layers, security scanning
- **MCP**: Proper tool/resource registration, error handling
- **Mock Data Systems**: All analysis modules return realistic mock data for development/testing
- **Memory Analysis**: Read-only access, proper validation, container-based execution
- **Structure Hunting**: Pattern-based discovery, field-by-field validation, Dgraph storage
- **Security**: Follow best practices, never expose secrets/keys, container sandboxing

## Platform Architecture

### Multi-Service Architecture
The platform consists of 10 specialized containers with development/production configurations:
- **Load balancing**: Nginx reverse proxy with service discovery
- **Service mesh**: Proper container isolation with inter-service communication
- **Real-time events**: WebSocket support with event distribution
- **Database layer**: Dgraph graph database with Redis caching
- **AI/ML stack**: TensorFlow and scikit-learn for intelligent analysis
- **Binary analysis**: Capstone, YARA, Ghidra, and Frida integration
- **Memory forensics**: Advanced heap analysis and corruption detection
- **Automation**: Intelligent triage and workflow optimization

### Container Communication
- **MCP Protocol**: All inter-container communication uses MCP
- **Port Mapping**: d2-analysis (5900:VNC), mcp-coordinator (8000:API)
- **Shared Volumes**: `/data/outputs` for analysis results

### Development Features
- **Mock Data Systems**: Enable development without game files
- **Hot Reload**: Development containers support live code changes
- **Comprehensive Testing**: Unit, integration, and security tests
- **Cross-platform Setup**: Windows (batch/PowerShell) and Python scripts

### Security Architecture
- Multi-tier networks with security zone enforcement
- Container sandboxing and process isolation
- Encrypted data storage (Dgraph + Redis)
- Resource limits and network policies

## Enhanced Build and Development Commands

### Comprehensive Makefile Commands
```bash
# Build and Environment
make build              # Build all containers with no cache
make build-quick        # Quick build using cache
make dev               # Start development environment
make prod              # Start production environment  
make stop              # Stop all services
make restart           # Restart all services
make clean             # Clean containers and volumes
make clean-all         # Deep clean including images

# Testing and Validation
make test              # Run all tests (unit + integration)
make test-unit         # Run unit tests only
make test-integration  # Run integration tests
make test-performance  # Run performance benchmarks
make health            # Check service health

# Analysis Workflows
make analyze-sample FILE=path/to/binary    # Analyze specific file
make logs                                  # View all service logs
make logs-d2                              # View D2 analysis logs only

# Setup and Initialization
make setup             # Initial project setup
make init              # Initialize after first setup
make quickstart        # Interactive quick start guide
```

### Development Workflow
```bash
# Full platform initialization
make quickstart        # Interactive setup with health checks

# Development with hot reload
make dev
make health           # Verify all services are healthy

# Run comprehensive tests
make test             # Full test suite
make test-performance # Performance benchmarks

# Analysis workflows
make analyze-sample FILE=./samples/malware.exe
```

## Advanced Analysis Examples

### Static Binary Analysis
```bash
# Submit binary for comprehensive static analysis
curl -X POST -F "file=@sample.exe" \
  -F "analysis_depth=comprehensive" \
  http://localhost:8001/analyze/static

# Check analysis status
curl http://localhost:8001/analyze/status/12345

# Get detailed results
curl http://localhost:8001/analyze/result/12345 | jq '.'
```

### Ghidra Decompilation
```bash
# Submit for decompilation
curl -X POST -F "binary=@sample.exe" \
  -F "analysis_type=comprehensive" \
  http://localhost:8002/decompile

# Get decompiled functions
curl http://localhost:8002/decompile/result/12345 | jq '.functions'
```

### Dynamic Analysis with Frida
```bash
# Start dynamic analysis with API hooking
curl -X POST -F "binary=@sample.exe" \
  -d '{"hooks": ["CreateFileA", "WriteFile"], "timeout": 120}' \
  http://localhost:8003/analyze/dynamic

# Get runtime behavior results
curl http://localhost:8003/analyze/result/12345 | jq '.api_calls'
```

### Memory Forensics
```bash
# Create memory dump of running process
curl -X POST -H "Content-Type: application/json" \
  -d '{"pid": 1234, "include_analysis": true}' \
  http://localhost:8004/dump/create

# Analyze uploaded memory dump
curl -X POST -F "file=@memory.dump" \
  -F "analysis_depth=comprehensive" \
  http://localhost:8004/analyze/upload
```

### AI-Powered Analysis
```bash
# Intelligent threat triage
curl -X POST -H "Content-Type: application/json" \
  -d '{
    "analysis_results": {
      "file_info": {"entropy": 7.8, "size": 1048576},
      "imports": {"kernel32.dll": ["CreateRemoteThread", "WriteProcessMemory"]},
      "strings": ["malware", "encrypt", "ransom"]
    },
    "priority_override": "high"
  }' \
  http://localhost:8005/triage/intelligent

# Automated workflow optimization
curl -X POST -H "Content-Type: application/json" \
  -d '{
    "sample_info": {"file_size": 10485760, "file_type": "PE"},
    "resource_constraints": {"max_cores": 4, "max_memory_gb": 8}
  }' \
  http://localhost:8005/workflow/optimize
```

## Performance Characteristics

### Analysis Speed
- **Static Analysis**: 1-30 seconds (depending on binary size)
- **Ghidra Decompilation**: 1-10 minutes (comprehensive analysis)
- **Dynamic Analysis**: 30 seconds - 5 minutes (configurable timeout)
- **AI Triage**: 5-30 seconds (depending on complexity)
- **Memory Forensics**: 2-15 minutes (depending on dump size)

### Resource Requirements
- **Minimum**: 8GB RAM, 4 CPU cores, 50GB storage
- **Recommended**: 16GB RAM, 8 CPU cores, 100GB storage
- **Production**: 32GB RAM, 16 CPU cores, 500GB storage

### Throughput
- **Concurrent Analyses**: 5-10 (depending on hardware)
- **Daily Analysis Capacity**: 500-2000 samples
- **Storage Efficiency**: Deduplication and compression built-in

This platform is production-ready for security research, malware analysis, game mechanics analysis, and reverse engineering education. It provides comprehensive automated and semi-automated binary analysis capabilities with AI-driven intelligence.

## Current Status and Development Plans

### Completed Memory Analysis Features ✅

#### Core System Infrastructure
- **Project Reorganization**: Moved tools to `tools/memory_hunters/`, examples to `examples/memory_analysis/`
- **Documentation System**: Complete documentation in `docs/memory_analysis/` (5 files, 2000+ lines)
- **Production Tools**: 6 production-ready memory hunters with validation
- **Educational Examples**: 3 educational examples with learning objectives

#### Memory Structure Discovery
- **Static Offset Discovery**: D2Client.dll+0x11BBFC (Current Player), D2Client.dll+0x11BC14 (RosterUnit)
- **Live Memory Access**: Direct `/proc/PID/mem` reading via d2-analysis container
- **Structure Validation**: Field-by-field verification with known live values
- **Base Address Discovery**: Automated D2Client.dll base address detection via gdb

#### Database Integration
- **Dgraph Schema**: Complete graph database schema with relationships
- **Data Storage**: Live character data, memory offsets, structure definitions
- **Query System**: GraphQL queries for character stats, analysis sessions
- **Reference Data**: JSON reference files with discovered offsets and structures

#### Verified Structure Layouts
- **UnitAny Structure**: 236 bytes, 61 fields, complete field breakdown
- **RosterUnit Structure**: 132 bytes, 18 fields, party/roster data
- **PlayerData Structure**: 40 bytes, character names and quest data
- **Live Character Data**: Extracted from Level 1 Sorceress and Level 99 Druid

### Planned Memory Analysis Enhancements 🚧

#### Advanced Structure Discovery
- **StatList Structure**: Complete statistics system analysis
- **Inventory Structure**: Equipment and item data extraction
- **Skill Tree Analysis**: Character abilities and skill points
- **Area/Level Data**: Current zone and map information

#### Real-time Monitoring
- **Character Change Detection**: Monitor stat changes, level progression
- **Position Tracking**: Real-time coordinate and movement monitoring
- **Health/Mana Monitoring**: Live HP/MP changes and regeneration
- **Inventory Monitoring**: Equipment changes and item acquisition

#### Enhanced Analysis Tools
- **Pattern Learning**: AI-based structure pattern discovery
- **Multi-Character Analysis**: Analyze multiple characters simultaneously
- **Historical Tracking**: Track character progression over time
- **Anomaly Detection**: Identify unusual stat changes or impossible values

#### Security and Anti-Cheat Features
- **Impossible Stats Detection**: Flag unrealistic character attributes
- **Progression Validation**: Verify legitimate experience and level gains
- **Item Validation**: Check for impossible or duplicated items
- **Speed/Movement Analysis**: Detect movement speed anomalies

#### Cross-Platform Support
- **Windows Native**: Direct Windows memory access (non-Wine)
- **Multiple D2 Versions**: Support for different Diablo 2 versions
- **Generic Framework**: Extensible to other games and applications
- **Performance Optimization**: Faster memory scanning and analysis

### Integration Roadmap 🎯

#### MCP Protocol Enhancement
- **Memory Analysis MCP Tools**: Register all hunters as MCP tools
- **Real-time Events**: WebSocket updates for character changes
- **Batch Operations**: Efficient multi-structure analysis
- **Error Handling**: Comprehensive error reporting and recovery

#### Web Dashboard Integration
- **Live Memory View**: Real-time character data visualization
- **Structure Explorer**: Interactive memory structure browser
- **Analysis History**: View past analysis sessions and discoveries
- **Graph Visualization**: Visual representation of memory relationships

#### Development Workflow Improvements
- **Automated Testing**: Unit tests for all structure parsers
- **Performance Benchmarks**: Memory access speed optimization
- **Code Generation**: Auto-generate hunters from structure definitions
- **Documentation Sync**: Keep docs synchronized with code changes

### Known Limitations and Future Work 📋

#### Current Limitations
- **Wine Environment Only**: Currently limited to Wine/Linux containers
- **Static Offsets**: Offsets may change with game updates
- **Single Process**: Analyzes one D2 process at a time
- **Manual Validation**: Structure validation requires known values

#### Planned Solutions
- **Dynamic Offset Discovery**: Automatically find offsets after game updates
- **Multi-Process Support**: Analyze multiple D2 instances simultaneously
- **Automated Validation**: AI-based structure validation without known values
- **Native Windows Support**: Direct Windows memory access capabilities

#### Long-term Vision
- **Universal Game Analysis**: Framework for analyzing any game
- **Automated Cheat Detection**: Real-time cheat detection system
- **Community Integration**: Share discoveries with reverse engineering community
- **Research Platform**: Academic research tool for game security

### Contributing Guidelines 🤝

#### Memory Analysis Contributions
1. **New Structure Hunters**: Add hunters for undiscovered structures
2. **Documentation Updates**: Keep documentation current with code changes
3. **Performance Improvements**: Optimize memory access and parsing
4. **Cross-platform Support**: Add Windows native support
5. **Testing Coverage**: Add tests for all new functionality

#### Current Priority Areas
- **Inventory/Equipment Analysis**: High priority for completeness
- **Skill System Analysis**: Medium priority for character analysis
- **Performance Optimization**: Medium priority for scalability
- **Windows Native Support**: Low priority (Wine works well)

This comprehensive memory analysis system represents significant progress in reverse engineering automation and provides a solid foundation for advanced game analysis and security research.