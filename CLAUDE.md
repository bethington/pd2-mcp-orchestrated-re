# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a container-focused platform for reverse engineering and analysis of applications, with specialized support for Project Diablo 2. The platform uses the Model Context Protocol (MCP) with Claude AI intelligence for orchestrated analysis.

## Common Development Commands

### Build and Deployment
```bash
# Build all containers
docker-compose build
make build

# Start development environment
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
make dev

# Start production environment
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
make prod

# Run tests
docker-compose run --rm analysis-engine python -m pytest tests/ -v
make test

# Clean up containers and volumes
docker-compose down -v --remove-orphans
docker system prune -f
make clean
```

### Platform-Specific Commands
```bash
# Windows users
setup.bat quickstart
setup.ps1 quickstart

# Cross-platform
python quickstart.py
```

### Health Monitoring
```bash
# Check service health
make health

# View logs
docker-compose logs -f
docker-compose logs -f d2-analysis  # D2 analysis logs only
```

## Architecture Overview

### Container-First Architecture
Each container is self-contained with its own configurations, dependencies, and code:

- **containers/d2-analysis/** - Game analysis (Wine + D2 + VNC)
- **containers/mcp-coordinator/** - MCP orchestration hub  
- **containers/analysis-engine/** - Core analysis processing
- **containers/network-monitor/** - Network packet analysis
- **containers/web-dashboard/** - Web UI and reporting

### Shared Libraries
- **shared/mcp/** - MCP protocol implementations
- **shared/analysis/** - Common analysis utilities  
- **shared/game/** - D2-specific game logic
- **shared/data/** - Data models and storage
- **shared/claude/** - AI orchestration logic

### Data Storage
- **data/pd2/** - Project Diablo 2 game files
- **data/outputs/** - Analysis results, reports, logs, memory dumps

## Key Architectural Patterns

### Multi-Service Architecture
The platform consists of 8 specialized containers with development/production configurations:
- Load balancing via Nginx reverse proxy
- Service mesh with proper isolation
- Real-time event distribution system with WebSocket support
- Dgraph graph database with Redis caching layer

### Container Communication
- **MCP Protocol**: All inter-container communication uses MCP
- **Port Mapping**: d2-analysis (5900:VNC), mcp-coordinator (8000:API)
- **Shared Volumes**: `/data/outputs` for analysis results

### Service Endpoints
- **VNC Access**: `vnc://localhost:5900` (Direct game view)
- **Web Dashboard**: `http://localhost:80` (Analysis interface)
- **MCP Coordinator**: `http://localhost:8000` (API and orchestration)
- **Dgraph UI**: `http://localhost:8081` (Database management)
- **Jupyter Lab**: `http://localhost:8888` (Analysis notebooks)

## Development Patterns

### File Organization Rules
1. **Container-Specific**: Each container owns its configs/scripts in `containers/<name>/`
2. **Shared Code**: Common utilities go in `shared/` directory
3. **Runtime Data**: All outputs and game files in `data/` directory
4. **No Config Mixing**: Container configs stay with their respective containers

### Coding Conventions
- **Python**: Type hints, docstrings, error handling, Python 3.10+
- **Shell Scripts**: Executable, error checking, logging
- **Docker**: Multi-stage builds, minimal layers, security scanning
- **MCP**: Proper tool/resource registration, error handling

### Mock Data Systems
All analysis modules return realistic mock data to enable development and testing without game files. This should be replaced with live game data once Project Diablo 2 files are available.

## Testing and Validation

The project includes comprehensive validation:
- Service health checks and status reporting
- Cross-platform setup with system checks
- Example workflows and usage patterns
- Complete analysis examples in `examples/` directory

## Security and Analysis Features

### Analysis Capabilities
- **Real-time Character Monitoring**: Stats, level, experience, inventory
- **Memory Structure Analysis**: Game state, network buffers, heap analysis  
- **Network Protocol Analysis**: Packet capture, protocol reverse engineering
- **Behavioral Analysis**: Player pattern detection, anomaly identification
- **Security Research**: Cheat detection, exploit identification, vulnerability research

### Security Architecture
- Multi-tier networks with security zone enforcement
- Container sandboxing and process isolation
- Encrypted data storage (Dgraph + Redis)
- Resource limits and network policies

This platform is production-ready for security research, game mechanics analysis, and reverse engineering education.