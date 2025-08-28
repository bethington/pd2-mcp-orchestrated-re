# Advanced Reverse Engineering Platform

A comprehensive, container-first platform for reverse engineering and malware analysis with specialized support for Project Diablo 2. Features AI-driven automation, multi-tool orchestration, and advanced binary analysis capabilities.

## 🎯 Overview

This platform provides:
- **Advanced Static Analysis** with Capstone, YARA, and multi-format binary parsing
- **Professional Decompilation** using Ghidra headless analyzer
- **Memory Forensics** with heap analysis and corruption detection
- **AI-Powered Classification** using ML models for threat detection
- **Intelligent Triage** with automated prioritization and workflow optimization
- **Live game analysis** with containerized Diablo 2 environment
- **MCP-orchestrated tool coordination** for adaptive analysis
- **Real-time monitoring** of character stats, inventory, and behavior

## 🐳 Container-First Architecture (10 Specialized Services)

Each container is self-contained with its own configurations, dependencies, and code:

```text
containers/
├── d2-analysis/        🎮 Game analysis (Wine + D2 + VNC)
├── mcp-coordinator/    🧠 MCP orchestration hub  
├── analysis-engine/    ⚙️ Core binary analysis (Capstone, YARA, PE/ELF parsing)
├── ghidra-analysis/    🔍 Professional decompilation service
├── memory-forensics/   🧠 Advanced memory analysis and heap forensics
├── ai-analysis/        🤖 ML-driven triage and threat classification
├── network-monitor/    🌐 Network packet analysis
└── web-dashboard/      📊 Web UI and reporting

shared/                 📚 Common libraries used across containers
├── mcp/               # MCP protocol implementations
├── analysis/          # Common analysis utilities  
├── game/              # D2-specific game logic
├── data/              # Data models and storage
└── claude/            # AI orchestration logic
```

### Service Architecture Diagram
```
                        ┌─────────────────────────────────┐
                        │        Claude AI Assistant      │
                        │      (External Interface)       │
                        └─────────────────┬───────────────┘
                                          │
                        ┌─────────────────▼───────────────┐
                        │       MCP Coordinator           │
                        │    (Ports 8000/9000)           │
                        │   Orchestration & WebSocket     │
                        └─────────────────┬───────────────┘
                                          │
                ┌─────────────────────────┼─────────────────────────┐
                │                         │                         │
        ┌───────▼───────┐       ┌─────────▼─────────┐      ┌────────▼────────┐
        │ D2 Analysis   │       │  Analysis Engine  │      │ Memory Analysis │
        │ (Wine + VNC)  │       │  Static/Dynamic   │      │ Live Structures │
        │ 5900/8765/3000│       │    (Port 8001)    │      │  Hunt & Validate│
        └───────┬───────┘       └─────────┬─────────┘      └────────┬────────┘
                │                         │                         │
        ┌───────▼───────┐                 │                         │
        │  noVNC Proxy  │                 │                         │
        │  (Port 5901)  │                 │                         │
        └───────────────┘                 │                         │
                │                         │                         │
                └─────────────────────────┼─────────────────────────┘
                                          │
        ┌─────────────────────────────────┼─────────────────────────────────┐
        │                                 │                                 │
┌───────▼───────┐  ┌──────────────────────▼──────┐  ┌───────────────────────▼──┐
│ Specialized   │  │    Infrastructure           │  │   Data & Storage         │
│ Services      │  │    Services                 │  │   Layer                  │
├───────────────┤  ├─────────────────────────────┤  ├──────────────────────────┤
│ Ghidra :8002  │  │ Web Dashboard :80/443       │  │ Dgraph Database :8081    │
│ Memory :8004  │  │ Nginx Proxy   :8090         │  │ Redis Cache     :6379    │
│ AI/ML  :8005  │  │ Network Monitor (shared)    │  │ Game Files      (volume) │
└───────────────┘  └─────────────────────────────┘  └──────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Project Diablo 2 game files
- 8GB+ RAM recommended
- Windows/Linux host system

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd pd2-mcp-orchestrated-re
```

2. **Setup game files:**
```bash
make setup-game-files
# Copy your PD2 files to data/game_files/pd2/
```

3. **Build and start the platform:**
```bash
make build
make dev
```

4. **Verify deployment:**
```bash
make health
```

### Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| Web Dashboard | http://localhost:80 | Main analysis interface |
| MCP Coordinator | http://localhost:8000 | API orchestration |
| Analysis Engine | http://localhost:8001 | Static binary analysis |
| Ghidra Analysis | http://localhost:8002 | Decompilation service |
| Memory Forensics | http://localhost:8004 | Memory analysis |
| AI Analysis | http://localhost:8005 | ML-driven analysis |
| VNC (Game) | vnc://localhost:5900 | Direct game view |
| Dgraph UI | http://localhost:8081 | Database interface |

## 📊 Usage Examples

### Basic Binary Analysis
```bash
# Analyze a binary sample
make analyze-sample FILE=./samples/malware.exe

# Quick basic analysis
curl -X POST -F "file=@sample.exe" \
  http://localhost:8001/analyze/static?analysis_depth=comprehensive
```

### AI-Powered Triage
```bash
# Submit for intelligent triage
curl -X POST -H "Content-Type: application/json" \
  -d '{"analysis_results": {...}, "priority_override": "high"}' \
  http://localhost:8005/triage/intelligent
```

### Memory Forensics
```bash
# Create memory dump of process
curl -X POST -H "Content-Type: application/json" \
  -d '{"pid": 1234, "include_analysis": true}' \
  http://localhost:8004/dump/create
```

### Ghidra Decompilation
```bash
# Decompile binary
curl -X POST -F "binary=@sample.exe" \
  -F "analysis_type=comprehensive" \
  http://localhost:8002/decompile
```

### Game Character Monitoring
```python
from src.game.d2.character_tracker import CharacterTracker

tracker = CharacterTracker()
stats = await tracker.get_current_stats()
print(f"Character Level: {stats['level']}")
```

## 🔧 Configuration

### Environment Variables
```bash
# Container Configuration
SESSION_ID=my_analysis_session
AUTO_START_GAME=true
DEBUG=false

# Analysis Settings  
MONITORING_INTERVAL=1000
SECURITY_SCAN_INTERVAL=60000
```

### Game Files Structure
Your PD2 installation should match this structure in `data/game_files/pd2/`:
```
ProjectD2/
├── Game.exe                 # Main executable
├── D2Client.dll            # Core game libraries
├── ProjectDiablo.dll       # PD2 modifications  
├── pd2data.mpq            # Game data archives
└── ...                    # (See copilot-instructions.md for complete listing)
```

## 🛡️ Security Features

- **Cheat Detection:** Real-time monitoring for impossible stats/items
- **Memory Analysis:** Pattern recognition and anomaly detection
- **Network Analysis:** Protocol validation and exploit detection  
- **Behavioral Analysis:** Player action pattern analysis
- **Audit Logging:** Complete activity tracking and reporting

## 📈 Analysis Capabilities

### Character Analysis
- Real-time stat monitoring
- Progression anomaly detection
- Attribute validation
- Experience gain pattern analysis

### Inventory Analysis  
- Item acquisition tracking
- Value anomaly detection
- Duplication detection
- Impossible item identification

### Memory Analysis
- Live memory dumps
- Structure integrity validation
- Pattern recognition across snapshots
- Vulnerability identification

### Network Analysis
- Packet capture and analysis
- Protocol compliance checking
- Traffic pattern analysis
- Exploit attempt detection

## 🤖 Claude AI Integration

The platform leverages Claude AI for:
- **Adaptive Analysis:** Dynamically adjusting analysis based on findings
- **Pattern Recognition:** Identifying complex behavioral patterns  
- **Report Generation:** Creating comprehensive, actionable reports
- **Anomaly Correlation:** Connecting seemingly unrelated events
- **Recommendation Engine:** Suggesting follow-up analysis

## 🔨 Development

### Adding New Analysis Modules
1. Create module in `src/analysis/`
2. Register with MCP Coordinator
3. Implement MCP server interface
4. Add to Claude orchestration logic

### Container Development
```bash
# Start development environment
make dev

# View logs
make logs-d2

# Rebuild specific container
docker-compose build d2-analysis
```

### Testing
```bash
make test
```

## 🧠 Memory Analysis System

The platform includes a comprehensive memory analysis system for reverse engineering Project Diablo 2:

### Features
- **Live Memory Reading**: Direct extraction from running Game.exe processes
- **Structure Discovery**: Automated hunting for game structures (RosterUnit, UnitAny, PlayerData)
- **Static Offset Discovery**: Finding stable memory offsets like `D2Client.dll+0x11BBFC`
- **Graph Database Storage**: Complete relationship modeling in Dgraph
- **Real-time Validation**: Field-by-field verification of extracted structures

### Quick Start
```bash
# Hunt for RosterUnit structure with known values
python tools/memory_hunters/rosterunit_hunter.py

# Extract current player data
python tools/memory_hunters/current_player_unit_demo.py

# Store discoveries in graph database
python tools/memory_hunters/store_memory_data_dgraph.py
```

### Discovered Structures
| Structure | Size | Offset | Description |
|-----------|------|--------|-------------|
| UnitAny (Current Player) | 236 bytes | D2Client.dll+0x11BBFC | Main player structure |
| RosterUnit (Party Data) | 132 bytes | D2Client.dll+0x11BC14 | Party/roster information |
| PlayerData | 40 bytes | Via UnitAny+0x14 | Character name, quests, waypoints |

### Documentation
- **[Memory Analysis Documentation](docs/memory_analysis/README.md)** - Complete guide and API reference
- **[Usage Guide](docs/memory_analysis/usage_guide.md)** - Step-by-step instructions
- **[Development Guide](docs/memory_analysis/development_guide.md)** - Extending the system
- **[Troubleshooting](docs/memory_analysis/troubleshooting.md)** - Common issues and solutions

## 📚 Directory Structure

### Core Platform
- `src/core/` - Session management, event bus, coordination
- `src/game/d2/` - Diablo 2 specific analysis modules
- `src/analysis/` - Memory, network, behavioral analysis
- `claude/` - AI orchestration and intelligent analysis
- `containers/` - Docker containers for each service

### Memory Analysis System
- `tools/memory_hunters/` - Production memory analysis tools
- `examples/memory_analysis/` - Educational examples and demonstrations
- `docs/memory_analysis/` - Complete documentation and guides
- `data/reference/` - Structure definitions and discovered offsets

### Configuration & Data
- `config/` - Platform configuration and schemas
- `data/pd2/` - Project Diablo 2 game files
- `data/outputs/` - Analysis results, reports, logs, memory dumps
- `examples/` - Usage examples and demonstrations

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-analysis`)
3. Commit changes (`git commit -m 'Add amazing analysis'`)
4. Push to branch (`git push origin feature/amazing-analysis`)
5. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This platform is for educational and research purposes only. Ensure compliance with applicable terms of service and local laws when analyzing software.

## 🆘 Support

- **Issues:** [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions:** [GitHub Discussions](https://github.com/your-repo/discussions)
- **Documentation:** [.github/copilot-instructions.md](/.github/copilot-instructions.md)

---

**Built with ❤️ for the reverse engineering community**
