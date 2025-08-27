# Memory Analysis Documentation

This directory contains comprehensive documentation for the D2 memory analysis capabilities of the PD2 MCP Orchestrated RE platform.

## Overview

The memory analysis system provides real-time extraction and analysis of Project Diablo 2 game structures from running processes. It supports both static analysis and live memory reading with graph database storage.

## Key Features

- **Live Memory Reading**: Direct extraction from running Game.exe processes
- **Structure Validation**: Field-by-field verification of game structures  
- **Graph Database Integration**: Storage and relationship modeling in Dgraph
- **Cross-Platform Support**: Works in Wine/Linux container environments
- **Real-Time Monitoring**: Continuous tracking of character stats and positions

## Architecture

```
Memory Analysis System
├── Tools (tools/memory_hunters/)
│   ├── Core Hunters - Production memory analysis tools
│   ├── Container Integration - Docker/Wine memory access
│   └── Database Storage - Dgraph integration
├── Examples (examples/memory_analysis/)
│   ├── Demonstrations - Educational examples
│   ├── Live Extraction - Real-time examples
│   └── Validation - Testing and verification
└── Documentation (docs/memory_analysis/)
    ├── API Reference - Function documentation
    ├── Structure Layouts - Memory maps and offsets
    └── Usage Guides - How-to instructions
```

## Quick Start

1. **Start the platform**:
   ```bash
   docker-compose up -d
   ```

2. **Run a basic memory hunt**:
   ```bash
   python tools/memory_hunters/rosterunit_hunter.py
   ```

3. **View results in Dgraph**:
   - Open http://localhost:8081/ 
   - Query: `{ characters(func: type(Character)) { char.name char.class } }`

## Documentation Files

- [**API Reference**](api_reference.md) - Complete function and class documentation
- [**Memory Structures**](memory_structures.md) - D2 structure layouts and offsets  
- [**Usage Guide**](usage_guide.md) - Step-by-step instructions
- [**Development Guide**](development_guide.md) - Extending the system
- [**Troubleshooting**](troubleshooting.md) - Common issues and solutions

### Quick Navigation

- **Getting Started**: [Usage Guide](usage_guide.md) → [Memory Structures](memory_structures.md)
- **Development**: [Development Guide](development_guide.md) → [API Reference](api_reference.md)
- **Issues**: [Troubleshooting](troubleshooting.md) → [Usage Guide](usage_guide.md)

## Discovered Memory Offsets

| Structure | Offset | Address | Description |
|-----------|---------|---------|-------------|
| Current Player Unit | D2Client.dll+0x11BBFC | UnitAny* | Main player structure (236 bytes) |
| RosterUnit List | D2Client.dll+0x11BC14 | RosterUnit* | Party/roster data (132 bytes) |
| D2Client Base | 0x6FAB0000 | Module | Base address (Wine environment) |

## Live Data Examples

### Character Data Extracted
- **Level 1 Sorceress "Xerzes"**: STR=10, ENE=35, DEX=25, VIT=10
- **Level 99 Druid "Druid"**: STR=27, ENE=20, DEX=28, VIT=25
- **Real Memory Addresses**: 0x0E45AB00, 0x0E447D00
- **Live Positions**: World coordinates and act information

## Security and Ethics

This platform is designed for:
- ✅ **Defensive Security Research** - Game security analysis
- ✅ **Educational Purposes** - Learning reverse engineering
- ✅ **Game Mechanics Study** - Understanding D2 internals
- ✅ **Anti-Cheat Development** - Detecting unauthorized modifications

**Not intended for**:
- ❌ Creating game cheats or hacks
- ❌ Circumventing anti-cheat systems
- ❌ Exploiting online gameplay
- ❌ Commercial cheat development

## Contributing

When adding new memory analysis capabilities:

1. Follow the established directory structure
2. Include comprehensive documentation
3. Add validation and testing
4. Update the reference files
5. Store discoveries in Dgraph

## Support

For technical support:
- Review the [Troubleshooting Guide](troubleshooting.md)
- Check existing GitHub issues
- Create detailed bug reports with logs