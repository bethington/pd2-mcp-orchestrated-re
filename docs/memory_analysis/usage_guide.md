# Memory Analysis Usage Guide

This guide provides step-by-step instructions for using the D2 memory analysis tools.

## Prerequisites

### System Requirements
- Docker and Docker Compose
- Python 3.10+ (for local scripts)
- At least 4GB RAM
- 10GB free disk space

### Platform Setup
1. **Clone and start the platform**:
   ```bash
   cd pd2-mcp-orchestrated-re
   docker-compose up -d
   ```

2. **Verify services are running**:
   ```bash
   docker-compose ps
   ```
   
   Expected services:
   - `d2-analysis` (D2 game and analysis)
   - `dgraph-alpha` (Graph database)
   - `dgraph-zero` (Graph database coordinator)

3. **Check D2 game is running**:
   ```bash
   docker exec d2-analysis ps aux | grep Game.exe
   ```

## Basic Usage

### 1. Hunt for RosterUnit Structure

The RosterUnit hunter finds party/roster information using known live values.

```bash
# Run the RosterUnit hunter
python tools/memory_hunters/rosterunit_hunter.py
```

**Expected output**:
```
TARGET: ROSTERUNIT MEMORY HUNTING - LIVE GAME DATA
============================================================

Target Structure: RosterUnit
   Size: 132 bytes (0x84)
   Fields: 18

Known Live Values:
   szName = 'Xerzes'
   dwPartyLife = 40
   wLevel = 1

PHASE 1: Generate Memory Signatures
--------------------------------------------------
  • Generated 'name_signature': Player name 'Xerzes' at offset 0x00
  • Generated 'party_life_signature': Party life 40 at offset 0x14
  • Generated 'level_signature': Level 1 at offset 0x20
```

### 2. Extract Current Player Unit

The Current Player Unit extractor gets the main player structure.

```bash
# Run the Current Player Unit demo
python tools/memory_hunters/current_player_unit_demo.py
```

This will show:
- Complete UnitAny structure (236 bytes)
- Live character statistics
- World position data
- Memory addresses and pointers

### 3. Live Memory Extraction

Extract real data from the running D2 process:

```bash
# Run live memory extraction
python examples/memory_analysis/live_memory_extractor.py
```

This connects to the d2-analysis container and reads actual game memory.

## Advanced Usage

### Store Data in Graph Database

Store discoveries in Dgraph for relationship analysis:

```bash
# Store memory data in Dgraph
python tools/memory_hunters/store_memory_data_dgraph.py
```

**Verify storage**:
1. Open Dgraph UI: http://localhost:8081/
2. Run query:
   ```graphql
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

### Container-Based Extraction

Run memory analysis directly inside the container:

```bash
# Extract using container's memory analyzer
python tools/memory_hunters/extract_from_container.py
```

This method:
- Executes analysis inside the d2-analysis container
- Uses the container's built-in memory analyzer
- Provides the most accurate results

### PlayerData Analysis

Analyze player-specific data (name, quests, waypoints):

```bash
# Run PlayerData hunting demo
python examples/memory_analysis/demo_playerdata_hunt.py
```

## Working with Live Data

### Reading Real Game Memory

To read actual memory from a running D2 process:

1. **Ensure Game.exe is running**:
   ```bash
   docker exec d2-analysis ps aux | grep Game.exe
   ```

2. **Find D2Client.dll base address**:
   ```bash
   docker exec d2-analysis gdb -p $(docker exec d2-analysis pgrep Game.exe) -batch -ex "info proc mappings" | grep d2client
   ```

3. **Calculate target addresses**:
   - Current Player Unit: `D2Client.dll base + 0x11BBFC`
   - RosterUnit List: `D2Client.dll base + 0x11BC14`

4. **Extract structures**:
   ```python
   # Example Python code for direct memory access
   import struct
   
   d2client_base = 0x6FAB0000  # From gdb output
   player_unit_addr = d2client_base + 0x11BBFC
   
   with open('/proc/14/mem', 'rb') as mem:
       mem.seek(player_unit_addr)
       unit_ptr_bytes = mem.read(4)
       unit_ptr = struct.unpack('<L', unit_ptr_bytes)[0]
       
       # Read UnitAny structure
       mem.seek(unit_ptr)
       unit_data = mem.read(236)
       
       # Parse fields
       dwType = struct.unpack('<L', unit_data[0x00:0x04])[0]
       dwTxtFileNo = struct.unpack('<L', unit_data[0x04:0x08])[0]
       # ... continue parsing
   ```

### Validating Extracted Data

Always validate extracted data:

1. **Check unit type**: Should be 0 for players
2. **Verify class ID**: Should be 0-6 for valid classes
3. **Validate pointers**: Should point to reasonable memory addresses
4. **Check coordinates**: Should be within valid map bounds
5. **Verify stats**: Should match expected ranges for character level

## Common Workflows

### Workflow 1: Character Analysis

1. Run RosterUnit hunter to find basic character info
2. Extract Current Player Unit for detailed data
3. Store results in Dgraph for analysis
4. Query relationships between characters and sessions

### Workflow 2: Real-time Monitoring

1. Set up continuous extraction loop
2. Monitor character stat changes
3. Track position movements
4. Alert on significant changes

### Workflow 3: Structure Discovery

1. Use pattern scanning to find new structures
2. Validate field layouts and sizes
3. Cross-reference with existing structures
4. Document discoveries in reference files

## Output Formats

### Console Output
All tools provide detailed console output with:
- Progress indicators
- Field-by-field breakdowns
- Validation results
- Memory dumps (hex + ASCII)

### JSON Reference Files
Results stored in `data/reference/live_memory_offsets.json`:
- Static memory offsets
- Structure layouts
- Field definitions
- Live example data

### Graph Database
Structured data in Dgraph with:
- Memory offsets and relationships
- Character data with stats
- Analysis sessions and timestamps
- Cross-references between structures

## Troubleshooting

### Common Issues

1. **"Process not found" error**:
   - Verify Game.exe is running: `docker exec d2-analysis ps aux | grep Game`
   - Restart d2-analysis container: `docker-compose restart d2-analysis`

2. **"Permission denied" on memory access**:
   - Ensure running inside container or with proper permissions
   - Use container-based extraction methods

3. **"Invalid memory address" errors**:
   - Verify D2Client.dll base address has not changed
   - Recalculate absolute addresses from current base

4. **Unicode encoding errors**:
   - Set environment: `export PYTHONIOENCODING=utf-8`
   - Use container-based scripts which handle encoding properly

5. **Dgraph connection failed**:
   - Start Dgraph services: `docker-compose up -d dgraph-alpha dgraph-zero`
   - Wait for services to initialize (30 seconds)

### Debug Mode

Enable verbose output for debugging:

```bash
# Set debug environment variable
export DEBUG=1

# Run tools with debug output
python tools/memory_hunters/rosterunit_hunter.py
```

### Getting Help

1. Check the [Troubleshooting Guide](troubleshooting.md)
2. Review container logs: `docker-compose logs d2-analysis`
3. Verify service health: `curl http://localhost:8081/health`
4. Create GitHub issues with:
   - Complete error messages
   - System information
   - Steps to reproduce

## Best Practices

### Security
- Only use for defensive security research
- Do not modify game memory
- Respect intellectual property rights
- Follow ethical disclosure practices

### Performance
- Limit memory reading frequency
- Cache results when possible
- Use efficient data structures
- Monitor resource usage

### Documentation
- Document all discoveries
- Update reference files
- Add validation tests
- Include example usage

### Version Control
- Commit working discoveries
- Tag stable versions
- Document breaking changes
- Maintain backwards compatibility