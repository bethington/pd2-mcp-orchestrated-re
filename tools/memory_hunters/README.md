# Memory Hunters - Production Tools

This directory contains production-ready memory analysis tools for Project Diablo 2.

## Tools Overview

### Core Structure Hunters

#### `rosterunit_hunter.py`
Hunt for RosterUnit structures using known live game values.

**Purpose**: Extract party/roster information from memory
**Input**: Known character data (name, level, party life)
**Output**: Complete 132-byte RosterUnit structure with validation

```bash
python rosterunit_hunter.py
```

**Features**:
- Pattern-based memory scanning
- Field-by-field validation 
- Complete structure extraction
- Verification data output

#### `current_player_unit_demo.py`
Demonstrate Current Player Unit (UnitAny) structure extraction.

**Purpose**: Show how to access the main player structure
**Output**: 236-byte UnitAny structure with key fields

```bash
python current_player_unit_demo.py
```

**Features**:
- Complete UnitAny field breakdown
- Statistics system access
- Position and world context
- Pointer validation

#### `current_player_unit_full.py`
Extract complete UnitAny structure with all 61 fields.

**Purpose**: Full structure analysis and verification
**Output**: Complete field-by-field breakdown with hex dump

```bash
python current_player_unit_full.py
```

**Features**:
- All 236 bytes analyzed
- Field descriptions and meanings
- Raw memory dump
- Comprehensive validation

### Live Memory Access

#### `extract_from_container.py`
Execute memory analysis directly inside the d2-analysis container.

**Purpose**: Use container's built-in memory analyzer
**Method**: Direct container execution
**Accuracy**: Highest (native container access)

```bash
python extract_from_container.py
```

**Features**:
- Container-native execution
- Built-in memory analyzer integration
- Direct Game.exe process access
- Real-time structure validation

#### `real_live_memory.py`
Extract realistic live memory data representation.

**Purpose**: Show expected memory layout and values
**Output**: Structured memory data with realistic values

```bash
python real_live_memory.py
```

**Features**:
- Realistic memory layout
- Expected field values
- Validation examples
- Educational demonstrations

### Database Integration

#### `store_memory_data_dgraph.py`
Store discovered memory data in Dgraph graph database.

**Purpose**: Persist memory analysis results with relationships
**Storage**: Dgraph graph database
**Features**: Full relationship modeling

```bash
python store_memory_data_dgraph.py
```

**Capabilities**:
- Complete schema setup
- Memory offset storage
- Structure definition storage
- Live character data storage
- Analysis session tracking
- Graph relationship creation

**Database Schema**:
- **Modules**: D2 DLL information
- **MemoryOffsets**: Static memory offsets
- **MemoryStructures**: Structure layouts
- **Characters**: Live character data
- **AnalysisSessions**: Analysis tracking

## Usage Guidelines

### Prerequisites
- Docker containers running (d2-analysis, dgraph)
- Game.exe process active
- Proper permissions for memory access

### Basic Workflow
1. **Structure Discovery**: Use hunters to find structures
2. **Validation**: Verify extracted data matches expectations
3. **Storage**: Store discoveries in Dgraph
4. **Analysis**: Query relationships and patterns

### Advanced Usage

#### Custom Structure Hunting
Create new hunters by extending base classes:

```python
from memory_hunters.base import MemoryHunter

class CustomStructureHunter(MemoryHunter):
    def __init__(self):
        self.structure_layout = {
            "name": "CustomStructure",
            "size": 0x40,
            "fields": [...]
        }
    
    def hunt_structure(self):
        # Implement hunting logic
        pass
```

#### Live Monitoring
Set up continuous monitoring:

```python
import time
from current_player_unit_demo import CurrentPlayerUnitDemo

monitor = CurrentPlayerUnitDemo()
while True:
    data = monitor.get_live_data()
    # Process changes
    time.sleep(1)
```

### Error Handling

All tools include comprehensive error handling:
- Memory access validation
- Pointer verification
- Structure size checks
- Field value validation

### Output Formats

#### Console Output
- Progress indicators
- Field-by-field breakdowns
- Validation results
- Memory dumps (hex + ASCII)

#### File Output
- JSON reference files
- Memory dumps
- Structure definitions

#### Database Storage
- Graph relationships
- Queryable data
- Historical tracking

## Configuration

### Environment Variables
```bash
export DEBUG=1              # Enable debug output
export CONTAINER_NAME=d2-analysis  # Container name
export DGRAPH_URL=http://localhost:8081  # Dgraph endpoint
```

### Memory Offsets
Key offsets stored in `data/reference/live_memory_offsets.json`:
- Current Player Unit: `D2Client.dll+0x11BBFC`
- RosterUnit List: `D2Client.dll+0x11BC14`

## Security Considerations

### Ethical Use
- ✅ Defensive security research
- ✅ Educational purposes
- ✅ Game mechanics analysis
- ❌ Cheat development
- ❌ Online exploitation

### Memory Safety
- Read-only access
- No memory modification
- Proper error handling
- Resource cleanup

## Troubleshooting

### Common Issues

1. **Process Access Denied**
   - Run inside container
   - Check process permissions

2. **Invalid Memory Addresses**
   - Verify D2Client.dll base address
   - Recalculate offsets

3. **Structure Validation Failures**
   - Check game state (character loaded)
   - Verify known values match game

### Debug Tools
- Memory dump analysis
- Pointer validation
- Structure size verification
- Field value checking

## Contributing

When adding new tools:

1. Follow naming convention: `structure_hunter.py`
2. Include comprehensive docstrings
3. Add error handling and validation
4. Update this README
5. Add usage examples
6. Include test cases

### Code Standards
- Python 3.10+ compatibility
- Type hints for all functions
- Comprehensive error handling
- Detailed logging
- Unit tests where applicable