# Memory Analysis API Reference

This document provides comprehensive API documentation for the memory analysis system.

## Core Classes

### MemoryHunter Base Class

Base class for all memory structure hunting tools.

```python
class MemoryHunter:
    def __init__(self):
        self.container_name = "d2-analysis"
        self.base_address = None
        self.process_id = None
    
    def find_process(self) -> int:
        """Find the Game.exe process ID"""
        
    def get_base_address(self, module_name: str) -> int:
        """Get base address for specified module"""
        
    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from specified address"""
        
    def validate_structure(self, data: bytes) -> dict:
        """Validate extracted structure data"""
```

### RosterUnitHunter

Hunts for RosterUnit structures containing party information.

```python
class RosterUnitHunter(MemoryHunter):
    def __init__(self):
        super().__init__()
        self.structure_size = 132  # 0x84 bytes
        self.target_values = {
            "szName": "Xerzes",
            "dwPartyLife": 40,
            "wLevel": 1
        }
    
    def hunt_structure(self) -> dict:
        """Hunt for RosterUnit structure with known values"""
        
    def parse_roster_unit(self, data: bytes) -> dict:
        """Parse RosterUnit structure from raw memory"""
        
    def validate_roster_data(self, roster_data: dict) -> bool:
        """Validate extracted roster data"""
```

#### Methods

##### `hunt_structure() -> dict`

Searches for RosterUnit structures using known live values.

**Returns:**
- `dict`: Complete structure data with validation results

**Example:**
```python
hunter = RosterUnitHunter()
result = hunter.hunt_structure()
print(f"Found at: {result['memory_address']}")
print(f"Player: {result['data']['szName']}")
```

##### `parse_roster_unit(data: bytes) -> dict`

Parses raw memory bytes into RosterUnit field structure.

**Parameters:**
- `data` (bytes): 132 bytes of raw memory data

**Returns:**
- `dict`: Parsed field values with names and offsets

**Field Layout:**
```python
{
    'szName': (0x00, 16, 'char[16]'),       # Player name
    'dwUnitId': (0x10, 4, 'DWORD'),        # Unit identifier
    'dwPartyLife': (0x14, 4, 'DWORD'),     # Party life %
    'dwClassId': (0x1C, 4, 'DWORD'),       # Character class
    'wLevel': (0x20, 2, 'WORD'),           # Character level
    'wPartyId': (0x22, 2, 'WORD'),         # Party ID
    'dwLevelId': (0x24, 4, 'DWORD'),       # Area/level ID
    'Xpos': (0x28, 4, 'DWORD'),            # X position
    'Ypos': (0x2C, 4, 'DWORD'),            # Y position
    'dwPartyFlags': (0x30, 4, 'DWORD'),    # Party flags
    'pNext': (0x80, 4, 'RosterUnit*')      # Next unit pointer
}
```

### CurrentPlayerUnitDemo

Demonstrates extraction of UnitAny (Current Player Unit) structures.

```python
class CurrentPlayerUnitDemo(MemoryHunter):
    def __init__(self):
        super().__init__()
        self.structure_size = 236  # 0xEC bytes
        self.static_offset = 0x11BBFC  # D2Client.dll offset
    
    def extract_unit_any(self) -> dict:
        """Extract Current Player Unit structure"""
        
    def get_character_stats(self) -> dict:
        """Get character statistics from UnitAny"""
        
    def get_position(self) -> tuple:
        """Get character world coordinates"""
```

#### Methods

##### `extract_unit_any() -> dict`

Extracts the complete UnitAny structure for the current player.

**Returns:**
- `dict`: Complete UnitAny data with all 61 fields

**Key Fields:**
```python
{
    'dwType': 0,                    # Unit type (0=Player)
    'dwTxtFileNo': 1,              # Character class ID
    'dwUnitId': 3,                 # Unique identifier
    'pPlayerData': 0x0E447D14,     # Player data pointer
    'dwAct': 0,                    # Current act
    'pStats': 0x0E447D38,          # Statistics pointer
    'wX': 5726,                    # World X coordinate
    'wY': 4539,                    # World Y coordinate
    'dwFlags': 0x80000080,         # Unit flags
    'dwFlags2': 0x00000008         # Extended flags
}
```

##### `get_character_stats() -> dict`

Retrieves character statistics from the StatList structure.

**Returns:**
- `dict`: Character stats with readable names

**Example Output:**
```python
{
    'strength': 10,
    'energy': 35,
    'dexterity': 25,
    'vitality': 10,
    'hitpoints': 45,
    'mana': 50,
    'level': 1,
    'experience': 0
}
```

### LiveMemoryExtractor

Extracts memory data directly from the d2-analysis container.

```python
class LiveMemoryExtractor:
    def __init__(self):
        self.container_name = "d2-analysis"
        self.api_endpoint = "http://localhost:3001"
    
    def connect_to_container(self) -> bool:
        """Establish connection to analysis container"""
        
    def execute_memory_analysis(self) -> dict:
        """Execute memory analysis inside container"""
        
    def read_proc_memory(self, pid: int, address: int, size: int) -> bytes:
        """Direct /proc/PID/mem reading"""
```

#### Methods

##### `execute_memory_analysis() -> dict`

Executes complete memory analysis workflow inside the container.

**Returns:**
- `dict`: Analysis results with discovered structures

**Workflow:**
1. Find Game.exe process
2. Locate D2Client.dll base address
3. Calculate absolute addresses from static offsets
4. Read memory structures
5. Validate and parse data

##### `read_proc_memory(pid: int, address: int, size: int) -> bytes`

Directly reads from /proc/PID/mem for live memory access.

**Parameters:**
- `pid` (int): Process ID of Game.exe
- `address` (int): Memory address to read from
- `size` (int): Number of bytes to read

**Returns:**
- `bytes`: Raw memory data

**Example:**
```python
extractor = LiveMemoryExtractor()
pid = 14  # Game.exe process ID
address = 0x6FAB0000 + 0x11BBFC  # D2Client + offset
data = extractor.read_proc_memory(pid, address, 4)  # Read pointer
```

## Database Integration

### DgraphStorage

Handles storage and retrieval of memory analysis data in Dgraph.

```python
class DgraphStorage:
    def __init__(self, dgraph_url: str = "http://localhost:8080"):
        self.client = None
        self.dgraph_url = dgraph_url
    
    def setup_schema(self) -> bool:
        """Initialize Dgraph schema for memory data"""
        
    def store_memory_offset(self, offset_data: dict) -> str:
        """Store memory offset in database"""
        
    def store_character_data(self, char_data: dict) -> str:
        """Store character data with relationships"""
        
    def query_characters(self) -> list:
        """Query all stored characters"""
```

#### Schema Types

##### Module
```graphql
type Module {
    module.name: string @index(exact) .
    module.base_address: string .
    module.size: int .
    module.path: string .
}
```

##### MemoryOffset
```graphql
type MemoryOffset {
    offset.name: string @index(exact) .
    offset.address: string .
    offset.module: uid @reverse .
    offset.description: string .
    offset.data_type: string .
}
```

##### Character
```graphql
type Character {
    char.name: string @index(exact) .
    char.class: string .
    char.level: int .
    char.memory_address: string .
    char.stats: uid @reverse .
    char.position: uid @reverse .
    char.analysis_session: uid @reverse .
}
```

#### Methods

##### `setup_schema() -> bool`

Initializes complete Dgraph schema for memory analysis data.

**Returns:**
- `bool`: True if schema setup successful

**Schema Includes:**
- Module definitions (D2Client.dll, etc.)
- Memory offsets and static addresses
- Character data with statistics
- Analysis sessions and timestamps
- Graph relationships between entities

##### `store_character_data(char_data: dict) -> str`

Stores complete character data with relationships.

**Parameters:**
- `char_data` (dict): Character data with stats and position

**Returns:**
- `str`: Dgraph UID of created character node

**Example:**
```python
storage = DgraphStorage()
char_data = {
    'name': 'Xerzes',
    'class': 'Sorceress',
    'level': 1,
    'memory_address': '0x0E45AB00',
    'stats': {
        'strength': 10,
        'energy': 35,
        'dexterity': 25,
        'vitality': 10
    },
    'position': {'x': 5726, 'y': 4539, 'act': 0}
}
uid = storage.store_character_data(char_data)
```

## Memory Structure Definitions

### Static Offsets

#### D2Client.dll Offsets
```python
STATIC_OFFSETS = {
    "D2Client.dll": {
        "base_address": "0x6FAB0000",  # Wine environment
        "offsets": {
            "current_player_unit": 0x11BBFC,  # UnitAny*
            "rosterunit_list": 0x11BC14,      # RosterUnit*
        }
    }
}
```

### Structure Layouts

#### UnitAny Structure (236 bytes)
```python
UNITANY_LAYOUT = {
    "size": 0xEC,
    "fields": [
        {"name": "dwType", "offset": 0x00, "size": 4, "type": "DWORD"},
        {"name": "dwTxtFileNo", "offset": 0x04, "size": 4, "type": "DWORD"},
        {"name": "dwUnitId", "offset": 0x0C, "size": 4, "type": "DWORD"},
        {"name": "dwMode", "offset": 0x10, "size": 4, "type": "DWORD"},
        {"name": "pPlayerData", "offset": 0x14, "size": 4, "type": "PlayerData*"},
        {"name": "dwAct", "offset": 0x18, "size": 4, "type": "DWORD"},
        {"name": "pStats", "offset": 0x5C, "size": 4, "type": "StatList*"},
        {"name": "wX", "offset": 0x8C, "size": 2, "type": "WORD"},
        {"name": "wY", "offset": 0x8E, "size": 2, "type": "WORD"},
        {"name": "pInfo", "offset": 0xA8, "size": 4, "type": "Info*"},
        {"name": "dwFlags", "offset": 0xC4, "size": 4, "type": "DWORD"},
        {"name": "dwFlags2", "offset": 0xC8, "size": 4, "type": "DWORD"},
    ]
}
```

#### RosterUnit Structure (132 bytes)
```python
ROSTERUNIT_LAYOUT = {
    "size": 0x84,
    "fields": [
        {"name": "szName", "offset": 0x00, "size": 16, "type": "char[16]"},
        {"name": "dwUnitId", "offset": 0x10, "size": 4, "type": "DWORD"},
        {"name": "dwPartyLife", "offset": 0x14, "size": 4, "type": "DWORD"},
        {"name": "dwClassId", "offset": 0x1C, "size": 4, "type": "DWORD"},
        {"name": "wLevel", "offset": 0x20, "size": 2, "type": "WORD"},
        {"name": "wPartyId", "offset": 0x22, "size": 2, "type": "WORD"},
        {"name": "dwLevelId", "offset": 0x24, "size": 4, "type": "DWORD"},
        {"name": "Xpos", "offset": 0x28, "size": 4, "type": "DWORD"},
        {"name": "Ypos", "offset": 0x2C, "size": 4, "type": "DWORD"},
        {"name": "dwPartyFlags", "offset": 0x30, "size": 4, "type": "DWORD"},
        {"name": "pNext", "offset": 0x80, "size": 4, "type": "RosterUnit*"}
    ]
}
```

## Utility Functions

### Memory Reading Utilities

```python
def read_dword(address: int) -> int:
    """Read DWORD (4 bytes) from memory address"""
    with open('/proc/PID/mem', 'rb') as mem:
        mem.seek(address)
        data = mem.read(4)
        return struct.unpack('<L', data)[0]

def read_word(address: int) -> int:
    """Read WORD (2 bytes) from memory address"""
    with open('/proc/PID/mem', 'rb') as mem:
        mem.seek(address)
        data = mem.read(2)
        return struct.unpack('<H', data)[0]

def read_string(address: int, max_length: int = 16) -> str:
    """Read null-terminated string from memory"""
    with open('/proc/PID/mem', 'rb') as mem:
        mem.seek(address)
        data = mem.read(max_length)
        return data.split(b'\x00')[0].decode('ascii', errors='ignore')
```

### Structure Parsing

```python
def parse_structure(data: bytes, layout: dict) -> dict:
    """Parse binary data using structure layout definition"""
    result = {}
    for field in layout["fields"]:
        offset = field["offset"]
        size = field["size"]
        field_data = data[offset:offset+size]
        
        if field["type"] == "DWORD":
            value = struct.unpack('<L', field_data)[0]
        elif field["type"] == "WORD":
            value = struct.unpack('<H', field_data)[0]
        elif field["type"].startswith("char["):
            value = field_data.split(b'\x00')[0].decode('ascii', errors='ignore')
        else:
            value = f"0x{field_data.hex().upper()}"
        
        result[field["name"]] = value
    
    return result
```

### Validation Functions

```python
def validate_unit_type(unit_type: int) -> bool:
    """Validate UnitAny type field"""
    valid_types = [0, 1, 2, 3, 4, 5]  # Player, Monster, Object, etc.
    return unit_type in valid_types

def validate_character_class(class_id: int) -> bool:
    """Validate character class ID"""
    valid_classes = list(range(7))  # 0-6 for D2 classes
    return class_id in valid_classes

def validate_memory_address(address: int) -> bool:
    """Validate memory address is in reasonable range"""
    min_addr = 0x00400000  # Typical process base
    max_addr = 0x7FFFFFFF  # User-space limit
    return min_addr <= address <= max_addr
```

## Error Handling

### Common Exceptions

```python
class MemoryAnalysisError(Exception):
    """Base exception for memory analysis errors"""
    pass

class ProcessNotFoundError(MemoryAnalysisError):
    """Game process not found"""
    pass

class MemoryAccessError(MemoryAnalysisError):
    """Cannot access process memory"""
    pass

class StructureValidationError(MemoryAnalysisError):
    """Structure validation failed"""
    pass

class ContainerConnectionError(MemoryAnalysisError):
    """Cannot connect to analysis container"""
    pass
```

### Error Handling Examples

```python
try:
    hunter = RosterUnitHunter()
    result = hunter.hunt_structure()
except ProcessNotFoundError:
    print("Game.exe not running - start D2 first")
except MemoryAccessError as e:
    print(f"Cannot read memory: {e}")
    print("Try running inside d2-analysis container")
except StructureValidationError as e:
    print(f"Invalid structure data: {e}")
    print("Check game state and known values")
```

## Configuration

### Environment Variables

```python
import os

# Container configuration
CONTAINER_NAME = os.getenv('CONTAINER_NAME', 'd2-analysis')
API_ENDPOINT = os.getenv('API_ENDPOINT', 'http://localhost:3001')

# Database configuration
DGRAPH_URL = os.getenv('DGRAPH_URL', 'http://localhost:8080')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')

# Debug settings
DEBUG_MODE = os.getenv('DEBUG', '0') == '1'
VERBOSE_LOGGING = os.getenv('VERBOSE', '0') == '1'
```

### Configuration Files

Memory analysis tools can be configured via JSON files in `data/reference/`:

- `live_memory_offsets.json`: Static memory offsets and structure layouts
- `d2_structures.json`: Complete structure definitions
- `api_signatures.json`: Function signatures for dynamic analysis

## Performance Considerations

### Memory Reading Optimization

```python
# Batch memory reads for efficiency
def read_multiple_addresses(addresses: list, sizes: list) -> dict:
    """Read from multiple addresses in single operation"""
    results = {}
    with open('/proc/PID/mem', 'rb') as mem:
        for addr, size in zip(addresses, sizes):
            mem.seek(addr)
            results[addr] = mem.read(size)
    return results

# Cache frequently accessed data
from functools import lru_cache

@lru_cache(maxsize=128)
def get_base_address(module_name: str) -> int:
    """Cached base address lookup"""
    # Implementation here
    pass
```

### Resource Management

```python
import contextlib

@contextlib.contextmanager
def memory_reader(pid: int):
    """Context manager for safe memory access"""
    try:
        mem_file = open(f'/proc/{pid}/mem', 'rb')
        yield mem_file
    finally:
        mem_file.close()

# Usage
with memory_reader(14) as mem:
    mem.seek(address)
    data = mem.read(size)
```

## Security Considerations

### Safe Memory Access

- Always validate addresses before reading
- Limit read sizes to prevent excessive memory consumption  
- Handle permission errors gracefully
- Never write to process memory

### Ethical Guidelines

- Use only for defensive security research
- Respect game terms of service
- Do not distribute cheat tools
- Follow responsible disclosure for vulnerabilities

## Examples

See the `examples/memory_analysis/` directory for complete working examples:

- `demo_playerdata_hunt.py`: PlayerData structure hunting
- `live_memory_extractor.py`: Real-time memory extraction
- `playerdata_hunter_live.py`: Live PlayerData analysis

See the `tools/memory_hunters/` directory for production tools:

- `rosterunit_hunter.py`: RosterUnit structure hunting
- `current_player_unit_demo.py`: UnitAny structure extraction
- `store_memory_data_dgraph.py`: Database storage integration