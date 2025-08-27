# Memory Analysis Development Guide

This guide provides instructions for extending and contributing to the memory analysis system.

## Development Environment Setup

### Prerequisites

- Docker and Docker Compose installed
- Python 3.10+ for local development
- Git for version control
- VNC viewer for game inspection

### Local Development Setup

1. **Clone and initialize:**
   ```bash
   git clone <repository>
   cd pd2-mcp-orchestrated-re
   git init  # If not already a git repo
   ```

2. **Start development environment:**
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
   ```

3. **Verify setup:**
   ```bash
   make health
   docker exec d2-analysis ps aux | grep Game.exe
   ```

### Development Workflow

1. **Create feature branch:**
   ```bash
   git checkout -b feature/new-structure-hunter
   ```

2. **Development cycle:**
   - Write code in appropriate directory
   - Test with live memory data
   - Update documentation
   - Run validation tests

3. **Commit and merge:**
   ```bash
   git add .
   git commit -m "Add new structure hunter"
   git push origin feature/new-structure-hunter
   ```

## Architecture Overview

### Directory Structure

```
pd2-mcp-orchestrated-re/
├── tools/memory_hunters/          # Production analysis tools
│   ├── rosterunit_hunter.py      # RosterUnit structure hunting
│   ├── current_player_unit_demo.py # UnitAny extraction
│   └── store_memory_data_dgraph.py # Database integration
├── examples/memory_analysis/      # Educational examples  
│   ├── demo_playerdata_hunt.py   # PlayerData hunting demo
│   └── live_memory_extractor.py  # Container integration
├── docs/memory_analysis/          # Documentation
│   ├── README.md                 # Overview and quick start
│   ├── memory_structures.md      # Structure layouts
│   ├── usage_guide.md           # Step-by-step instructions
│   ├── api_reference.md         # API documentation
│   └── troubleshooting.md       # Common issues
├── data/reference/               # Reference data
│   ├── D2Structs.h              # C structure definitions
│   └── live_memory_offsets.json # Discovered offsets
└── shared/                      # Shared libraries
    ├── analysis/                # Analysis utilities
    └── mcp/                    # MCP integration
```

### Core Components

#### Memory Hunter Base Class

All structure hunters inherit from this base:

```python
class MemoryHunter:
    """Base class for memory structure hunting"""
    
    def __init__(self):
        self.container_name = "d2-analysis"
        self.base_address = None
        self.process_id = None
        self.debug = os.getenv('DEBUG', '0') == '1'
    
    def find_process(self) -> int:
        """Find Game.exe process ID"""
        
    def get_module_base(self, module_name: str) -> int:
        """Get module base address"""
        
    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from address"""
        
    def validate_structure(self, data: bytes) -> dict:
        """Validate extracted structure"""
```

#### Container Integration

All memory access goes through the d2-analysis container:

```python
class ContainerMemoryAccess:
    """Handle memory access via container"""
    
    def execute_in_container(self, command: list) -> str:
        """Execute command inside container"""
        
    def read_proc_memory(self, pid: int, address: int, size: int) -> bytes:
        """Read from /proc/PID/mem inside container"""
        
    def get_process_mappings(self, pid: int) -> list:
        """Get memory mappings for process"""
```

## Creating New Structure Hunters

### Step 1: Define Structure Layout

First, add your structure to `data/reference/D2Structs.h`:

```c
// Add your structure definition
struct NewStructure {
    char szName[32];        // 0x00 - Structure name
    DWORD dwValue1;         // 0x20 - First value
    DWORD dwValue2;         // 0x24 - Second value  
    WORD wFlags;            // 0x28 - Flags
    BYTE bReserved[6];      // 0x2A - Reserved
};  // Size: 0x30 (48 bytes)
```

### Step 2: Create Hunter Class

Create new hunter in `tools/memory_hunters/`:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NewStructure Memory Hunter

Hunts for NewStructure in live D2 memory using known values.
"""

import os
import sys
import struct
import subprocess
from typing import Dict, Optional, Tuple

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.memory_hunters.base import MemoryHunter

class NewStructureHunter(MemoryHunter):
    """Hunt for NewStructure in memory"""
    
    def __init__(self):
        super().__init__()
        self.structure_name = "NewStructure"
        self.structure_size = 0x30  # 48 bytes
        
        # Known values for pattern matching
        self.target_values = {
            "szName": "ExpectedName",
            "dwValue1": 12345,
            "dwValue2": 67890,
            "wFlags": 0x0042
        }
        
        # Structure field layout
        self.field_layout = [
            {"name": "szName", "offset": 0x00, "size": 32, "type": "char[32]"},
            {"name": "dwValue1", "offset": 0x20, "size": 4, "type": "DWORD"},
            {"name": "dwValue2", "offset": 0x24, "size": 4, "type": "DWORD"},
            {"name": "wFlags", "offset": 0x28, "size": 2, "type": "WORD"},
            {"name": "bReserved", "offset": 0x2A, "size": 6, "type": "BYTE[6]"}
        ]
    
    def hunt_structure(self) -> Dict:
        """
        Hunt for NewStructure using known values
        
        Returns:
            Dict containing discovered structure data
        """
        print(f"TARGET: {self.structure_name.upper()} MEMORY HUNTING")
        print("=" * 60)
        
        # Step 1: Find process and base addresses
        pid = self.find_process()
        if not pid:
            raise ProcessNotFoundError("Game.exe process not found")
        
        d2client_base = self.get_module_base("d2client.dll")
        
        # Step 2: Generate search patterns
        patterns = self.generate_patterns()
        
        # Step 3: Search memory (simulated for now)
        memory_address = self.simulate_memory_search(patterns)
        
        # Step 4: Extract and validate structure
        structure_data = self.extract_structure(memory_address)
        validation_result = self.validate_structure_data(structure_data)
        
        return {
            "structure_name": self.structure_name,
            "memory_address": f"0x{memory_address:08X}",
            "size": self.structure_size,
            "data": structure_data,
            "validation": validation_result,
            "patterns": patterns
        }
    
    def generate_patterns(self) -> Dict:
        """Generate memory search patterns from known values"""
        patterns = {}
        
        # Name pattern
        name_bytes = self.target_values["szName"].encode('ascii')
        patterns["name_signature"] = {
            "description": f"Structure name '{self.target_values['szName']}'",
            "bytes": name_bytes,
            "offset": 0x00,
            "confidence": "high"
        }
        
        # Value patterns  
        value1_bytes = struct.pack('<L', self.target_values["dwValue1"])
        patterns["value1_signature"] = {
            "description": f"Value1 {self.target_values['dwValue1']}",
            "bytes": value1_bytes,
            "offset": 0x20,
            "confidence": "medium"
        }
        
        flags_bytes = struct.pack('<H', self.target_values["wFlags"])
        patterns["flags_signature"] = {
            "description": f"Flags 0x{self.target_values['wFlags']:04X}",
            "bytes": flags_bytes,
            "offset": 0x28,
            "confidence": "medium"
        }
        
        return patterns
    
    def simulate_memory_search(self, patterns: Dict) -> int:
        """
        Simulate memory search for development
        Replace with real memory scanning in production
        """
        # Simulated memory address for development
        base_address = 0x0E450000
        
        print("\nPHASE 1: Memory Pattern Search")
        print("-" * 50)
        
        for name, pattern in patterns.items():
            print(f"  • Searching for {pattern['description']}")
            print(f"    Pattern: {pattern['bytes'].hex().upper()}")
            print(f"    Found at: 0x{base_address + pattern['offset']:08X}")
        
        return base_address
    
    def extract_structure(self, memory_address: int) -> Dict:
        """Extract complete structure from memory address"""
        
        # For development, simulate structure data
        # In production, read from actual memory
        simulated_data = bytearray(self.structure_size)
        
        # Fill with realistic data
        name = self.target_values["szName"].encode('ascii')
        simulated_data[0x00:0x00+len(name)] = name
        
        struct.pack_into('<L', simulated_data, 0x20, self.target_values["dwValue1"])
        struct.pack_into('<L', simulated_data, 0x24, self.target_values["dwValue2"]) 
        struct.pack_into('<H', simulated_data, 0x28, self.target_values["wFlags"])
        
        # Parse fields
        structure_data = {}
        for field in self.field_layout:
            offset = field["offset"]
            size = field["size"]
            field_data = simulated_data[offset:offset+size]
            
            if field["type"] == "DWORD":
                value = struct.unpack('<L', field_data)[0]
            elif field["type"] == "WORD":
                value = struct.unpack('<H', field_data)[0]
            elif field["type"].startswith("char["):
                value = field_data.split(b'\x00')[0].decode('ascii', errors='ignore')
            elif field["type"].startswith("BYTE["):
                value = field_data.hex().upper()
            else:
                value = f"0x{field_data.hex().upper()}"
            
            structure_data[field["name"]] = {
                "offset": f"0x{offset:02X}",
                "value": value,
                "type": field["type"],
                "size": size
            }
        
        return structure_data
    
    def validate_structure_data(self, data: Dict) -> Dict:
        """Validate extracted structure data"""
        validation = {
            "is_valid": True,
            "checks": {},
            "confidence": "high"
        }
        
        # Check name
        name_check = data["szName"]["value"] == self.target_values["szName"]
        validation["checks"]["name_match"] = {
            "passed": name_check,
            "expected": self.target_values["szName"],
            "actual": data["szName"]["value"]
        }
        
        # Check values
        value1_check = data["dwValue1"]["value"] == self.target_values["dwValue1"]
        validation["checks"]["value1_match"] = {
            "passed": value1_check,
            "expected": self.target_values["dwValue1"],
            "actual": data["dwValue1"]["value"]
        }
        
        # Overall validation
        validation["is_valid"] = all(check["passed"] for check in validation["checks"].values())
        
        return validation

def main():
    """Main execution function"""
    try:
        hunter = NewStructureHunter()
        result = hunter.hunt_structure()
        
        print(f"\n✓ SUCCESS: Found {result['structure_name']} structure")
        print(f"  Memory Address: {result['memory_address']}")
        print(f"  Size: {result['size']} bytes")
        print(f"  Validation: {'PASSED' if result['validation']['is_valid'] else 'FAILED'}")
        
        # Display structure fields
        print(f"\n{result['structure_name']} Fields:")
        print("-" * 50)
        for field_name, field_info in result['data'].items():
            print(f"  {field_info['offset']}: {field_name:<12} = {field_info['value']}")
        
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
```

### Step 3: Create Base Hunter (Optional)

If you need common functionality, create a base class in `tools/memory_hunters/base.py`:

```python
#!/usr/bin/env python3
"""Base classes for memory hunters"""

import os
import subprocess
import struct
from typing import Dict, Optional, List

class MemoryHunter:
    """Base class for all memory structure hunters"""
    
    def __init__(self):
        self.container_name = "d2-analysis"
        self.debug = os.getenv('DEBUG', '0') == '1'
        self.process_id = None
        self.base_addresses = {}
    
    def find_process(self) -> Optional[int]:
        """Find Game.exe process ID"""
        try:
            result = subprocess.run([
                'docker', 'exec', self.container_name, 'pgrep', 'Game.exe'
            ], capture_output=True, text=True, check=True)
            
            pid = int(result.stdout.strip())
            self.process_id = pid
            return pid
            
        except (subprocess.CalledProcessError, ValueError):
            return None
    
    def get_module_base(self, module_name: str) -> Optional[int]:
        """Get base address for specified module"""
        if module_name in self.base_addresses:
            return self.base_addresses[module_name]
        
        if not self.process_id:
            self.find_process()
        
        try:
            result = subprocess.run([
                'docker', 'exec', self.container_name, 'gdb', 
                '-p', str(self.process_id), '-batch', 
                '-ex', 'info proc mappings'
            ], capture_output=True, text=True, check=True)
            
            for line in result.stdout.split('\n'):
                if module_name.lower() in line.lower():
                    base_addr = int(line.split()[0], 16)
                    self.base_addresses[module_name] = base_addr
                    return base_addr
                    
        except subprocess.CalledProcessError:
            pass
        
        return None
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from specified address"""
        if not self.process_id:
            return None
        
        try:
            # Read via container
            command = [
                'docker', 'exec', self.container_name, 'python3', '-c',
                f'''
import struct
with open("/proc/{self.process_id}/mem", "rb") as mem:
    mem.seek({address})
    data = mem.read({size})
    print(data.hex())
'''
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            hex_data = result.stdout.strip()
            return bytes.fromhex(hex_data)
            
        except subprocess.CalledProcessError:
            return None
    
    def log(self, message: str):
        """Debug logging"""
        if self.debug:
            print(f"[DEBUG] {message}")

class ProcessNotFoundError(Exception):
    """Game process not found"""
    pass

class MemoryAccessError(Exception):
    """Cannot access process memory"""
    pass

class StructureValidationError(Exception):
    """Structure validation failed"""
    pass
```

### Step 4: Add Tests

Create test file in `tests/memory_hunters/test_new_structure.py`:

```python
#!/usr/bin/env python3
"""Tests for NewStructure hunter"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.memory_hunters.new_structure_hunter import NewStructureHunter

class TestNewStructureHunter(unittest.TestCase):
    
    def setUp(self):
        self.hunter = NewStructureHunter()
    
    def test_pattern_generation(self):
        """Test pattern generation from known values"""
        patterns = self.hunter.generate_patterns()
        
        self.assertIn("name_signature", patterns)
        self.assertIn("value1_signature", patterns) 
        self.assertEqual(patterns["name_signature"]["offset"], 0x00)
        self.assertEqual(patterns["value1_signature"]["offset"], 0x20)
    
    def test_structure_extraction(self):
        """Test structure field extraction"""
        data = self.hunter.extract_structure(0x12345678)
        
        self.assertIn("szName", data)
        self.assertIn("dwValue1", data)
        self.assertEqual(data["szName"]["value"], "ExpectedName")
        self.assertEqual(data["dwValue1"]["value"], 12345)
    
    def test_validation(self):
        """Test structure validation"""
        data = self.hunter.extract_structure(0x12345678)
        validation = self.hunter.validate_structure_data(data)
        
        self.assertTrue(validation["is_valid"])
        self.assertIn("name_match", validation["checks"])
        self.assertTrue(validation["checks"]["name_match"]["passed"])
    
    @patch('subprocess.run')
    def test_process_finding(self, mock_run):
        """Test Game.exe process finding"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "12345"
        
        pid = self.hunter.find_process()
        self.assertEqual(pid, 12345)

if __name__ == "__main__":
    unittest.main()
```

### Step 5: Add Documentation

Update documentation files:

1. **Add to API Reference** (`docs/memory_analysis/api_reference.md`):
   ```markdown
   ### NewStructureHunter
   
   Hunts for NewStructure containing custom data.
   
   #### Methods
   
   ##### `hunt_structure() -> dict`
   Searches for NewStructure using known values.
   ```

2. **Add to Usage Guide** (`docs/memory_analysis/usage_guide.md`):
   ```markdown
   ### Hunt for NewStructure
   
   ```bash
   python tools/memory_hunters/new_structure_hunter.py
   ```
   ```

3. **Update README** (`tools/memory_hunters/README.md`):
   ```markdown
   #### `new_structure_hunter.py`
   Hunt for NewStructure using known live game values.
   
   **Purpose**: Extract custom structure data from memory
   **Input**: Known structure values
   **Output**: Complete structure with validation
   ```

## Database Integration

### Adding New Schema Types

To store new structure data in Dgraph:

1. **Define schema in** `tools/memory_hunters/store_memory_data_dgraph.py`:

```python
def setup_schema(self):
    schema = '''
    # Existing schema...
    
    type NewStructure {
        newstruct.name: string @index(exact) .
        newstruct.value1: int .
        newstruct.value2: int .
        newstruct.flags: string .
        newstruct.memory_address: string .
        newstruct.analysis_session: uid @reverse .
    }
    '''
```

2. **Add storage method:**

```python
def store_new_structure(self, struct_data: dict) -> str:
    """Store NewStructure data in Dgraph"""
    
    mutation = f'''
    {{
        set {{
            _:newstruct <dgraph.type> "NewStructure" .
            _:newstruct <newstruct.name> "{struct_data['name']}" .
            _:newstruct <newstruct.value1> {struct_data['value1']} .
            _:newstruct <newstruct.value2> {struct_data['value2']} .
            _:newstruct <newstruct.flags> "0x{struct_data['flags']:04X}" .
            _:newstruct <newstruct.memory_address> "{struct_data['memory_address']}" .
        }}
    }}
    '''
    
    response = self.client.txn().mutate(set_obj=mutation)
    return response.uids.get('newstruct', '')
```

3. **Add query methods:**

```python
def query_new_structures(self) -> list:
    """Query all NewStructure data"""
    
    query = '''
    {
        structures(func: type(NewStructure)) {
            uid
            newstruct.name
            newstruct.value1
            newstruct.value2
            newstruct.flags
            newstruct.memory_address
        }
    }
    '''
    
    response = self.client.txn().query(query)
    return json.loads(response.json)['structures']
```

## Real Memory Integration

### Converting from Simulation to Live Memory

1. **Replace simulated data with real memory reads:**

```python
def extract_structure(self, memory_address: int) -> Dict:
    """Extract structure from real memory"""
    
    # Read actual memory instead of simulation
    raw_data = self.read_memory(memory_address, self.structure_size)
    if not raw_data:
        raise MemoryAccessError("Failed to read memory")
    
    # Parse fields from real data
    structure_data = {}
    for field in self.field_layout:
        offset = field["offset"]
        size = field["size"]
        field_data = raw_data[offset:offset+size]
        
        # Parse based on field type
        if field["type"] == "DWORD":
            value = struct.unpack('<L', field_data)[0]
        elif field["type"] == "WORD":
            value = struct.unpack('<H', field_data)[0]
        elif field["type"].startswith("char["):
            value = field_data.split(b'\x00')[0].decode('ascii', errors='ignore')
        else:
            value = f"0x{field_data.hex().upper()}"
        
        structure_data[field["name"]] = {
            "offset": f"0x{offset:02X}",
            "value": value,
            "type": field["type"],
            "size": size
        }
    
    return structure_data
```

2. **Add real memory scanning:**

```python
def scan_memory_for_pattern(self, pattern: bytes, start_addr: int, size: int) -> List[int]:
    """Scan memory for byte pattern"""
    matches = []
    
    # Read memory in chunks
    chunk_size = 4096
    for offset in range(0, size, chunk_size):
        chunk_data = self.read_memory(start_addr + offset, min(chunk_size, size - offset))
        if not chunk_data:
            continue
        
        # Search for pattern in chunk
        pos = 0
        while pos < len(chunk_data):
            found_pos = chunk_data.find(pattern, pos)
            if found_pos == -1:
                break
            
            matches.append(start_addr + offset + found_pos)
            pos = found_pos + 1
    
    return matches
```

## Testing and Validation

### Unit Testing

Run tests for your new hunter:

```bash
# Run specific tests
python -m pytest tests/memory_hunters/test_new_structure.py -v

# Run all memory hunter tests  
python -m pytest tests/memory_hunters/ -v

# Run with coverage
python -m pytest tests/memory_hunters/ --cov=tools.memory_hunters
```

### Integration Testing

Test with live memory:

```bash
# Ensure D2 is running
docker exec d2-analysis ps aux | grep Game.exe

# Run your hunter
python tools/memory_hunters/new_structure_hunter.py

# Verify output matches expectations
```

### Performance Testing

Profile memory operations:

```python
import cProfile
import pstats

def profile_hunter():
    hunter = NewStructureHunter()
    result = hunter.hunt_structure()
    return result

# Profile execution
cProfile.run('profile_hunter()', 'hunter_profile.stats')

# Analyze results
stats = pstats.Stats('hunter_profile.stats')
stats.sort_stats('tottime').print_stats(10)
```

## Contributing Guidelines

### Code Style

1. **Follow PEP 8 conventions**
2. **Use type hints:**
   ```python
   def extract_structure(self, address: int) -> Dict[str, Any]:
   ```

3. **Document functions:**
   ```python
   def hunt_structure(self) -> Dict:
       """
       Hunt for structure using known values
       
       Returns:
           Dict containing discovered structure data
       
       Raises:
           ProcessNotFoundError: If Game.exe not found
           MemoryAccessError: If memory access fails
       """
   ```

4. **Error handling:**
   ```python
   try:
       result = risky_operation()
   except SpecificError as e:
       self.log(f"Operation failed: {e}")
       raise
   ```

### Commit Messages

Use descriptive commit messages:

```bash
git commit -m "Add NewStructure hunter for custom data extraction

- Implements pattern-based memory scanning
- Adds field-by-field validation  
- Includes Dgraph storage integration
- Adds comprehensive test coverage"
```

### Pull Request Process

1. **Create feature branch**
2. **Implement changes with tests**
3. **Update documentation**
4. **Run validation suite**
5. **Submit PR with description**

### Documentation Standards

- Update API reference for new classes
- Add usage examples to guides
- Include troubleshooting for common issues
- Document any new configuration options

## Advanced Topics

### Cross-Platform Considerations

Handle different environments:

```python
def get_memory_file_path(self, pid: int) -> str:
    """Get memory file path for current platform"""
    if os.name == 'nt':  # Windows
        return f"//./PHYSICALMEMORY"  # Requires special handling
    else:  # Linux/Unix
        return f"/proc/{pid}/mem"
```

### Performance Optimization

1. **Batch memory operations**
2. **Cache frequently accessed data**
3. **Use memory mapping for large reads**
4. **Limit search spaces**

### Security Considerations

1. **Never write to process memory**
2. **Validate all input data**
3. **Handle permissions gracefully**
4. **Log security-relevant events**

## Future Enhancements

### Planned Features

1. **Pattern Learning**: AI-based pattern discovery
2. **Real-time Monitoring**: Continuous structure tracking  
3. **Cross-game Support**: Generic structure hunting
4. **Graph Analysis**: Relationship discovery in data

### Extension Points

1. **New Structure Types**: Easy to add via base classes
2. **Custom Validators**: Pluggable validation system
3. **Storage Backends**: Multiple database support
4. **Analysis Pipelines**: Automated discovery workflows

## Resources

### Internal Documentation
- API Reference: Complete function documentation
- Memory Structures: Layout definitions and offsets
- Usage Guide: Step-by-step instructions
- Troubleshooting: Common issues and solutions

### External Resources
- Diablo 2 technical documentation
- Reverse engineering guides
- Memory analysis papers
- Container security best practices