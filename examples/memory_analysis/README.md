# Memory Analysis Examples

This directory contains educational examples and demonstrations of D2 memory analysis techniques.

## Examples Overview

### Educational Demonstrations

#### `demo_playerdata_hunt.py`
Complete educational example of hunting for PlayerData structures.

**Purpose**: Teach memory analysis methodology
**Audience**: Learning reverse engineering
**Scope**: End-to-end structure discovery workflow

```bash
python demo_playerdata_hunt.py
```

**Learning Objectives**:
- Static analysis techniques
- Pattern generation methods
- Memory scanning strategies
- Structure validation approaches

**Workflow Demonstrated**:
1. **Static Analysis**: Analyze binaries for structure references
2. **String Search**: Find structure-related strings
3. **Pattern Matching**: Generate memory search patterns
4. **Control Flow Analysis**: Basic block and CFG analysis

#### `playerdata_hunter_live.py`
Live demonstration of PlayerData memory hunting.

**Purpose**: Show real-time memory hunting
**Focus**: PlayerData structure (40 bytes)
**Method**: Simulated live analysis

```bash
python playerdata_hunter_live.py
```

**Demonstrates**:
- Real-time memory scanning
- Structure validation
- Field analysis
- Complete workflow summary

#### `live_memory_extractor.py`
Example of extracting memory from analysis containers.

**Purpose**: Show container-based memory access
**Method**: API-based extraction from d2-analysis container
**Focus**: Container integration patterns

```bash
python live_memory_extractor.py
```

**Features**:
- Container API integration
- Memory pattern generation
- Live scanning simulation
- Structure validation examples

## Educational Content

### Learning Path

#### Beginner Level
1. **Start with**: `demo_playerdata_hunt.py`
   - Learn basic concepts
   - Understand workflow
   - See pattern generation

2. **Continue with**: `playerdata_hunter_live.py`
   - Real-time concepts
   - Live data analysis
   - Validation techniques

#### Intermediate Level
3. **Progress to**: `live_memory_extractor.py`
   - Container integration
   - API-based access
   - Error handling

4. **Advanced**: Production tools in `tools/memory_hunters/`
   - Real memory access
   - Graph database integration
   - Production workflows

### Concepts Covered

#### Memory Analysis Fundamentals
- **Static Analysis**: Binary examination without execution
- **Dynamic Analysis**: Live process memory reading
- **Pattern Matching**: Finding structures by signature
- **Validation**: Verifying extracted data integrity

#### Structure Discovery
- **Binary Analysis**: Examining executables for references
- **String Analysis**: Finding structure-related strings
- **Pattern Generation**: Creating memory search signatures
- **Field Validation**: Verifying structure layout

#### Reverse Engineering Methodology
- **Hypothesis Formation**: Making educated guesses
- **Evidence Collection**: Gathering supporting data
- **Validation Testing**: Proving theories correct
- **Documentation**: Recording discoveries

### Code Examples

#### Basic Memory Reading
```python
# Read DWORD from memory
import struct

def read_dword(address):
    with open('/proc/PID/mem', 'rb') as mem:
        mem.seek(address)
        data = mem.read(4)
        return struct.unpack('<L', data)[0]
```

#### Structure Parsing
```python
# Parse PlayerData structure
def parse_playerdata(data):
    name = data[0x00:0x10].split(b'\x00')[0].decode('ascii')
    quest_normal = struct.unpack('<L', data[0x10:0x14])[0]
    quest_nightmare = struct.unpack('<L', data[0x14:0x18])[0]
    quest_hell = struct.unpack('<L', data[0x18:0x1C])[0]
    return {
        'name': name,
        'quests': {
            'normal': quest_normal,
            'nightmare': quest_nightmare,
            'hell': quest_hell
        }
    }
```

#### Pattern Generation
```python
# Generate memory search pattern
def generate_pattern(known_values):
    pattern = bytearray(40)  # PlayerData size
    
    # Fill known fields
    name = known_values['name'].encode('ascii')
    pattern[0x00:0x00+len(name)] = name
    
    return bytes(pattern)
```

## Running Examples

### Prerequisites
```bash
# Ensure platform is running
docker-compose up -d

# Verify d2-analysis container
docker exec d2-analysis ps aux | grep Game.exe
```

### Execution Order

1. **Educational Sequence**:
   ```bash
   # Basic concepts
   python demo_playerdata_hunt.py
   
   # Live analysis
   python playerdata_hunter_live.py
   
   # Container integration
   python live_memory_extractor.py
   ```

2. **Advanced Exploration**:
   ```bash
   # Real memory access
   python ../tools/memory_hunters/rosterunit_hunter.py
   
   # Graph database storage
   python ../tools/memory_hunters/store_memory_data_dgraph.py
   ```

### Understanding Output

#### Console Output Sections
- **Setup**: Initialization and connection
- **Analysis**: Structure discovery process
- **Results**: Extracted data and validation
- **Summary**: Key findings and next steps

#### Educational Notes
Each example includes detailed explanations:
- Why certain techniques are used
- How patterns are generated
- What validation checks mean
- How to interpret results

## Customization

### Modifying Examples

#### Change Target Values
```python
# In demo_playerdata_hunt.py
self.target_values = {
    "player_name": "YourCharName",
    "level": 50,
    # ... other values
}
```

#### Add Custom Patterns
```python
# Add new pattern types
patterns["custom_signature"] = {
    "description": "Custom pattern description",
    "bytes": generate_custom_pattern(),
    "offset": 0x20,
    "confidence": "high"
}
```

#### Extend Validation
```python
# Add custom validation
def custom_validation(data):
    # Your validation logic
    if meets_criteria(data):
        return {"valid": True, "reason": "Passes custom check"}
    return {"valid": False, "reason": "Fails custom check"}
```

## Integration with Production Tools

### Moving to Production
After understanding examples, transition to production tools:

1. **Use Real Tools**: `tools/memory_hunters/`
2. **Store Results**: Dgraph integration
3. **Monitor Changes**: Real-time analysis
4. **Build Workflows**: Automated processes

### Best Practices Learned
- Always validate extracted data
- Handle errors gracefully
- Document discoveries thoroughly
- Use proper memory access patterns
- Respect system boundaries

## Troubleshooting Examples

### Common Learning Issues

1. **"No data found"**
   - Examples use simulated data
   - Real data requires running D2 process
   - Check container status

2. **"Pattern not found"**
   - Examples demonstrate concepts
   - Real patterns need game-specific values
   - Adjust target values to match

3. **"Connection failed"**
   - Container integration examples
   - Ensure d2-analysis is running
   - Check API endpoints

### Debug Features

Enable verbose output:
```python
# In any example file
DEBUG = True  # Set at top of file

# Or via environment
export DEBUG=1
python demo_playerdata_hunt.py
```

## Contributing Examples

### Adding New Examples

1. **Follow naming**: `demo_structure_name.py`
2. **Include documentation**: Comprehensive comments
3. **Add learning objectives**: Clear educational goals
4. **Provide examples**: Working code samples
5. **Update README**: Document new example

### Example Template
```python
#!/usr/bin/env python3
"""
Example: [Structure Name] Analysis
Educational demonstration of [concept]

Learning Objectives:
- Understand [concept 1]
- Learn [technique]
- Practice [skill]
"""

class ExampleAnalyzer:
    def __init__(self):
        # Educational setup
        pass
    
    def demonstrate_concept(self):
        # Step-by-step demonstration
        pass

if __name__ == "__main__":
    # Educational execution
    pass
```

## Further Learning

### Advanced Topics
- Real-time monitoring
- Multi-process analysis
- Cross-platform techniques
- Anti-analysis evasion

### Related Documentation
- [Memory Structures](../../docs/memory_analysis/memory_structures.md)
- [Usage Guide](../../docs/memory_analysis/usage_guide.md)
- [API Reference](../../docs/memory_analysis/api_reference.md)

### External Resources
- Reverse engineering tutorials
- Memory analysis papers
- Game hacking research (ethical)
- Security analysis methodologies