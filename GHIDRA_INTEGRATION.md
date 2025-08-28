# Ghidra MCP Integration

## Overview

This document describes the comprehensive integration of Ghidra static analysis capabilities with the Wine Debug MCP system, enabling Claude AI to perform advanced reverse engineering through the Model Context Protocol (MCP).

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌──────────────────┐
│   Claude AI     │◄──►│ MCP Coordinator │◄──►│ Ghidra Analysis  │
│                 │    │                 │    │    Container     │
│ - setup_context │    │ - Tool routing  │    │ - Headless mode  │
│ - list_functions│    │ - Session mgmt  │    │ - Decompilation  │
│ - get_pseudocode│    │ - Wine debug    │    │ - Function analysis│
│ - list_structures│   │   integration   │    │ - Binary parsing │
└─────────────────┘    └─────────────────┘    └──────────────────┘
                                ▲
                                │
                       ┌─────────────────┐
                       │ D2 Analysis     │
                       │   Container     │
                       │ - Live memory   │
                       │ - Wine runtime  │
                       │ - Game.exe      │
                       └─────────────────┘
```

## MCP Tools Available

### 1. setup_context(binary_path, analysis_type="detailed")
**Purpose**: Initialize Ghidra analysis on a binary
**Usage**: 
```python
setup_context("/analysis/d2_binaries/D2Client.dll", "comprehensive")
```
**Returns**: Analysis context, estimated functions, next steps

### 2. list_functions(include_exports=True, include_internals=True, include_ordinals=True)
**Purpose**: Get all functions in the binary
**Usage**: 
```python
list_functions(include_ordinals=True)
```
**Returns**: Function list with addresses, names, export status, summary statistics

### 3. get_pseudocode(function_name, function_address=None)
**Purpose**: Decompile function to readable C-like code
**Usage**: 
```python
get_pseudocode("GetCursorItem")
# or
get_pseudocode(function_address="0x10001234")
```
**Returns**: Pseudocode, assembly, signature, references, called functions

### 4. list_structures(include_builtin=False)
**Purpose**: Get data structures/types from binary
**Usage**: 
```python
list_structures(include_builtin=True)
```
**Returns**: Structure names, sizes, field information

### 5. get_structure(structure_name)
**Purpose**: Detailed structure analysis
**Usage**: 
```python
get_structure("UnitAny")
```
**Returns**: Field layout, types, sizes, cross-references

### 6. list_enums()
**Purpose**: Get enumeration types
**Usage**: 
```python
list_enums()
```
**Returns**: Enum names, values, contexts

### 7. get_enum(enum_name)
**Purpose**: Detailed enumeration analysis
**Usage**: 
```python
get_enum("UnitType")
```
**Returns**: Enum values, meanings, usage patterns

### 8. list_function_definitions(filter_pattern=None)
**Purpose**: Get function prototypes/signatures
**Usage**: 
```python
list_function_definitions(filter_pattern="Get.*Item")
```
**Returns**: Function signatures, return types, parameters

### 9. get_function_definition(function_name)
**Purpose**: Detailed function signature
**Usage**: 
```python
get_function_definition("GetCursorItem")
```
**Returns**: Complete signature, calling convention, parameter details

## Integration Points

### MCP Coordinator Endpoints

- **GET /ghidra/tools**: List available Ghidra MCP tools
- **POST /ghidra/execute**: Execute Ghidra tool with arguments

### Ghidra Analysis Server

- **http://ghidra-analysis:8002**: Headless Ghidra analysis server
- **Background analysis**: Long-running decompilation tasks
- **Project management**: Automatic cleanup and optimization

## Workflow Examples

### 1. Complete Function Analysis
```python
# 1. Setup binary context
result = setup_context("/analysis/d2_binaries/D2Client.dll", "detailed")

# 2. List all functions
functions = list_functions(include_ordinals=True)

# 3. Analyze specific function
pseudocode = get_pseudocode("GetCursorItem")

# 4. Get function signature
signature = get_function_definition("GetCursorItem")
```

### 2. Structure Discovery
```python
# 1. Setup context (if not already done)
setup_context("/analysis/d2_binaries/D2Client.dll")

# 2. List all structures
structures = list_structures()

# 3. Analyze specific structure
unit_any = get_structure("UnitAny")

# 4. Cross-reference with memory analysis
# (Combine with Wine debug memory scanning)
```

### 3. Exported Function Discovery
```python
# 1. Setup context
setup_context("/analysis/d2_binaries/D2Client.dll")

# 2. List exported functions only
exports = list_functions(include_internals=False, include_ordinals=True)

# 3. Analyze ordinal functions
for func in exports['functions']:
    if 'Ordinal_' in func['name']:
        pseudocode = get_pseudocode(func['name'])
        # Determine function purpose from pseudocode
```

## Advanced Features

### Cross-Correlation with Wine Debug
The Ghidra integration works seamlessly with Wine debug data:

1. **Static + Dynamic Analysis**: Ghidra provides static structure, Wine provides runtime behavior
2. **Memory Validation**: Compare Ghidra structures with live memory scans
3. **Function Call Tracing**: Ghidra signatures + Wine API monitoring
4. **Data Type Verification**: Validate discovered types against runtime data

### Performance Optimization

1. **Caching**: Analysis results cached across sessions
2. **Incremental Analysis**: Only re-analyze changed binaries
3. **Background Processing**: Long analysis runs in background
4. **Memory Management**: Automatic cleanup of old projects

## Configuration

### Environment Variables
- `GHIDRA_INSTALL_DIR`: Ghidra installation path
- `JAVA_OPTS`: JVM options for Ghidra (default: -Xmx4g)

### Docker Volumes
- `ghidra_projects`: Persistent Ghidra project storage
- `/app/pd2`: Project Diablo 2 game files
- `/app/outputs`: Analysis results and reports

## Error Handling

### Common Issues
1. **Binary Not Found**: Ensure binary path is correct and accessible
2. **Analysis Timeout**: Use "basic" analysis for large binaries
3. **Memory Issues**: Increase JAVA_OPTS memory allocation
4. **Context Not Set**: Always call setup_context() first

### Debugging
- Check Ghidra container logs: `docker logs ghidra-analysis`
- Verify server health: `curl http://localhost:8002/health`
- Monitor analysis progress via status endpoints

## Performance Metrics

### Expected Analysis Times
- **Basic Analysis**: 2-5 minutes for typical DLL
- **Detailed Analysis**: 5-15 minutes for comprehensive decompilation
- **Comprehensive Analysis**: 10-30 minutes for full binary analysis

### Resource Usage
- **Memory**: 4-8GB RAM recommended for large binaries
- **CPU**: Multi-threaded analysis scales with CPU cores
- **Storage**: ~100MB per analyzed binary for project data

## Integration with Test Scenarios

The Ghidra MCP tools are designed to enhance the existing test scenarios:

### Test Scenario 3: GetCursorItem Function Analysis
```python
# Enhanced with Ghidra
setup_context("/analysis/d2_binaries/D2Client.dll")
pseudocode = get_pseudocode("GetCursorItem")
signature = get_function_definition("GetCursorItem")

# Cross-validate with Wine debug
wine_trace = monitor_function_calls("GetCursorItem")
# Compare static analysis with runtime behavior
```

### Test Scenario 6: Exported Function Discovery
```python
# Ghidra-enhanced ordinal analysis
setup_context("/analysis/d2_binaries/D2Client.dll")
exports = list_functions(include_ordinals=True)

# Analyze each ordinal function
for ordinal in [f for f in exports['functions'] if 'Ordinal_' in f['name']]:
    pseudocode = get_pseudocode(ordinal['name'])
    # Determine function purpose from decompiled code
    # Suggest proper function names based on analysis
```

## Future Enhancements

### Planned Features
1. **Structure Auto-Discovery**: Automatically reconstruct data types
2. **API Pattern Recognition**: Identify common Windows API usage patterns
3. **Cross-Reference Analysis**: Advanced call graph analysis
4. **Vulnerability Detection**: Security-focused static analysis
5. **Binary Diffing**: Compare different versions of binaries

### Integration Improvements
1. **Real-time Analysis**: Live updates during Wine execution
2. **ML-Enhanced Naming**: AI-powered function/variable naming
3. **Documentation Generation**: Automatic API documentation
4. **Graph Visualization**: Interactive call graphs and data flow

## Security Considerations

### Sandboxing
- Ghidra runs in isolated container
- No network access during analysis
- Read-only access to game binaries

### Data Protection
- Analysis results stored locally
- No external data transmission
- Secure container-to-container communication

This comprehensive Ghidra integration provides Claude AI with powerful static analysis capabilities, complementing the existing Wine debug system for complete reverse engineering workflows.