# Wine Debug MCP Test Scenarios

## Overview

Comprehensive real-world test scenarios to validate the Wine Debug MCP integration for automated Diablo 2 reverse engineering. These tests verify data structure discovery, function monitoring, exported function analysis, and knowledge graph construction.

## Test Environment Setup

### Prerequisites
1. Docker containers built and running (`d2-analysis`, `mcp-coordinator`, `dgraph`)
2. Project Diablo 2 game files in `/data/pd2/`
3. Claude Desktop connected via MCP protocol
4. Reference structures available in `data/reference/D2Structs.h`

### Validation Data Sources
- **Ground Truth**: `D2Structs.h` - Contains 50+ documented structures
- **Ghidra Analysis**: Static analysis results for comparison
- **Memory Dumps**: Runtime validation of discovered structures
- **API Traces**: Function call patterns and parameters

---

## Test Scenario 1: UnitAny Structure Discovery

### Objective
Automatically discover and validate the core `UnitAny` structure (lines 569-622 in D2Structs.h)

### Test Procedure
1. **Initiate Discovery**:
   ```
   Claude: Use wine_debug_discover_structures tool with focus on "player character data"
   ```

2. **Expected MCP Execution**:
   - Wine API monitoring captures `D2Client.dll` calls
   - Memory dumps triggered on player movement/actions
   - Pattern recognition identifies repeated 0xEC-byte structures
   - Cross-correlation with known offsets (dwType:0x00, dwUnitId:0x0C, wX:0x8C, wY:0x8E)

3. **Validation Steps**:
   - Compare discovered structure size (should be 0xEC bytes)
   - Verify critical offsets match D2Structs.h reference
   - Check field types (DWORD vs WORD vs BYTE)
   - Validate pointer relationships (pAct, pInventory, pStats)

4. **Success Criteria**:
   - ≥95% field accuracy compared to reference
   - Correct structure size identification
   - Valid pointer chain discovery
   - Dgraph storage with proper relationships

### Expected Timeline
- Initial discovery: 2-5 minutes
- Validation and refinement: 10-15 minutes
- Dgraph documentation: 2-3 minutes

---

## Test Scenario 2: Inventory Structure Chain Discovery

### Objective
Discover interconnected structures: UnitAny → Inventory → ItemData

### Test Procedure
1. **Trigger Discovery**:
   ```
   Claude: Analyze inventory system structures starting from player unit
   ```

2. **Sequential Discovery Process**:
   - Start with UnitAny.pInventory (offset 0x60)
   - Follow pointer to Inventory structure
   - Trace pFirstItem/pLastItem to ItemData structures
   - Map item property chains and stat relationships

3. **Validation Against Reference**:
   - **Inventory** (lines 406-417): 0x2C bytes, key fields at offsets 0x0C, 0x10, 0x20
   - **ItemData** (lines 447-474): 0x88 bytes, BodyLocation:0x44, ItemLocation:0x45
   - **ItemPath** (lines 382-387): Position and movement data

4. **Cross-Validation Methods**:
   - Memory dump correlation during item pickup/drop
   - API trace matching during inventory operations
   - Static analysis comparison with Ghidra decompilation

### Success Criteria
- Complete structure chain mapped correctly
- All pointer relationships validated
- Item state changes tracked accurately
- 90%+ field mapping accuracy

---

## Test Scenario 3: GetCursorItem Function Analysis

### Objective
Monitor and analyze the `GetCursorItem` function in D2Client.dll

### Test Procedure
1. **Function Monitoring Setup**:
   ```
   Claude: Monitor D2Client function GetCursorItem with full parameter tracking
   ```

2. **Analysis Execution**:
   - Set Wine debug breakpoints on GetCursorItem calls
   - Capture function parameters, return values, and call stack
   - Track memory access patterns within function scope
   - Correlate with item structure discoveries

3. **Expected Discoveries**:
   - Function signature: `UnitAny* GetCursorItem(void)`
   - Return value validation against UnitAny structure
   - Call frequency patterns during different game actions
   - Memory access patterns to inventory structures

4. **Validation Methods**:
   - Compare with Ghidra decompilation results
   - Verify return value structure matches discovered UnitAny
   - Cross-check with inventory manipulation traces
   - Validate null return handling

### Documentation Requirements
- Complete function signature
- Parameter/return value documentation
- Call frequency analysis
- Related function discovery

---

## Test Scenario 4: Game State Structure Discovery

### Objective
Discover and validate `GameStructInfo` (lines 50-60 in D2Structs.h)

### Test Procedure
1. **Target Structure**:
   - szGameName[0x18] at offset 0x1B
   - szAccountName[0x30] at offset 0x89
   - szCharName[0x18] at offset 0xB9
   - szGamePassword[0x18] at offset 0x23F

2. **Discovery Process**:
   ```
   Claude: Discover game session data structures containing player and game information
   ```

3. **Validation Strategy**:
   - String pattern recognition in memory dumps
   - Cross-reference with network packet analysis
   - Verify offsets by monitoring game joins/character selection
   - Compare string lengths and null termination

4. **Expected Outcomes**:
   - Accurate structure size (≥0x257 bytes)
   - Correct string field identification
   - Proper offset calculations
   - Network protocol correlation

---

## Test Scenario 5: Room/Level Structure Hierarchy

### Objective
Map the complex Room1 → Room2 → Level → Act structure chain

### Test Procedure
1. **Hierarchical Discovery**:
   ```
   Claude: Map level and room structure relationships for current game area
   ```

2. **Structure Chain Analysis**:
   - **Room1** (lines 317-334): 0x80 bytes, pRoom2 at 0x10
   - **Room2** (lines 294-314): 0x60 bytes, pLevel at 0x58
   - **Level** (lines 276-292): 0x1D4 bytes, pRoom2First at 0x10
   - **Act** (lines 347-355): Act management structure

3. **Validation Through Movement**:
   - Monitor structure changes during area transitions
   - Track pointer updates during room loading
   - Correlate with map/automap updates
   - Verify coordinate systems and boundaries

### Success Metrics
- Complete hierarchy mapping
- Pointer relationship accuracy >95%
- Movement tracking validation
- Area transition documentation

---

## Test Scenario 6: Exported Function Discovery

### Objective
Analyze undefined exported functions from D2Client.dll ordinals

### Test Procedure
1. **Target Functions**:
   - `Ordinal_10007(void)` - undefined __stdcall
   - `Ordinal_10010(int *param_1, uint param_2, int *param_3)` - return int*

2. **Analysis Process**:
   ```
   Claude: Analyze exported ordinal functions 10007 and 10010 to determine purpose and proper naming
   ```

3. **Discovery Methods**:
   - Monitor ordinal call patterns during gameplay
   - Analyze parameter patterns and return values
   - Cross-correlate with known D2 function behaviors
   - Compare with similar signatures in documented functions

4. **Naming Convention Analysis**:
   - Parameter type patterns suggest functionality
   - Call frequency indicates importance
   - Memory access patterns reveal data structure interactions
   - Compare with Ghidra analysis for additional context

### Expected Results
- Function purpose identification
- Proper naming suggestions (e.g., GetSomethingState, UpdateSomethingData)
- Parameter documentation
- Usage pattern analysis

---

## Test Scenario 7: Monster Data Structure Discovery

### Objective
Discover MonsterData structure (lines 515-534) and validate against gameplay

### Test Procedure
1. **Structure Discovery**:
   ```
   Claude: Discover monster/enemy data structures during combat encounters
   ```

2. **Key Fields to Validate**:
   - Boss/Champion flags at offset 0x16
   - Enchantments array at offset 0x1C
   - Unique monster number at offset 0x26
   - Monster name at offset 0x2C

3. **Validation Through Combat**:
   - Monitor structure during different monster encounters
   - Verify flag changes for boss/champion monsters
   - Track enchantment modifications
   - Correlate names with visual display

4. **Cross-Validation**:
   - Compare with monster behavior analysis
   - Verify against MonsterTxt references
   - Check stat calculation accuracy

---

## Test Scenario 8: Memory Pattern Recognition

### Objective
Test automated pattern recognition across multiple structure types simultaneously

### Test Procedure
1. **Multi-Structure Analysis**:
   ```
   Claude: Perform comprehensive memory pattern analysis to discover all major game structures
   ```

2. **Pattern Recognition Validation**:
   - Identify repeating byte patterns for structure arrays
   - Detect pointer signatures and relationships
   - Recognize string patterns and encoding
   - Find structure boundaries and padding

3. **Accuracy Testing**:
   - Compare discovered patterns against known structures
   - Validate structure size calculations
   - Check pointer arithmetic accuracy
   - Verify padding and alignment detection

### Success Criteria
- >80% structure discovery rate
- <5% false positive rate
- Accurate size and offset calculations
- Proper relationship mapping

---

## Test Scenario 9: API Call Chain Analysis

### Objective
Trace complete API call chains for complex operations (item pickup, skill usage, movement)

### Test Procedure
1. **Complex Operation Tracing**:
   ```
   Claude: Trace complete API call sequence for item pickup operation
   ```

2. **Call Chain Analysis**:
   - Monitor D2Client.dll, D2Common.dll, D2Net.dll interactions
   - Track parameter flow between function calls
   - Identify critical decision points and validation
   - Map error handling and edge cases

3. **Validation Methods**:
   - Compare with known game mechanics
   - Verify against network packet sequences
   - Cross-check with memory state changes
   - Validate against user input correlation

---

## Test Scenario 10: DLL Function Code Retrieval via Ghidra

### Objective
Retrieve assembly and decompiled C++ code for specific DLL functions using Ghidra through the MCP Coordinator

### Test Procedure
1. **Function Code Retrieval Request**:
   ```
   Claude: Retrieve assembly and C++ code for D2Client.dll function GetCursorItem using Ghidra analysis
   ```

2. **MCP Execution Flow**:
   - MCP Coordinator receives function analysis request
   - Routes request to Ghidra Analysis container (port 8002)
   - Ghidra headless analyzer processes D2Client.dll
   - Locates function by name or ordinal number
   - Extracts assembly instructions and decompiled C++ code
   - Returns structured response with both code representations

3. **Expected Response Format**:
   ```json
   {
     "function_name": "GetCursorItem",
     "dll_name": "D2Client.dll",
     "address": "0x6FAD1234",
     "assembly_code": [
       "push ebp",
       "mov ebp,esp",
       "mov eax,dword ptr [0x6FB12345]",
       "test eax,eax",
       "je LAB_6FAD1250",
       "ret"
     ],
     "cpp_code": "UnitAny* GetCursorItem(void) {\n  if (cursorItem != nullptr) {\n    return cursorItem;\n  }\n  return nullptr;\n}",
     "function_signature": "UnitAny* __stdcall GetCursorItem(void)",
     "cross_references": ["0x6FAD5678", "0x6FAD9ABC"],
     "analysis_confidence": 0.95
   }
   ```

4. **Test Cases to Validate**:
   - **Known Functions**: GetCursorItem, GetPlayerUnit, GetSelectedUnit
   - **Ordinal Functions**: Ordinal_10007, Ordinal_10010, Ordinal_10019
   - **Complex Functions**: Functions with multiple parameters and return values
   - **Error Cases**: Non-existent functions, invalid DLL names

### Validation Steps
1. **Assembly Code Accuracy**:
   - Verify assembly instructions are valid x86 opcodes
   - Check memory addresses are within DLL address space
   - Validate jump targets and branch instructions
   - Cross-reference with manual disassembly tools

2. **C++ Code Quality**:
   - Ensure decompiled code compiles without syntax errors
   - Verify function signatures match expected patterns
   - Check variable naming conventions and type inference
   - Validate control flow and logic structure

3. **Cross-Reference Validation**:
   - Verify all listed cross-references point to valid locations
   - Check that calling functions are correctly identified
   - Validate jump table and switch statement analysis

4. **Performance Testing**:
   - Measure response time for different function complexities
   - Test concurrent requests for multiple functions
   - Validate memory usage during large DLL analysis

### Success Criteria
- **Assembly Accuracy**: 100% valid opcodes and addressing
- **C++ Compilation**: Decompiled code compiles without errors
- **Response Time**: <30 seconds for simple functions, <2 minutes for complex functions
- **Cross-Reference Accuracy**: ≥95% correct function relationships
- **Error Handling**: Proper error messages for invalid requests

### Extended Test Cases

#### Test Case A: Ordinal Function Analysis
```
Claude: Analyze D2Client.dll Ordinal_10010 and provide both assembly and C++ representations
```

**Expected Challenges**:
- Ordinal functions lack symbolic names
- May require parameter type inference
- Return value analysis more complex

#### Test Case B: Multi-Parameter Function
```
Claude: Retrieve code for D2Common.dll function with signature "int SomeFunction(UnitAny* unit, int param1, void* param2)"
```

**Validation Points**:
- Parameter types correctly identified
- Stack frame analysis accurate
- Calling convention properly detected

#### Test Case C: Batch Function Analysis
```
Claude: Analyze multiple functions: GetCursorItem, GetPlayerUnit, Ordinal_10007, and Ordinal_10019 from D2Client.dll
```

**Performance Metrics**:
- Total analysis time for batch processing
- Memory usage patterns
- Concurrent processing efficiency

#### Test Case D: Cross-DLL Analysis
```
Claude: Analyze function relationships between D2Client.dll GetPlayerUnit and D2Common.dll unit manipulation functions
```

**Expected Outcomes**:
- Inter-DLL function call identification
- Parameter passing analysis between DLLs
- Data structure sharing detection

### Integration with Knowledge Graph
1. **Function Code Storage**:
   - Store assembly and C++ code in Dgraph
   - Create relationships between functions and data structures
   - Link function analysis to memory structure discoveries

2. **Version Tracking**:
   - Track code changes across different game versions
   - Maintain historical analysis data
   - Correlate with structure evolution

3. **Analysis Correlation**:
   - Link function code with memory pattern analysis
   - Connect API call traces to decompiled logic
   - Cross-reference with runtime behavior data

### Error Handling Test Cases
- **Invalid DLL Name**: Request analysis for non-existent DLL
- **Invalid Function Name**: Request function that doesn't exist
- **Corrupted Binary**: Analyze damaged or encrypted DLL
- **Resource Exhaustion**: Large batch requests exceeding system limits

### Expected Timeline
- **Simple Function**: 10-30 seconds (GetCursorItem)
- **Complex Function**: 1-2 minutes (multi-parameter functions)
- **Ordinal Analysis**: 30-60 seconds (requires more inference)
- **Batch Processing**: 2-5 minutes (multiple functions)

---

## Test Scenario 11: Real-time Knowledge Graph Construction

### Objective
Validate automated Dgraph knowledge graph construction during gameplay

### Test Procedure
1. **Live Knowledge Building**:
   ```
   Claude: Begin live knowledge graph construction session with comprehensive structure discovery
   ```

2. **Graph Validation**:
   - Monitor node creation rate and accuracy
   - Verify relationship establishment
   - Check cross-reference consistency
   - Validate knowledge persistence and retrieval

3. **Query Testing**:
   - Test complex graph queries for structure relationships
   - Verify historical data accuracy
   - Check performance under continuous updates
   - Validate data integrity across sessions

### Success Metrics
- >95% accurate node relationships
- Sub-second query response times
- Zero data corruption incidents
- Complete audit trail maintenance

---

## Test Scenario 12: DLL Function Enumeration and Analysis

### Objective
Retrieve and analyze a comprehensive list of all functions from D2Client.dll through the MCP Coordinator, including exported functions, internal functions, and ordinal-based functions.

### Test Procedure
1. **Initiate Function Discovery**:
   ```
   Claude: Use analyze_dll_functions tool to enumerate all functions in D2Client.dll
   ```

2. **MCP Tool Execution**:
   ```json
   {
     "tool": "analyze_dll_functions", 
     "arguments": {
       "dll_path": "/app/pd2/ProjectD2/D2Client.dll",
       "dll_name": "D2Client.dll",
       "include_exports": true,
       "include_internals": true,
       "include_ordinals": true
     }
   }
   ```

3. **Expected Analysis Process**:
   - Parse PE headers for exported function table
   - Use Ghidra headless analysis for internal function discovery
   - Extract function names, addresses, and signatures
   - Correlate with D2Ptrs.h reference data for validation
   - Identify ordinal-based functions and calling conventions

4. **Response Format**:
   ```json
   {
     "success": true,
     "dll_analysis": {
       "dll_name": "D2Client.dll",
       "total_functions": 2847,
       "exported_functions": 156,
       "internal_functions": 2691,
       "functions": {
         "_": {
           "___add_12": {
             "parameters": ["param_1", "param_2"]
           },
           "___addl": {
             "parameters": ["param_1", "param_2", "param_3"]
           },
           "___ascii_stricmp": {
             "parameters": ["_Str1", "_Str2"]
           },
           "___ascii_strnicmp": {
             "parameters": ["_Str1", "_Str2", "_MaxCount"]
           },
           "___crtExitProcess": {
             "parameters": ["param_1"]
           },
           "___crtGetEnvironmentStringsA": {
             "parameters": ["local_4", "local_8"]
           },
           "___crtGetStringTypeA": {
             "parameters": ["_Plocinfo", "_DWInfoType", "_LpSrcStr", "_CchSrc", "_LpCharType", "_Code_page", "_BError", "local_8", "local_1c", "local_20", "local_24", "local_28", "local_2c", "local_30", "local_3c"]
           },
           "___crtInitCritSecAndSpinCount": {
             "parameters": ["param_1", "param_2", "local_8", "local_24"]
           },
           "___crtInitCritSecNoSpinCount@8": {
             "parameters": ["param_1"]
           },
           "___crtMessageBoxA": {
             "parameters": ["_LpText", "_LpCaption", "_UType", "local_8", "local_c", "local_14"]
           }
         },
         "AdjustPointer": {
           "parameters": ["param_1", "param_2"]
         },
         "BuildCatchObject": {
           "parameters": ["param_1", "param_2", "param_3", "param_4", "local_8"]
         },
         "Ca": {
           "CallCatchBlock": {
             "parameters": ["param_1", "param_2", "param_3", "param_4", "param_5", "param_6", "param_7", "local_8", "local_24", "local_3c", "local_40", "local_44", "local_48", "local_4c", "local_54"]
           },
           "CatchIt": {
             "parameters": ["param_1", "param_2", "param_3", "param_4", "param_5", "param_6", "param_7", "param_8", "param_9", "param_10", "param_11"]
           }
         },
         "doexit": {
           "parameters": ["param_1", "param_2", "param_3", "local_8"]
         },
         "entry": {
           "parameters": ["param_1", "param_2", "param_3", "local_8", "local_20"]
         },
         "F": {
           "FID_conflict": {
             "_": {
               "FID_conflict:__fread_lk": {
                 "parameters": ["_DstBuf", "_ElementSize", "_Count", "_File", "local_8", "local_c"]
               },
               "FID_conflict:__ld12tod": {
                 "parameters": ["_Ifp", "_D"]
               },
               "FID_conflict:__lock_file2": {
                 "parameters": ["_Index", "_File"]
               },
               "FID_conflict:_CallMemberFunction1": {
                 "parameters": ["param_1", "UNRECOVERED_JUMPTABLE"]
               },
               "FID_conflict:_iscntrl": {
                 "parameters": ["_C"]
               },
               "FID_conflict:_ungetc": {
                 "parameters": ["_Ch", "_File"]
               }
             }
           },
           "FindHandler": {
             "FindHandler": {
               "parameters": ["param_1", "param_2", "param_3", "param_4", "param_5", "param_6", "param_7", "param_8", "local_5", "local_c", "local_10", "local_14", "local_18", "local_1c", "local_20", "local_24", "local_28"]
             },
             "FindHandlerForForeignException": {
               "parameters": ["param_1", "param_2", "param_3", "param_4", "param_5", "param_6", "param_7", "param_8", "local_8", "local_c"]
             }
           }
         }
       },
       "analysis_metadata": {
         "base_address": "0x6FA80000",
         "dll_size": "0x830000",
         "analysis_confidence": 0.94,
         "analysis_timestamp": "2025-08-28T14:15:30.123456",
         "validation_results": {
           "ghidra_functions_discovered": 2847,
           "categorized_functions": 2847,
           "function_hierarchy_depth": 8,
           "parameter_analysis_coverage": 0.89
         }
       }
     },
     "mcp_tool": "analyze_dll_functions",
     "execution_time": 24.67
   }
   ```

### Validation Steps
1. **Cross-Reference with D2Ptrs.h**:
   - Validate against known function definitions in D2Ptrs.h
   - Check offset accuracy (accounting for ASLR/base address differences)
   - Verify function signatures and calling conventions
   - Confirm ordinal-based function discoveries

2. **Function Classification**:
   - Exported functions (visible to other DLLs)
   - Internal functions (private to D2Client.dll)
   - Callback functions and event handlers
   - Import Address Table (IAT) functions

3. **Address Validation**:
   - Compare with static analysis results from Ghidra
   - Account for base address differences between environments
   - Validate function prologue/epilogue patterns
   - Check for function thunks and wrappers

4. **Signature Analysis**:
   - Verify calling conventions (__stdcall, __fastcall, __cdecl)
   - Validate parameter types and counts
   - Check return value types
   - Identify variadic functions

### Success Criteria
- **Function Discovery Rate**: ≥95% of known D2Ptrs.h functions found
- **Address Accuracy**: ≥90% correct relative offsets (accounting for base address)
- **Signature Accuracy**: ≥85% correct function signatures
- **Performance**: Complete analysis within 30 seconds
- **Classification Accuracy**: ≥90% correct function type classification

### Advanced Validation
1. **Dynamic Validation**:
   - Hook discovered functions during game execution
   - Validate parameter passing and return values
   - Confirm function behavior matches signatures

2. **Cross-DLL Analysis**:
   - Identify inter-DLL function calls
   - Map function dependencies (D2Client.dll → D2Common.dll calls)
   - Validate import tables and dynamic linking

3. **Knowledge Graph Integration**:
   - Store function relationships in Dgraph
   - Create call graph networks
   - Track function usage patterns
   - Enable semantic function search

### Expected Results
Based on D2Ptrs.h reference, the analysis should discover:
- **Core Player Functions**: GetPlayerUnit, GetCursorItem, GetSelectedUnit
- **UI Functions**: PrintGameString, DrawRectFrame, SetUIState
- **Game Control**: Attack, ExitGame, clickMap
- **Inventory Functions**: LeftClickItem, submitItem, InitInventory
- **Network Functions**: SendPacket, ReceivePacket (via D2Net references)

### Error Handling Validation
- Test with corrupted DLL files
- Test with missing DLL files
- Test with permission-denied scenarios
- Validate graceful failure modes and error reporting

### Documentation Requirements
- Complete function catalog with signatures
- Function usage frequency analysis
- Cross-reference mapping with D2Ptrs.h
- Function relationship diagrams
- Performance benchmarks and optimization recommendations

This test scenario validates the comprehensive DLL function enumeration capability of the MCP system, enabling complete reverse engineering analysis of Project Diablo 2's client library with automated function discovery, signature analysis, and cross-reference validation.

---

## Test Execution Framework

### Automated Test Runner
```python
class WineDebugTestRunner:
    def run_scenario(self, scenario_id: int) -> TestResult:
        # Execute MCP calls through Claude
        # Validate against reference data
        # Generate comprehensive report
        pass
```

### Validation Pipeline
1. **Structure Accuracy**: Compare against D2Structs.h reference
2. **Cross-Validation**: Ghidra analysis correlation
3. **Runtime Validation**: Memory dump verification
4. **Knowledge Graph**: Query accuracy and relationship integrity

### Reporting Format
- **Discovery Rate**: Percentage of structures found correctly
- **Accuracy Score**: Field-level accuracy against reference
- **Performance Metrics**: Time to discovery and validation
- **Knowledge Quality**: Graph completeness and accuracy

### Success Thresholds
- **Discovery Rate**: ≥85% for known structures
- **Field Accuracy**: ≥95% for critical fields
- **Performance**: <30 minutes per complex structure
- **Knowledge Graph**: ≥98% relationship accuracy

This comprehensive test suite validates the entire Wine Debug MCP integration pipeline, ensuring reliable automated reverse engineering capabilities for Project Diablo 2 analysis with complete function code retrieval and decompilation support.