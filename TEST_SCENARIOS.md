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

## Test Scenario 10: Real-time Knowledge Graph Construction

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

This comprehensive test suite validates the entire Wine Debug MCP integration pipeline, ensuring reliable automated reverse engineering capabilities for Project Diablo 2 analysis.