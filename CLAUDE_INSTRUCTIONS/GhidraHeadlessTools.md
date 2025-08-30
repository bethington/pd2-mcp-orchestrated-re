# Ghidra Headless Tools for Project Diablo 2

Create fully functional, production-ready Ghidra headless tools for ProjectD2 with complete file I/O operations.

## Critical Requirements

- All tools must perform actual file system operations (no mock data)
- Must include comprehensive error handling and logging
- Output files must be written to disk with specified schemas
- Include validation that verifies output file contents

## MCP Tools to Implement

### 1. import_pd2_binaries

- Scan `/app/pd2/ProjectD2` directory for all .exe/.dll files (matches actual directory structure)
- Create/open Ghidra 'pd2' project at `/app/project` (matches volume mount `./data/outputs/ghidra/projects:/app/project:rw`)
- Import each binary with auto-analysis disabled
- analyzeHeadless /app/project pd2 -import /app/pd2/ProjectD2/*.{exe,dll} -noanalysis

### 2. analyze_pd2_binaries

- Open existing project at `data/outputs/ghidra/projects/pd2`
- Run AutoAnalysisManager.scheduleAnalysis() on each program
- Wait for analysis completion before proceeding
- Log analysis completion status

### 3. export_pd2_binaries

Extract and write actual data (not placeholders) to files with the following specifications:

#### JSON Outputs

Specify exact schema for:

- Functions: {name, address, signature, parameters, returnType, callers, callees}
- Structures: {name, size, fields[{name, type, offset}]}
- Instructions: {address, mnemonic, operands[], bytes[]}
- Strings: {value, address, encoding, references[]}

#### File Structure

```text
data/outputs/
 ├── metadata/
 │   ├── binaries.json              # Binary metadata (names, sizes, checksums)
 │   └── analysis_report.json       # Analysis summary and statistics
 ├── functions/
 │   ├── [binary_name]_functions.json    # Complete function data
 │   ├── [binary_name]_functions.parquet # Functions (high-performance queries)
 │   └── functions_summary.csv           # Functions overview (Excel-friendly)
 ├── structures/
 │   ├── [binary_name]_structures.json   # Data types and structures
 │   ├── [binary_name]_types.h          # C header definitions
 │   └── structures_summary.csv          # Structure overview
 ├── disassembly/
 │   ├── [binary_name]_full.asm         # Complete disassembly
 │   ├── [binary_name]_instructions.parquet # Instructions (analytical queries)
 │   └── [binary_name]_cfg.dot          # Control Flow Graph (Graphviz)
 ├── strings/
 │   ├── [binary_name]_strings.json     # String data with metadata
 │   ├── [binary_name]_strings.txt      # Plain strings (grep-friendly)
 │   └── strings_summary.csv            # Strings overview
 ├── cross_references/
 │   ├── [binary_name]_xrefs.json       # Complete cross-reference data
 │   ├── [binary_name]_calls.gml        # Call graph (graph analysis)
 │   └── xrefs_summary.csv              # XRef overview
 ├── decompiled/
 │   ├── [binary_name]/                 # Per-binary folder
 │   │   ├── functions/                 # Individual function files
 │   │   │   ├── main.c                 # Decompiled functions
 │   │   │   └── sub_401000.c
 │   │   └── [binary_name]_full.c       # Complete decompiled code
 ├── comments/
 │   ├── [binary_name]_comments.json    # All comment types
 │   └── comments_summary.csv           # Comments overview
 └── dgraph/
     ├── schema.dgraph                   # Dgraph schema definition
     ├── nodes.rdf                      # Nodes in RDF format
     ├── edges.rdf                      # Edges in RDF format
     └── bulk_loader/
         ├── [binary_name]_nodes.json   # JSON bulk loader nodes
         └── [binary_name]_edges.json   # JSON bulk loader edges
```

## Exact Schemas

### Functions JSON

```json
{
  "metadata": {
    "binary": "game.exe",
    "export_time": "2025-08-29T10:00:00Z",
    "function_count": 1250
  },
  "functions": [{
    "name": "main",
    "address": "0x401000",
    "end_address": "0x40109C",
    "size": 156,
    "signature": "int main(int argc, char** argv)",
    "parameters": [
      {"name": "argc", "type": "int", "register": "ECX"},
      {"name": "argv", "type": "char**", "register": "EDX"}
    ],
    "return_type": "int",
    "calling_convention": "stdcall",
    "callers": ["0x402000", "0x402100"],
    "callees": ["0x401100", "0x401200"],
    "basic_blocks": ["0x401000", "0x401020", "0x401050"],
    "stack_frame_size": 32,
    "has_varargs": false
  }]
}
```

### Parquet Schema (Functions)

```text
name: string
address: uint64
size: uint32
caller_count: uint16
callee_count: uint16
complexity: float32
binary: string
```

### Instructions Parquet Schema

```text
address: uint64
mnemonic: string
operand1: string
operand2: string
operand3: string
bytes: binary
size: uint8
binary: string
function_address: uint64
```

### Dgraph RDF Format

```rdf
<0x401000> <dgraph.type> "Function" .
<0x401000> <name> "main" .
<0x401000> <address> "0x401000" .
<0x401000> <calls> <0x401100> .
```

## Folder Organization Benefits

- **Type-based separation** - Easy to find specific data types
- **Format variety** - Multiple formats per data type for different use cases
- **Scalability** - Handles large projects with many binaries
- **Tool integration** - Formats chosen for specific tool ecosystems
- **Performance** - Parquet for fast analytical queries, CSV for quick viewing

## Validation Requirements

- Verify file existence and non-zero size for all outputs
- Validate JSON against schemas using JSON Schema validation
- Check Parquet file integrity and record counts
- Verify ASM syntax correctness
- Validate C header compilation
- Check DOT/GML graph format validity
- Ensure RDF triple format compliance
