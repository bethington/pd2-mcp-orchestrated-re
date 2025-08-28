# Ghidra Analysis Script - Comprehensive Binary Analysis
# This script runs inside Ghidra's headless environment
# @category: Analysis

import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import DataType

def main():
    """Main analysis function called by Ghidra headless mode"""
    
    # Get command line arguments
    args = getScriptArgs()
    if len(args) < 3:
        print("Usage: comprehensive_analysis.py <output_file> <decompile_file> <analysis_depth>")
        return
        
    output_file = args[0]
    decompile_file = args[1] 
    analysis_depth = args[2]
    
    print("Starting comprehensive analysis with depth: " + str(analysis_depth))
    
    # Initialize analysis results
    results = {
        "binary_info": {},
        "functions": [],
        "strings": [],
        "imports": [],
        "exports": [],
        "data_types": [],
        "memory_blocks": [],
        "cross_references": [],
        "statistics": {}
    }
    
    try:
        # Get current program
        program = getCurrentProgram()
        if not program:
            print("No program loaded")
            return
            
        # Basic program information
        results["binary_info"] = {
            "name": program.getName(),
            "executable_path": str(program.getExecutablePath()),
            "language": str(program.getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": hex(program.getImageBase().getOffset()),
            "min_address": str(program.getMinAddress()),
            "max_address": str(program.getMaxAddress())
        }
        
        print("Analyzing functions...")
        analyze_functions(program, results, analysis_depth)
        
        if analysis_depth in ["detailed", "comprehensive"]:
            print("Analyzing strings...")
            analyze_strings(program, results)
            
            print("Analyzing imports and exports...")
            analyze_imports_exports(program, results)
            
            print("Analyzing memory blocks...")
            analyze_memory_blocks(program, results)
            
        if analysis_depth == "comprehensive":
            print("Analyzing data types...")
            analyze_data_types(program, results)
            
            print("Analyzing cross references...")
            analyze_cross_references(program, results)
            
            print("Decompiling main functions...")
            decompile_main_functions(program, decompile_file)
            
        # Generate statistics
        results["statistics"] = {
            "total_functions": len(results["functions"]),
            "total_strings": len(results["strings"]),
            "total_imports": len(results["imports"]),
            "total_exports": len(results["exports"]),
            "analysis_depth": analysis_depth
        }
        
        # Write results to JSON file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        print("Analysis complete. Results written to " + str(output_file))
        
    except Exception as e:
        print("Analysis failed: " + str(e))
        # Write error to output file
        error_result = {"error": str(e), "analysis_incomplete": True}
        with open(output_file, 'w') as f:
            json.dump(error_result, f, indent=2)

def analyze_functions(program, results, analysis_depth):
    """Analyze all functions in the program"""
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # Get all functions
    
    for function in functions:
        func_data = {
            "name": function.getName(),
            "address": str(function.getEntryPoint()),
            "size": function.getBody().getNumAddresses(),
            "signature": str(function.getSignature()),
            "calling_convention": str(function.getCallingConvention()),
            "parameter_count": function.getParameterCount(),
            "local_variables": function.getLocalVariables().length if hasattr(function.getLocalVariables(), 'length') else 0
        }
        
        # Add detailed analysis for comprehensive mode
        if analysis_depth == "comprehensive":
            func_data.update({
                "stack_frame_size": function.getStackFrame().getFrameSize() if function.getStackFrame() else 0,
                "has_varargs": function.hasVarArgs(),
                "is_thunk": function.isThunk(),
                "call_fixup": str(function.getCallFixup()) if function.getCallFixup() else None
            })
            
        results["functions"].append(func_data)

def analyze_strings(program, results):
    """Extract string data from the program"""
    listing = program.getListing()
    data_iterator = listing.getDefinedData(True)
    
    for data in data_iterator:
        data_type = data.getDataType()
        if data_type and ("string" in str(data_type).lower() or "ascii" in str(data_type).lower()):
            string_data = {
                "address": str(data.getAddress()),
                "value": str(data.getValue()) if data.getValue() else "",
                "type": str(data_type),
                "length": data.getLength()
            }
            results["strings"].append(string_data)

def analyze_imports_exports(program, results):
    """Analyze import and export tables"""
    symbol_table = program.getSymbolTable()
    
    # Analyze external symbols (imports)
    external_symbols = symbol_table.getExternalSymbols()
    for symbol in external_symbols:
        import_data = {
            "name": symbol.getName(),
            "address": str(symbol.getAddress()) if symbol.getAddress() else "external",
            "source": str(symbol.getSource()),
            "library": str(symbol.getParentNamespace().getName()) if symbol.getParentNamespace() else "unknown"
        }
        results["imports"].append(import_data)
    
    # Analyze exports (global symbols)
    global_symbols = symbol_table.getGlobalSymbols("*")
    for symbol in global_symbols:
        if symbol.getSymbolType() == SymbolType.FUNCTION or symbol.getSymbolType() == SymbolType.LABEL:
            if not symbol.isExternal():
                export_data = {
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "type": str(symbol.getSymbolType())
                }
                results["exports"].append(export_data)

def analyze_memory_blocks(program, results):
    """Analyze memory block layout"""
    memory = program.getMemory()
    blocks = memory.getBlocks()
    
    for block in blocks:
        block_data = {
            "name": block.getName(),
            "start_address": str(block.getStart()),
            "end_address": str(block.getEnd()),
            "size": block.getSize(),
            "type": str(block.getType()),
            "permissions": {
                "read": block.isRead(),
                "write": block.isWrite(),
                "execute": block.isExecute()
            },
            "initialized": block.isInitialized(),
            "comment": block.getComment() if block.getComment() else ""
        }
        results["memory_blocks"].append(block_data)

def analyze_data_types(program, results):
    """Analyze defined data types"""
    data_type_manager = program.getDataTypeManager()
    all_data_types = data_type_manager.getAllDataTypes()
    
    for data_type in all_data_types:
        if not data_type.getName().startswith("__"):  # Skip internal types
            type_data = {
                "name": data_type.getName(),
                "category": str(data_type.getCategoryPath()),
                "size": data_type.getLength(),
                "description": data_type.getDescription() if hasattr(data_type, 'getDescription') else ""
            }
            results["data_types"].append(type_data)
            
            # Limit to avoid excessive data
            if len(results["data_types"]) > 100:
                break

def analyze_cross_references(program, results):
    """Analyze cross-references between functions and data"""
    reference_manager = program.getReferenceManager()
    
    # Get references for main functions
    function_manager = program.getFunctionManager()
    functions = list(function_manager.getFunctions(True))
    
    # Limit analysis to first 20 functions to avoid excessive data
    for function in functions[:20]:
        refs_from = reference_manager.getReferencesFrom(function.getEntryPoint())
        refs_to = reference_manager.getReferencesTo(function.getEntryPoint())
        
        xref_data = {
            "function": function.getName(),
            "address": str(function.getEntryPoint()),
            "references_from": [str(ref.getToAddress()) for ref in refs_from],
            "references_to": [str(ref.getFromAddress()) for ref in refs_to]
        }
        results["cross_references"].append(xref_data)

def decompile_main_functions(program, decompile_file):
    """Decompile main functions to C code"""
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    
    function_manager = program.getFunctionManager()
    functions = list(function_manager.getFunctions(True))
    
    decompiled_code = "// Decompiled C Code\n\n"
    
    # Decompile first 5 functions
    for i, function in enumerate(functions[:5]):
        try:
            decompiled_code += f"// Function: {function.getName()} @ {function.getEntryPoint()}\n"
            
            result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
            if result and result.decompileCompleted():
                c_code = result.getDecompiledFunction().getC()
                decompiled_code += c_code + "\n\n"
            else:
                decompiled_code += f"// Failed to decompile {function.getName()}\n\n"
                
        except Exception as e:
            decompiled_code += f"// Error decompiling {function.getName()}: {str(e)}\n\n"
    
    # Write decompiled code to file
    with open(decompile_file, 'w') as f:
        f.write(decompiled_code)
    
    decompiler.closeProgram()

if __name__ == "__main__":
    main()