# Ghidra Project Export Script
# This script exports a Ghidra project analysis for persistence
# @category: Export

import json
import os
from ghidra.app.util.exporter import GhidraScriptExporter
from ghidra.program.model.listing import Program

def main():
    """Export Ghidra project analysis to JSON format"""
    
    # Get command line arguments
    args = getScriptArgs()
    if len(args) < 1:
        print("Usage: export_project.py <output_file>")
        return
        
    output_file = args[0]
    
    print("Starting project export...")
    
    # Get current program
    program = getCurrentProgram()
    if not program:
        print("No program loaded")
        return
    
    # Initialize export data
    export_data = {
        "program_name": program.getName(),
        "program_path": str(program.getExecutablePath()) if program.getExecutablePath() else "",
        "creation_date": str(program.getCreationDate()),
        "language": str(program.getLanguage()),
        "compiler": str(program.getCompilerSpec()),
        "image_base": str(program.getImageBase()),
        "min_address": str(program.getMinAddress()),
        "max_address": str(program.getMaxAddress()),
        "functions": [],
        "data_types": [],
        "symbols": [],
        "memory_blocks": [],
        "analysis_options": {}
    }
    
    try:
        # Export function information
        function_manager = program.getFunctionManager()
        functions = function_manager.getFunctions(True)
        
        function_count = 0
        for function in functions:
            if function_count >= 100:  # Limit to prevent large files
                break
                
            try:
                func_data = {
                    "name": function.getName(),
                    "address": str(function.getEntryPoint()),
                    "signature": str(function.getSignature()),
                    "return_type": str(function.getReturnType()) if function.getReturnType() else "undefined",
                    "parameter_count": function.getParameterCount(),
                    "has_return": not function.hasNoReturn(),
                    "calling_convention": str(function.getCallingConvention()) if function.getCallingConvention() else "unknown"
                }
                
                # Get function body size
                body = function.getBody()
                if body:
                    func_data["size_bytes"] = body.getNumAddresses()
                else:
                    func_data["size_bytes"] = 0
                
                export_data["functions"].append(func_data)
                function_count += 1
                
            except Exception as e:
                print("Error processing function: " + str(e))
                continue
        
        # Export memory blocks
        memory = program.getMemory()
        blocks = memory.getBlocks()
        
        for block in blocks:
            try:
                block_data = {
                    "name": block.getName(),
                    "start_address": str(block.getStart()),
                    "end_address": str(block.getEnd()),
                    "size": block.getSize(),
                    "type": str(block.getType()) if hasattr(block, 'getType') else "UNKNOWN",
                    "permissions": {
                        "read": block.isRead(),
                        "write": block.isWrite(),
                        "execute": block.isExecute()
                    }
                }
                export_data["memory_blocks"].append(block_data)
                
            except Exception as e:
                print("Error processing memory block: " + str(e))
                continue
        
        # Export symbols (limited)
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getAllSymbols(True)
        
        symbol_count = 0
        for symbol in symbols:
            if symbol_count >= 50:  # Limit symbols
                break
                
            try:
                symbol_data = {
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "namespace": str(symbol.getParentNamespace()),
                    "symbol_type": str(symbol.getSymbolType()),
                    "is_external": symbol.isExternal(),
                    "is_global": symbol.isGlobal()
                }
                export_data["symbols"].append(symbol_data)
                symbol_count += 1
                
            except Exception as e:
                print("Error processing symbol: " + str(e))
                continue
        
        # Export analysis summary
        export_data["analysis_summary"] = {
            "total_functions": len(export_data["functions"]),
            "total_symbols": len(export_data["symbols"]),
            "total_memory_blocks": len(export_data["memory_blocks"]),
            "program_size": export_data["max_address"],
            "export_timestamp": str(java.util.Date())
        }
        
        # Write to JSON file
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print("Project export completed successfully")
        print("Functions exported: " + str(len(export_data["functions"])))
        print("Symbols exported: " + str(len(export_data["symbols"])))
        print("Memory blocks exported: " + str(len(export_data["memory_blocks"])))
        print("Output file: " + output_file)
        
    except Exception as e:
        print("Project export failed: " + str(e))
        # Write error result
        error_data = {
            "error": str(e),
            "program_name": program.getName() if program else "Unknown"
        }
        with open(output_file, 'w') as f:
            json.dump(error_data, f, indent=2)

if __name__ == "__main__":
    main()