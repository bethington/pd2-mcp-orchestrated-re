# Ghidra Function Enumeration Script
# This script extracts all functions from an analyzed binary
# @category: Analysis

import json
import os
from java.util import ArrayList
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType, RefType, SourceType
# from ghidra.program.model.symbol.Namespace import GlobalNamespace  # Not needed

def main():
    """Main function enumeration script called by Ghidra headless mode"""
    
    # Get command line arguments
    args = getScriptArgs()
    if len(args) < 4:
        print("Usage: function_enumeration.py <output_file> <include_exports> <include_internals> <include_ordinals>")
        return
        
    output_file = args[0]
    include_exports = args[1].lower() == "true"
    include_internals = args[2].lower() == "true"
    include_ordinals = args[3].lower() == "true"
    
    print("Starting function enumeration...")
    print("Include exports: " + str(include_exports))
    print("Include internals: " + str(include_internals))
    print("Include ordinals: " + str(include_ordinals))
    
    # Initialize results
    results = {
        "functions": [],
        "summary": {
            "total_functions": 0,
            "exported_functions": 0,
            "internal_functions": 0,
            "ordinal_functions": 0,
            "named_functions": 0,
            "analysis_timestamp": "",
            "binary_name": ""
        }
    }
    
    try:
        # Get current program
        program = getCurrentProgram()
        if not program:
            print("No program loaded")
            return
            
        results["summary"]["binary_name"] = program.getName()
        print("Analyzing binary: " + program.getName())
        
        # Get function manager
        function_manager = program.getFunctionManager()
        functions = function_manager.getFunctions(True)  # Get all functions
        
        # Get symbol table for export information
        symbol_table = program.getSymbolTable()
        
        function_list = []
        exported_count = 0
        internal_count = 0
        ordinal_count = 0
        named_count = 0
        
        for function in functions:
            try:
                func_name = function.getName()
                func_address = str(function.getEntryPoint())
                func_signature = str(function.getSignature())
                
                # Determine function type
                func_type = "internal"  # Default
                is_export = False
                ordinal = None
                references_count = 0
                
                # Check if function is exported
                symbols = symbol_table.getSymbols(function.getEntryPoint())
                for symbol in symbols:
                    if symbol.getSymbolType() == SymbolType.FUNCTION:
                        if symbol.isExternal() == False and symbol.isGlobal():
                            is_export = True
                            func_type = "exported"
                            break
                
                # Check for ordinal-based functions
                if "Ordinal_" in func_name or func_name.startswith("ORD"):
                    func_type = "ordinal"
                    # Try to extract ordinal number
                    try:
                        if "Ordinal_" in func_name:
                            ordinal = int(func_name.split("Ordinal_")[1])
                        ordinal_count += 1
                    except:
                        pass
                
                # Count references to this function
                reference_manager = program.getReferenceManager()
                refs_to = reference_manager.getReferencesTo(function.getEntryPoint())
                references_count = len(list(refs_to))
                
                # Count function types
                if func_type == "exported":
                    exported_count += 1
                elif func_type == "internal":
                    internal_count += 1
                    
                if not func_name.startswith("FUN_"):
                    named_count += 1
                
                # Create function entry
                func_entry = {
                    "name": func_name,
                    "address": func_address,
                    "type": func_type,
                    "signature": func_signature,
                    "ordinal": ordinal,
                    "references_count": references_count,
                    "parameter_count": function.getParameterCount(),
                    "has_return_value": not function.hasNoReturn(),
                    "calling_convention": str(function.getCallingConvention()),
                    "is_external": False,
                    "is_export": is_export
                }
                
                # Add size information
                func_body = function.getBody()
                if func_body:
                    func_entry["size_bytes"] = func_body.getNumAddresses()
                else:
                    func_entry["size_bytes"] = 0
                
                # Apply filters based on include flags
                should_include = False
                if func_type == "exported" and include_exports:
                    should_include = True
                elif func_type == "internal" and include_internals:
                    should_include = True
                elif func_type == "ordinal" and include_ordinals:
                    should_include = True
                
                if should_include:
                    function_list.append(func_entry)
                
            except Exception as e:
                print("Error processing function " + str(function.getName()) + ": " + str(e))
                continue
        
        # Update results
        results["functions"] = function_list
        results["summary"]["total_functions"] = len(function_list)
        results["summary"]["exported_functions"] = exported_count  
        results["summary"]["internal_functions"] = internal_count
        results["summary"]["ordinal_functions"] = ordinal_count
        results["summary"]["named_functions"] = named_count
        
        print("Found " + str(len(function_list)) + " functions matching criteria")
        print("Exported: " + str(exported_count))
        print("Internal: " + str(internal_count))
        print("Ordinal: " + str(ordinal_count))
        print("Named: " + str(named_count))
        
        # Write results to JSON file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        print("Function enumeration complete. Results written to " + output_file)
        
    except Exception as e:
        print("Function enumeration failed: " + str(e))
        # Write error to output file
        error_result = {
            "error": str(e), 
            "functions": [],
            "analysis_incomplete": True
        }
        with open(output_file, 'w') as f:
            json.dump(error_result, f, indent=2)

if __name__ == "__main__":
    main()