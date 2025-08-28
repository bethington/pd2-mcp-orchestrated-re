# Ghidra Function Decompilation Script
# This script decompiles a specific function and extracts pseudocode
# @category: Analysis

import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import GenericAddress

def main():
    """Main function decompilation script called by Ghidra headless mode"""
    
    # Get command line arguments
    args = getScriptArgs()
    if len(args) < 3:
        print("Usage: function_decompilation.py <output_file> <function_name> <function_address>")
        return
        
    output_file = args[0]
    function_name = args[1] if args[1] != "null" else None
    function_address = args[2] if args[2] != "null" else None
    
    print("Starting function decompilation...")
    print("Function name: " + str(function_name))
    print("Function address: " + str(function_address))
    
    # Initialize results
    results = {
        "function_name": function_name,
        "function_address": function_address,
        "success": False,
        "pseudocode": "",
        "assembly": [],
        "signature": "",
        "references": [],
        "called_functions": [],
        "local_variables": [],
        "parameters": [],
        "return_type": "",
        "analysis_metadata": {
            "decompilation_time_ms": 0,
            "analysis_confidence": 0.0,
            "ghidra_version": "11.0.1"
        }
    }
    
    try:
        # Get current program
        program = getCurrentProgram()
        if not program:
            print("No program loaded")
            results["error"] = "No program loaded"
            write_results(output_file, results)
            return
            
        print("Analyzing binary: " + program.getName())
        
        # Find the function to decompile
        target_function = find_target_function(program, function_name, function_address)
        if not target_function:
            error_msg = "Function not found: " + str(function_name if function_name else function_address)
            print(error_msg)
            results["error"] = error_msg
            write_results(output_file, results)
            return
        
        print("Found function: " + target_function.getName() + " at " + str(target_function.getEntryPoint()))
        
        # Extract basic function information
        results["function_name"] = target_function.getName()
        results["function_address"] = str(target_function.getEntryPoint())
        results["signature"] = str(target_function.getSignature())
        results["return_type"] = str(target_function.getReturnType()) if target_function.getReturnType() else "undefined"
        
        # Extract parameters
        parameters = target_function.getParameters()
        for param in parameters:
            param_info = {
                "name": param.getName(),
                "type": str(param.getDataType()),
                "ordinal": param.getOrdinal()
            }
            results["parameters"].append(param_info)
        
        # Extract local variables
        variables = target_function.getLocalVariables()
        for var in variables:
            var_info = {
                "name": var.getName(),
                "type": str(var.getDataType()),
                "stack_offset": var.getStackOffset() if hasattr(var, 'getStackOffset') else None
            }
            results["local_variables"].append(var_info)
        
        # Get assembly instructions
        results["assembly"] = extract_assembly(target_function)
        
        # Get cross-references
        results["references"] = extract_references(program, target_function)
        
        # Get called functions
        results["called_functions"] = extract_called_functions(program, target_function)
        
        # Perform decompilation
        start_time = java.lang.System.currentTimeMillis()
        pseudocode = decompile_function(program, target_function)
        end_time = java.lang.System.currentTimeMillis()
        
        if pseudocode:
            results["success"] = True
            results["pseudocode"] = pseudocode
            results["analysis_metadata"]["analysis_confidence"] = 0.85  # High confidence for successful decompilation
            print("Decompilation successful")
        else:
            results["error"] = "Decompilation failed - function may be too complex or corrupted"
            results["analysis_metadata"]["analysis_confidence"] = 0.0
            print("Decompilation failed")
        
        results["analysis_metadata"]["decompilation_time_ms"] = int(end_time - start_time)
        
        # Write results to JSON file
        write_results(output_file, results)
        print("Function decompilation complete. Results written to " + output_file)
        
    except Exception as e:
        print("Function decompilation failed: " + str(e))
        results["error"] = str(e)
        results["analysis_metadata"]["analysis_confidence"] = 0.0
        write_results(output_file, results)

def find_target_function(program, function_name, function_address):
    """Find the target function by name or address"""
    function_manager = program.getFunctionManager()
    
    # Try to find by address first (most reliable)
    if function_address:
        try:
            if function_address.startswith("0x"):
                addr_value = long(function_address, 16)
            else:
                addr_value = long(function_address, 16)
            
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value)
            function = function_manager.getFunctionAt(address)
            if function:
                return function
                
            # Try to find function containing this address
            function = function_manager.getFunctionContaining(address)
            if function:
                return function
                
        except Exception as e:
            print("Error parsing address: " + str(e))
    
    # Try to find by name
    if function_name:
        functions = function_manager.getFunctions(True)
        for function in functions:
            if function.getName() == function_name:
                return function
            # Try partial name match
            if function_name.lower() in function.getName().lower():
                return function
    
    return None

def extract_assembly(function):
    """Extract assembly instructions from function"""
    assembly_lines = []
    
    try:
        instruction_set = function.getProgram().getListing().getInstructions(function.getBody(), True)
        count = 0
        for instruction in instruction_set:
            if count >= 50:  # Limit to first 50 instructions
                break
            
            asm_line = {
                "address": str(instruction.getAddress()),
                "mnemonic": instruction.getMnemonicString(),
                "operands": str(instruction.getDefaultOperandRepresentation(0)) if instruction.getNumOperands() > 0 else "",
                "full_instruction": str(instruction)
            }
            assembly_lines.append(asm_line)
            count += 1
            
    except Exception as e:
        print("Error extracting assembly: " + str(e))
    
    return assembly_lines

def extract_references(program, function):
    """Extract cross-references to/from the function"""
    references = []
    
    try:
        reference_manager = program.getReferenceManager()
        
        # References TO this function
        refs_to = reference_manager.getReferencesTo(function.getEntryPoint())
        for ref in refs_to:
            ref_info = {
                "type": "reference_to",
                "from_address": str(ref.getFromAddress()),
                "reference_type": str(ref.getReferenceType())
            }
            references.append(ref_info)
            if len(references) >= 20:  # Limit to first 20
                break
                
        # References FROM this function  
        refs_from = reference_manager.getReferencesFrom(function.getEntryPoint())
        for ref in refs_from:
            ref_info = {
                "type": "reference_from", 
                "to_address": str(ref.getToAddress()),
                "reference_type": str(ref.getReferenceType())
            }
            references.append(ref_info)
            if len(references) >= 40:  # Total limit of 40
                break
                
    except Exception as e:
        print("Error extracting references: " + str(e))
    
    return references

def extract_called_functions(program, function):
    """Extract functions called by this function"""
    called_functions = []
    
    try:
        reference_manager = program.getReferenceManager()
        function_manager = program.getFunctionManager()
        
        # Get all instructions in the function
        instruction_set = program.getListing().getInstructions(function.getBody(), True)
        for instruction in instruction_set:
            # Get references from each instruction
            refs = reference_manager.getReferencesFrom(instruction.getAddress())
            for ref in refs:
                if ref.getReferenceType().isCall():
                    target_function = function_manager.getFunctionAt(ref.getToAddress())
                    if target_function:
                        func_info = {
                            "name": target_function.getName(),
                            "address": str(target_function.getEntryPoint()),
                            "call_address": str(ref.getFromAddress())
                        }
                        called_functions.append(func_info)
                        
                        if len(called_functions) >= 10:  # Limit to 10 called functions
                            return called_functions
                        
    except Exception as e:
        print("Error extracting called functions: " + str(e))
    
    return called_functions

def decompile_function(program, function):
    """Decompile the function to C pseudocode"""
    try:
        # Initialize decompiler
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        
        # Try to set decompiler options (may fail in some Ghidra versions)
        try:
            options = decompiler.getOptions()
            if options:
                options.setDefaultTimeout(30)  # 30 second timeout
        except:
            print("Could not set decompiler options - using defaults")
        
        # Decompile the function
        print("Starting decompilation of function: " + function.getName())
        result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
        
        if result and result.decompileCompleted():
            # Get the C code
            decompiled_function = result.getDecompiledFunction()
            if decompiled_function:
                c_code = decompiled_function.getC()
                print("Decompilation successful")
                
                # Clean up the decompiler
                decompiler.closeProgram()
                
                return str(c_code)
            else:
                print("Decompiled function is null")
        else:
            error_msg = "Decompilation incomplete"
            if result and result.getErrorMessage():
                error_msg += ": " + result.getErrorMessage()
            print(error_msg)
        
        # Clean up the decompiler
        decompiler.closeProgram()
        return None
            
    except Exception as e:
        print("Decompilation error: " + str(e))
        return None

def write_results(output_file, results):
    """Write results to JSON file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    except Exception as e:
        print("Error writing results: " + str(e))

if __name__ == "__main__":
    main()