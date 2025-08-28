#!/usr/bin/env python3
"""
Wine-Ghidra MCP Integration Tools
Provides Claude AI with access to Ghidra reverse engineering capabilities via MCP protocol
"""

import asyncio
import aiohttp
import json
import logging
from typing import Dict, List, Optional, Any, Union
import structlog
from pathlib import Path

logger = structlog.get_logger()

class GhidraMCPTools:
    """MCP Tools for integrating Ghidra static analysis with Wine dynamic analysis"""
    
    def __init__(self, ghidra_server_url: str = "http://ghidra-analysis:8002"):
        """
        Initialize Ghidra MCP Tools
        
        Args:
            ghidra_server_url: URL of the Ghidra analysis server
        """
        self.ghidra_server_url = ghidra_server_url
        self.session = None
        self.current_binary = None
        self.current_context = None
        
    async def get_session(self):
        """Get or create aiohttp session"""
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def close(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Return list of available MCP tools for Claude"""
        return [
            {
                "name": "setup_context",
                "description": "Run Ghidra on a binary to set up analysis context",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string", 
                            "description": "Path to binary file (e.g., /analysis/d2_binaries/D2Client.dll)"
                        },
                        "analysis_type": {
                            "type": "string",
                            "enum": ["basic", "detailed", "comprehensive"],
                            "default": "detailed",
                            "description": "Depth of analysis to perform"
                        }
                    },
                    "required": ["binary_path"]
                }
            },
            {
                "name": "list_functions",
                "description": "Get list of all functions in the current binary",
                "input_schema": {
                    "type": "object", 
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Binary path (uses current context if not specified)"
                        },
                        "include_exports": {
                            "type": "boolean",
                            "default": True,
                            "description": "Include exported functions"
                        },
                        "include_internals": {
                            "type": "boolean", 
                            "default": True,
                            "description": "Include internal functions"
                        },
                        "include_ordinals": {
                            "type": "boolean",
                            "default": True, 
                            "description": "Include ordinal functions"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "get_pseudocode",
                "description": "Get decompiled pseudocode for a specific function",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Name of function to decompile (e.g., 'GetCursorItem')"
                        },
                        "function_address": {
                            "type": "string", 
                            "description": "Address of function (alternative to name, e.g., '0x10001000')"
                        },
                        "binary_path": {
                            "type": "string",
                            "description": "Binary path (uses current context if not specified)"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "list_structures",
                "description": "Get list of all data structures/types in the binary",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Binary path (uses current context if not specified)"
                        },
                        "include_builtin": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include built-in system structures"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "get_structure",
                "description": "Get detailed information about a specific structure/type",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "structure_name": {
                            "type": "string",
                            "description": "Name of structure to analyze"
                        },
                        "binary_path": {
                            "type": "string", 
                            "description": "Binary path (uses current context if not specified)"
                        }
                    },
                    "required": ["structure_name"]
                }
            },
            {
                "name": "list_enums",
                "description": "Get list of all enumerations in the binary", 
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Binary path (uses current context if not specified)"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "get_enum",
                "description": "Get values and details of a specific enumeration",
                "input_schema": {
                    "type": "object", 
                    "properties": {
                        "enum_name": {
                            "type": "string",
                            "description": "Name of enumeration to analyze"
                        },
                        "binary_path": {
                            "type": "string",
                            "description": "Binary path (uses current context if not specified)"
                        }
                    },
                    "required": ["enum_name"]
                }
            },
            {
                "name": "list_function_definitions",
                "description": "Get function prototypes/signatures for all functions",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string", 
                            "description": "Binary path (uses current context if not specified)"
                        },
                        "filter_pattern": {
                            "type": "string",
                            "description": "Optional regex pattern to filter function names"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "get_function_definition",
                "description": "Get detailed function signature including return type and parameters",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Name of function to get signature for"
                        },
                        "binary_path": {
                            "type": "string",
                            "description": "Binary path (uses current context if not specified)"
                        }
                    },
                    "required": ["function_name"]
                }
            }
        ]
    
    async def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP tool calls from Claude"""
        try:
            if tool_name == "setup_context":
                return await self.setup_context(**arguments)
            elif tool_name == "list_functions":
                return await self.list_functions(**arguments)  
            elif tool_name == "get_pseudocode":
                return await self.get_pseudocode(**arguments)
            elif tool_name == "list_structures":
                return await self.list_structures(**arguments)
            elif tool_name == "get_structure":
                return await self.get_structure(**arguments)
            elif tool_name == "list_enums":
                return await self.list_enums(**arguments)
            elif tool_name == "get_enum":
                return await self.get_enum(**arguments)
            elif tool_name == "list_function_definitions":
                return await self.list_function_definitions(**arguments)
            elif tool_name == "get_function_definition":
                return await self.get_function_definition(**arguments)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
                
        except Exception as e:
            logger.error("Tool call failed", tool=tool_name, error=str(e))
            return {"error": f"Tool execution failed: {str(e)}"}
    
    async def setup_context(self, binary_path: str, analysis_type: str = "detailed") -> Dict[str, Any]:
        """
        Run Ghidra on a binary to establish analysis context
        
        Args:
            binary_path: Path to binary file
            analysis_type: Depth of analysis (basic, detailed, comprehensive)
            
        Returns:
            Analysis setup results
        """
        logger.info("Setting up Ghidra context", binary=binary_path, analysis=analysis_type)
        
        session = await self.get_session()
        
        try:
            # Start Ghidra analysis
            async with session.post(
                f"{self.ghidra_server_url}/analyze/binary",
                json={
                    "binary_path": binary_path,
                    "analysis_type": analysis_type,
                    "include_decompilation": True,
                    "include_strings": True
                }
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    analysis_id = result.get("analysis_id")
                    
                    # Wait for analysis completion (with timeout)
                    max_wait = 600  # 10 minutes
                    wait_time = 0
                    
                    while wait_time < max_wait:
                        await asyncio.sleep(10)  # Check every 10 seconds
                        wait_time += 10
                        
                        async with session.get(
                            f"{self.ghidra_server_url}/analyze/status/{analysis_id}"
                        ) as status_response:
                            if status_response.status == 200:
                                status_data = await status_response.json()
                                
                                if status_data["status"] == "completed":
                                    self.current_binary = binary_path
                                    self.current_context = analysis_id
                                    
                                    return {
                                        "success": True,
                                        "binary_path": binary_path,
                                        "analysis_id": analysis_id,
                                        "analysis_type": analysis_type,
                                        "status": "Context established successfully",
                                        "estimated_functions": "Analyzing...",
                                        "next_steps": [
                                            "Use list_functions() to see all available functions",
                                            "Use get_pseudocode(function_name) to decompile specific functions",
                                            "Use list_structures() to see data types"
                                        ]
                                    }
                                elif status_data["status"] == "failed":
                                    return {
                                        "error": f"Analysis failed: {status_data.get('error_message', 'Unknown error')}",
                                        "binary_path": binary_path
                                    }
                    
                    return {
                        "error": "Analysis timeout - taking longer than expected",
                        "binary_path": binary_path,
                        "analysis_id": analysis_id,
                        "suggestion": "Check status manually or try with basic analysis_type"
                    }
                    
                else:
                    error_data = await response.json()
                    return {
                        "error": f"Failed to start analysis: {error_data.get('detail', 'Unknown error')}",
                        "binary_path": binary_path
                    }
                    
        except Exception as e:
            return {
                "error": f"Connection to Ghidra server failed: {str(e)}",
                "binary_path": binary_path,
                "server_url": self.ghidra_server_url
            }
    
    async def list_functions(self, binary_path: Optional[str] = None, 
                           include_exports: bool = True, 
                           include_internals: bool = True,
                           include_ordinals: bool = True) -> Dict[str, Any]:
        """Get list of all functions in binary"""
        
        if binary_path is None:
            binary_path = self.current_binary
            
        if binary_path is None:
            return {
                "error": "No binary context set. Use setup_context() first.",
                "suggestion": "Call setup_context(binary_path) to establish analysis context"
            }
        
        session = await self.get_session()
        
        try:
            # Extract DLL name from path
            dll_name = Path(binary_path).stem
            
            async with session.post(
                f"{self.ghidra_server_url}/analyze/functions", 
                json={
                    "binary_path": binary_path,
                    "dll_name": dll_name,
                    "include_exports": include_exports,
                    "include_internals": include_internals, 
                    "include_ordinals": include_ordinals
                }
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    functions = result.get("functions", [])
                    
                    return {
                        "success": True,
                        "binary_path": binary_path,
                        "total_functions": len(functions),
                        "functions": functions,
                        "summary": {
                            "exported": len([f for f in functions if f.get("is_export", False)]),
                            "internal": len([f for f in functions if not f.get("is_export", False)]),
                            "with_names": len([f for f in functions if not f.get("name", "").startswith("FUN_")]),
                            "ordinals": len([f for f in functions if "Ordinal_" in f.get("name", "")])
                        }
                    }
                else:
                    error_data = await response.json()
                    return {"error": f"Function listing failed: {error_data.get('detail', 'Unknown error')}"}
                    
        except Exception as e:
            return {"error": f"Failed to list functions: {str(e)}"}
    
    async def get_pseudocode(self, function_name: Optional[str] = None,
                           function_address: Optional[str] = None, 
                           binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Get decompiled pseudocode for a function"""
        
        if binary_path is None:
            binary_path = self.current_binary
            
        if binary_path is None:
            return {
                "error": "No binary context set. Use setup_context() first.",
                "suggestion": "Call setup_context(binary_path) to establish analysis context"
            }
        
        if not function_name and not function_address:
            return {
                "error": "Either function_name or function_address required",
                "example": "get_pseudocode(function_name='GetCursorItem')"
            }
        
        session = await self.get_session()
        
        try:
            if function_name:
                # Analyze function by name
                async with session.post(
                    f"{self.ghidra_server_url}/analyze/function_by_name",
                    json={
                        "binary_path": binary_path,
                        "function_name": function_name,
                        "dll_name": Path(binary_path).stem
                    }
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        return {
                            "success": True,
                            "function_name": function_name,
                            "binary_path": binary_path,
                            "address": result.get("address", "Unknown"),
                            "signature": result.get("signature", "Unknown"),
                            "pseudocode": result.get("decompiled_code", "No pseudocode available"),
                            "assembly": result.get("disassembly", "No assembly available"),
                            "references": result.get("references", []),
                            "called_functions": result.get("called_functions", [])
                        }
                    else:
                        error_data = await response.json()
                        return {"error": f"Function decompilation failed: {error_data.get('detail', 'Unknown error')}"}
            
            else:  # function_address provided
                async with session.post(
                    f"{self.ghidra_server_url}/decompile/function",
                    json={
                        "binary_path": binary_path,
                        "function_address": function_address
                    }
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        return {
                            "success": True,
                            "function_address": function_address,
                            "binary_path": binary_path,
                            "pseudocode": result.get("pseudocode", "No pseudocode available"),
                            "assembly": result.get("assembly", "No assembly available")
                        }
                    else:
                        error_data = await response.json()
                        return {"error": f"Function decompilation failed: {error_data.get('detail', 'Unknown error')}"}
                    
        except Exception as e:
            return {"error": f"Failed to get pseudocode: {str(e)}"}
    
    async def list_structures(self, binary_path: Optional[str] = None, include_builtin: bool = False) -> Dict[str, Any]:
        """Get list of data structures/types"""
        # Note: This would need to be implemented in the Ghidra server
        # For now, return a placeholder that explains the capability
        
        if binary_path is None:
            binary_path = self.current_binary
            
        return {
            "info": "Structure listing not yet implemented in Ghidra server",
            "binary_path": binary_path,
            "planned_features": [
                "User-defined structures from binary analysis",
                "Reconstructed data types from decompilation",
                "Windows API structures if include_builtin=True"
            ],
            "workaround": "Use get_pseudocode() to see structure usage in functions"
        }
    
    async def get_structure(self, structure_name: str, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Get details of a specific structure"""
        
        if binary_path is None:
            binary_path = self.current_binary
            
        return {
            "info": "Structure details not yet implemented in Ghidra server", 
            "structure_name": structure_name,
            "binary_path": binary_path,
            "planned_features": [
                "Structure field layout and types",
                "Size and alignment information",
                "Cross-references to structure usage"
            ],
            "workaround": "Check decompiled code for structure usage patterns"
        }
    
    async def list_enums(self, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Get list of enumerations"""
        
        if binary_path is None:
            binary_path = self.current_binary
            
        return {
            "info": "Enumeration listing not yet implemented in Ghidra server",
            "binary_path": binary_path,
            "planned_features": [
                "Discovered enumerations from analysis",
                "Constants and #define values",
                "Flag combinations and bitmasks"
            ]
        }
    
    async def get_enum(self, enum_name: str, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Get enumeration values and details"""
        
        if binary_path is None:
            binary_path = self.current_binary
            
        return {
            "info": "Enumeration details not yet implemented in Ghidra server",
            "enum_name": enum_name,
            "binary_path": binary_path,
            "planned_features": [
                "Enumeration values and their meanings",
                "Usage contexts within the binary",
                "Related constants and definitions"
            ]
        }
    
    async def list_function_definitions(self, binary_path: Optional[str] = None, 
                                      filter_pattern: Optional[str] = None) -> Dict[str, Any]:
        """Get function prototypes/signatures"""
        
        # This leverages the existing list_functions but focuses on signatures
        functions_result = await self.list_functions(binary_path)
        
        if "error" in functions_result:
            return functions_result
        
        functions = functions_result.get("functions", [])
        
        # Extract signatures/prototypes
        definitions = []
        for func in functions:
            definition = {
                "name": func.get("name", "Unknown"),
                "address": func.get("address", "Unknown"),
                "signature": func.get("signature", "Unknown"),
                "return_type": func.get("return_type", "Unknown"),
                "parameters": func.get("parameters", []),
                "is_export": func.get("is_export", False)
            }
            
            # Apply filter if specified
            if filter_pattern is None or filter_pattern.lower() in func.get("name", "").lower():
                definitions.append(definition)
        
        return {
            "success": True,
            "binary_path": binary_path,
            "total_definitions": len(definitions),
            "filter_applied": filter_pattern,
            "function_definitions": definitions
        }
    
    async def get_function_definition(self, function_name: str, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed function signature"""
        
        # This leverages get_pseudocode but focuses on signature details
        result = await self.get_pseudocode(function_name=function_name, binary_path=binary_path)
        
        if "error" in result:
            return result
        
        return {
            "success": True,
            "function_name": function_name,
            "binary_path": result.get("binary_path"),
            "address": result.get("address"),
            "signature": result.get("signature"),
            "return_type": "Extracted from signature",  # Would need parsing
            "parameters": "Extracted from signature",   # Would need parsing
            "calling_convention": "Unknown",  # Could be extracted from analysis
            "full_definition": result.get("signature", "Unknown")
        }


# Integration with MCP Coordinator
def create_ghidra_mcp_integration(ghidra_server_url: str = "http://ghidra-analysis:8002"):
    """Factory function to create Ghidra MCP tools integration"""
    return GhidraMCPTools(ghidra_server_url)