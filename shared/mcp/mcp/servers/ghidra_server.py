"""
Ghidra static analysis MCP server implementation
"""

import asyncio
import json
import tempfile
import subprocess
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import structlog
from mcp.server import Server
from mcp.types import Resource, Tool, TextContent

logger = structlog.get_logger()

class GhidraMCPServer:
    """MCP server for Ghidra static analysis"""
    
    def __init__(self, ghidra_install_path: str = "/opt/ghidra"):
        self.server = Server("ghidra-analysis")
        self.ghidra_install_path = ghidra_install_path
        self.active_projects = {}
        self.analysis_cache = {}
        
        self.setup_handlers()
        logger.info("Ghidra MCP Server initialized")
    
    def setup_handlers(self):
        @self.server.list_resources()
        async def list_resources():
            return [
                Resource(
                    uri="ghidra://analysis/binary_info",
                    name="Binary Analysis Information",
                    mimeType="application/json",
                    description="Detailed binary file analysis results"
                ),
                Resource(
                    uri="ghidra://analysis/functions",
                    name="Function Analysis",
                    mimeType="application/json",
                    description="Extracted function signatures and call graphs"
                ),
                Resource(
                    uri="ghidra://analysis/strings",
                    name="String Analysis", 
                    mimeType="application/json",
                    description="Extracted strings and cross-references"
                ),
                Resource(
                    uri="ghidra://analysis/imports",
                    name="Import Analysis",
                    mimeType="application/json",
                    description="Imported functions and libraries"
                ),
                Resource(
                    uri="ghidra://analysis/exports",
                    name="Export Analysis",
                    mimeType="application/json",
                    description="Exported functions and symbols"
                ),
                Resource(
                    uri="ghidra://analysis/cross_references",
                    name="Cross Reference Analysis",
                    mimeType="application/json",
                    description="Cross-references between code and data"
                )
            ]
        
        @self.server.read_resource()
        async def read_resource(uri: str):
            try:
                if uri.startswith("ghidra://analysis/"):
                    analysis_type = uri.split("/")[-1]
                    
                    # Check cache first
                    if analysis_type in self.analysis_cache:
                        return TextContent(
                            type="text",
                            text=json.dumps(self.analysis_cache[analysis_type], indent=2)
                        )
                    
                    return TextContent(
                        type="text",
                        text=json.dumps({"error": f"No analysis data available for {analysis_type}"})
                    )
                    
            except Exception as e:
                logger.error(f"Error reading resource {uri}", error=str(e))
                return TextContent(
                    type="text",
                    text=json.dumps({"error": f"Failed to read {uri}: {str(e)}"})
                )
        
        @self.server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="analyze_binary",
                    description="Perform comprehensive static analysis on a binary file",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "binary_path": {
                                "type": "string",
                                "description": "Path to the binary file to analyze"
                            },
                            "analysis_depth": {
                                "type": "string",
                                "enum": ["basic", "standard", "comprehensive"],
                                "default": "standard",
                                "description": "Depth of analysis to perform"
                            },
                            "output_format": {
                                "type": "string",
                                "enum": ["json", "xml", "html"],
                                "default": "json",
                                "description": "Output format for analysis results"
                            }
                        },
                        "required": ["binary_path"]
                    }
                ),
                Tool(
                    name="extract_functions",
                    description="Extract function information from analyzed binary",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "project_name": {
                                "type": "string",
                                "description": "Name of the Ghidra project"
                            },
                            "filter_pattern": {
                                "type": "string",
                                "description": "Optional regex pattern to filter functions"
                            },
                            "include_analysis": {
                                "type": "boolean",
                                "default": True,
                                "description": "Include detailed function analysis"
                            }
                        }
                    }
                ),
                Tool(
                    name="search_patterns",
                    description="Search for specific patterns in the binary",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "project_name": {
                                "type": "string",
                                "description": "Name of the Ghidra project"
                            },
                            "search_type": {
                                "type": "string",
                                "enum": ["strings", "bytes", "instructions", "references"],
                                "description": "Type of pattern to search for"
                            },
                            "pattern": {
                                "type": "string",
                                "description": "Pattern to search for"
                            },
                            "case_sensitive": {
                                "type": "boolean",
                                "default": False,
                                "description": "Whether search should be case sensitive"
                            }
                        },
                        "required": ["project_name", "search_type", "pattern"]
                    }
                ),
                Tool(
                    name="generate_call_graph",
                    description="Generate call graph for the analyzed binary",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "project_name": {
                                "type": "string",
                                "description": "Name of the Ghidra project"
                            },
                            "function_filter": {
                                "type": "string",
                                "description": "Optional function name filter"
                            },
                            "max_depth": {
                                "type": "integer",
                                "default": 10,
                                "description": "Maximum depth for call graph traversal"
                            },
                            "output_format": {
                                "type": "string",
                                "enum": ["json", "dot", "svg"],
                                "default": "json",
                                "description": "Output format for call graph"
                            }
                        }
                    }
                ),
                Tool(
                    name="decompile_function",
                    description="Decompile a specific function to C-like code",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "project_name": {
                                "type": "string",
                                "description": "Name of the Ghidra project"
                            },
                            "function_address": {
                                "type": "string",
                                "description": "Address of the function to decompile (hex format)"
                            },
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function to decompile (alternative to address)"
                            },
                            "include_comments": {
                                "type": "boolean",
                                "default": True,
                                "description": "Include comments in decompiled output"
                            }
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict):
            try:
                if name == "analyze_binary":
                    return await self.analyze_binary(arguments)
                elif name == "extract_functions":
                    return await self.extract_functions(arguments)
                elif name == "search_patterns":
                    return await self.search_patterns(arguments)
                elif name == "generate_call_graph":
                    return await self.generate_call_graph(arguments)
                elif name == "decompile_function":
                    return await self.decompile_function(arguments)
                else:
                    return [TextContent(
                        type="text",
                        text=f"Unknown tool: {name}"
                    )]
            except Exception as e:
                logger.error(f"Error calling tool {name}", error=str(e))
                return [TextContent(
                    type="text",
                    text=f"Error executing {name}: {str(e)}"
                )]
    
    async def analyze_binary(self, args: Dict[str, Any]):
        """Analyze a binary file with Ghidra"""
        binary_path = args.get("binary_path")
        analysis_depth = args.get("analysis_depth", "standard")
        output_format = args.get("output_format", "json")
        
        if not os.path.exists(binary_path):
            return [TextContent(
                type="text",
                text=f"Error: Binary file not found: {binary_path}"
            )]
        
        try:
            # Create temporary project
            project_name = f"analysis_{int(asyncio.get_event_loop().time())}"
            project_dir = f"/tmp/ghidra_projects/{project_name}"
            os.makedirs(project_dir, exist_ok=True)
            
            # Create Ghidra analysis script
            script_content = self._generate_analysis_script(
                binary_path, project_dir, project_name, analysis_depth
            )
            
            script_path = f"/tmp/{project_name}_analysis.py"
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            # Run Ghidra analysis
            result = await self._run_ghidra_headless([
                f"/tmp/ghidra_projects",  # Project location
                project_name,             # Project name
                "-import", binary_path,   # Import binary
                "-postScript", script_path,  # Post-analysis script
                "-deleteProject"          # Clean up after analysis
            ])
            
            if result.returncode == 0:
                # Parse results
                results_file = f"/tmp/{project_name}_results.json"
                if os.path.exists(results_file):
                    with open(results_file, 'r') as f:
                        analysis_results = json.load(f)
                    
                    # Cache results
                    self.analysis_cache.update(analysis_results)
                    
                    os.unlink(results_file)  # Clean up
                    os.unlink(script_path)   # Clean up
                    
                    return [TextContent(
                        type="text",
                        text=json.dumps({
                            "status": "success",
                            "project_name": project_name,
                            "binary_path": binary_path,
                            "analysis_depth": analysis_depth,
                            "results_summary": {
                                "functions_found": len(analysis_results.get("functions", [])),
                                "strings_found": len(analysis_results.get("strings", [])),
                                "imports_found": len(analysis_results.get("imports", [])),
                                "exports_found": len(analysis_results.get("exports", []))
                            }
                        }, indent=2)
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"Error: Analysis completed but no results file found"
                    )]
            else:
                return [TextContent(
                    type="text",
                    text=f"Error: Ghidra analysis failed: {result.stderr}"
                )]
                
        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            return [TextContent(
                type="text",
                text=f"Analysis failed: {str(e)}"
            )]
    
    async def extract_functions(self, args: Dict[str, Any]):
        """Extract function information from analyzed binary"""
        # This would extract from cached analysis results
        functions = self.analysis_cache.get("functions", [])
        
        filter_pattern = args.get("filter_pattern")
        if filter_pattern:
            import re
            pattern = re.compile(filter_pattern)
            functions = [f for f in functions if pattern.search(f.get("name", ""))]
        
        return [TextContent(
            type="text",
            text=json.dumps({
                "total_functions": len(functions),
                "functions": functions[:100]  # Limit output
            }, indent=2)
        )]
    
    async def search_patterns(self, args: Dict[str, Any]):
        """Search for patterns in the analyzed binary"""
        search_type = args.get("search_type")
        pattern = args.get("pattern")
        case_sensitive = args.get("case_sensitive", False)
        
        results = []
        
        if search_type == "strings":
            strings = self.analysis_cache.get("strings", [])
            for string_info in strings:
                string_value = string_info.get("value", "")
                if case_sensitive:
                    if pattern in string_value:
                        results.append(string_info)
                else:
                    if pattern.lower() in string_value.lower():
                        results.append(string_info)
        
        return [TextContent(
            type="text",
            text=json.dumps({
                "search_type": search_type,
                "pattern": pattern,
                "matches_found": len(results),
                "results": results[:50]  # Limit output
            }, indent=2)
        )]
    
    async def generate_call_graph(self, args: Dict[str, Any]):
        """Generate call graph for the analyzed binary"""
        functions = self.analysis_cache.get("functions", [])
        
        # Build call graph structure
        call_graph = {
            "nodes": [],
            "edges": []
        }
        
        for func in functions:
            call_graph["nodes"].append({
                "id": func.get("address"),
                "name": func.get("name"),
                "size": func.get("size", 0)
            })
            
            # Add calls as edges
            for call in func.get("calls", []):
                call_graph["edges"].append({
                    "source": func.get("address"),
                    "target": call.get("target_address"),
                    "type": call.get("type", "call")
                })
        
        return [TextContent(
            type="text",
            text=json.dumps(call_graph, indent=2)
        )]
    
    async def decompile_function(self, args: Dict[str, Any]):
        """Decompile a specific function"""
        function_address = args.get("function_address")
        function_name = args.get("function_name")
        
        # Find function in cache
        functions = self.analysis_cache.get("functions", [])
        target_function = None
        
        for func in functions:
            if (function_address and func.get("address") == function_address) or \
               (function_name and func.get("name") == function_name):
                target_function = func
                break
        
        if not target_function:
            return [TextContent(
                type="text",
                text="Error: Function not found in analysis cache"
            )]
        
        # Return decompiled code (would be actual decompilation in real implementation)
        return [TextContent(
            type="text",
            text=json.dumps({
                "function_name": target_function.get("name"),
                "function_address": target_function.get("address"),
                "decompiled_code": target_function.get("decompiled_code", "// Decompiled code not available"),
                "function_signature": target_function.get("signature"),
                "parameters": target_function.get("parameters", []),
                "local_variables": target_function.get("local_variables", [])
            }, indent=2)
        )]
    
    def _generate_analysis_script(self, binary_path: str, project_dir: str, project_name: str, depth: str) -> str:
        """Generate Python script for Ghidra analysis"""
        return f"""
# Ghidra analysis script
import json
import os

# Get current program
program = currentProgram
listing = program.getListing()
symbol_table = program.getSymbolTable()

results = {{
    "binary_info": {{}},
    "functions": [],
    "strings": [],
    "imports": [],
    "exports": []
}}

# Basic binary information
results["binary_info"] = {{
    "name": program.getName(),
    "executable_path": program.getExecutablePath(),
    "executable_format": program.getExecutableFormat(),
    "language_id": str(program.getLanguageID()),
    "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
    "image_base": "0x" + format(program.getImageBase().getOffset(), 'x'),
    "min_address": "0x" + format(program.getMinAddress().getOffset(), 'x'),
    "max_address": "0x" + format(program.getMaxAddress().getOffset(), 'x')
}}

# Extract functions
function_manager = program.getFunctionManager()
functions = function_manager.getFunctions(True)

for func in functions:
    func_info = {{
        "name": func.getName(),
        "address": "0x" + format(func.getEntryPoint().getOffset(), 'x'),
        "size": func.getBody().getNumAddresses(),
        "signature": str(func.getSignature()),
        "parameters": [],
        "calls": []
    }}
    
    # Get parameters
    for param in func.getParameters():
        func_info["parameters"].append({{
            "name": param.getName(),
            "data_type": str(param.getDataType()),
            "ordinal": param.getOrdinal()
        }})
    
    # Get function calls
    references = func.getEntryPoint().getReferenceIteratorTo()
    while references.hasNext():
        ref = references.next()
        if ref.getReferenceType().isCall():
            func_info["calls"].append({{
                "target_address": "0x" + format(ref.getFromAddress().getOffset(), 'x'),
                "type": str(ref.getReferenceType())
            }})
    
    results["functions"].append(func_info)

# Extract strings
string_table = program.getListing().getDefinedData(True)
for data in string_table:
    if data.hasStringValue():
        string_info = {{
            "address": "0x" + format(data.getAddress().getOffset(), 'x'),
            "value": str(data.getValue()),
            "length": data.getLength(),
            "data_type": str(data.getDataType())
        }}
        results["strings"].append(string_info)

# Extract imports/exports
external_manager = program.getExternalManager()
external_locations = external_manager.getExternalLocations()

while external_locations.hasNext():
    external_loc = external_locations.next()
    if external_loc.getSource() == external_loc.IMPORT:
        results["imports"].append({{
            "name": external_loc.getLabel(),
            "library": external_loc.getLibraryName(),
            "address": "0x" + format(external_loc.getAddress().getOffset(), 'x')
        }})

# Save results
with open("/tmp/{project_name}_results.json", "w") as f:
    json.dump(results, f, indent=2)
"""
    
    async def _run_ghidra_headless(self, args: List[str]) -> subprocess.CompletedProcess:
        """Run Ghidra in headless mode"""
        ghidra_script = os.path.join(self.ghidra_install_path, "support", "analyzeHeadless")
        
        if not os.path.exists(ghidra_script):
            # Try alternative path
            ghidra_script = os.path.join(self.ghidra_install_path, "support", "analyzeHeadless.bat")
        
        full_command = [ghidra_script] + args
        
        process = await asyncio.create_subprocess_exec(
            *full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/tmp"
        )
        
        stdout, stderr = await process.communicate()
        
        return subprocess.CompletedProcess(
            args=full_command,
            returncode=process.returncode,
            stdout=stdout.decode() if stdout else "",
            stderr=stderr.decode() if stderr else ""
        )

async def main():
    server = GhidraMCPServer()
    
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await server.server.run(read_stream, write_stream, server.server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
