"""
Ghidra Headless Analysis Engine
Automated decompilation and function analysis using Ghidra headless mode
"""

import os
import subprocess
import json
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path
import structlog
from datetime import datetime
from analysis_cache import GhidraAnalysisCache
from ghidra_project_manager import GhidraProjectManager

logger = structlog.get_logger()

class GhidraHeadlessAnalyzer:
    """Headless Ghidra analysis for automated decompilation"""
    
    def __init__(self):
        self.ghidra_install = os.environ.get('GHIDRA_INSTALL_DIR', '/home/analysis/ghidra')
        self.headless_script = os.path.join(self.ghidra_install, 'support', 'analyzeHeadless')
        self.projects_dir = '/home/analysis/projects'
        self.scripts_dir = '/home/analysis/scripts'
        self.outputs_dir = '/home/analysis/outputs'
        
        # Ensure directories exist
        Path(self.projects_dir).mkdir(exist_ok=True)
        Path(self.outputs_dir).mkdir(exist_ok=True)
        
        # Initialize cache and project managers
        self.cache = GhidraAnalysisCache()
        self.project_manager = GhidraProjectManager()
        self._cache_initialized = False
        
        # Ensure persistent directories exist
        self._ensure_persistent_dirs()
        
        logger.info("Ghidra headless analyzer initialized", 
                   ghidra_path=self.ghidra_install,
                   persistent_projects=self.project_manager.persistent_projects_dir,
                   exports_dir=self.project_manager.exports_dir)
    
    def _ensure_persistent_dirs(self):
        """Ensure persistent directories exist in host volume"""
        try:
            # Create host-mounted persistent directories
            host_outputs_dir = '/app/outputs/ghidra'
            projects_dir = os.path.join(host_outputs_dir, 'projects')
            exports_dir = os.path.join(host_outputs_dir, 'exports')
            
            os.makedirs(projects_dir, exist_ok=True)
            os.makedirs(exports_dir, exist_ok=True)
            
            logger.info("Persistent directories created", 
                       projects_dir=projects_dir,
                       exports_dir=exports_dir)
                       
        except Exception as e:
            logger.error("Failed to create persistent directories", error=str(e))
    
    async def _ensure_cache_initialized(self):
        """Initialize cache manager if not already done"""
        if not self._cache_initialized:
            try:
                await self.cache.initialize()
                self._cache_initialized = True
                logger.info("Cache manager initialized successfully")
            except Exception as e:
                logger.error("Failed to initialize cache manager", error=str(e))
                raise
        
    async def analyze_binary(self, binary_path: str, analysis_depth: str = "detailed", 
                           force_reanalysis: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive Ghidra analysis on a binary with caching
        
        Args:
            binary_path: Path to binary file
            analysis_depth: 'basic', 'detailed', or 'comprehensive'
            force_reanalysis: Skip cache and force new analysis
            
        Returns:
            Analysis results including decompilation
        """
        if not os.path.exists(binary_path):
            return {"error": f"Binary file not found: {binary_path}"}
            
        if not os.path.exists(self.headless_script):
            return {"error": f"Ghidra installation not found at {self.ghidra_install}"}
        
        # Initialize cache if needed
        await self._ensure_cache_initialized()
        
        # Check cache first (unless forced reanalysis)
        if not force_reanalysis:
            cached_result = await self.cache.get_cached_analysis(binary_path)
            if cached_result and not await self.cache.needs_reanalysis(binary_path):
                logger.info("Using cached analysis results", 
                           binary_path=binary_path,
                           functions_count=len(cached_result.get("functions", [])),
                           cache_age=cached_result.get("cache_timestamp"))
                return {
                    **cached_result,
                    "from_cache": True,
                    "cache_hit": True
                }
            
        logger.info("Performing new Ghidra analysis", 
                   binary_path=binary_path, 
                   analysis_depth=analysis_depth,
                   force_reanalysis=force_reanalysis)
            
        try:
            # Use project manager to get appropriate project path
            project_path, project_name, should_preserve = self.project_manager.create_or_get_project_path(binary_path)
            
            logger.info("Project configuration determined", 
                       project_name=project_name,
                       project_path=project_path,
                       preserve_project=should_preserve, 
                       binary=os.path.basename(binary_path))
            
            # Prepare output files
            output_file = os.path.join(self.outputs_dir, f"{project_name}_results.json")
            decompile_file = os.path.join(self.outputs_dir, f"{project_name}_decompile.c")
            
            # Run Ghidra analysis
            analysis_result = await self._run_ghidra_analysis(
                binary_path, project_path, project_name, output_file, 
                decompile_file, analysis_depth, should_preserve
            )
            
            # Parse results
            if analysis_result["success"]:
                parsed_results = await self._parse_analysis_results(output_file, decompile_file)
                analysis_result.update(parsed_results)
                
                # Store results in cache
                await self.cache.store_analysis_results(binary_path, analysis_result)
                analysis_result["from_cache"] = False
                analysis_result["cache_stored"] = True
                
                # Export project if should preserve
                if should_preserve:
                    try:
                        exported_files = self.project_manager.export_project_analysis(
                            binary_path, project_path, project_name)
                        analysis_result["exported_files"] = exported_files
                        logger.info("Project analysis exported for persistence", 
                                   binary=os.path.basename(binary_path),
                                   exported_files=len(exported_files))
                    except Exception as e:
                        logger.warning("Failed to export project analysis", 
                                     binary=binary_path, error=str(e))
                
            return analysis_result
            
        except Exception as e:
            logger.error("Ghidra analysis failed", binary_path=binary_path, error=str(e))
            return {"error": str(e)}
            
    async def _run_ghidra_analysis(
        self, 
        binary_path: str, 
        project_path: str, 
        project_name: str,
        output_file: str,
        decompile_file: str,
        analysis_depth: str,
        preserve_project: bool = False
    ) -> Dict[str, Any]:
        """Run Ghidra headless analysis"""
        try:
            # Ensure project directory exists
            os.makedirs(project_path, exist_ok=True)
            
            # Build Ghidra command
            cmd = [
                self.headless_script,
                project_path,
                project_name,
                "-import", binary_path,
                "-postScript", os.path.join(self.scripts_dir, "comprehensive_analysis.py"),
                output_file,
                decompile_file,
                analysis_depth,
                "-analysisTimeoutPerFile", "300"  # 5 minute timeout
            ]
            
            # Only delete project if not preserving
            if not preserve_project:
                cmd.append("-deleteProject")
                logger.info("Project will be deleted after analysis", preserve=preserve_project)
            else:
                logger.info("Project will be preserved for future use", 
                           project_name=project_name, preserve=preserve_project)
            
            logger.info("Starting Ghidra analysis", cmd=" ".join(cmd))
            
            # Run Ghidra analysis
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute overall timeout
            )
            
            if process.returncode == 0:
                logger.info("Ghidra analysis completed successfully")
                return {
                    "success": True,
                    "stdout": process.stdout,
                    "stderr": process.stderr
                }
            else:
                logger.error("Ghidra analysis failed", 
                           returncode=process.returncode, 
                           stderr=process.stderr)
                return {
                    "success": False,
                    "error": f"Ghidra analysis failed with code {process.returncode}",
                    "stderr": process.stderr
                }
                
        except subprocess.TimeoutExpired:
            logger.error("Ghidra analysis timed out")
            return {
                "success": False,
                "error": "Analysis timed out"
            }
        except Exception as e:
            logger.error("Ghidra execution error", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _parse_analysis_results(self, output_file: str, decompile_file: str) -> Dict[str, Any]:
        """Parse Ghidra analysis results"""
        results = {
            "functions": [],
            "strings": [],
            "imports": [],
            "exports": [],
            "data_types": [],
            "decompiled_code": "",
            "statistics": {}
        }
        
        try:
            # Parse JSON output if available
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    json_data = json.load(f)
                    results.update(json_data)
                    
            # Read decompiled code if available
            if os.path.exists(decompile_file):
                with open(decompile_file, 'r') as f:
                    results["decompiled_code"] = f.read()
                    
        except Exception as e:
            logger.warning("Failed to parse some analysis results", error=str(e))
            
        return results
        
    async def decompile_function(self, binary_path: str, function_address: str) -> Dict[str, Any]:
        """Decompile a specific function"""
        try:
            project_name = f"func_analysis_{datetime.now().strftime('%H%M%S')}"
            project_path = os.path.join(self.projects_dir, project_name)
            
            output_file = os.path.join(self.outputs_dir, f"{project_name}_function.c")
            
            cmd = [
                self.headless_script,
                project_path,
                project_name,
                "-import", binary_path,
                "-postScript", os.path.join(self.scripts_dir, "decompile_function.py"),
                function_address,
                output_file,
                "-deleteProject"
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if process.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    decompiled_code = f.read()
                    
                return {
                    "success": True,
                    "function_address": function_address,
                    "decompiled_code": decompiled_code
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to decompile function",
                    "stderr": process.stderr
                }
                
        except Exception as e:
            logger.error("Function decompilation failed", error=str(e))
            return {"error": str(e)}
            
    async def analyze_function_by_name(self, binary_path: str, function_name: str, dll_name: str = "", function_address: str = None) -> Dict[str, Any]:
        """
        Analyze and decompile a specific function using real Ghidra analysis with caching
        
        Args:
            binary_path: Path to binary file  
            function_name: Name of function (e.g., "GetCursorItem", "Ordinal_10010")
            dll_name: Name of DLL for context (e.g., "D2Client.dll")
            function_address: Optional hex address of function (e.g., "0x6FAD1234")
            
        Returns:
            Complete function analysis with real decompiled pseudocode and assembly
        """
        if not os.path.exists(binary_path):
            return {"error": f"Binary file not found: {binary_path}"}
        
        # Initialize cache if needed
        await self._ensure_cache_initialized()
        
        # Check if we have cached results for the entire binary
        cached_analysis = await self.cache.get_cached_analysis(binary_path)
        if cached_analysis and not await self.cache.needs_reanalysis(binary_path):
            # Look for the specific function in cached results
            cached_functions = cached_analysis.get("functions", [])
            for func in cached_functions:
                if (func.get("name") == function_name or 
                    func.get("address") == function_address):
                    logger.info("Using cached function analysis", 
                               function=function_name, binary=binary_path)
                    return {
                        "success": True,
                        "function_name": func.get("name"),
                        "address": func.get("address"),
                        "signature": func.get("signature"),
                        "decompiled_code": func.get("pseudocode", ""),
                        "disassembly": func.get("assembly", []),
                        "references": func.get("references", []),
                        "called_functions": func.get("called_functions", []),
                        "from_cache": True
                    }
            
        try:
            logger.info("Starting real Ghidra function decompilation", 
                       binary=binary_path, function=function_name, address=function_address)
            
            # Use project manager to get appropriate project path
            project_path, project_name, should_preserve = self.project_manager.create_or_get_project_path(binary_path)
            
            # Create output file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_func_name = function_name.replace(':', '_').replace('/', '_') if function_name else "unknown"
            output_file = os.path.join(self.outputs_dir, f"{project_name}_{safe_func_name}_{timestamp}_decompile.json")
            
            # Build Ghidra headless command for function decompilation
            cmd = [
                self.headless_script,
                project_path,
                project_name,
                "-import", binary_path,
                "-scriptPath", self.scripts_dir,
                "-postScript", "function_decompilation.py",
                output_file,
                function_name or "null",
                function_address or "null",
                "-analysisTimeoutPerFile", "180"  # 3 minute timeout for single function
            ]
            
            # Only delete project if not preserving
            if not should_preserve:
                cmd.append("-deleteProject")
                logger.info("Using temporary project - will delete after analysis", 
                           project_name=project_name)
            else:
                logger.info("Using persistent project - preserving after analysis", 
                           project_name=project_name, binary=os.path.basename(binary_path))
            
            logger.info("Running Ghidra function decompilation", cmd=" ".join(cmd))
            
            # Run Ghidra analysis
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=240,  # 4 minute timeout
                cwd="/home/analysis"
            )
            
            if process.returncode != 0:
                logger.error("Ghidra function decompilation failed", 
                           returncode=process.returncode, 
                           stderr=process.stderr)
                return {
                    "error": f"Ghidra decompilation failed with code {process.returncode}",
                    "stderr": process.stderr[:1000],  # Limit error output
                    "function_name": function_name,
                    "binary_path": binary_path
                }
            
            # Read and parse decompilation results
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        ghidra_results = json.load(f)
                    
                    # Check if decompilation failed
                    if "error" in ghidra_results:
                        logger.error("Ghidra function decompilation script failed", 
                                   error=ghidra_results["error"])
                        return {
                            "error": f"Function decompilation failed: {ghidra_results['error']}",
                            "function_name": function_name,
                            "binary_path": binary_path
                        }
                    
                    # Format response to match expected API format
                    result = {
                        "success": ghidra_results.get("success", False),
                        "function_name": ghidra_results.get("function_name", function_name),
                        "binary_path": binary_path,
                        "dll_name": dll_name if dll_name else os.path.basename(binary_path),
                        "address": ghidra_results.get("function_address", function_address),
                        "signature": ghidra_results.get("signature", ""),
                        "pseudocode": ghidra_results.get("pseudocode", ""),
                        "assembly": ghidra_results.get("assembly", []),
                        "references": ghidra_results.get("references", []),
                        "called_functions": ghidra_results.get("called_functions", []),
                        "local_variables": ghidra_results.get("local_variables", []),
                        "parameters": ghidra_results.get("parameters", []),
                        "return_type": ghidra_results.get("return_type", ""),
                        "analysis_metadata": {
                            "analysis_confidence": ghidra_results.get("analysis_metadata", {}).get("analysis_confidence", 0.0),
                            "decompilation_time_ms": ghidra_results.get("analysis_metadata", {}).get("decompilation_time_ms", 0),
                            "analysis_timestamp": datetime.now().isoformat(),
                            "ghidra_version": "11.0.1",
                            "analysis_complete": True
                        }
                    }
                    
                    logger.info("Function decompilation completed successfully", 
                              function=function_name,
                              success=result["success"],
                              confidence=result["analysis_metadata"]["analysis_confidence"])
                    
                    # Export project for core binaries
                    if should_preserve and result["success"]:
                        try:
                            exported_files = self.project_manager.export_project_analysis(
                                binary_path, project_path, project_name
                            )
                            if exported_files:
                                result["analysis_metadata"]["exported_files"] = exported_files
                                logger.info("Project analysis exported for persistent storage",
                                           binary=os.path.basename(binary_path),
                                           exports=list(exported_files.keys()))
                        except Exception as e:
                            logger.warning("Failed to export project analysis", 
                                         binary=binary_path, error=str(e))
                    
                    # Clean up output file
                    try:
                        os.remove(output_file)
                    except:
                        pass
                        
                    return result
                    
                except json.JSONDecodeError as e:
                    logger.error("Failed to parse Ghidra decompilation results", error=str(e))
                    return {
                        "error": f"Failed to parse decompilation results: {str(e)}",
                        "function_name": function_name,
                        "binary_path": binary_path
                    }
            else:
                logger.error("Ghidra decompilation output file not found", output_file=output_file)
                return {
                    "error": "Decompilation completed but no results file found",
                    "function_name": function_name,
                    "binary_path": binary_path,
                    "expected_output": output_file
                }
                
        except subprocess.TimeoutExpired:
            logger.error("Ghidra function decompilation timed out", function=function_name)
            return {
                "error": "Decompilation timed out after 4 minutes",
                "function_name": function_name,
                "binary_path": binary_path
            }
        except Exception as e:
            logger.error("Function decompilation failed", error=str(e), function=function_name)
            return {
                "error": f"Decompilation failed: {str(e)}",
                "function_name": function_name,
                "binary_path": binary_path
            }
            
    async def analyze_all_functions(self, binary_path: str, dll_name: str, 
                                   include_exports: bool = True, 
                                   include_internals: bool = True, 
                                   include_ordinals: bool = True) -> Dict[str, Any]:
        """
        Enumerate and analyze all functions in a DLL using real Ghidra analysis
        
        Args:
            binary_path: Path to DLL file
            dll_name: Name of DLL (e.g., "D2Client.dll")
            include_exports: Include exported functions
            include_internals: Include internal functions  
            include_ordinals: Include ordinal-based functions
            
        Returns:
            Complete DLL analysis with all discovered functions from Ghidra
        """
        if not os.path.exists(binary_path):
            return {"error": f"Binary file not found: {binary_path}"}
            
        try:
            logger.info("Starting real Ghidra function enumeration", 
                       binary=binary_path, dll=dll_name,
                       exports=include_exports, internals=include_internals, ordinals=include_ordinals)
            
            # Create unique project and output names
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            project_name = f"functions_{timestamp}"
            project_path = os.path.join(self.projects_dir, project_name)
            output_file = os.path.join(self.outputs_dir, f"{project_name}_functions.json")
            
            # Ensure project directory exists
            os.makedirs(project_path, exist_ok=True)
            
            # Build Ghidra headless command for function enumeration
            cmd = [
                self.headless_script,
                project_path,
                project_name,
                "-import", binary_path,
                "-scriptPath", self.scripts_dir,
                "-postScript", "function_enumeration.py",
                output_file,
                str(include_exports).lower(),
                str(include_internals).lower(), 
                str(include_ordinals).lower(),
                "-analysisTimeoutPerFile", "300",  # 5 minute timeout
                "-deleteProject"  # Clean up after analysis
            ]
            
            logger.info("Running Ghidra function enumeration", cmd=" ".join(cmd))
            
            # Run Ghidra analysis
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=360,  # 6 minute timeout
                cwd="/home/analysis"
            )
            
            if process.returncode != 0:
                logger.error("Ghidra function enumeration failed", 
                           returncode=process.returncode, 
                           stderr=process.stderr)
                return {
                    "error": f"Ghidra analysis failed with code {process.returncode}",
                    "stderr": process.stderr[:1000],  # Limit error output
                    "binary_path": binary_path
                }
            
            # Read and parse analysis results
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        ghidra_results = json.load(f)
                    
                    # Check if analysis failed
                    if "error" in ghidra_results:
                        logger.error("Ghidra function enumeration script failed", 
                                   error=ghidra_results["error"])
                        return {
                            "error": f"Function enumeration failed: {ghidra_results['error']}",
                            "binary_path": binary_path
                        }
                    
                    # Extract function data
                    functions = ghidra_results.get("functions", [])
                    summary = ghidra_results.get("summary", {})
                    
                    # Format response to match expected API format
                    result = {
                        "success": True,
                        "binary_path": binary_path,
                        "dll_name": dll_name,
                        "total_functions": len(functions),
                        "functions": functions,
                        "summary": {
                            "exported": summary.get("exported_functions", 0),
                            "internal": summary.get("internal_functions", 0), 
                            "ordinal": summary.get("ordinal_functions", 0),
                            "with_names": summary.get("named_functions", 0)
                        },
                        "analysis_metadata": {
                            "binary_name": summary.get("binary_name", dll_name),
                            "analysis_timestamp": summary.get("analysis_timestamp", datetime.now().isoformat()),
                            "ghidra_version": "11.0.1",
                            "analysis_complete": True
                        }
                    }
                    
                    logger.info("Function enumeration completed successfully", 
                              total_functions=len(functions), 
                              exported=result["summary"]["exported"],
                              internal=result["summary"]["internal"])
                    
                    # Clean up output file
                    try:
                        os.remove(output_file)
                    except:
                        pass
                        
                    return result
                    
                except json.JSONDecodeError as e:
                    logger.error("Failed to parse Ghidra results", error=str(e))
                    return {
                        "error": f"Failed to parse analysis results: {str(e)}",
                        "binary_path": binary_path
                    }
            else:
                logger.error("Ghidra analysis output file not found", output_file=output_file)
                return {
                    "error": "Analysis completed but no results file found",
                    "binary_path": binary_path,
                    "expected_output": output_file
                }
                
        except subprocess.TimeoutExpired:
            logger.error("Ghidra function enumeration timed out", binary=binary_path)
            return {
                "error": "Analysis timed out after 6 minutes",
                "binary_path": binary_path
            }
        except Exception as e:
            logger.error("Function enumeration failed", error=str(e), dll=dll_name)
            return {
                "error": f"Analysis failed: {str(e)}",
                "dll_name": dll_name,
                "binary_path": binary_path
            }
            
    async def analyze_strings(self, binary_path: str) -> Dict[str, Any]:
        """Extract and analyze strings from binary"""
        try:
            project_name = f"strings_{datetime.now().strftime('%H%M%S')}"
            project_path = os.path.join(self.projects_dir, project_name)
            
            output_file = os.path.join(self.outputs_dir, f"{project_name}_strings.json")
            
            cmd = [
                self.headless_script,
                project_path,
                project_name,
                "-import", binary_path,
                "-postScript", os.path.join(self.scripts_dir, "extract_strings.py"),
                output_file,
                "-deleteProject"
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if process.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    strings_data = json.load(f)
                    
                return {
                    "success": True,
                    "strings": strings_data
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to extract strings"
                }
                
        except Exception as e:
            logger.error("String analysis failed", error=str(e))
            return {"error": str(e)}
            
    def get_supported_formats(self) -> List[str]:
        """Get list of supported binary formats"""
        return [
            "PE", "ELF", "Mach-O", "COFF", "Raw Binary",
            "MS-DOS", "NE", "LE", "LX", "PEF", "GZIP"
        ]
        
    def cleanup_old_projects(self, max_age_hours: int = 24):
        """Clean up old analysis projects"""
        try:
            import time
            current_time = time.time()
            
            for project_dir in Path(self.projects_dir).iterdir():
                if project_dir.is_dir():
                    # Check modification time
                    mod_time = project_dir.stat().st_mtime
                    age_hours = (current_time - mod_time) / 3600
                    
                    if age_hours > max_age_hours:
                        logger.info("Cleaning up old project", project=project_dir.name)
                        # Remove project directory (implement carefully)
                        
        except Exception as e:
            logger.warning("Project cleanup failed", error=str(e))