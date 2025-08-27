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
        
        logger.info("Ghidra headless analyzer initialized", ghidra_path=self.ghidra_install)
        
    async def analyze_binary(self, binary_path: str, analysis_depth: str = "detailed") -> Dict[str, Any]:
        """
        Perform comprehensive Ghidra analysis on a binary
        
        Args:
            binary_path: Path to binary file
            analysis_depth: 'basic', 'detailed', or 'comprehensive'
            
        Returns:
            Analysis results including decompilation
        """
        if not os.path.exists(binary_path):
            return {"error": f"Binary file not found: {binary_path}"}
            
        if not os.path.exists(self.headless_script):
            return {"error": f"Ghidra installation not found at {self.ghidra_install}"}
            
        try:
            # Create unique project for this analysis
            project_name = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            project_path = os.path.join(self.projects_dir, project_name)
            
            # Prepare output files
            output_file = os.path.join(self.outputs_dir, f"{project_name}_results.json")
            decompile_file = os.path.join(self.outputs_dir, f"{project_name}_decompile.c")
            
            # Run Ghidra analysis
            analysis_result = await self._run_ghidra_analysis(
                binary_path, project_path, project_name, output_file, decompile_file, analysis_depth
            )
            
            # Parse results
            if analysis_result["success"]:
                parsed_results = await self._parse_analysis_results(output_file, decompile_file)
                analysis_result.update(parsed_results)
                
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
        analysis_depth: str
    ) -> Dict[str, Any]:
        """Run Ghidra headless analysis"""
        try:
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
                "-analysisTimeoutPerFile", "300",  # 5 minute timeout
                "-deleteProject"  # Clean up after analysis
            ]
            
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