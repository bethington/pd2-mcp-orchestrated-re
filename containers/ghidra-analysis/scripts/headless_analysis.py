"""
Ghidra Headless Analysis Script
Python wrapper for Ghidra headless analyzer
"""

import os
import subprocess
import tempfile
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class GhidraHeadlessAnalyzer:
    """Wrapper for Ghidra headless analysis"""
    
    def __init__(self, ghidra_path: str = "/opt/ghidra"):
        self.ghidra_path = ghidra_path
        self.analyzer_script = os.path.join(ghidra_path, "support/analyzeHeadless")
    
    async def analyze_binary(self, binary_path: str, project_name: str = None) -> Dict[str, Any]:
        """Analyze binary using Ghidra headless mode"""
        try:
            if not project_name:
                project_name = f"analysis_{os.path.basename(binary_path)}"
            
            # Create temporary project directory
            with tempfile.TemporaryDirectory() as temp_dir:
                project_dir = os.path.join(temp_dir, "ghidra_projects")
                os.makedirs(project_dir, exist_ok=True)
                
                # Run Ghidra analysis
                cmd = [
                    self.analyzer_script,
                    project_dir,
                    project_name,
                    "-import", binary_path,
                    "-analyze"
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minute timeout
                )
                
                analysis_result = {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "functions": self._extract_functions(result.stdout),
                    "imports": self._extract_imports(result.stdout),
                    "exports": self._extract_exports(result.stdout)
                }
                
                return analysis_result
                
        except subprocess.TimeoutExpired:
            return {"error": "Analysis timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    def _extract_functions(self, output: str) -> list:
        """Extract function information from Ghidra output"""
        # This is a simplified parser - real implementation would be more sophisticated
        functions = []
        lines = output.split('\n')
        
        for line in lines:
            if 'FUN_' in line or 'Function' in line:
                functions.append(line.strip())
        
        return functions[:50]  # Limit results
    
    def _extract_imports(self, output: str) -> list:
        """Extract import information"""
        imports = []
        lines = output.split('\n')
        
        for line in lines:
            if 'IMPORT' in line.upper() or 'import' in line:
                imports.append(line.strip())
        
        return imports[:100]  # Limit results
    
    def _extract_exports(self, output: str) -> list:
        """Extract export information"""
        exports = []
        lines = output.split('\n')
        
        for line in lines:
            if 'EXPORT' in line.upper() or 'export' in line:
                exports.append(line.strip())
        
        return exports[:100]  # Limit results