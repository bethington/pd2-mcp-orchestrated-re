"""
Advanced Reverse Engineering MCP Tools
Orchestrates comprehensive binary analysis across multiple specialized containers
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import structlog
import os

logger = structlog.get_logger()

class AdvancedReverseEngineeringTools:
    """
    Comprehensive reverse engineering toolkit that coordinates multiple analysis services
    """
    
    def __init__(self):
        self.analysis_engine_url = os.getenv('ANALYSIS_ENGINE_URL', 'http://analysis-engine:8001')
        self.ghidra_analysis_url = os.getenv('GHIDRA_ANALYSIS_URL', 'http://ghidra-analysis:8002') 
        self.d2_analysis_url = os.getenv('D2_ANALYSIS_URL', 'http://d2-analysis:8765')
        self.network_monitor_url = os.getenv('NETWORK_MONITOR_URL', 'http://network-monitor:8768')
        
        logger.info("Advanced RE tools initialized", 
                   services={
                       "analysis_engine": self.analysis_engine_url,
                       "ghidra_analysis": self.ghidra_analysis_url,
                       "d2_analysis": self.d2_analysis_url,
                       "network_monitor": self.network_monitor_url
                   })
                   
    async def analyze_binary_comprehensive(
        self, 
        binary_path: str, 
        analysis_depth: str = "comprehensive",
        include_decompilation: bool = True,
        include_dynamic: bool = True
    ) -> Dict[str, Any]:
        """
        Perform comprehensive binary analysis using all available tools
        
        Args:
            binary_path: Path to binary file
            analysis_depth: 'basic', 'detailed', or 'comprehensive'
            include_decompilation: Include Ghidra decompilation
            include_dynamic: Include dynamic analysis if applicable
            
        Returns:
            Aggregated analysis results from all tools
        """
        logger.info("Starting comprehensive binary analysis", 
                   binary_path=binary_path, 
                   analysis_depth=analysis_depth)
        
        analysis_results = {
            "binary_path": binary_path,
            "analysis_start_time": datetime.now().isoformat(),
            "analysis_depth": analysis_depth,
            "static_analysis": {},
            "decompilation": {},
            "dynamic_analysis": {},
            "security_assessment": {},
            "aggregated_findings": {},
            "analysis_metadata": {}
        }
        
        try:
            # Phase 1: Static Analysis with Capstone/PE parser
            logger.info("Phase 1: Static analysis")
            static_results = await self._perform_static_analysis(binary_path, analysis_depth)
            analysis_results["static_analysis"] = static_results
            
            # Phase 2: Ghidra Decompilation (if requested)
            if include_decompilation:
                logger.info("Phase 2: Ghidra decompilation")
                decompilation_results = await self._perform_ghidra_analysis(binary_path, analysis_depth)
                analysis_results["decompilation"] = decompilation_results
            
            # Phase 3: Security Assessment
            logger.info("Phase 3: Security assessment") 
            security_results = await self._perform_security_analysis(binary_path)
            analysis_results["security_assessment"] = security_results
            
            # Phase 4: Dynamic Analysis (if game binary and dynamic requested)
            if include_dynamic and self._is_game_binary(static_results):
                logger.info("Phase 4: Dynamic analysis")
                dynamic_results = await self._perform_dynamic_analysis(binary_path)
                analysis_results["dynamic_analysis"] = dynamic_results
            
            # Phase 5: Aggregate and correlate findings
            logger.info("Phase 5: Aggregating findings")
            aggregated = await self._aggregate_findings(analysis_results)
            analysis_results["aggregated_findings"] = aggregated
            
            analysis_results["analysis_end_time"] = datetime.now().isoformat()
            analysis_results["status"] = "completed"
            
            logger.info("Comprehensive analysis completed", 
                       binary_path=binary_path,
                       total_functions=aggregated.get("total_functions", 0),
                       security_score=aggregated.get("security_score", 0))
            
            return analysis_results
            
        except Exception as e:
            logger.error("Comprehensive analysis failed", binary_path=binary_path, error=str(e))
            analysis_results["status"] = "failed"
            analysis_results["error"] = str(e)
            return analysis_results
    
    async def _perform_static_analysis(self, binary_path: str, analysis_depth: str) -> Dict[str, Any]:
        """Perform static analysis using analysis engine"""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "binary_path": binary_path,
                    "analysis_depth": analysis_depth,
                    "include_disassembly": True,
                    "include_strings": True,
                    "include_security_analysis": True
                }
                
                async with session.post(
                    f"{self.analysis_engine_url}/analyze/binary",
                    json=payload
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Poll for completion if analysis was queued
                        if "analysis_id" in result:
                            return await self._wait_for_analysis_completion(
                                session, 
                                f"{self.analysis_engine_url}/analyze/status/{result['analysis_id']}",
                                f"{self.analysis_engine_url}/analyze/result/{result['analysis_id']}"
                            )
                        else:
                            return result
                    else:
                        error_text = await response.text()
                        return {"error": f"Static analysis failed: {error_text}"}
                        
        except Exception as e:
            logger.error("Static analysis request failed", error=str(e))
            return {"error": str(e)}
    
    async def _perform_ghidra_analysis(self, binary_path: str, analysis_depth: str) -> Dict[str, Any]:
        """Perform decompilation using Ghidra"""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "binary_path": binary_path,
                    "analysis_type": analysis_depth,
                    "include_decompilation": True,
                    "include_strings": True
                }
                
                async with session.post(
                    f"{self.ghidra_analysis_url}/analyze/binary",
                    json=payload
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Poll for completion if analysis was queued
                        if "analysis_id" in result:
                            return await self._wait_for_analysis_completion(
                                session,
                                f"{self.ghidra_analysis_url}/analyze/status/{result['analysis_id']}",
                                f"{self.ghidra_analysis_url}/analyze/result/{result['analysis_id']}"
                            )
                        else:
                            return result
                    else:
                        error_text = await response.text()
                        return {"error": f"Ghidra analysis failed: {error_text}"}
                        
        except Exception as e:
            logger.error("Ghidra analysis request failed", error=str(e))
            return {"error": str(e)}
    
    async def _perform_security_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform security-focused analysis"""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"binary_path": binary_path}
                
                async with session.post(
                    f"{self.analysis_engine_url}/security/analyze",
                    json=payload
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        return {"error": f"Security analysis failed: {error_text}"}
                        
        except Exception as e:
            logger.error("Security analysis request failed", error=str(e))
            return {"error": str(e)}
    
    async def _perform_dynamic_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Perform dynamic analysis if binary is a game executable"""
        try:
            # Check if game is running and can be analyzed
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.d2_analysis_url}/game/status") as response:
                    if response.status == 200:
                        game_status = await response.json()
                        
                        if game_status.get("game_running", False):
                            # Perform live analysis
                            memory_analysis = await self._get_memory_analysis()
                            network_analysis = await self._get_network_analysis()
                            
                            return {
                                "memory_analysis": memory_analysis,
                                "network_analysis": network_analysis,
                                "game_status": game_status
                            }
                        else:
                            return {"message": "Game not running, skipping dynamic analysis"}
                    else:
                        return {"error": "Could not connect to game analysis service"}
                        
        except Exception as e:
            logger.error("Dynamic analysis failed", error=str(e))
            return {"error": str(e)}
    
    async def _get_memory_analysis(self) -> Dict[str, Any]:
        """Get live memory analysis from game"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.d2_analysis_url}/memory/live-dump") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": "Memory analysis failed"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _get_network_analysis(self) -> Dict[str, Any]:
        """Get network traffic analysis"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.network_monitor_url}/analysis/traffic") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": "Network analysis failed"}
        except Exception as e:
            return {"error": str(e)}
    
    async def _wait_for_analysis_completion(
        self, 
        session: aiohttp.ClientSession, 
        status_url: str, 
        result_url: str,
        max_wait_minutes: int = 15
    ) -> Dict[str, Any]:
        """Wait for background analysis to complete"""
        import asyncio
        
        max_iterations = max_wait_minutes * 4  # Check every 15 seconds
        
        for i in range(max_iterations):
            try:
                async with session.get(status_url) as response:
                    if response.status == 200:
                        status = await response.json()
                        
                        if status.get("status") == "completed":
                            # Get final results
                            async with session.get(result_url) as result_response:
                                if result_response.status == 200:
                                    return await result_response.json()
                                else:
                                    return {"error": "Failed to retrieve completed results"}
                                    
                        elif status.get("status") == "failed":
                            return {"error": f"Analysis failed: {status.get('error_message', 'Unknown error')}"}
                        
                        # Still processing, wait and try again
                        await asyncio.sleep(15)
                    else:
                        return {"error": "Failed to check analysis status"}
                        
            except Exception as e:
                logger.warning("Error checking analysis status", error=str(e))
                await asyncio.sleep(15)
        
        return {"error": f"Analysis timed out after {max_wait_minutes} minutes"}
    
    def _is_game_binary(self, static_results: Dict[str, Any]) -> bool:
        """Determine if binary is likely a game executable"""
        if "error" in static_results:
            return False
            
        # Check for game-related indicators
        binary_name = static_results.get("file_info", {}).get("filename", "").lower()
        
        game_indicators = [
            "game.exe", "diablo", "d2", "projectd2", "pd2",
            "diablo2.exe", "d2se.exe", "plugy.exe"
        ]
        
        for indicator in game_indicators:
            if indicator in binary_name:
                return True
        
        # Check imports for game-related DLLs
        imports = static_results.get("imports", [])
        game_dlls = ["d3d9.dll", "opengl32.dll", "winmm.dll", "dsound.dll"]
        
        for import_entry in imports:
            dll_name = import_entry.get("dll", "").lower()
            if dll_name in game_dlls:
                return True
        
        return False
    
    async def _aggregate_findings(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate and correlate findings from all analysis phases"""
        aggregated = {
            "summary": {},
            "total_functions": 0,
            "total_strings": 0,
            "total_imports": 0,
            "security_score": 0,
            "risk_factors": [],
            "interesting_findings": [],
            "recommended_actions": []
        }
        
        # Aggregate static analysis results
        static_results = analysis_results.get("static_analysis", {})
        if "error" not in static_results:
            aggregated["total_functions"] += len(static_results.get("functions", []))
            aggregated["total_strings"] += len(static_results.get("strings", []))
            aggregated["total_imports"] += len(static_results.get("imports", []))
        
        # Aggregate Ghidra results
        ghidra_results = analysis_results.get("decompilation", {})
        if "error" not in ghidra_results:
            ghidra_functions = ghidra_results.get("functions", [])
            aggregated["total_functions"] = max(aggregated["total_functions"], len(ghidra_functions))
        
        # Security assessment
        security_results = analysis_results.get("security_assessment", {})
        if "error" not in security_results:
            security_analysis = security_results.get("security_analysis", {})
            aggregated["security_score"] = security_analysis.get("risk_score", 0)
            
            # Add risk factors
            if not security_analysis.get("aslr_enabled", False):
                aggregated["risk_factors"].append("ASLR not enabled")
            if not security_analysis.get("dep_enabled", False):
                aggregated["risk_factors"].append("DEP not enabled")
            if security_analysis.get("packer_detected", False):
                aggregated["risk_factors"].append("Packer detected")
            if security_analysis.get("anti_debug", False):
                aggregated["risk_factors"].append("Anti-debugging techniques")
        
        # Generate recommendations
        if aggregated["security_score"] > 5:
            aggregated["recommended_actions"].append("High security risk - manual review recommended")
        if aggregated["total_functions"] > 10000:
            aggregated["recommended_actions"].append("Large binary - focus on entry points and exports")
        if len(aggregated["risk_factors"]) > 2:
            aggregated["recommended_actions"].append("Multiple security issues - comprehensive security audit needed")
        
        # Create summary
        aggregated["summary"] = {
            "analysis_quality": "comprehensive" if aggregated["total_functions"] > 0 else "limited",
            "binary_complexity": "high" if aggregated["total_functions"] > 5000 else "moderate" if aggregated["total_functions"] > 1000 else "low",
            "security_posture": "poor" if aggregated["security_score"] > 6 else "fair" if aggregated["security_score"] > 3 else "good"
        }
        
        return aggregated
    
    # Specific tool functions for direct access
    
    async def disassemble_function(self, binary_path: str, function_address: str) -> Dict[str, Any]:
        """Disassemble a specific function"""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"binary_path": binary_path, "function_address": function_address}
                
                async with session.post(
                    f"{self.ghidra_analysis_url}/decompile/function",
                    json=payload
                ) as response:
                    return await response.json()
                    
        except Exception as e:
            return {"error": str(e)}
    
    async def extract_strings(self, binary_path: str, method: str = "capstone") -> Dict[str, Any]:
        """Extract strings using specified method"""
        try:
            if method == "ghidra":
                url = f"{self.ghidra_analysis_url}/analyze/strings"
            else:
                url = f"{self.analysis_engine_url}/analyze/pe"
                
            async with aiohttp.ClientSession() as session:
                payload = {"binary_path": binary_path}
                
                async with session.post(url, json=payload) as response:
                    result = await response.json()
                    return {"strings": result.get("strings", [])}
                    
        except Exception as e:
            return {"error": str(e)}
    
    async def security_scan(self, binary_path: str) -> Dict[str, Any]:
        """Perform focused security scan"""
        return await self._perform_security_analysis(binary_path)
    
    async def get_analysis_capabilities(self) -> Dict[str, Any]:
        """Get comprehensive list of analysis capabilities"""
        capabilities = {
            "static_analysis": [
                "PE/ELF parsing", "x86/x64 disassembly", "Control flow graphs",
                "Import/export analysis", "String extraction", "Section analysis"
            ],
            "dynamic_analysis": [
                "Live memory analysis", "Process monitoring", "Network traffic analysis",
                "Game state tracking", "Real-time debugging"
            ],
            "decompilation": [
                "Function decompilation", "Data type reconstruction", "Symbol recovery",
                "Cross-reference analysis", "Call graph generation"
            ],
            "security_analysis": [
                "Vulnerability assessment", "Exploit detection", "Packer identification",
                "Anti-debug detection", "Security mitigation analysis"
            ],
            "supported_formats": ["PE", "ELF", "Mach-O", "Raw binary"],
            "architectures": ["x86", "x64", "ARM", "ARM64"]
        }
        
        return capabilities