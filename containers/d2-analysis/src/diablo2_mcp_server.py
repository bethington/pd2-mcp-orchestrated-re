#!/usr/bin/env python3
"""
Enhanced Diablo 2 MCP Server with platform integration
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import structlog

# Initialize logger first
logger = structlog.get_logger()

# Import platform modules first
import sys
sys.path.append('/app')

# Import MCP modules with correct structure from v1.13.1
try:
    from mcp.server import Server, NotificationOptions, InitializationOptions
    from mcp import types as mcp_types
    Resource = mcp_types.Resource
    Tool = mcp_types.Tool
    TextContent = mcp_types.TextContent
    ImageContent = mcp_types.ImageContent
    logger.info("Successfully imported MCP modules from v1.13.1")
except ImportError as e:
    # Fallback to importlib approach if needed
    import importlib
    mcp_pkg = importlib.import_module('mcp')
    mcp_server_module = importlib.import_module('mcp.server')
    mcp_types_module = importlib.import_module('mcp.types')
    Server = mcp_server_module.Server
    Resource = mcp_types_module.Resource
    Tool = mcp_types_module.Tool
    TextContent = mcp_types_module.TextContent
    ImageContent = mcp_types_module.ImageContent
    logger.warning(f"Using fallback imports: {e}")

from src.game.d2.character_tracker import CharacterTracker
from src.game.d2.inventory_manager import InventoryManager
from src.analysis.memory.analyzer import MemoryAnalyzer
from src.analysis.network.packet_analyzer import PacketAnalyzer
from src.analysis.behavioral.pattern_detector import PatternDetector
from src.core.session_manager import SessionManager
from src.data.storage.dgraph_client import DgraphClient

class EnhancedD2MCPServer:
    def __init__(self):
        self.server = Server("diablo2-enhanced")
        self.character_tracker = CharacterTracker()
        self.inventory_manager = InventoryManager()
        self.memory_analyzer = MemoryAnalyzer()
        self.packet_analyzer = PacketAnalyzer()
        self.pattern_detector = PatternDetector()
        self.session_manager = SessionManager()
        self.dgraph_client = DgraphClient()
        
        self.current_session = None
        self.monitoring_active = False
        self.analysis_data = {
            "character_stats": {},
            "inventory": [],
            "network_packets": [],
            "memory_snapshots": [],
            "behavioral_patterns": [],
            "security_events": []
        }
        
        self.setup_handlers()
        logger.info("Enhanced D2 MCP Server initialized")

    def setup_handlers(self):
        @self.server.list_resources()
        async def list_resources():
            return [
                Resource(
                    uri="d2://game/character",
                    name="Character Statistics and Progression",
                    mimeType="application/json",
                    description="Real-time character stats, level, experience, and attributes"
                ),
                Resource(
                    uri="d2://game/inventory", 
                    name="Character Inventory and Items",
                    mimeType="application/json",
                    description="Complete inventory state with item details and values"
                ),
                Resource(
                    uri="d2://network/packets",
                    name="Network Packet Analysis",
                    mimeType="application/json", 
                    description="Captured and analyzed D2 network traffic"
                ),
                Resource(
                    uri="d2://memory/live_dump",
                    name="Live Memory Analysis",
                    mimeType="application/json",
                    description="Real-time memory structure analysis"
                ),
                Resource(
                    uri="d2://analysis/behavioral",
                    name="Behavioral Pattern Analysis", 
                    mimeType="application/json",
                    description="Player behavior analysis and anomaly detection"
                ),
                Resource(
                    uri="d2://security/events",
                    name="Security Event Log",
                    mimeType="application/json",
                    description="Detected security events and potential exploits"
                ),
                Resource(
                    uri="d2://session/screenshots",
                    name="Session Screenshots",
                    mimeType="application/json",
                    description="Timestamped screenshots from game session"
                )
            ]

        @self.server.read_resource()
        async def read_resource(uri: str):
            try:
                if uri == "d2://game/character":
                    char_data = await self.character_tracker.get_current_stats()
                    return TextContent(
                        type="text",
                        text=json.dumps(char_data, indent=2)
                    )
                    
                elif uri == "d2://game/inventory":
                    inventory_data = await self.inventory_manager.get_full_inventory()
                    return TextContent(
                        type="text",
                        text=json.dumps(inventory_data, indent=2)
                    )
                    
                elif uri == "d2://network/packets":
                    packet_data = await self.packet_analyzer.get_recent_packets(limit=100)
                    return TextContent(
                        type="text",
                        text=json.dumps(packet_data, indent=2)
                    )
                    
                elif uri == "d2://memory/live_dump":
                    memory_data = await self.memory_analyzer.create_live_dump()
                    return TextContent(
                        type="text", 
                        text=json.dumps(memory_data, indent=2)
                    )
                    
                elif uri == "d2://analysis/behavioral":
                    behavioral_data = await self.pattern_detector.analyze_patterns()
                    return TextContent(
                        type="text",
                        text=json.dumps(behavioral_data, indent=2)
                    )
                    
                elif uri == "d2://security/events":
                    security_events = self.analysis_data["security_events"]
                    return TextContent(
                        type="text",
                        text=json.dumps(security_events, indent=2)
                    )
                    
                elif uri == "d2://session/screenshots":
                    screenshots = await self.get_session_screenshots()
                    return TextContent(
                        type="text",
                        text=json.dumps(screenshots, indent=2)
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
                    name="start_monitoring_session",
                    description="Start comprehensive D2 monitoring session",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "character_name": {"type": "string"},
                            "analysis_goals": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Analysis objectives: security, performance, behavior, etc."
                            },
                            "monitoring_duration": {
                                "type": "integer", 
                                "default": 3600,
                                "description": "Monitoring duration in seconds"
                            }
                        }
                    }
                ),
                Tool(
                    name="analyze_memory_structure",
                    description="Deep analysis of D2 memory structures",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target_structure": {
                                "type": "string",
                                "enum": ["character", "inventory", "world_state", "network_buffers"]
                            },
                            "analysis_depth": {
                                "type": "string",
                                "enum": ["surface", "detailed", "comprehensive"]
                            }
                        }
                    }
                ),
                Tool(
                    name="inject_test_scenario",
                    description="Inject controlled test scenarios for analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scenario_type": {
                                "type": "string",
                                "enum": ["item_spawn", "experience_gain", "movement_test", "network_test"]
                            },
                            "parameters": {"type": "object"}
                        }
                    }
                ),
                Tool(
                    name="detect_security_anomalies",
                    description="Scan for security anomalies and potential exploits",
                    inputSchema={
                        "type": "object", 
                        "properties": {
                            "detection_types": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "enum": ["memory_corruption", "packet_injection", "timing_attacks", "cheat_signatures"]
                                }
                            }
                        }
                    }
                ),
                Tool(
                    name="capture_screenshot",
                    description="Capture screenshot of the D2 game desktop",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "description": {
                                "type": "string", 
                                "description": "Optional description of what the screenshot shows"
                            },
                            "quality": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100,
                                "default": 90,
                                "description": "Screenshot quality (1-100)"
                            }
                        }
                    }
                ),
                Tool(
                    name="generate_analysis_report",
                    description="Generate comprehensive analysis report",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "report_type": {
                                "type": "string",
                                "enum": ["security", "performance", "behavioral", "comprehensive"]
                            },
                            "include_recommendations": {"type": "boolean", "default": True}
                        }
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict):
            try:
                if name == "start_monitoring_session":
                    return await self.start_monitoring_session(arguments)
                elif name == "analyze_memory_structure":
                    return await self.analyze_memory_structure(arguments)
                elif name == "inject_test_scenario":
                    return await self.inject_test_scenario(arguments)
                elif name == "detect_security_anomalies":
                    return await self.detect_security_anomalies(arguments)
                elif name == "capture_screenshot":
                    return await self.capture_screenshot(arguments)
                elif name == "generate_analysis_report":
                    return await self.generate_analysis_report(arguments)
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

    async def start_monitoring_session(self, args: Dict[str, Any]):
        """Start comprehensive monitoring session"""
        character_name = args.get("character_name", "Unknown")
        analysis_goals = args.get("analysis_goals", ["general"])
        duration = args.get("monitoring_duration", 3600)
        
        # Create session in platform
        self.current_session = await self.session_manager.create_session(
            binary_path="/game/pd2/ProjectD2/Game.exe",
            analysis_goals=analysis_goals
        )
        
        # Start monitoring tasks
        self.monitoring_active = True
        asyncio.create_task(self._monitoring_loop())
        
        logger.info(f"Started monitoring session for {character_name}")
        
        return [TextContent(
            type="text",
            text=f"Monitoring session started for character '{character_name}'\n"
                 f"Session ID: {self.current_session}\n" 
                 f"Duration: {duration} seconds\n"
                 f"Analysis goals: {', '.join(analysis_goals)}"
        )]

    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Update character stats
                char_stats = await self.character_tracker.get_current_stats()
                if char_stats:
                    self.analysis_data["character_stats"] = char_stats
                    await self.dgraph_client.store_character_snapshot(
                        self.current_session, char_stats
                    )

                # Update inventory
                inventory = await self.inventory_manager.get_full_inventory()
                if inventory:
                    self.analysis_data["inventory"] = inventory

                # Analyze network packets
                packets = await self.packet_analyzer.get_recent_packets(limit=50)
                if packets:
                    self.analysis_data["network_packets"].extend(packets[-10:])  # Keep recent

                # Check for security events
                await self._check_security_events()

                # Pattern analysis
                patterns = await self.pattern_detector.analyze_recent_activity()
                if patterns:
                    self.analysis_data["behavioral_patterns"].extend(patterns)

                await asyncio.sleep(1.0)  # Monitor every second
                
            except Exception as e:
                logger.error("Error in monitoring loop", error=str(e))
                await asyncio.sleep(5.0)

    async def _check_security_events(self):
        """Check for security events and anomalies"""
        # Implement security checks
        pass

    async def analyze_memory_structure(self, args: Dict[str, Any]):
        """Analyze specific memory structures"""
        target = args.get("target_structure", "character")
        depth = args.get("analysis_depth", "detailed")
        
        result = await self.memory_analyzer.analyze_structure(target, depth)
        
        return [TextContent(
            type="text",
            text=f"Memory analysis for {target} (depth: {depth})\n"
                 f"Results: {json.dumps(result, indent=2)}"
        )]

    async def inject_test_scenario(self, args: Dict[str, Any]):
        """Inject test scenarios for analysis"""
        scenario_type = args.get("scenario_type", "movement_test")
        parameters = args.get("parameters", {})
        
        # Implement scenario injection logic
        result = {"scenario": scenario_type, "status": "injected", "parameters": parameters}
        
        return [TextContent(
            type="text",
            text=f"Test scenario injected: {scenario_type}\n"
                 f"Parameters: {json.dumps(parameters, indent=2)}"
        )]

    async def detect_security_anomalies(self, args: Dict[str, Any]):
        """Detect security anomalies"""
        detection_types = args.get("detection_types", ["cheat_signatures"])
        
        anomalies = []
        for detection_type in detection_types:
            # Implement detection logic for each type
            anomaly = await self._run_security_detection(detection_type)
            if anomaly:
                anomalies.append(anomaly)
        
        return [TextContent(
            type="text",
            text=f"Security anomaly scan complete\n"
                 f"Detected {len(anomalies)} anomalies\n"
                 f"Details: {json.dumps(anomalies, indent=2)}"
        )]

    async def capture_screenshot(self, args: Dict[str, Any]):
        """Capture screenshot of the D2 desktop"""
        import subprocess
        import datetime
        
        description = args.get("description", "D2 game screenshot")
        quality = args.get("quality", 90)
        
        # Generate timestamp-based filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"d2_screenshot_{timestamp}.png"
        filepath = f"/screenshots/{filename}"
        
        try:
            # Use scrot to capture screenshot of display :1
            cmd = [
                "scrot", 
                "-q", str(quality),  # Quality
                "-z",  # Compress
                filepath
            ]
            
            # Set DISPLAY environment variable for X11
            env = {"DISPLAY": ":1"}
            
            result = subprocess.run(
                cmd, 
                env=env, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode == 0:
                # Create metadata file
                metadata = {
                    "timestamp": time.time(),
                    "description": description,
                    "filename": filename,
                    "path": filepath,
                    "session_id": self.current_session,
                    "quality": quality,
                    "capture_method": "scrot"
                }
                
                # Save metadata
                metadata_file = filepath.replace(".png", "_metadata.json")
                with open(metadata_file, "w") as f:
                    json.dump(metadata, f, indent=2)
                
                logger.info(f"Screenshot captured: {filename}")
                
                return [TextContent(
                    type="text",
                    text=f"Screenshot captured successfully!\n"
                         f"Filename: {filename}\n"
                         f"Path: {filepath}\n" 
                         f"Description: {description}\n"
                         f"Quality: {quality}%\n"
                         f"Metadata: {json.dumps(metadata, indent=2)}"
                )]
            else:
                error_msg = result.stderr or "Unknown error"
                logger.error(f"Screenshot capture failed: {error_msg}")
                return [TextContent(
                    type="text",
                    text=f"Screenshot capture failed: {error_msg}"
                )]
                
        except subprocess.TimeoutExpired:
            return [TextContent(
                type="text", 
                text="Screenshot capture timed out"
            )]
        except Exception as e:
            logger.error(f"Screenshot capture error: {str(e)}")
            return [TextContent(
                type="text",
                text=f"Screenshot capture error: {str(e)}"
            )]

    async def generate_analysis_report(self, args: Dict[str, Any]):
        """Generate comprehensive analysis report"""
        report_type = args.get("report_type", "comprehensive")
        include_recommendations = args.get("include_recommendations", True)
        
        report = {
            "report_type": report_type,
            "timestamp": time.time(),
            "session_id": self.current_session,
            "summary": "Analysis report generated",
            "data": self.analysis_data
        }
        
        if include_recommendations:
            report["recommendations"] = await self._generate_recommendations()
        
        return [TextContent(
            type="text",
            text=f"Analysis report generated ({report_type})\n"
                 f"{json.dumps(report, indent=2)}"
        )]

    async def _run_security_detection(self, detection_type: str):
        """Run specific security detection"""
        # Implement detection logic
        return None

    async def _generate_recommendations(self):
        """Generate security and performance recommendations"""
        return ["Monitor memory usage", "Check network patterns", "Validate user behavior"]

    async def get_session_screenshots(self):
        """Get session screenshots"""
        screenshots_dir = Path("/screenshots")
        if not screenshots_dir.exists():
            return []
            
        screenshots = []
        for screenshot_file in screenshots_dir.glob("*.png"):
            screenshots.append({
                "timestamp": screenshot_file.stat().st_mtime,
                "filename": screenshot_file.name,
                "path": str(screenshot_file)
            })
            
        return sorted(screenshots, key=lambda x: x["timestamp"], reverse=True)

async def main():
    server = EnhancedD2MCPServer()
    
    # Start MCP server
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await server.server.run(read_stream, write_stream, server.server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
