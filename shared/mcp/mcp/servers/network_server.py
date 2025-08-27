"""
Network analysis MCP server for packet capture and protocol analysis
"""

import asyncio
import json
import time
import struct
import socket
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import structlog
from mcp.server import Server
from mcp.types import Resource, Tool, TextContent

logger = structlog.get_logger()

class NetworkPacket:
    """Network packet representation"""
    
    def __init__(self, timestamp: float, direction: str, protocol: str, 
                 src_addr: str, dst_addr: str, src_port: int, dst_port: int, 
                 data: bytes, packet_size: int):
        self.timestamp = timestamp
        self.direction = direction  # "inbound" or "outbound"
        self.protocol = protocol    # "TCP", "UDP", etc.
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.data = data
        self.packet_size = packet_size
        self.packet_id = None
        self.analyzed = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary"""
        return {
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "direction": self.direction,
            "protocol": self.protocol,
            "src_addr": self.src_addr,
            "dst_addr": self.dst_addr,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "data_hex": self.data.hex() if self.data else "",
            "packet_id": self.packet_id,
            "analyzed": self.analyzed
        }

class D2ProtocolAnalyzer:
    """Diablo 2 protocol analyzer"""
    
    # Known D2 packet types
    D2_PACKET_TYPES = {
        0x01: "Walk (to location)",
        0x02: "Walk (to unit)",
        0x03: "Run (to location)",
        0x04: "Run (to unit)",
        0x05: "Left click skill (location)",
        0x06: "Left click skill (unit)",
        0x07: "Left click skill (location)",
        0x08: "Left click skill (unit)",
        0x09: "Request unit data",
        0x0A: "Request unit data",
        0x0B: "Player chat",
        0x0C: "NPC interaction",
        0x0D: "NPC purchase/sell",
        0x0E: "Player position update",
        0x0F: "Player attributes update",
        0x10: "Player skills update",
        0x11: "Player attributes update",
        0x12: "Request skill tree",
        0x13: "Assign attribute points",
        0x14: "Assign skill points",
        0x15: "Player reassignment",
        0x16: "Small gold pickup",
        0x17: "Add experience",
        0x18: "Add attribute points",
        0x19: "Add skill points",
        0x1A: "Level up",
        0x1B: "Add skill",
        0x1C: "Update skill",
        0x1D: "Chat message",
        0x26: "Game info",
        0x51: "Item pickup",
        0x52: "Item drop",
        0x5A: "Merc for hire list",
        0x81: "Merc hire",
        0x9C: "Item action",
        0x9D: "Body/secondary hand item swap"
    }
    
    def analyze_packet(self, packet: NetworkPacket) -> Dict[str, Any]:
        """Analyze a D2 network packet"""
        analysis = {
            "packet_type": "unknown",
            "d2_packet_id": None,
            "d2_packet_name": None,
            "payload_size": len(packet.data),
            "analysis_confidence": 0.0,
            "parsed_data": {}
        }
        
        if not packet.data:
            return analysis
        
        try:
            # Check if this looks like a D2 packet
            if self._is_d2_packet(packet):
                packet_id = packet.data[0]
                analysis["d2_packet_id"] = f"0x{packet_id:02x}"
                analysis["d2_packet_name"] = self.D2_PACKET_TYPES.get(packet_id, "Unknown D2 packet")
                analysis["packet_type"] = "diablo2"
                analysis["analysis_confidence"] = 0.8
                
                # Parse specific packet types
                analysis["parsed_data"] = self._parse_d2_packet(packet_id, packet.data)
            else:
                analysis["packet_type"] = "generic"
                analysis["analysis_confidence"] = 0.1
                
        except Exception as e:
            logger.warning(f"Packet analysis failed: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def _is_d2_packet(self, packet: NetworkPacket) -> bool:
        """Determine if packet is likely a D2 protocol packet"""
        # Check common D2 characteristics
        if len(packet.data) < 1:
            return False
        
        # D2 typically uses specific ports
        d2_ports = [4000, 6112, 6113, 6114]
        if packet.src_port in d2_ports or packet.dst_port in d2_ports:
            # Check for known packet IDs
            packet_id = packet.data[0]
            if packet_id in self.D2_PACKET_TYPES:
                return True
        
        # Check for D2-like patterns in data
        if len(packet.data) >= 2:
            # D2 packets often have specific size patterns
            if packet.data[0] in self.D2_PACKET_TYPES and len(packet.data) >= 2:
                return True
        
        return False
    
    def _parse_d2_packet(self, packet_id: int, data: bytes) -> Dict[str, Any]:
        """Parse D2 packet data based on packet ID"""
        parsed = {}
        
        try:
            if packet_id == 0x01:  # Walk to location
                if len(data) >= 5:
                    x = struct.unpack("<H", data[1:3])[0]
                    y = struct.unpack("<H", data[3:5])[0]
                    parsed = {"action": "walk", "x": x, "y": y}
            
            elif packet_id == 0x0B:  # Player chat
                if len(data) >= 3:
                    chat_type = data[1]
                    msg_end = data.find(b'\x00', 2)
                    if msg_end != -1:
                        message = data[2:msg_end].decode('latin-1', errors='ignore')
                        parsed = {"chat_type": chat_type, "message": message}
            
            elif packet_id == 0x0E:  # Player position update
                if len(data) >= 6:
                    x = struct.unpack("<H", data[1:3])[0]
                    y = struct.unpack("<H", data[3:5])[0]
                    parsed = {"action": "position_update", "x": x, "y": y}
            
            elif packet_id == 0x15:  # Player reassignment
                if len(data) >= 8:
                    unit_type = data[1]
                    unit_id = struct.unpack("<I", data[2:6])[0]
                    x = struct.unpack("<H", data[6:8])[0]
                    y = struct.unpack("<H", data[8:10])[0] if len(data) >= 10 else 0
                    parsed = {"unit_type": unit_type, "unit_id": unit_id, "x": x, "y": y}
            
            elif packet_id == 0x26:  # Game info
                if len(data) >= 4:
                    game_type = data[1]
                    difficulty = data[2]
                    parsed = {"game_type": game_type, "difficulty": difficulty}
            
            else:
                # Generic parsing for unknown packets
                parsed = {
                    "raw_size": len(data),
                    "first_bytes": data[:min(16, len(data))].hex()
                }
                
        except Exception as e:
            parsed = {"parse_error": str(e)}
        
        return parsed

class NetworkMCPServer:
    """MCP server for network analysis and packet capture"""
    
    def __init__(self):
        self.server = Server("network-analysis")
        self.captured_packets = []
        self.packet_filters = {}
        self.capture_active = False
        self.d2_analyzer = D2ProtocolAnalyzer()
        self.statistics = {
            "total_packets": 0,
            "d2_packets": 0,
            "other_packets": 0,
            "capture_start_time": None,
            "last_packet_time": None
        }
        
        self.setup_handlers()
        logger.info("Network MCP Server initialized")
    
    def setup_handlers(self):
        @self.server.list_resources()
        async def list_resources():
            return [
                Resource(
                    uri="network://capture/packets",
                    name="Captured Network Packets",
                    mimeType="application/json",
                    description="Real-time captured network packets"
                ),
                Resource(
                    uri="network://analysis/d2_packets",
                    name="Diablo 2 Protocol Analysis",
                    mimeType="application/json",
                    description="Analyzed D2 protocol packets with parsing"
                ),
                Resource(
                    uri="network://statistics/traffic",
                    name="Network Traffic Statistics",
                    mimeType="application/json",
                    description="Traffic analysis and statistics"
                ),
                Resource(
                    uri="network://patterns/suspicious",
                    name="Suspicious Network Patterns",
                    mimeType="application/json",
                    description="Detected suspicious network activity"
                )
            ]
        
        @self.server.read_resource()
        async def read_resource(uri: str):
            try:
                if uri == "network://capture/packets":
                    return TextContent(
                        type="text",
                        text=json.dumps({
                            "total_packets": len(self.captured_packets),
                            "packets": [p.to_dict() for p in self.captured_packets[-100:]]  # Last 100
                        }, indent=2)
                    )
                
                elif uri == "network://analysis/d2_packets":
                    d2_packets = [p for p in self.captured_packets 
                                 if self.d2_analyzer._is_d2_packet(p)]
                    
                    analyzed_packets = []
                    for packet in d2_packets[-50:]:  # Last 50 D2 packets
                        packet_dict = packet.to_dict()
                        packet_dict["d2_analysis"] = self.d2_analyzer.analyze_packet(packet)
                        analyzed_packets.append(packet_dict)
                    
                    return TextContent(
                        type="text",
                        text=json.dumps({
                            "d2_packets_found": len(d2_packets),
                            "analyzed_packets": analyzed_packets
                        }, indent=2)
                    )
                
                elif uri == "network://statistics/traffic":
                    return TextContent(
                        type="text",
                        text=json.dumps(self._generate_traffic_statistics(), indent=2)
                    )
                
                elif uri == "network://patterns/suspicious":
                    return TextContent(
                        type="text",
                        text=json.dumps(self._detect_suspicious_patterns(), indent=2)
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
                    name="start_packet_capture",
                    description="Start capturing network packets",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "interface": {
                                "type": "string",
                                "default": "eth0",
                                "description": "Network interface to capture on"
                            },
                            "filter": {
                                "type": "string",
                                "description": "Packet filter (BPF syntax)"
                            },
                            "duration": {
                                "type": "integer",
                                "default": 300,
                                "description": "Capture duration in seconds"
                            }
                        }
                    }
                ),
                Tool(
                    name="stop_packet_capture",
                    description="Stop packet capture",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="analyze_d2_traffic",
                    description="Analyze captured Diablo 2 network traffic",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "time_window": {
                                "type": "integer",
                                "default": 60,
                                "description": "Analysis time window in seconds"
                            },
                            "include_raw_data": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include raw packet data in analysis"
                            }
                        }
                    }
                ),
                Tool(
                    name="detect_bot_behavior",
                    description="Detect potential bot behavior in network traffic",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sensitivity": {
                                "type": "string",
                                "enum": ["low", "medium", "high"],
                                "default": "medium",
                                "description": "Detection sensitivity level"
                            },
                            "time_window": {
                                "type": "integer",
                                "default": 300,
                                "description": "Analysis time window in seconds"
                            }
                        }
                    }
                ),
                Tool(
                    name="generate_traffic_report",
                    description="Generate comprehensive network traffic report",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "report_type": {
                                "type": "string",
                                "enum": ["summary", "detailed", "security_focused"],
                                "default": "summary",
                                "description": "Type of report to generate"
                            },
                            "include_visualizations": {
                                "type": "boolean",
                                "default": False,
                                "description": "Include traffic visualization data"
                            }
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict):
            try:
                if name == "start_packet_capture":
                    return await self.start_packet_capture(arguments)
                elif name == "stop_packet_capture":
                    return await self.stop_packet_capture(arguments)
                elif name == "analyze_d2_traffic":
                    return await self.analyze_d2_traffic(arguments)
                elif name == "detect_bot_behavior":
                    return await self.detect_bot_behavior(arguments)
                elif name == "generate_traffic_report":
                    return await self.generate_traffic_report(arguments)
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
    
    async def start_packet_capture(self, args: Dict[str, Any]):
        """Start packet capture"""
        if self.capture_active:
            return [TextContent(
                type="text",
                text="Packet capture is already active"
            )]
        
        interface = args.get("interface", "eth0")
        packet_filter = args.get("filter", "")
        duration = args.get("duration", 300)
        
        try:
            self.capture_active = True
            self.statistics["capture_start_time"] = time.time()
            
            # Start capture task
            asyncio.create_task(self._capture_packets(interface, packet_filter, duration))
            
            return [TextContent(
                type="text",
                text=json.dumps({
                    "status": "capture_started",
                    "interface": interface,
                    "filter": packet_filter,
                    "duration": duration,
                    "message": f"Packet capture started on {interface}"
                }, indent=2)
            )]
            
        except Exception as e:
            self.capture_active = False
            return [TextContent(
                type="text",
                text=f"Failed to start packet capture: {str(e)}"
            )]
    
    async def stop_packet_capture(self, args: Dict[str, Any]):
        """Stop packet capture"""
        if not self.capture_active:
            return [TextContent(
                type="text",
                text="No active packet capture"
            )]
        
        self.capture_active = False
        
        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "capture_stopped",
                "total_packets_captured": len(self.captured_packets),
                "capture_duration": time.time() - (self.statistics["capture_start_time"] or 0)
            }, indent=2)
        )]
    
    async def analyze_d2_traffic(self, args: Dict[str, Any]):
        """Analyze D2 traffic patterns"""
        time_window = args.get("time_window", 60)
        include_raw_data = args.get("include_raw_data", False)
        
        # Filter packets within time window
        cutoff_time = time.time() - time_window
        recent_packets = [p for p in self.captured_packets if p.timestamp >= cutoff_time]
        
        # Filter for D2 packets
        d2_packets = [p for p in recent_packets if self.d2_analyzer._is_d2_packet(p)]
        
        # Analyze packet types
        packet_type_counts = {}
        for packet in d2_packets:
            if packet.data:
                packet_id = packet.data[0]
                packet_name = self.d2_analyzer.D2_PACKET_TYPES.get(packet_id, f"Unknown (0x{packet_id:02x})")
                packet_type_counts[packet_name] = packet_type_counts.get(packet_name, 0) + 1
        
        analysis_result = {
            "time_window_seconds": time_window,
            "total_packets_analyzed": len(recent_packets),
            "d2_packets_found": len(d2_packets),
            "d2_packet_types": packet_type_counts,
            "traffic_rate": len(d2_packets) / time_window if time_window > 0 else 0,
            "analysis_summary": {
                "most_common_packet": max(packet_type_counts.items(), key=lambda x: x[1])[0] if packet_type_counts else None,
                "unique_packet_types": len(packet_type_counts),
                "average_packet_size": sum(len(p.data) for p in d2_packets) / len(d2_packets) if d2_packets else 0
            }
        }
        
        if include_raw_data:
            analysis_result["packet_details"] = [
                {
                    "timestamp": p.timestamp,
                    "packet_id": f"0x{p.data[0]:02x}" if p.data else None,
                    "size": len(p.data),
                    "analysis": self.d2_analyzer.analyze_packet(p)
                } for p in d2_packets[-20:]  # Last 20 packets
            ]
        
        return [TextContent(
            type="text",
            text=json.dumps(analysis_result, indent=2)
        )]
    
    async def detect_bot_behavior(self, args: Dict[str, Any]):
        """Detect potential bot behavior"""
        sensitivity = args.get("sensitivity", "medium")
        time_window = args.get("time_window", 300)
        
        # Filter recent packets
        cutoff_time = time.time() - time_window
        recent_packets = [p for p in self.captured_packets if p.timestamp >= cutoff_time]
        d2_packets = [p for p in recent_packets if self.d2_analyzer._is_d2_packet(p)]
        
        bot_indicators = {
            "excessive_repetition": False,
            "inhuman_timing": False,
            "suspicious_patterns": [],
            "confidence_score": 0.0
        }
        
        if len(d2_packets) < 10:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "bot_behavior_detected": False,
                    "reason": "Insufficient packet data for analysis",
                    "packets_analyzed": len(d2_packets)
                }, indent=2)
            )]
        
        # Check for excessive repetition
        packet_sequences = []
        for i in range(len(d2_packets) - 2):
            sequence = tuple(p.data[0] if p.data else 0 for p in d2_packets[i:i+3])
            packet_sequences.append(sequence)
        
        sequence_counts = {}
        for seq in packet_sequences:
            sequence_counts[seq] = sequence_counts.get(seq, 0) + 1
        
        max_repetition = max(sequence_counts.values()) if sequence_counts else 0
        if max_repetition > 5:  # Threshold for bot detection
            bot_indicators["excessive_repetition"] = True
            bot_indicators["confidence_score"] += 0.3
        
        # Check timing patterns
        intervals = []
        for i in range(1, len(d2_packets)):
            interval = d2_packets[i].timestamp - d2_packets[i-1].timestamp
            intervals.append(interval)
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            interval_variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # Very consistent timing might indicate automation
            if interval_variance < 0.01 and len(intervals) > 20:
                bot_indicators["inhuman_timing"] = True
                bot_indicators["confidence_score"] += 0.4
        
        # Additional pattern checks based on sensitivity
        if sensitivity == "high":
            # More aggressive detection
            if max_repetition > 3:
                bot_indicators["suspicious_patterns"].append("High packet repetition")
                bot_indicators["confidence_score"] += 0.2
        
        bot_detected = bot_indicators["confidence_score"] > 0.5
        
        return [TextContent(
            type="text",
            text=json.dumps({
                "bot_behavior_detected": bot_detected,
                "confidence_score": bot_indicators["confidence_score"],
                "indicators": bot_indicators,
                "packets_analyzed": len(d2_packets),
                "analysis_period": time_window,
                "recommendation": "Manual review recommended" if bot_detected else "Normal behavior detected"
            }, indent=2)
        )]
    
    async def generate_traffic_report(self, args: Dict[str, Any]):
        """Generate comprehensive traffic report"""
        report_type = args.get("report_type", "summary")
        
        stats = self._generate_traffic_statistics()
        
        report = {
            "report_type": report_type,
            "generation_time": datetime.now().isoformat(),
            "statistics": stats
        }
        
        if report_type in ["detailed", "security_focused"]:
            # Add detailed analysis
            d2_packets = [p for p in self.captured_packets if self.d2_analyzer._is_d2_packet(p)]
            
            report["detailed_analysis"] = {
                "d2_protocol_breakdown": self._analyze_d2_protocol_usage(d2_packets),
                "traffic_patterns": self._analyze_traffic_patterns(d2_packets),
                "temporal_analysis": self._analyze_temporal_patterns(d2_packets)
            }
        
        if report_type == "security_focused":
            # Add security analysis
            report["security_analysis"] = {
                "suspicious_activity": self._detect_suspicious_patterns(),
                "anomalies": self._detect_traffic_anomalies(),
                "recommendations": self._generate_security_recommendations()
            }
        
        return [TextContent(
            type="text",
            text=json.dumps(report, indent=2)
        )]
    
    async def _capture_packets(self, interface: str, packet_filter: str, duration: int):
        """Simulate packet capture (in real implementation, would use actual capture)"""
        logger.info(f"Starting packet capture on {interface}")
        
        start_time = time.time()
        while self.capture_active and (time.time() - start_time) < duration:
            # Simulate captured packets (in real implementation, would capture from network)
            await self._simulate_packet_capture()
            await asyncio.sleep(0.1)  # 100ms intervals
        
        self.capture_active = False
        logger.info("Packet capture completed")
    
    async def _simulate_packet_capture(self):
        """Simulate packet capture for development/testing"""
        # Generate simulated D2 packets
        import random
        
        if random.random() < 0.3:  # 30% chance of generating a packet
            timestamp = time.time()
            
            # Generate realistic D2 packet
            packet_types = [0x01, 0x02, 0x0B, 0x0E, 0x15, 0x26]
            packet_id = random.choice(packet_types)
            
            # Create packet data based on type
            if packet_id == 0x01:  # Walk packet
                data = struct.pack("<BHH", packet_id, random.randint(100, 800), random.randint(100, 600))
            elif packet_id == 0x0B:  # Chat packet
                message = "Test message"
                data = struct.pack("<BB", packet_id, 0x01) + message.encode() + b'\x00'
            else:
                data = bytes([packet_id]) + b'\x00' * random.randint(1, 10)
            
            packet = NetworkPacket(
                timestamp=timestamp,
                direction="inbound" if random.random() < 0.5 else "outbound",
                protocol="TCP",
                src_addr="127.0.0.1",
                dst_addr="127.0.0.1",
                src_port=4000,
                dst_port=random.randint(30000, 40000),
                data=data,
                packet_size=len(data)
            )
            
            self.captured_packets.append(packet)
            self.statistics["total_packets"] += 1
            self.statistics["last_packet_time"] = timestamp
            
            # Keep only recent packets to manage memory
            if len(self.captured_packets) > 10000:
                self.captured_packets = self.captured_packets[-5000:]
    
    def _generate_traffic_statistics(self) -> Dict[str, Any]:
        """Generate traffic statistics"""
        d2_packets = [p for p in self.captured_packets if self.d2_analyzer._is_d2_packet(p)]
        
        return {
            "total_packets": len(self.captured_packets),
            "d2_packets": len(d2_packets),
            "other_packets": len(self.captured_packets) - len(d2_packets),
            "capture_duration": (self.statistics["last_packet_time"] or 0) - (self.statistics["capture_start_time"] or 0),
            "packets_per_second": len(self.captured_packets) / max(1, (time.time() - (self.statistics["capture_start_time"] or time.time()))),
            "average_packet_size": sum(p.packet_size for p in self.captured_packets) / len(self.captured_packets) if self.captured_packets else 0,
            "protocol_distribution": self._get_protocol_distribution()
        }
    
    def _get_protocol_distribution(self) -> Dict[str, int]:
        """Get protocol distribution"""
        distribution = {}
        for packet in self.captured_packets:
            distribution[packet.protocol] = distribution.get(packet.protocol, 0) + 1
        return distribution
    
    def _detect_suspicious_patterns(self) -> Dict[str, Any]:
        """Detect suspicious network patterns"""
        return {
            "high_frequency_packets": False,
            "unusual_packet_sizes": False,
            "suspicious_destinations": [],
            "potential_exploits": [],
            "confidence_level": "low"
        }
    
    def _analyze_d2_protocol_usage(self, packets: List[NetworkPacket]) -> Dict[str, Any]:
        """Analyze D2 protocol usage patterns"""
        packet_counts = {}
        for packet in packets:
            if packet.data:
                packet_id = packet.data[0]
                packet_name = self.d2_analyzer.D2_PACKET_TYPES.get(packet_id, f"Unknown_{packet_id:02x}")
                packet_counts[packet_name] = packet_counts.get(packet_name, 0) + 1
        
        return {
            "packet_type_frequency": packet_counts,
            "total_d2_packets": len(packets),
            "most_common_packets": sorted(packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    
    def _analyze_traffic_patterns(self, packets: List[NetworkPacket]) -> Dict[str, Any]:
        """Analyze traffic patterns"""
        if not packets:
            return {}
        
        intervals = []
        for i in range(1, len(packets)):
            intervals.append(packets[i].timestamp - packets[i-1].timestamp)
        
        return {
            "average_interval": sum(intervals) / len(intervals) if intervals else 0,
            "min_interval": min(intervals) if intervals else 0,
            "max_interval": max(intervals) if intervals else 0,
            "total_duration": packets[-1].timestamp - packets[0].timestamp if len(packets) > 1 else 0
        }
    
    def _analyze_temporal_patterns(self, packets: List[NetworkPacket]) -> Dict[str, Any]:
        """Analyze temporal patterns in traffic"""
        if not packets:
            return {}
        
        # Group packets by time periods
        hour_counts = {}
        for packet in packets:
            hour = int(packet.timestamp) // 3600
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        return {
            "packets_by_hour": hour_counts,
            "peak_hour": max(hour_counts.items(), key=lambda x: x[1])[0] if hour_counts else None,
            "activity_periods": len(hour_counts)
        }
    
    def _detect_traffic_anomalies(self) -> List[Dict[str, Any]]:
        """Detect traffic anomalies"""
        anomalies = []
        
        # Check for unusual packet sizes
        sizes = [p.packet_size for p in self.captured_packets]
        if sizes:
            avg_size = sum(sizes) / len(sizes)
            for packet in self.captured_packets:
                if packet.packet_size > avg_size * 5:  # 5x larger than average
                    anomalies.append({
                        "type": "oversized_packet",
                        "timestamp": packet.timestamp,
                        "size": packet.packet_size,
                        "average_size": avg_size
                    })
        
        return anomalies[:10]  # Limit results
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if len(self.captured_packets) > 1000:
            recommendations.append("High traffic volume detected - consider implementing rate limiting")
        
        d2_packet_ratio = len([p for p in self.captured_packets if self.d2_analyzer._is_d2_packet(p)]) / len(self.captured_packets)
        if d2_packet_ratio < 0.5:
            recommendations.append("Significant non-D2 traffic detected - investigate for potential security issues")
        
        if not recommendations:
            recommendations.append("No immediate security concerns identified")
        
        return recommendations

async def main():
    server = NetworkMCPServer()
    
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await server.server.run(read_stream, write_stream, server.server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
