#!/usr/bin/env python3
"""
Network Packet Analyzer for D2 Traffic Monitoring
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any
import struct
import socket
from scapy.all import sniff, IP, TCP, UDP, Raw
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class D2PacketAnalyzer:
    def __init__(self):
        self.capture_filter = "port 4000 or port 6112 or port 6113"
        self.interface = "eth0"
        self.packets_captured = []
        self.d2_packets = []
        
    def analyze_d2_packet(self, packet):
        """Analyze Diablo 2 specific packets"""
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.dport in [4000, 6112, 6113] or tcp_layer.sport in [4000, 6112, 6113]:
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw])
                    return self.parse_d2_payload(payload, tcp_layer.dport)
        return None
    
    def parse_d2_payload(self, payload: bytes, port: int) -> Dict[str, Any]:
        """Parse Diablo 2 packet payload"""
        if len(payload) < 1:
            return None
            
        packet_info = {
            "timestamp": time.time(),
            "port": port,
            "size": len(payload),
            "type": "unknown"
        }
        
        # Basic D2 packet identification
        if port == 4000:  # Game server
            packet_info["type"] = "game_data"
            if len(payload) > 0:
                packet_info["packet_id"] = payload[0]
                
        elif port in [6112, 6113]:  # Battle.net
            packet_info["type"] = "battlenet"
            
        packet_info["payload"] = payload.hex()
        return packet_info
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            self.packets_captured.append(packet)
            
            d2_packet = self.analyze_d2_packet(packet)
            if d2_packet:
                self.d2_packets.append(d2_packet)
                logger.info(f"D2 Packet: {d2_packet['type']} on port {d2_packet['port']}")
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start_capture(self):
        """Start packet capture"""
        logger.info(f"Starting packet capture on {self.interface} with filter: {self.capture_filter}")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self.packet_handler,
                store=0
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            # Fall back to simple socket capture if scapy fails
            self.fallback_capture()
    
    def fallback_capture(self):
        """Fallback capture method"""
        logger.info("Using fallback capture method")
        while True:
            try:
                time.sleep(1)
                # Simple placeholder - would implement raw socket capture
                logger.info("Monitoring network...")
            except KeyboardInterrupt:
                break
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent D2 packets"""
        return self.d2_packets[-limit:]
    
    def save_capture_data(self, filename: str):
        """Save captured data to file"""
        with open(filename, 'w') as f:
            json.dump({
                "total_packets": len(self.packets_captured),
                "d2_packets": len(self.d2_packets),
                "recent_d2_packets": self.get_recent_packets()
            }, f, indent=2)

async def main():
    analyzer = D2PacketAnalyzer()
    
    # Start capture in background
    loop = asyncio.get_event_loop()
    capture_task = loop.run_in_executor(None, analyzer.start_capture)
    
    # Status reporting
    while True:
        await asyncio.sleep(10)
        logger.info(f"Captured {len(analyzer.packets_captured)} total, {len(analyzer.d2_packets)} D2 packets")

if __name__ == "__main__":
    asyncio.run(main())
