"""
Memory Analyzer for Diablo 2
"""

import asyncio
import psutil
import struct
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import structlog

logger = structlog.get_logger()

class MemoryAnalyzer:
    def __init__(self):
        self.game_process: Optional[psutil.Process] = None
        self.base_address = None
        self.memory_snapshots = []
        self.known_structures = {
            "character": {
                "size": 1024,
                "fields": {
                    "name": {"offset": 0x00, "type": "string", "size": 16},
                    "level": {"offset": 0x10, "type": "uint32"},
                    "experience": {"offset": 0x14, "type": "uint64"},
                    "health": {"offset": 0x1C, "type": "uint32"},
                    "mana": {"offset": 0x20, "type": "uint32"},
                }
            },
            "inventory": {
                "size": 2048,
                "fields": {
                    "item_count": {"offset": 0x00, "type": "uint32"},
                    "items": {"offset": 0x04, "type": "array", "element_size": 32}
                }
            }
        }
        logger.info("Memory analyzer initialized")
        
    async def find_game_process(self) -> bool:
        """Find and attach to game process"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() in ['game.exe', 'diablo ii.exe', 'd2.exe']:
                    self.game_process = psutil.Process(proc.info['pid'])
                    self.base_address = self._get_base_address()
                    logger.info("Attached to game process", pid=proc.info['pid'])
                    return True
        except Exception as e:
            logger.error("Error finding game process", error=str(e))
            
        return False
        
    def _get_base_address(self) -> Optional[int]:
        """Get base address of game executable"""
        if not self.game_process:
            return None
            
        try:
            # This would normally use process memory mapping
            # For now, return a mock base address
            return 0x00400000
        except Exception as e:
            logger.error("Error getting base address", error=str(e))
            return None
            
    async def create_live_dump(self) -> Dict[str, Any]:
        """Create a live memory dump of key structures"""
        if not self.game_process:
            if not await self.find_game_process():
                return {"error": "Game process not found"}
                
        try:
            dump_data = {
                "timestamp": datetime.now().isoformat(),
                "process_id": self.game_process.pid,
                "base_address": hex(self.base_address) if self.base_address else "unknown",
                "structures": {}
            }
            
            # Dump known structures
            for struct_name, struct_info in self.known_structures.items():
                structure_data = await self._dump_structure(struct_name, struct_info)
                dump_data["structures"][struct_name] = structure_data
                
            # Store snapshot
            self.memory_snapshots.append(dump_data)
            
            # Keep only recent snapshots
            if len(self.memory_snapshots) > 50:
                self.memory_snapshots = self.memory_snapshots[-25:]
                
            return dump_data
            
        except Exception as e:
            logger.error("Error creating memory dump", error=str(e))
            return {"error": str(e)}
            
    async def _dump_structure(self, struct_name: str, struct_info: Dict[str, Any]) -> Dict[str, Any]:
        """Dump a specific memory structure"""
        try:
            # Mock memory reading for development
            # In production, this would use actual memory reading techniques
            
            structure_data = {
                "name": struct_name,
                "size": struct_info["size"],
                "fields": {},
                "raw_data": "mock_binary_data",  # Would contain actual binary data
                "analysis": {}
            }
            
            # Mock field extraction
            import random
            for field_name, field_info in struct_info["fields"].items():
                if field_info["type"] == "string":
                    structure_data["fields"][field_name] = f"mock_{field_name}"
                elif field_info["type"] == "uint32":
                    structure_data["fields"][field_name] = random.randint(0, 4294967295)
                elif field_info["type"] == "uint64":
                    structure_data["fields"][field_name] = random.randint(0, 18446744073709551615)
                elif field_info["type"] == "array":
                    # Mock array data
                    structure_data["fields"][field_name] = [f"element_{i}" for i in range(5)]
                    
            return structure_data
            
        except Exception as e:
            logger.error(f"Error dumping structure {struct_name}", error=str(e))
            return {"error": str(e)}
            
    async def analyze_structure(self, target_structure: str, analysis_depth: str = "detailed") -> Dict[str, Any]:
        """Analyze specific memory structure"""
        if target_structure not in self.known_structures:
            return {"error": f"Unknown structure: {target_structure}"}
            
        try:
            struct_info = self.known_structures[target_structure]
            
            # Create memory dump
            dump = await self.create_live_dump()
            if "error" in dump:
                return dump
                
            structure_data = dump["structures"].get(target_structure, {})
            
            analysis = {
                "structure": target_structure,
                "analysis_depth": analysis_depth,
                "timestamp": datetime.now().isoformat(),
                "findings": [],
                "anomalies": [],
                "patterns": []
            }
            
            # Perform analysis based on depth
            if analysis_depth in ["detailed", "comprehensive"]:
                analysis["findings"].extend(await self._analyze_structure_integrity(structure_data))
                
            if analysis_depth == "comprehensive":
                analysis["patterns"].extend(await self._analyze_structure_patterns(target_structure))
                analysis["anomalies"].extend(await self._detect_structure_anomalies(structure_data))
                
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing structure {target_structure}", error=str(e))
            return {"error": str(e)}
            
    async def _analyze_structure_integrity(self, structure_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze structure for integrity issues"""
        findings = []
        
        # Check for null or invalid pointers
        for field_name, field_value in structure_data.get("fields", {}).items():
            if isinstance(field_value, int) and field_value == 0:
                findings.append({
                    "type": "null_pointer",
                    "field": field_name,
                    "description": f"Field {field_name} contains null pointer",
                    "severity": "medium"
                })
                
        return findings
        
    async def _analyze_structure_patterns(self, structure_name: str) -> List[Dict[str, Any]]:
        """Analyze patterns in structure changes over time"""
        patterns = []
        
        # Analyze historical snapshots
        relevant_snapshots = []
        for snapshot in self.memory_snapshots:
            if structure_name in snapshot.get("structures", {}):
                relevant_snapshots.append(snapshot)
                
        if len(relevant_snapshots) > 1:
            # Look for patterns in structure changes
            patterns.append({
                "type": "change_frequency",
                "description": f"Structure {structure_name} has {len(relevant_snapshots)} snapshots",
                "data": {"snapshot_count": len(relevant_snapshots)}
            })
            
        return patterns
        
    async def _detect_structure_anomalies(self, structure_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in structure data"""
        anomalies = []
        
        # Check for unusual values
        fields = structure_data.get("fields", {})
        
        # Example: Check for impossible health values
        if "health" in fields and isinstance(fields["health"], int):
            if fields["health"] > 10000:  # Unusually high health
                anomalies.append({
                    "type": "unusual_health",
                    "value": fields["health"],
                    "description": f"Health value {fields['health']} is unusually high",
                    "severity": "medium"
                })
                
        return anomalies
        
    async def compare_snapshots(self, snapshot1_idx: int, snapshot2_idx: int) -> Dict[str, Any]:
        """Compare two memory snapshots"""
        if (snapshot1_idx >= len(self.memory_snapshots) or 
            snapshot2_idx >= len(self.memory_snapshots)):
            return {"error": "Invalid snapshot indices"}
            
        snap1 = self.memory_snapshots[snapshot1_idx]
        snap2 = self.memory_snapshots[snapshot2_idx]
        
        comparison = {
            "snapshot1": {
                "index": snapshot1_idx,
                "timestamp": snap1["timestamp"]
            },
            "snapshot2": {
                "index": snapshot2_idx,
                "timestamp": snap2["timestamp"]
            },
            "differences": {}
        }
        
        # Compare structures
        for struct_name in snap1.get("structures", {}):
            if struct_name in snap2.get("structures", {}):
                struct_diff = await self._compare_structures(
                    snap1["structures"][struct_name],
                    snap2["structures"][struct_name]
                )
                if struct_diff:
                    comparison["differences"][struct_name] = struct_diff
                    
        return comparison
        
    async def _compare_structures(self, struct1: Dict[str, Any], struct2: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two structure instances"""
        differences = {}
        
        fields1 = struct1.get("fields", {})
        fields2 = struct2.get("fields", {})
        
        # Find changed fields
        for field_name in fields1.keys() | fields2.keys():
            val1 = fields1.get(field_name)
            val2 = fields2.get(field_name)
            
            if val1 != val2:
                differences[field_name] = {
                    "old_value": val1,
                    "new_value": val2,
                    "change_type": "modified" if field_name in fields1 and field_name in fields2 else "added" if field_name in fields2 else "removed"
                }
                
        return differences
        
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory analysis statistics"""
        stats = {
            "snapshots_count": len(self.memory_snapshots),
            "process_attached": self.game_process is not None and self.game_process.is_running() if self.game_process else False,
            "base_address": hex(self.base_address) if self.base_address else None,
            "known_structures": list(self.known_structures.keys())
        }
        
        if self.game_process:
            try:
                memory_info = self.game_process.memory_info()
                stats["process_memory"] = {
                    "rss": memory_info.rss,
                    "vms": memory_info.vms
                }
            except Exception:
                pass
                
        return stats
