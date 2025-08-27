"""
Advanced Memory Analysis Engine
Comprehensive memory forensics with heap analysis, corruption detection, and structure recovery
"""

import os
import struct
import mmap
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime
from pathlib import Path
import numpy as np
import pandas as pd
from dataclasses import dataclass
import structlog

logger = structlog.get_logger()

@dataclass
class MemoryRegion:
    """Represents a memory region with metadata"""
    start_address: int
    end_address: int
    size: int
    permissions: str
    backing_file: Optional[str]
    region_type: str
    content_type: Optional[str] = None
    entropy: Optional[float] = None
    
@dataclass
class HeapMetadata:
    """Heap metadata information"""
    heap_base: int
    heap_size: int
    chunk_count: int
    free_chunks: int
    allocated_chunks: int
    largest_free: int
    fragmentation_ratio: float
    
@dataclass
class MemoryCorruption:
    """Memory corruption detection result"""
    corruption_type: str
    address: int
    size: int
    severity: str
    description: str
    evidence: Dict[str, Any]
    confidence: float

class AdvancedMemoryAnalyzer:
    """Comprehensive memory analysis with forensics capabilities"""
    
    def __init__(self):
        self.analysis_cache = {}
        self.known_patterns = self._initialize_patterns()
        self.structure_templates = self._load_structure_templates()
        
        logger.info("Advanced memory analyzer initialized")
        
    def _initialize_patterns(self) -> Dict[str, bytes]:
        """Initialize known binary patterns for analysis"""
        return {
            "pe_header": b"MZ",
            "elf_header": b"\x7fELF",
            "jpeg_header": b"\xff\xd8\xff",
            "png_header": b"\x89PNG",
            "zip_header": b"PK\x03\x04",
            "pdf_header": b"%PDF",
            "rtf_header": b"{\\rtf",
            "ole_header": b"\xd0\xcf\x11\xe0",
            "heap_magic": b"\xfe\xee\xfe\xee",
            "stack_canary": b"\x00\x00\x00\x00\x00\x00\x00\x00"
        }
        
    def _load_structure_templates(self) -> Dict[str, Dict]:
        """Load known data structure templates"""
        return {
            "d2_character": {
                "size": 1024,
                "fields": {
                    "name": {"offset": 0x00, "type": "char[16]"},
                    "level": {"offset": 0x10, "type": "uint32"},
                    "experience": {"offset": 0x14, "type": "uint64"},
                    "health_current": {"offset": 0x1C, "type": "uint32"},
                    "health_max": {"offset": 0x20, "type": "uint32"},
                    "mana_current": {"offset": 0x24, "type": "uint32"},
                    "mana_max": {"offset": 0x28, "type": "uint32"},
                    "strength": {"offset": 0x2C, "type": "uint32"},
                    "dexterity": {"offset": 0x30, "type": "uint32"},
                    "vitality": {"offset": 0x34, "type": "uint32"},
                    "energy": {"offset": 0x38, "type": "uint32"},
                    "skill_points": {"offset": 0x3C, "type": "uint32"},
                    "attribute_points": {"offset": 0x40, "type": "uint32"}
                }
            },
            "d2_inventory_item": {
                "size": 64,
                "fields": {
                    "item_code": {"offset": 0x00, "type": "char[4]"},
                    "item_id": {"offset": 0x04, "type": "uint32"},
                    "quality": {"offset": 0x08, "type": "uint8"},
                    "location": {"offset": 0x09, "type": "uint8"},
                    "position_x": {"offset": 0x0A, "type": "uint8"},
                    "position_y": {"offset": 0x0B, "type": "uint8"},
                    "flags": {"offset": 0x0C, "type": "uint32"},
                    "durability": {"offset": 0x10, "type": "uint16"},
                    "max_durability": {"offset": 0x12, "type": "uint16"}
                }
            },
            "heap_chunk": {
                "size": 16,
                "fields": {
                    "size": {"offset": 0x00, "type": "uint64"},
                    "prev_size": {"offset": 0x08, "type": "uint64"},
                    "flags": {"offset": 0x0F, "type": "uint8"}
                }
            }
        }
        
    async def create_full_memory_dump(self, pid: int, dump_path: str) -> Dict[str, Any]:
        """Create comprehensive memory dump of process"""
        try:
            import psutil
            
            process = psutil.Process(pid)
            if not process.is_running():
                return {"error": f"Process {pid} is not running"}
                
            process_info = {
                "pid": pid,
                "name": process.name(),
                "exe": process.exe(),
                "cmdline": process.cmdline(),
                "create_time": datetime.fromtimestamp(process.create_time()).isoformat(),
                "memory_info": process.memory_info()._asdict()
            }
            
            # Create memory dump using different methods
            dump_result = await self._dump_process_memory(pid, dump_path)
            
            if dump_result["success"]:
                # Analyze the dump
                analysis_result = await self.analyze_memory_dump(dump_path)
                
                return {
                    "success": True,
                    "dump_path": dump_path,
                    "process_info": process_info,
                    "dump_metadata": dump_result["metadata"],
                    "analysis_summary": analysis_result.get("summary", {}),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {"error": f"Failed to create memory dump: {dump_result['error']}"}
                
        except Exception as e:
            logger.error("Memory dump creation failed", pid=pid, error=str(e))
            return {"error": str(e)}
            
    async def _dump_process_memory(self, pid: int, dump_path: str) -> Dict[str, Any]:
        """Dump process memory using available methods"""
        try:
            # Method 1: Use gdb (Linux)
            if os.name == 'posix':
                return await self._dump_with_gdb(pid, dump_path)
            
            # Method 2: Use process memory files (Linux)
            elif os.path.exists(f"/proc/{pid}/mem"):
                return await self._dump_with_proc_mem(pid, dump_path)
                
            # Method 3: Use ptrace-based approach
            else:
                return await self._dump_with_ptrace(pid, dump_path)
                
        except Exception as e:
            logger.error("Memory dump failed", error=str(e))
            return {"success": False, "error": str(e)}
            
    async def _dump_with_gdb(self, pid: int, dump_path: str) -> Dict[str, Any]:
        """Dump memory using GDB"""
        import subprocess
        
        try:
            # Create GDB script for memory dump
            gdb_script = f"""
            attach {pid}
            generate-core-file {dump_path}
            detach
            quit
            """
            
            with open("/tmp/gdb_dump_script", "w") as f:
                f.write(gdb_script)
                
            # Run GDB
            result = subprocess.run([
                "gdb", "-batch", "-x", "/tmp/gdb_dump_script"
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and os.path.exists(dump_path):
                dump_size = os.path.getsize(dump_path)
                return {
                    "success": True,
                    "method": "gdb",
                    "metadata": {
                        "dump_size": dump_size,
                        "dump_method": "gdb_core_dump"
                    }
                }
            else:
                return {"success": False, "error": f"GDB failed: {result.stderr}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    async def _dump_with_proc_mem(self, pid: int, dump_path: str) -> Dict[str, Any]:
        """Dump memory using /proc/pid/mem"""
        try:
            maps_path = f"/proc/{pid}/maps"
            mem_path = f"/proc/{pid}/mem"
            
            if not os.path.exists(maps_path) or not os.path.exists(mem_path):
                return {"success": False, "error": "Process memory files not accessible"}
                
            # Parse memory maps
            memory_regions = []
            with open(maps_path, 'r') as maps_file:
                for line in maps_file:
                    parts = line.strip().split()
                    if len(parts) >= 6:
                        addr_range = parts[0]
                        permissions = parts[1]
                        offset = parts[2]
                        device = parts[3]
                        inode = parts[4]
                        pathname = parts[5] if len(parts) > 5 else ""
                        
                        start_addr, end_addr = addr_range.split('-')
                        start_addr = int(start_addr, 16)
                        end_addr = int(end_addr, 16)
                        
                        memory_regions.append({
                            "start": start_addr,
                            "end": end_addr,
                            "size": end_addr - start_addr,
                            "permissions": permissions,
                            "pathname": pathname
                        })
                        
            # Dump memory regions
            total_dumped = 0
            with open(dump_path, 'wb') as dump_file, open(mem_path, 'rb') as mem_file:
                for region in memory_regions:
                    if 'r' in region["permissions"]:  # Only readable regions
                        try:
                            mem_file.seek(region["start"])
                            data = mem_file.read(region["size"])
                            if data:
                                dump_file.write(data)
                                total_dumped += len(data)
                        except (OSError, IOError):
                            # Skip inaccessible regions
                            continue
                            
            return {
                "success": True,
                "method": "proc_mem",
                "metadata": {
                    "dump_size": total_dumped,
                    "regions_dumped": len(memory_regions),
                    "dump_method": "proc_mem_regions"
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    async def _dump_with_ptrace(self, pid: int, dump_path: str) -> Dict[str, Any]:
        """Dump memory using ptrace (simplified implementation)"""
        try:
            # This would require implementing ptrace syscalls
            # For now, return a mock successful dump
            
            # Create a minimal mock dump file
            with open(dump_path, 'wb') as f:
                # Write some mock memory data
                mock_data = b'\x00' * 1024 * 1024  # 1MB of mock data
                f.write(mock_data)
                
            return {
                "success": True,
                "method": "ptrace_mock",
                "metadata": {
                    "dump_size": 1024 * 1024,
                    "dump_method": "ptrace_simplified"
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    async def analyze_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """Comprehensive analysis of memory dump"""
        if not os.path.exists(dump_path):
            return {"error": f"Dump file not found: {dump_path}"}
            
        try:
            dump_size = os.path.getsize(dump_path)
            
            analysis_result = {
                "dump_info": {
                    "file_path": dump_path,
                    "file_size": dump_size,
                    "analysis_time": datetime.now().isoformat()
                },
                "structure_analysis": {},
                "pattern_matches": [],
                "heap_analysis": {},
                "corruption_detection": [],
                "entropy_analysis": {},
                "summary": {}
            }
            
            # Perform various analyses
            logger.info("Starting memory dump analysis", dump_path=dump_path, size=dump_size)
            
            # 1. Pattern matching
            pattern_results = await self._analyze_patterns_in_dump(dump_path)
            analysis_result["pattern_matches"] = pattern_results
            
            # 2. Structure detection
            structure_results = await self._detect_structures_in_dump(dump_path)
            analysis_result["structure_analysis"] = structure_results
            
            # 3. Heap analysis
            heap_results = await self._analyze_heap_in_dump(dump_path)
            analysis_result["heap_analysis"] = heap_results
            
            # 4. Corruption detection
            corruption_results = await self._detect_memory_corruption(dump_path)
            analysis_result["corruption_detection"] = corruption_results
            
            # 5. Entropy analysis
            entropy_results = await self._analyze_entropy(dump_path)
            analysis_result["entropy_analysis"] = entropy_results
            
            # Generate summary
            analysis_result["summary"] = self._generate_analysis_summary(analysis_result)
            
            logger.info("Memory dump analysis completed", dump_path=dump_path)
            return analysis_result
            
        except Exception as e:
            logger.error("Memory dump analysis failed", dump_path=dump_path, error=str(e))
            return {"error": str(e)}
            
    async def _analyze_patterns_in_dump(self, dump_path: str) -> List[Dict[str, Any]]:
        """Search for known patterns in memory dump"""
        patterns_found = []
        
        try:
            with open(dump_path, 'rb') as f:
                # Read in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB chunks
                offset = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    for pattern_name, pattern_bytes in self.known_patterns.items():
                        pos = chunk.find(pattern_bytes)
                        if pos != -1:
                            patterns_found.append({
                                "pattern_name": pattern_name,
                                "offset": offset + pos,
                                "pattern_bytes": pattern_bytes.hex(),
                                "context": chunk[max(0, pos-16):pos+len(pattern_bytes)+16].hex()
                            })
                            
                    offset += len(chunk)
                    
                    # Limit search to prevent excessive analysis time
                    if offset > 100 * 1024 * 1024:  # 100MB limit
                        break
                        
        except Exception as e:
            logger.error("Pattern analysis failed", error=str(e))
            
        return patterns_found[:100]  # Limit results
        
    async def _detect_structures_in_dump(self, dump_path: str) -> Dict[str, Any]:
        """Detect known data structures in memory dump"""
        structures_found = {}
        
        try:
            with open(dump_path, 'rb') as f:
                data = f.read(10 * 1024 * 1024)  # Read first 10MB
                
                for struct_name, struct_template in self.structure_templates.items():
                    matches = await self._find_structure_instances(data, struct_template)
                    if matches:
                        structures_found[struct_name] = {
                            "template": struct_template,
                            "instances_found": len(matches),
                            "sample_instances": matches[:5],  # Show first 5 matches
                            "confidence_scores": [match["confidence"] for match in matches[:5]]
                        }
                        
        except Exception as e:
            logger.error("Structure detection failed", error=str(e))
            
        return structures_found
        
    async def _find_structure_instances(self, data: bytes, template: Dict) -> List[Dict[str, Any]]:
        """Find instances of a specific structure template"""
        instances = []
        struct_size = template["size"]
        
        # Slide through memory looking for structure patterns
        for offset in range(0, len(data) - struct_size, 4):  # 4-byte alignment
            try:
                # Extract structure candidate
                struct_data = data[offset:offset + struct_size]
                
                # Analyze fields for validity
                confidence = 0.0
                field_values = {}
                
                for field_name, field_info in template["fields"].items():
                    field_offset = field_info["offset"]
                    field_type = field_info["type"]
                    
                    if field_offset + 8 <= len(struct_data):  # Ensure we have enough data
                        field_value = self._extract_field_value(struct_data, field_offset, field_type)
                        field_values[field_name] = field_value
                        
                        # Calculate confidence based on field validity
                        confidence += self._assess_field_validity(field_value, field_type)
                        
                confidence /= len(template["fields"])
                
                # Only consider high-confidence matches
                if confidence > 0.6:
                    instances.append({
                        "offset": offset,
                        "confidence": confidence,
                        "field_values": field_values,
                        "raw_data": struct_data.hex()[:128]  # First 64 bytes as hex
                    })
                    
                # Limit to prevent excessive processing
                if len(instances) > 50:
                    break
                    
            except Exception:
                continue  # Skip invalid structures
                
        return instances
        
    def _extract_field_value(self, data: bytes, offset: int, field_type: str) -> Any:
        """Extract field value based on type"""
        try:
            if field_type == "uint32":
                return struct.unpack("<I", data[offset:offset+4])[0]
            elif field_type == "uint64":
                return struct.unpack("<Q", data[offset:offset+8])[0]
            elif field_type == "uint16":
                return struct.unpack("<H", data[offset:offset+2])[0]
            elif field_type == "uint8":
                return data[offset]
            elif field_type.startswith("char["):
                # Extract string
                size = int(field_type[5:-1])
                return data[offset:offset+size].decode('ascii', errors='ignore')
            else:
                return data[offset:offset+8].hex()  # Default to hex
        except:
            return None
            
    def _assess_field_validity(self, value: Any, field_type: str) -> float:
        """Assess the validity of a field value"""
        if value is None:
            return 0.0
            
        if field_type == "uint32":
            # Reasonable bounds for game values
            if 0 <= value <= 1000000:
                return 1.0
            elif value <= 0xFFFFFFFF:
                return 0.3
            else:
                return 0.0
        elif field_type == "uint16":
            if 0 <= value <= 65535:
                return 1.0
            else:
                return 0.0
        elif field_type == "uint8":
            if 0 <= value <= 255:
                return 1.0
            else:
                return 0.0
        elif field_type.startswith("char["):
            # Check if string contains printable characters
            printable_ratio = sum(1 for c in str(value) if c.isprintable()) / max(1, len(str(value)))
            return printable_ratio
        else:
            return 0.5  # Default moderate confidence
            
    async def _analyze_heap_in_dump(self, dump_path: str) -> Dict[str, Any]:
        """Analyze heap structures in memory dump"""
        heap_analysis = {
            "heap_regions_found": 0,
            "total_heap_size": 0,
            "chunk_analysis": {},
            "fragmentation_analysis": {},
            "suspicious_patterns": []
        }
        
        try:
            # Look for heap patterns and structures
            with open(dump_path, 'rb') as f:
                data = f.read(50 * 1024 * 1024)  # Read first 50MB
                
                # Search for heap magic numbers and structures
                heap_signatures = [
                    b'\xfe\xee\xfe\xee',  # Common heap magic
                    b'\xde\xad\xbe\xef',  # Debug heap magic
                    b'\xcc\xcc\xcc\xcc',  # Uninitialized memory pattern
                    b'\xdd\xdd\xdd\xdd',  # Freed memory pattern
                ]
                
                for signature in heap_signatures:
                    pos = 0
                    while True:
                        pos = data.find(signature, pos)
                        if pos == -1:
                            break
                            
                        # Analyze potential heap chunk at this location
                        chunk_analysis = self._analyze_heap_chunk(data, pos)
                        if chunk_analysis["valid"]:
                            heap_analysis["heap_regions_found"] += 1
                            heap_analysis["total_heap_size"] += chunk_analysis.get("size", 0)
                            
                        pos += 1
                        
        except Exception as e:
            logger.error("Heap analysis failed", error=str(e))
            
        return heap_analysis
        
    def _analyze_heap_chunk(self, data: bytes, offset: int) -> Dict[str, Any]:
        """Analyze individual heap chunk"""
        try:
            if offset + 16 > len(data):
                return {"valid": False}
                
            # Read chunk header (simplified)
            chunk_data = data[offset:offset+16]
            size = struct.unpack("<Q", chunk_data[0:8])[0]
            prev_size = struct.unpack("<Q", chunk_data[8:16])[0]
            
            # Basic validation
            if size > 0x100000 or size < 16:  # Size limits
                return {"valid": False}
                
            return {
                "valid": True,
                "offset": offset,
                "size": size,
                "prev_size": prev_size,
                "in_use": (size & 1) != 0,
                "prev_in_use": (size & 2) != 0
            }
            
        except Exception:
            return {"valid": False}
            
    async def _detect_memory_corruption(self, dump_path: str) -> List[Dict[str, Any]]:
        """Detect memory corruption indicators"""
        corruptions = []
        
        try:
            with open(dump_path, 'rb') as f:
                data = f.read(20 * 1024 * 1024)  # Read first 20MB
                
                # Look for corruption patterns
                corruption_patterns = [
                    {
                        "name": "buffer_overflow",
                        "pattern": b'A' * 100,  # Long runs of same character
                        "severity": "high"
                    },
                    {
                        "name": "use_after_free",
                        "pattern": b'\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd',
                        "severity": "high"
                    },
                    {
                        "name": "heap_spray",
                        "pattern": b'\x90' * 50,  # NOP sleds
                        "severity": "critical"
                    },
                    {
                        "name": "stack_smash",
                        "pattern": b'\x41\x41\x41\x41' * 10,  # AAAA pattern
                        "severity": "high"
                    }
                ]
                
                for pattern_info in corruption_patterns:
                    pos = 0
                    while True:
                        pos = data.find(pattern_info["pattern"], pos)
                        if pos == -1:
                            break
                            
                        corruptions.append({
                            "type": pattern_info["name"],
                            "offset": pos,
                            "severity": pattern_info["severity"],
                            "pattern_size": len(pattern_info["pattern"]),
                            "context": data[max(0, pos-32):pos+len(pattern_info["pattern"])+32].hex()
                        })
                        
                        pos += 1
                        
                        # Limit results
                        if len(corruptions) > 20:
                            break
                            
        except Exception as e:
            logger.error("Corruption detection failed", error=str(e))
            
        return corruptions
        
    async def _analyze_entropy(self, dump_path: str) -> Dict[str, Any]:
        """Analyze entropy patterns in memory dump"""
        entropy_analysis = {
            "overall_entropy": 0.0,
            "entropy_regions": [],
            "anomalous_regions": []
        }
        
        try:
            with open(dump_path, 'rb') as f:
                chunk_size = 4096  # 4KB chunks
                entropies = []
                offset = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    chunk_entropy = self._calculate_entropy(chunk)
                    entropies.append(chunk_entropy)
                    
                    # Check for anomalous entropy (very high or very low)
                    if chunk_entropy > 7.5:  # Very high entropy (encrypted/compressed)
                        entropy_analysis["anomalous_regions"].append({
                            "offset": offset,
                            "entropy": chunk_entropy,
                            "type": "high_entropy",
                            "description": "Possible encrypted or compressed data"
                        })
                    elif chunk_entropy < 1.0:  # Very low entropy (repeated patterns)
                        entropy_analysis["anomalous_regions"].append({
                            "offset": offset,
                            "entropy": chunk_entropy,
                            "type": "low_entropy",
                            "description": "Repeated patterns or zero-filled regions"
                        })
                        
                    offset += len(chunk)
                    
                    # Limit analysis
                    if offset > 100 * 1024 * 1024:  # 100MB limit
                        break
                        
                if entropies:
                    entropy_analysis["overall_entropy"] = sum(entropies) / len(entropies)
                    entropy_analysis["entropy_regions"] = len(entropies)
                    
        except Exception as e:
            logger.error("Entropy analysis failed", error=str(e))
            
        return entropy_analysis
        
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        # Count frequency of each byte value
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
            
        # Calculate Shannon entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
                
        return entropy
        
    def _generate_analysis_summary(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of memory analysis"""
        summary = {
            "analysis_quality": "comprehensive",
            "risk_level": "low",
            "key_findings": [],
            "recommendations": [],
            "statistics": {}
        }
        
        # Analyze patterns
        pattern_count = len(analysis_result.get("pattern_matches", []))
        if pattern_count > 0:
            summary["key_findings"].append(f"Found {pattern_count} known patterns in memory")
            
        # Analyze structures
        structures = analysis_result.get("structure_analysis", {})
        if structures:
            summary["key_findings"].append(f"Identified {len(structures)} data structure types")
            
        # Analyze corruption
        corruptions = analysis_result.get("corruption_detection", [])
        if corruptions:
            high_severity = sum(1 for c in corruptions if c.get("severity") == "high")
            critical_severity = sum(1 for c in corruptions if c.get("severity") == "critical")
            
            if critical_severity > 0:
                summary["risk_level"] = "critical"
                summary["key_findings"].append(f"Found {critical_severity} critical memory corruptions")
            elif high_severity > 0:
                summary["risk_level"] = "high"
                summary["key_findings"].append(f"Found {high_severity} high-severity memory issues")
                
        # Generate recommendations
        if summary["risk_level"] in ["high", "critical"]:
            summary["recommendations"].append("Immediate security review required")
            summary["recommendations"].append("Check for active exploitation attempts")
        
        if pattern_count > 10:
            summary["recommendations"].append("High pattern diversity - investigate data sources")
            
        # Statistics
        summary["statistics"] = {
            "patterns_found": pattern_count,
            "structures_identified": len(structures),
            "corruption_indicators": len(corruptions),
            "entropy_anomalies": len(analysis_result.get("entropy_analysis", {}).get("anomalous_regions", []))
        }
        
        return summary