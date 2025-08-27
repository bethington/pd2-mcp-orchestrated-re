"""
Heap Analysis Module
Advanced heap structure analysis and memory corruption detection
"""

import struct
import logging
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class HeapAnalyzer:
    """Advanced heap analysis for memory forensics"""
    
    def __init__(self):
        self.heap_structures = {}
        self.corruption_patterns = {
            'buffer_overflow': b'\x41\x41\x41\x41',  # Common overflow pattern
            'use_after_free': b'\xfe\xee\xfe\xee',   # Freed memory pattern
            'heap_spray': b'\x90\x90\x90\x90'        # NOP sled pattern
        }
    
    async def analyze_heap(self, memory_data: bytes, base_address: int = 0) -> Dict[str, Any]:
        """Analyze heap structures in memory data"""
        try:
            results = {
                "heap_chunks": [],
                "corruption_detected": [],
                "fragmentation_analysis": {},
                "suspicious_patterns": [],
                "heap_statistics": {}
            }
            
            # Analyze heap chunks
            chunks = self._find_heap_chunks(memory_data, base_address)
            results["heap_chunks"] = chunks
            
            # Check for corruption
            corruption = self._detect_corruption(memory_data)
            results["corruption_detected"] = corruption
            
            # Fragmentation analysis
            fragmentation = self._analyze_fragmentation(chunks)
            results["fragmentation_analysis"] = fragmentation
            
            # Statistics
            stats = self._calculate_statistics(chunks)
            results["heap_statistics"] = stats
            
            logger.info(f"Heap analysis completed: {len(chunks)} chunks found")
            return results
            
        except Exception as e:
            logger.error(f"Heap analysis failed: {e}")
            return {"error": str(e)}
    
    def _find_heap_chunks(self, data: bytes, base_addr: int) -> List[Dict[str, Any]]:
        """Find and parse heap chunks"""
        chunks = []
        offset = 0
        
        while offset < len(data) - 16:  # Minimum chunk header size
            try:
                # Simple heap chunk detection (platform-specific)
                size = struct.unpack('<I', data[offset:offset+4])[0]
                
                if self._is_valid_chunk_size(size):
                    chunk = {
                        "offset": offset,
                        "address": base_addr + offset,
                        "size": size & ~0x7,  # Remove flags
                        "flags": size & 0x7,
                        "in_use": bool(size & 0x1),
                        "prev_in_use": bool(size & 0x2),
                        "data_preview": data[offset+8:offset+24].hex() if offset+24 < len(data) else ""
                    }
                    chunks.append(chunk)
                    
                    # Move to next chunk
                    chunk_size = size & ~0x7
                    if chunk_size > 0 and chunk_size < 0x100000:  # Sanity check
                        offset += chunk_size
                    else:
                        offset += 16  # Skip invalid chunk
                else:
                    offset += 4  # Search for next potential chunk
                    
            except (struct.error, IndexError):
                offset += 4
                continue
        
        return chunks[:100]  # Limit results
    
    def _is_valid_chunk_size(self, size: int) -> bool:
        """Validate if size looks like a valid heap chunk size"""
        clean_size = size & ~0x7
        return (clean_size >= 16 and clean_size < 0x1000000 and 
                clean_size % 8 == 0)
    
    def _detect_corruption(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect heap corruption patterns"""
        corruptions = []
        
        for pattern_name, pattern_bytes in self.corruption_patterns.items():
            offset = 0
            while True:
                pos = data.find(pattern_bytes, offset)
                if pos == -1:
                    break
                
                corruptions.append({
                    "type": pattern_name,
                    "offset": pos,
                    "pattern": pattern_bytes.hex(),
                    "confidence": 0.8
                })
                
                offset = pos + len(pattern_bytes)
                if len(corruptions) >= 50:  # Limit results
                    break
        
        return corruptions
    
    def _analyze_fragmentation(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze heap fragmentation"""
        if not chunks:
            return {"fragmentation_ratio": 0.0, "free_chunks": 0, "used_chunks": 0}
        
        free_chunks = [c for c in chunks if not c.get("in_use", True)]
        used_chunks = [c for c in chunks if c.get("in_use", False)]
        
        total_free_size = sum(c["size"] for c in free_chunks)
        total_used_size = sum(c["size"] for c in used_chunks)
        total_size = total_free_size + total_used_size
        
        fragmentation_ratio = total_free_size / total_size if total_size > 0 else 0.0
        
        return {
            "fragmentation_ratio": fragmentation_ratio,
            "free_chunks": len(free_chunks),
            "used_chunks": len(used_chunks),
            "total_free_size": total_free_size,
            "total_used_size": total_used_size,
            "average_free_size": total_free_size / len(free_chunks) if free_chunks else 0,
            "largest_free_chunk": max(c["size"] for c in free_chunks) if free_chunks else 0
        }
    
    def _calculate_statistics(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate heap statistics"""
        if not chunks:
            return {}
        
        sizes = [c["size"] for c in chunks]
        
        return {
            "total_chunks": len(chunks),
            "total_size": sum(sizes),
            "average_chunk_size": sum(sizes) / len(sizes),
            "min_chunk_size": min(sizes),
            "max_chunk_size": max(sizes),
            "size_distribution": self._calculate_size_distribution(sizes)
        }
    
    def _calculate_size_distribution(self, sizes: List[int]) -> Dict[str, int]:
        """Calculate size distribution buckets"""
        buckets = {
            "small_0_64": 0,
            "medium_64_512": 0,
            "large_512_4096": 0,
            "xlarge_4096_plus": 0
        }
        
        for size in sizes:
            if size <= 64:
                buckets["small_0_64"] += 1
            elif size <= 512:
                buckets["medium_64_512"] += 1
            elif size <= 4096:
                buckets["large_512_4096"] += 1
            else:
                buckets["xlarge_4096_plus"] += 1
        
        return buckets