"""
Memory Dump Analysis Module
Advanced analysis of memory dumps and forensics artifacts
"""

import os
import struct
import hashlib
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class MemoryDumpAnalyzer:
    """Advanced memory dump analysis"""
    
    def __init__(self):
        self.known_signatures = {
            'pe_header': b'MZ',
            'elf_header': b'\x7fELF',
            'zip_header': b'PK',
            'pdf_header': b'%PDF',
            'jpeg_header': b'\xff\xd8\xff',
            'png_header': b'\x89PNG'
        }
    
    async def analyze_dump(self, dump_path: str) -> Dict[str, Any]:
        """Analyze memory dump file"""
        try:
            if not os.path.exists(dump_path):
                return {"error": "Dump file not found"}
            
            results = {
                "file_info": {},
                "memory_regions": [],
                "embedded_files": [],
                "strings": [],
                "suspicious_patterns": [],
                "entropy_analysis": {},
                "statistics": {}
            }
            
            # File information
            results["file_info"] = self._get_file_info(dump_path)
            
            # Read dump data (limit to first 50MB for analysis)
            with open(dump_path, 'rb') as f:
                data = f.read(50 * 1024 * 1024)
            
            # Memory region analysis
            regions = self._analyze_memory_regions(data)
            results["memory_regions"] = regions
            
            # Find embedded files
            embedded = self._find_embedded_files(data)
            results["embedded_files"] = embedded
            
            # Extract strings
            strings = self._extract_strings(data)
            results["strings"] = strings[:100]  # Limit results
            
            # Entropy analysis
            entropy = self._calculate_entropy_analysis(data)
            results["entropy_analysis"] = entropy
            
            # Statistics
            stats = self._calculate_statistics(data, results)
            results["statistics"] = stats
            
            logger.info(f"Memory dump analysis completed: {dump_path}")
            return results
            
        except Exception as e:
            logger.error(f"Memory dump analysis failed: {e}")
            return {"error": str(e)}
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        stat = os.stat(file_path)
        
        with open(file_path, 'rb') as f:
            # Calculate hash of first 1MB
            data_sample = f.read(1024 * 1024)
            file_hash = hashlib.sha256(data_sample).hexdigest()
        
        return {
            "path": file_path,
            "size": stat.st_size,
            "size_mb": stat.st_size / (1024 * 1024),
            "created_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "hash_sample": file_hash
        }
    
    def _analyze_memory_regions(self, data: bytes) -> List[Dict[str, Any]]:
        """Analyze different memory regions"""
        regions = []
        chunk_size = 64 * 1024  # 64KB chunks
        
        for offset in range(0, len(data), chunk_size):
            chunk = data[offset:offset + chunk_size]
            if len(chunk) < 1024:  # Skip small chunks
                continue
            
            region = {
                "offset": offset,
                "size": len(chunk),
                "entropy": self._calculate_entropy(chunk),
                "null_percentage": chunk.count(0) / len(chunk) * 100,
                "printable_percentage": self._calculate_printable_percentage(chunk),
                "signatures_found": self._find_signatures_in_chunk(chunk)
            }
            
            # Classify region type based on characteristics
            region["type"] = self._classify_region_type(region)
            regions.append(region)
            
            if len(regions) >= 100:  # Limit results
                break
        
        return regions
    
    def _find_embedded_files(self, data: bytes) -> List[Dict[str, Any]]:
        """Find embedded files in memory dump"""
        embedded = []
        
        for sig_name, signature in self.known_signatures.items():
            offset = 0
            while True:
                pos = data.find(signature, offset)
                if pos == -1:
                    break
                
                # Try to determine file size
                file_size = self._estimate_embedded_file_size(data, pos, sig_name)
                
                embedded.append({
                    "type": sig_name,
                    "offset": pos,
                    "estimated_size": file_size,
                    "signature": signature.hex(),
                    "preview": data[pos:pos+32].hex()
                })
                
                offset = pos + len(signature)
                if len(embedded) >= 50:  # Limit results
                    break
        
        return embedded
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from memory"""
        strings = []
        current_string = ""
        
        for byte in data:
            char = chr(byte) if 32 <= byte <= 126 else None
            
            if char:
                current_string += char
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
                
                if len(strings) >= 1000:  # Limit extraction
                    break
        
        # Add final string if valid
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def _calculate_entropy_analysis(self, data: bytes) -> Dict[str, Any]:
        """Calculate entropy analysis for the entire dump"""
        chunk_size = 4096
        entropies = []
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) >= 1024:
                entropy = self._calculate_entropy(chunk)
                entropies.append(entropy)
        
        if not entropies:
            return {"error": "No chunks for entropy analysis"}
        
        return {
            "average_entropy": sum(entropies) / len(entropies),
            "min_entropy": min(entropies),
            "max_entropy": max(entropies),
            "high_entropy_chunks": len([e for e in entropies if e > 7.5]),
            "low_entropy_chunks": len([e for e in entropies if e < 2.0]),
            "total_chunks": len(entropies)
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return min(entropy, 8.0)  # Cap at 8.0
    
    def _calculate_printable_percentage(self, data: bytes) -> float:
        """Calculate percentage of printable characters"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        return (printable_count / len(data)) * 100
    
    def _find_signatures_in_chunk(self, chunk: bytes) -> List[str]:
        """Find known signatures in memory chunk"""
        found = []
        for sig_name, signature in self.known_signatures.items():
            if signature in chunk:
                found.append(sig_name)
        return found
    
    def _classify_region_type(self, region: Dict[str, Any]) -> str:
        """Classify memory region type based on characteristics"""
        entropy = region["entropy"]
        null_pct = region["null_percentage"]
        printable_pct = region["printable_percentage"]
        
        if null_pct > 90:
            return "zero_filled"
        elif entropy > 7.5:
            return "encrypted_or_compressed"
        elif printable_pct > 70:
            return "text_or_strings"
        elif entropy < 2.0:
            return "structured_data"
        elif region["signatures_found"]:
            return "embedded_files"
        else:
            return "mixed_data"
    
    def _estimate_embedded_file_size(self, data: bytes, offset: int, file_type: str) -> int:
        """Estimate size of embedded file"""
        # Simple size estimation based on file type
        if file_type == "pe_header":
            try:
                # Read PE header to get size
                if offset + 60 < len(data):
                    pe_offset = struct.unpack('<I', data[offset+60:offset+64])[0]
                    if offset + pe_offset + 24 < len(data):
                        size_of_image = struct.unpack('<I', data[offset+pe_offset+80:offset+pe_offset+84])[0]
                        return min(size_of_image, 10 * 1024 * 1024)  # Cap at 10MB
            except:
                pass
        
        # Default estimation - look for next signature or null region
        max_search = min(1024 * 1024, len(data) - offset)  # Search up to 1MB
        
        for i in range(offset + 1, offset + max_search):
            # Look for long null sequences as potential end
            if data[i:i+64] == b'\x00' * 64:
                return i - offset
        
        return min(max_search, 1024 * 1024)  # Default 1MB max
    
    def _calculate_statistics(self, data: bytes, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall statistics"""
        return {
            "total_size": len(data),
            "regions_analyzed": len(results.get("memory_regions", [])),
            "embedded_files_found": len(results.get("embedded_files", [])),
            "strings_extracted": len(results.get("strings", [])),
            "unique_signatures": len(set(
                sig for region in results.get("memory_regions", [])
                for sig in region.get("signatures_found", [])
            )),
            "analysis_timestamp": datetime.now().isoformat()
        }