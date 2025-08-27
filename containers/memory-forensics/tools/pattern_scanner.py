"""
Pattern Scanner Tool
Scan memory for specific patterns and signatures
"""

import re
import struct
from typing import List, Dict, Any

class PatternScanner:
    """Advanced pattern scanning for memory analysis"""
    
    def __init__(self):
        self.patterns = {}
    
    def add_pattern(self, name: str, pattern: bytes, description: str = ""):
        """Add a pattern to scan for"""
        self.patterns[name] = {
            'pattern': pattern,
            'description': description
        }
    
    def scan_memory(self, data: bytes, start_offset: int = 0) -> List[Dict[str, Any]]:
        """Scan memory for all registered patterns"""
        matches = []
        
        for name, pattern_info in self.patterns.items():
            pattern = pattern_info['pattern']
            offset = start_offset
            
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                
                matches.append({
                    'pattern_name': name,
                    'offset': pos,
                    'size': len(pattern),
                    'description': pattern_info['description'],
                    'context': data[max(0, pos-16):pos+len(pattern)+16].hex()
                })
                
                offset = pos + 1
        
        return matches