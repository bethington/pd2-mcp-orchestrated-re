"""
Enhanced Diablo 2 data structures for memory analysis
"""

import struct
from typing import Dict, List, Optional, Any, NamedTuple
from enum import Enum, IntEnum
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

class D2DataType(Enum):
    """Diablo 2 data types"""
    BYTE = "byte"
    WORD = "word"  
    DWORD = "dword"
    FLOAT = "float"
    STRING = "string"
    POINTER = "pointer"
    STRUCT = "struct"

class D2ItemQuality(IntEnum):
    """Item quality levels"""
    LOW_QUALITY = 1
    NORMAL = 2
    HIGH_QUALITY = 3
    MAGIC = 4
    SET = 5
    RARE = 6
    UNIQUE = 7
    CRAFTED = 8

class D2CharacterClass(IntEnum):
    """Character classes"""
    AMAZON = 0
    SORCERESS = 1
    NECROMANCER = 2
    PALADIN = 3
    BARBARIAN = 4
    DRUID = 5
    ASSASSIN = 6

class D2GameMode(IntEnum):
    """Game modes"""
    NORMAL = 0
    NIGHTMARE = 1
    HELL = 2

@dataclass
class D2MemoryStructure:
    """Base class for D2 memory structures"""
    name: str
    offset: int
    size: int
    fields: Dict[str, Any]
    
    def read_from_memory(self, memory_data: bytes, base_offset: int = 0) -> Dict[str, Any]:
        """Read structure from memory data"""
        result = {}
        struct_offset = base_offset + self.offset
        
        for field_name, field_info in self.fields.items():
            field_offset = struct_offset + field_info.get("offset", 0)
            field_type = field_info.get("type", D2DataType.DWORD)
            field_size = field_info.get("size", 4)
            
            try:
                if field_offset + field_size <= len(memory_data):
                    raw_data = memory_data[field_offset:field_offset + field_size]
                    result[field_name] = self._parse_field_data(raw_data, field_type, field_info)
                else:
                    result[field_name] = None
                    
            except Exception as e:
                logger.warning(f"Failed to read field {field_name}: {e}")
                result[field_name] = None
        
        return result
    
    def _parse_field_data(self, data: bytes, data_type: D2DataType, field_info: Dict[str, Any]) -> Any:
        """Parse field data based on type"""
        if not data:
            return None
            
        try:
            if data_type == D2DataType.BYTE:
                return struct.unpack("<B", data[:1])[0]
            elif data_type == D2DataType.WORD:
                return struct.unpack("<H", data[:2])[0]
            elif data_type == D2DataType.DWORD:
                return struct.unpack("<I", data[:4])[0]
            elif data_type == D2DataType.FLOAT:
                return struct.unpack("<f", data[:4])[0]
            elif data_type == D2DataType.STRING:
                # Null-terminated string
                null_pos = data.find(b'\x00')
                if null_pos != -1:
                    return data[:null_pos].decode('latin-1', errors='ignore')
                return data.decode('latin-1', errors='ignore')
            elif data_type == D2DataType.POINTER:
                return struct.unpack("<I", data[:4])[0]
            else:
                return data.hex()
                
        except Exception as e:
            logger.warning(f"Failed to parse {data_type}: {e}")
            return None

# Character data structure
D2_CHARACTER_STRUCTURE = D2MemoryStructure(
    name="D2Character",
    offset=0x0,
    size=0x300,  # Approximate size
    fields={
        "character_name": {
            "offset": 0x14,
            "type": D2DataType.STRING,
            "size": 16,
            "description": "Character name"
        },
        "character_class": {
            "offset": 0x28,
            "type": D2DataType.BYTE,
            "size": 1,
            "description": "Character class ID"
        },
        "character_level": {
            "offset": 0x2B,
            "type": D2DataType.BYTE,
            "size": 1,
            "description": "Character level"
        },
        "experience": {
            "offset": 0x2C,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Current experience points"
        },
        "strength": {
            "offset": 0x40,
            "type": D2DataType.WORD,
            "size": 2,
            "description": "Strength attribute"
        },
        "dexterity": {
            "offset": 0x42,
            "type": D2DataType.WORD,
            "size": 2,
            "description": "Dexterity attribute"
        },
        "vitality": {
            "offset": 0x44,
            "type": D2DataType.WORD,
            "size": 2,
            "description": "Vitality attribute"
        },
        "energy": {
            "offset": 0x46,
            "type": D2DataType.WORD,
            "size": 2,
            "description": "Energy attribute"
        },
        "current_hp": {
            "offset": 0x60,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Current hit points"
        },
        "max_hp": {
            "offset": 0x64,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Maximum hit points"
        },
        "current_mana": {
            "offset": 0x68,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Current mana points"
        },
        "max_mana": {
            "offset": 0x6C,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Maximum mana points"
        },
        "gold": {
            "offset": 0x100,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Gold amount"
        },
        "difficulty": {
            "offset": 0x104,
            "type": D2DataType.BYTE,
            "size": 1,
            "description": "Current difficulty"
        }
    }
)

# Item data structure
D2_ITEM_STRUCTURE = D2MemoryStructure(
    name="D2Item",
    offset=0x0,
    size=0x150,  # Approximate size
    fields={
        "item_code": {
            "offset": 0x0,
            "type": D2DataType.STRING,
            "size": 4,
            "description": "3-character item code"
        },
        "item_quality": {
            "offset": 0x8,
            "type": D2DataType.BYTE,
            "size": 1,
            "description": "Item quality level"
        },
        "item_level": {
            "offset": 0x9,
            "type": D2DataType.BYTE,
            "size": 1,
            "description": "Item level"
        },
        "durability_current": {
            "offset": 0x10,
            "type": D2DataType.WORD,
            "size": 2,
            "description": "Current durability"
        },
        "durability_max": {
            "offset": 0x12,
            "type": D2DataType.WORD,
            "size": 2,
            "description": "Maximum durability"
        },
        "item_flags": {
            "offset": 0x18,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Item flags bitfield"
        },
        "socket_count": {
            "offset": 0x20,
            "type": D2DataType.BYTE,
            "size": 1,
            "description": "Number of sockets"
        },
        "price": {
            "offset": 0x30,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Item price/value"
        }
    }
)

# Game state structure
D2_GAME_STATE_STRUCTURE = D2MemoryStructure(
    name="D2GameState",
    offset=0x0,
    size=0x200,
    fields={
        "game_mode": {
            "offset": 0x0,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Current game mode"
        },
        "difficulty": {
            "offset": 0x4,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Game difficulty"
        },
        "area_id": {
            "offset": 0x8,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Current area ID"
        },
        "game_time": {
            "offset": 0x10,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Game time in frames"
        },
        "player_count": {
            "offset": 0x20,
            "type": D2DataType.BYTE,
            "size": 1,
            "description": "Number of players in game"
        },
        "game_flags": {
            "offset": 0x24,
            "type": D2DataType.DWORD,
            "size": 4,
            "description": "Game state flags"
        }
    }
)

# Network packet structures for PD2
@dataclass
class D2NetworkPacket:
    """Diablo 2 network packet structure"""
    packet_id: int
    size: int
    data: bytes
    timestamp: float
    direction: str  # "send" or "receive"
    
    def parse_packet_data(self) -> Dict[str, Any]:
        """Parse packet data based on packet ID"""
        if not self.data:
            return {}
        
        try:
            # Common packet types
            if self.packet_id == 0x01:  # Walk request
                return self._parse_walk_packet()
            elif self.packet_id == 0x02:  # Walk verify
                return self._parse_walk_verify_packet()
            elif self.packet_id == 0x0C:  # Chat message
                return self._parse_chat_packet()
            elif self.packet_id == 0x15:  # Player reassign
                return self._parse_player_reassign_packet()
            elif self.packet_id == 0x20:  # Player update
                return self._parse_player_update_packet()
            else:
                return {"raw_data": self.data.hex()}
                
        except Exception as e:
            logger.warning(f"Failed to parse packet {self.packet_id:02x}: {e}")
            return {"error": str(e), "raw_data": self.data.hex()}
    
    def _parse_walk_packet(self) -> Dict[str, Any]:
        """Parse walk request packet"""
        if len(self.data) >= 5:
            x = struct.unpack("<H", self.data[1:3])[0]
            y = struct.unpack("<H", self.data[3:5])[0]
            return {"type": "walk", "x": x, "y": y}
        return {}
    
    def _parse_walk_verify_packet(self) -> Dict[str, Any]:
        """Parse walk verify packet"""
        if len(self.data) >= 7:
            x = struct.unpack("<H", self.data[1:3])[0]
            y = struct.unpack("<H", self.data[3:5])[0]
            stamina = struct.unpack("<H", self.data[5:7])[0]
            return {"type": "walk_verify", "x": x, "y": y, "stamina": stamina}
        return {}
    
    def _parse_chat_packet(self) -> Dict[str, Any]:
        """Parse chat message packet"""
        if len(self.data) >= 3:
            msg_type = self.data[1]
            # Find null terminator for message
            msg_end = self.data.find(b'\x00', 2)
            if msg_end != -1:
                message = self.data[2:msg_end].decode('latin-1', errors='ignore')
                return {"type": "chat", "message_type": msg_type, "message": message}
        return {}
    
    def _parse_player_reassign_packet(self) -> Dict[str, Any]:
        """Parse player reassign packet"""
        if len(self.data) >= 8:
            unit_type = self.data[1]
            unit_id = struct.unpack("<I", self.data[2:6])[0]
            x = struct.unpack("<H", self.data[6:8])[0]
            y = struct.unpack("<H", self.data[8:10])[0] if len(self.data) >= 10 else 0
            return {"type": "player_reassign", "unit_type": unit_type, "unit_id": unit_id, "x": x, "y": y}
        return {}
    
    def _parse_player_update_packet(self) -> Dict[str, Any]:
        """Parse player update packet"""
        if len(self.data) >= 6:
            unit_id = struct.unpack("<I", self.data[1:5])[0]
            update_type = self.data[5]
            return {"type": "player_update", "unit_id": unit_id, "update_type": update_type}
        return {}

class D2StructureAnalyzer:
    """Analyzes D2 memory structures and patterns"""
    
    def __init__(self):
        self.known_structures = {
            "character": D2_CHARACTER_STRUCTURE,
            "item": D2_ITEM_STRUCTURE,
            "game_state": D2_GAME_STATE_STRUCTURE
        }
        self.discovered_patterns = {}
        
    def analyze_memory_region(self, memory_data: bytes, base_address: int = 0) -> Dict[str, Any]:
        """Analyze a memory region for known structures"""
        results = {
            "base_address": base_address,
            "size": len(memory_data),
            "structures_found": [],
            "patterns": [],
            "anomalies": []
        }
        
        # Search for known structures
        for struct_name, structure in self.known_structures.items():
            matches = self._find_structure_matches(memory_data, structure)
            if matches:
                results["structures_found"].extend(matches)
        
        # Look for patterns
        patterns = self._identify_patterns(memory_data)
        results["patterns"] = patterns
        
        # Detect anomalies
        anomalies = self._detect_anomalies(memory_data)
        results["anomalies"] = anomalies
        
        return results
    
    def _find_structure_matches(self, memory_data: bytes, structure: D2MemoryStructure) -> List[Dict[str, Any]]:
        """Find instances of a structure in memory"""
        matches = []
        
        # Simple pattern matching - look for characteristic signatures
        if structure.name == "D2Character":
            # Look for character name patterns (16-byte aligned strings)
            for i in range(0, len(memory_data) - structure.size, 16):
                potential_match = memory_data[i:i + structure.size]
                parsed = structure.read_from_memory(potential_match)
                
                # Validate if this looks like a character structure
                if self._validate_character_structure(parsed):
                    matches.append({
                        "structure": structure.name,
                        "offset": i,
                        "confidence": self._calculate_confidence(parsed),
                        "data": parsed
                    })
        
        return matches
    
    def _validate_character_structure(self, parsed_data: Dict[str, Any]) -> bool:
        """Validate if parsed data looks like a valid character structure"""
        # Check for reasonable values
        if parsed_data.get("character_level"):
            level = parsed_data["character_level"]
            if not (1 <= level <= 99):  # Valid level range
                return False
        
        if parsed_data.get("character_class"):
            char_class = parsed_data["character_class"]
            if char_class not in [c.value for c in D2CharacterClass]:
                return False
        
        # Check for reasonable attribute values
        for attr in ["strength", "dexterity", "vitality", "energy"]:
            if parsed_data.get(attr):
                value = parsed_data[attr]
                if not (1 <= value <= 1000):  # Reasonable attribute range
                    return False
        
        return True
    
    def _calculate_confidence(self, parsed_data: Dict[str, Any]) -> float:
        """Calculate confidence score for a structure match"""
        confidence = 0.0
        valid_fields = 0
        total_fields = len(parsed_data)
        
        for field_name, value in parsed_data.items():
            if value is not None:
                valid_fields += 1
                
                # Add confidence based on field validation
                if field_name == "character_level" and 1 <= value <= 99:
                    confidence += 0.2
                elif field_name == "character_class" and value in [c.value for c in D2CharacterClass]:
                    confidence += 0.2
                elif field_name in ["strength", "dexterity", "vitality", "energy"] and 1 <= value <= 1000:
                    confidence += 0.1
        
        # Base confidence on ratio of valid fields
        base_confidence = valid_fields / total_fields if total_fields > 0 else 0
        
        return min(1.0, base_confidence + confidence)
    
    def _identify_patterns(self, memory_data: bytes) -> List[Dict[str, Any]]:
        """Identify patterns in memory data"""
        patterns = []
        
        # Look for repeated sequences
        for seq_len in [4, 8, 16, 32]:
            repeated_sequences = self._find_repeated_sequences(memory_data, seq_len)
            patterns.extend(repeated_sequences)
        
        # Look for null-terminated strings
        strings = self._find_strings(memory_data)
        if strings:
            patterns.append({
                "type": "strings",
                "count": len(strings),
                "strings": strings[:10]  # Limit output
            })
        
        return patterns
    
    def _find_repeated_sequences(self, data: bytes, sequence_length: int) -> List[Dict[str, Any]]:
        """Find repeated byte sequences"""
        sequences = {}
        
        for i in range(len(data) - sequence_length + 1):
            seq = data[i:i + sequence_length]
            if seq not in sequences:
                sequences[seq] = []
            sequences[seq].append(i)
        
        # Find sequences that repeat
        repeated = []
        for seq, positions in sequences.items():
            if len(positions) >= 3:  # At least 3 occurrences
                repeated.append({
                    "type": "repeated_sequence",
                    "sequence": seq.hex(),
                    "length": sequence_length,
                    "count": len(positions),
                    "positions": positions[:10]  # Limit output
                })
        
        return repeated
    
    def _find_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Find printable strings in memory data"""
        strings = []
        current_string = b""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    try:
                        string = current_string.decode('ascii')
                        strings.append(string)
                    except UnicodeDecodeError:
                        pass
                current_string = b""
        
        # Check final string
        if len(current_string) >= min_length:
            try:
                string = current_string.decode('ascii')
                strings.append(string)
            except UnicodeDecodeError:
                pass
        
        return strings
    
    def _detect_anomalies(self, memory_data: bytes) -> List[Dict[str, Any]]:
        """Detect potential anomalies in memory data"""
        anomalies = []
        
        # Check for unusual patterns that might indicate code injection
        # or memory corruption
        
        # Look for executable code patterns (x86 opcodes)
        code_patterns = [
            b"\x55\x8B\xEC",  # push ebp; mov ebp, esp (common function prologue)
            b"\x33\xC0",      # xor eax, eax
            b"\x90\x90\x90",  # nop sled
            b"\xCC\xCC\xCC",  # int3 (debug breakpoints)
        ]
        
        for pattern in code_patterns:
            positions = self._find_pattern_positions(memory_data, pattern)
            if positions:
                anomalies.append({
                    "type": "potential_code",
                    "pattern": pattern.hex(),
                    "positions": positions[:5],  # Limit output
                    "description": "Potential executable code pattern"
                })
        
        # Look for shellcode patterns
        shellcode_indicators = [
            b"\x31\xC0",      # xor eax, eax
            b"\x50\x68",      # push eax; push
            b"\x8B\x54\x24",  # mov edx, [esp+XX]
        ]
        
        for indicator in shellcode_indicators:
            positions = self._find_pattern_positions(memory_data, indicator)
            if len(positions) >= 3:  # Multiple occurrences might indicate shellcode
                anomalies.append({
                    "type": "potential_shellcode",
                    "pattern": indicator.hex(),
                    "positions": positions[:5],
                    "description": "Pattern commonly found in shellcode"
                })
        
        return anomalies
    
    def _find_pattern_positions(self, data: bytes, pattern: bytes) -> List[int]:
        """Find all positions of a pattern in data"""
        positions = []
        start = 0
        
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        return positions

# Singleton analyzer instance
d2_analyzer = D2StructureAnalyzer()
