"""
Data Structure Mapping System for MCP Integration

This system automatically maps discovered data structures to MCP-compatible
formats and provides runtime access patterns for dynamic data interaction.
"""

import struct
import ctypes
from typing import Dict, List, Any, Optional, Union, Type, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)


class DataType(Enum):
    """Supported data types for structure mapping"""
    UINT8 = "uint8"
    UINT16 = "uint16" 
    UINT32 = "uint32"
    UINT64 = "uint64"
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32" 
    INT64 = "int64"
    FLOAT32 = "float32"
    FLOAT64 = "float64"
    CHAR = "char"
    STRING = "string"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    UNION = "union"
    BITFIELD = "bitfield"


@dataclass
class FieldDefinition:
    """Definition of a structure field"""
    name: str
    data_type: DataType
    offset: int
    size: int
    array_count: int = 1
    pointer_depth: int = 0
    bit_offset: int = 0
    bit_width: int = 0
    description: str = ""
    default_value: Any = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    access_pattern: str = "read_write"  # read_only, write_only, read_write
    
    def is_array(self) -> bool:
        """Check if field is an array"""
        return self.array_count > 1
    
    def is_pointer(self) -> bool:
        """Check if field is a pointer"""
        return self.pointer_depth > 0
    
    def is_bitfield(self) -> bool:
        """Check if field is a bitfield"""
        return self.bit_width > 0
    
    def get_total_size(self) -> int:
        """Get total size including arrays"""
        return self.size * self.array_count


@dataclass
class StructureDefinition:
    """Definition of a data structure"""
    name: str
    size: int
    fields: List[FieldDefinition]
    alignment: int = 4
    pack: bool = False
    description: str = ""
    base_address: Optional[int] = None
    discovery_id: Optional[str] = None
    confidence: float = 0.0
    creation_time: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    
    def get_field(self, name: str) -> Optional[FieldDefinition]:
        """Get field by name"""
        return next((f for f in self.fields if f.name == name), None)
    
    def get_fields_by_type(self, data_type: DataType) -> List[FieldDefinition]:
        """Get fields by data type"""
        return [f for f in self.fields if f.data_type == data_type]
    
    def validate_structure(self) -> List[str]:
        """Validate structure definition and return any issues"""
        issues = []
        
        if not self.fields:
            issues.append("Structure has no fields")
            
        if self.size <= 0:
            issues.append("Structure size must be positive")
            
        # Check field offsets
        for field in self.fields:
            if field.offset < 0:
                issues.append(f"Field {field.name} has negative offset")
            
            if field.offset + field.get_total_size() > self.size:
                issues.append(f"Field {field.name} exceeds structure bounds")
        
        # Check for overlapping fields (except unions)
        sorted_fields = sorted(self.fields, key=lambda f: f.offset)
        for i in range(len(sorted_fields) - 1):
            current = sorted_fields[i]
            next_field = sorted_fields[i + 1]
            
            current_end = current.offset + current.get_total_size()
            if current_end > next_field.offset:
                issues.append(f"Fields {current.name} and {next_field.name} overlap")
        
        return issues


class StructureMapper:
    """Maps discovered data structures to runtime-accessible formats"""
    
    def __init__(self):
        self.structures: Dict[str, StructureDefinition] = {}
        self.ctypes_cache: Dict[str, Type] = {}
        self.struct_format_cache: Dict[str, str] = {}
        
        # Type mapping tables
        self.type_to_ctypes = {
            DataType.UINT8: ctypes.c_uint8,
            DataType.UINT16: ctypes.c_uint16,
            DataType.UINT32: ctypes.c_uint32,
            DataType.UINT64: ctypes.c_uint64,
            DataType.INT8: ctypes.c_int8,
            DataType.INT16: ctypes.c_int16,
            DataType.INT32: ctypes.c_int32,
            DataType.INT64: ctypes.c_int64,
            DataType.FLOAT32: ctypes.c_float,
            DataType.FLOAT64: ctypes.c_double,
            DataType.CHAR: ctypes.c_char,
            DataType.POINTER: ctypes.c_void_p
        }
        
        self.type_to_struct = {
            DataType.UINT8: 'B',
            DataType.UINT16: 'H',
            DataType.UINT32: 'I',
            DataType.UINT64: 'Q',
            DataType.INT8: 'b',
            DataType.INT16: 'h',
            DataType.INT32: 'i',
            DataType.INT64: 'q',
            DataType.FLOAT32: 'f',
            DataType.FLOAT64: 'd',
            DataType.CHAR: 'c',
            DataType.POINTER: 'P'
        }
        
        self.type_sizes = {
            DataType.UINT8: 1,
            DataType.UINT16: 2,
            DataType.UINT32: 4,
            DataType.UINT64: 8,
            DataType.INT8: 1,
            DataType.INT16: 2,
            DataType.INT32: 4,
            DataType.INT64: 8,
            DataType.FLOAT32: 4,
            DataType.FLOAT64: 8,
            DataType.CHAR: 1,
            DataType.POINTER: 8  # Assuming 64-bit
        }
    
    def register_structure(self, structure: StructureDefinition) -> bool:
        """Register a new data structure"""
        try:
            # Validate structure
            issues = structure.validate_structure()
            if issues:
                logger.warning(f"Structure validation issues for {structure.name}: {issues}")
            
            # Store structure
            self.structures[structure.name] = structure
            
            # Clear caches for this structure
            self._clear_caches(structure.name)
            
            logger.info(f"Registered structure: {structure.name} ({structure.size} bytes, {len(structure.fields)} fields)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register structure {structure.name}: {e}")
            return False
    
    def create_structure_from_discovery(self, discovery_data: Dict[str, Any], 
                                      discovery_id: str) -> Optional[StructureDefinition]:
        """Create a structure definition from discovery data"""
        try:
            name = discovery_data.get("name", f"discovered_struct_{discovery_id}")
            size = discovery_data.get("size", 0)
            fields_data = discovery_data.get("fields", [])
            
            fields = []
            for field_data in fields_data:
                field = self._create_field_from_data(field_data)
                if field:
                    fields.append(field)
            
            structure = StructureDefinition(
                name=name,
                size=size,
                fields=fields,
                alignment=discovery_data.get("alignment", 4),
                description=discovery_data.get("description", ""),
                base_address=discovery_data.get("address"),
                discovery_id=discovery_id,
                confidence=discovery_data.get("confidence", 0.0)
            )
            
            return structure
            
        except Exception as e:
            logger.error(f"Failed to create structure from discovery: {e}")
            return None
    
    def _create_field_from_data(self, field_data: Dict[str, Any]) -> Optional[FieldDefinition]:
        """Create field definition from discovery data"""
        try:
            name = field_data.get("name", "unknown_field")
            type_str = field_data.get("type", "uint32")
            offset = field_data.get("offset", 0)
            size = field_data.get("size", 4)
            
            # Map type string to DataType enum
            data_type = self._parse_data_type(type_str)
            
            # Handle arrays
            array_count = 1
            if "[" in type_str and "]" in type_str:
                try:
                    start = type_str.index("[") + 1
                    end = type_str.index("]")
                    array_count = int(type_str[start:end])
                except (ValueError, IndexError):
                    pass
            
            # Handle pointers
            pointer_depth = type_str.count("*")
            
            field = FieldDefinition(
                name=name,
                data_type=data_type,
                offset=offset,
                size=size,
                array_count=array_count,
                pointer_depth=pointer_depth,
                description=field_data.get("description", ""),
                access_pattern=field_data.get("access_pattern", "read_write")
            )
            
            return field
            
        except Exception as e:
            logger.error(f"Failed to create field from data: {e}")
            return None
    
    def _parse_data_type(self, type_str: str) -> DataType:
        """Parse type string to DataType enum"""
        # Clean up type string
        base_type = type_str.lower().replace("*", "").replace("[", "").split("]")[0].strip()
        
        # Common type mappings
        type_mapping = {
            "uint8": DataType.UINT8, "u8": DataType.UINT8, "byte": DataType.UINT8,
            "uint16": DataType.UINT16, "u16": DataType.UINT16, "word": DataType.UINT16,
            "uint32": DataType.UINT32, "u32": DataType.UINT32, "dword": DataType.UINT32,
            "uint64": DataType.UINT64, "u64": DataType.UINT64, "qword": DataType.UINT64,
            "int8": DataType.INT8, "i8": DataType.INT8,
            "int16": DataType.INT16, "i16": DataType.INT16, "short": DataType.INT16,
            "int32": DataType.INT32, "i32": DataType.INT32, "int": DataType.INT32,
            "int64": DataType.INT64, "i64": DataType.INT64, "long": DataType.INT64,
            "float32": DataType.FLOAT32, "f32": DataType.FLOAT32, "float": DataType.FLOAT32,
            "float64": DataType.FLOAT64, "f64": DataType.FLOAT64, "double": DataType.FLOAT64,
            "char": DataType.CHAR,
            "string": DataType.STRING, "str": DataType.STRING,
            "pointer": DataType.POINTER, "ptr": DataType.POINTER
        }
        
        return type_mapping.get(base_type, DataType.UINT32)  # Default to uint32
    
    def create_ctypes_class(self, structure_name: str) -> Optional[Type]:
        """Create a ctypes class for the structure"""
        if structure_name in self.ctypes_cache:
            return self.ctypes_cache[structure_name]
        
        if structure_name not in self.structures:
            return None
        
        structure = self.structures[structure_name]
        
        try:
            # Create fields for ctypes class
            ctypes_fields = []
            
            for field in structure.fields:
                if field.data_type in self.type_to_ctypes:
                    field_type = self.type_to_ctypes[field.data_type]
                    
                    # Handle arrays
                    if field.is_array():
                        field_type = field_type * field.array_count
                    
                    # Handle pointers
                    if field.is_pointer():
                        for _ in range(field.pointer_depth):
                            field_type = ctypes.POINTER(field_type)
                    
                    ctypes_fields.append((field.name, field_type))
            
            # Create the ctypes structure class
            class_name = f"{structure_name}_ctypes"
            
            if structure.pack:
                class StructClass(ctypes.Structure):
                    _pack_ = 1
                    _fields_ = ctypes_fields
            else:
                class StructClass(ctypes.Structure):
                    _fields_ = ctypes_fields
            
            # Cache and return
            self.ctypes_cache[structure_name] = StructClass
            return StructClass
            
        except Exception as e:
            logger.error(f"Failed to create ctypes class for {structure_name}: {e}")
            return None
    
    def create_struct_format(self, structure_name: str) -> Optional[str]:
        """Create struct.pack/unpack format string for the structure"""
        if structure_name in self.struct_format_cache:
            return self.struct_format_cache[structure_name]
        
        if structure_name not in self.structures:
            return None
        
        structure = self.structures[structure_name]
        
        try:
            format_parts = []
            
            # Add endianness and packing
            if structure.pack:
                format_parts.append("=")  # Native endianness, no padding
            else:
                format_parts.append("@")  # Native endianness, native alignment
            
            # Sort fields by offset
            sorted_fields = sorted(structure.fields, key=lambda f: f.offset)
            current_offset = 0
            
            for field in sorted_fields:
                # Add padding if needed
                if field.offset > current_offset:
                    padding = field.offset - current_offset
                    format_parts.append(f"{padding}x")
                
                # Add field format
                if field.data_type in self.type_to_struct:
                    field_format = self.type_to_struct[field.data_type]
                    
                    # Handle arrays
                    if field.is_array():
                        field_format = f"{field.array_count}{field_format}"
                    
                    format_parts.append(field_format)
                    current_offset = field.offset + field.get_total_size()
            
            format_string = "".join(format_parts)
            self.struct_format_cache[structure_name] = format_string
            return format_string
            
        except Exception as e:
            logger.error(f"Failed to create struct format for {structure_name}: {e}")
            return None
    
    def parse_data(self, structure_name: str, data: bytes, 
                  base_address: int = 0) -> Optional[Dict[str, Any]]:
        """Parse binary data using structure definition"""
        if structure_name not in self.structures:
            return None
        
        structure = self.structures[structure_name]
        
        try:
            result = {
                "structure_name": structure_name,
                "base_address": base_address,
                "size": len(data),
                "fields": {}
            }
            
            # Update access tracking
            structure.access_count += 1
            structure.last_accessed = datetime.now()
            
            # Parse each field
            for field in structure.fields:
                if field.offset + field.get_total_size() > len(data):
                    logger.warning(f"Field {field.name} extends beyond data length")
                    continue
                
                field_data = data[field.offset:field.offset + field.get_total_size()]
                field_value = self._parse_field_data(field, field_data)
                
                result["fields"][field.name] = {
                    "type": field.data_type.value,
                    "offset": field.offset,
                    "size": field.get_total_size(),
                    "value": field_value,
                    "address": base_address + field.offset if base_address else None
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse data for {structure_name}: {e}")
            return None
    
    def _parse_field_data(self, field: FieldDefinition, data: bytes) -> Any:
        """Parse data for a specific field"""
        try:
            if field.data_type == DataType.UINT8:
                return struct.unpack("B", data[:1])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}B", data))
            elif field.data_type == DataType.UINT16:
                return struct.unpack("H", data[:2])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}H", data))
            elif field.data_type == DataType.UINT32:
                return struct.unpack("I", data[:4])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}I", data))
            elif field.data_type == DataType.UINT64:
                return struct.unpack("Q", data[:8])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}Q", data))
            elif field.data_type == DataType.INT8:
                return struct.unpack("b", data[:1])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}b", data))
            elif field.data_type == DataType.INT16:
                return struct.unpack("h", data[:2])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}h", data))
            elif field.data_type == DataType.INT32:
                return struct.unpack("i", data[:4])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}i", data))
            elif field.data_type == DataType.INT64:
                return struct.unpack("q", data[:8])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}q", data))
            elif field.data_type == DataType.FLOAT32:
                return struct.unpack("f", data[:4])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}f", data))
            elif field.data_type == DataType.FLOAT64:
                return struct.unpack("d", data[:8])[0] if field.array_count == 1 else list(struct.unpack(f"{field.array_count}d", data))
            elif field.data_type == DataType.CHAR:
                if field.array_count == 1:
                    return data[:1].decode('ascii', errors='replace')
                else:
                    return data[:field.array_count].decode('ascii', errors='replace').rstrip('\x00')
            elif field.data_type == DataType.STRING:
                return data.decode('ascii', errors='replace').rstrip('\x00')
            elif field.data_type == DataType.POINTER:
                if len(data) >= 8:  # 64-bit pointer
                    return hex(struct.unpack("Q", data[:8])[0])
                elif len(data) >= 4:  # 32-bit pointer
                    return hex(struct.unpack("I", data[:4])[0])
                else:
                    return "0x0"
            else:
                return data.hex()  # Return hex for unknown types
                
        except Exception as e:
            logger.error(f"Failed to parse field {field.name}: {e}")
            return None
    
    def create_mcp_schema(self, structure_name: str) -> Optional[Dict[str, Any]]:
        """Create MCP-compatible schema for the structure"""
        if structure_name not in self.structures:
            return None
        
        structure = self.structures[structure_name]
        
        schema = {
            "type": "object",
            "title": structure.name,
            "description": structure.description or f"Data structure {structure.name} ({structure.size} bytes)",
            "properties": {
                "structure_name": {"type": "string", "const": structure.name},
                "base_address": {"type": ["string", "null"], "description": "Base memory address (hex)"},
                "size": {"type": "integer", "description": "Total structure size in bytes"},
                "fields": {
                    "type": "object",
                    "properties": {},
                    "description": "Structure field values"
                }
            },
            "required": ["structure_name", "size", "fields"]
        }
        
        # Add field schemas
        for field in structure.fields:
            field_schema = {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "const": field.data_type.value},
                    "offset": {"type": "integer", "description": "Field offset in bytes"},
                    "size": {"type": "integer", "description": "Field size in bytes"},
                    "address": {"type": ["string", "null"], "description": "Field memory address (hex)"},
                    "value": self._get_field_value_schema(field)
                },
                "required": ["type", "offset", "size", "value"],
                "description": field.description or f"{field.data_type.value} field"
            }
            
            schema["properties"]["fields"]["properties"][field.name] = field_schema
        
        return schema
    
    def _get_field_value_schema(self, field: FieldDefinition) -> Dict[str, Any]:
        """Get JSON schema for field value"""
        if field.data_type in [DataType.UINT8, DataType.UINT16, DataType.UINT32, DataType.UINT64,
                              DataType.INT8, DataType.INT16, DataType.INT32, DataType.INT64]:
            if field.is_array():
                return {"type": "array", "items": {"type": "integer"}}
            else:
                return {"type": "integer"}
        elif field.data_type in [DataType.FLOAT32, DataType.FLOAT64]:
            if field.is_array():
                return {"type": "array", "items": {"type": "number"}}
            else:
                return {"type": "number"}
        elif field.data_type in [DataType.CHAR, DataType.STRING]:
            return {"type": "string"}
        elif field.data_type == DataType.POINTER:
            return {"type": "string", "pattern": "^0x[0-9a-fA-F]+$"}
        else:
            return {"type": "string", "description": "Hex-encoded data"}
    
    def get_structure_info(self, structure_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a structure"""
        if structure_name not in self.structures:
            return None
        
        structure = self.structures[structure_name]
        
        return {
            "name": structure.name,
            "size": structure.size,
            "field_count": len(structure.fields),
            "alignment": structure.alignment,
            "packed": structure.pack,
            "description": structure.description,
            "base_address": hex(structure.base_address) if structure.base_address else None,
            "discovery_id": structure.discovery_id,
            "confidence": structure.confidence,
            "creation_time": structure.creation_time.isoformat(),
            "access_count": structure.access_count,
            "last_accessed": structure.last_accessed.isoformat() if structure.last_accessed else None,
            "fields": [
                {
                    "name": field.name,
                    "type": field.data_type.value,
                    "offset": field.offset,
                    "size": field.get_total_size(),
                    "array_count": field.array_count,
                    "pointer_depth": field.pointer_depth,
                    "description": field.description,
                    "access_pattern": field.access_pattern
                }
                for field in structure.fields
            ]
        }
    
    def list_structures(self) -> List[Dict[str, Any]]:
        """List all registered structures"""
        return [
            {
                "name": name,
                "size": struct.size,
                "field_count": len(struct.fields),
                "confidence": struct.confidence,
                "access_count": struct.access_count,
                "last_accessed": struct.last_accessed.isoformat() if struct.last_accessed else None
            }
            for name, struct in self.structures.items()
        ]
    
    def _clear_caches(self, structure_name: str):
        """Clear cached data for a structure"""
        if structure_name in self.ctypes_cache:
            del self.ctypes_cache[structure_name]
        if structure_name in self.struct_format_cache:
            del self.struct_format_cache[structure_name]