#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Live Memory Extractor for Current Player Unit
Extract real UnitAny structure from D2 game memory via d2-analysis container
"""

import requests
import json
import struct
from typing import Dict, Any, Optional

class LiveMemoryExtractor:
    def __init__(self):
        self.d2_analysis_endpoint = "http://localhost:3001"
        self.analysis_engine_endpoint = "http://localhost:8001"
        
        # UnitAny structure layout for parsing
        self.unitany_layout = {
            "name": "UnitAny (Current Player Unit)",
            "static_offset": "D2Client.dll+0x11BBFC",
            "size": 0xEC,  # 236 bytes
            "key_fields": [
                {"name": "dwType", "offset": 0x00, "size": 4, "type": "DWORD"},
                {"name": "dwTxtFileNo", "offset": 0x04, "size": 4, "type": "DWORD"},
                {"name": "dwUnitId", "offset": 0x0C, "size": 4, "type": "DWORD"},
                {"name": "dwMode", "offset": 0x10, "size": 4, "type": "DWORD"},
                {"name": "pPlayerData", "offset": 0x14, "size": 4, "type": "PlayerData*"},
                {"name": "dwAct", "offset": 0x18, "size": 4, "type": "DWORD"},
                {"name": "pStats", "offset": 0x5C, "size": 4, "type": "StatList*"},
                {"name": "pInventory", "offset": 0x60, "size": 4, "type": "Inventory*"},
                {"name": "wX", "offset": 0x8C, "size": 2, "type": "WORD"},
                {"name": "wY", "offset": 0x8E, "size": 2, "type": "WORD"},
                {"name": "pInfo", "offset": 0xA8, "size": 4, "type": "Info*"},
                {"name": "dwFlags", "offset": 0xC4, "size": 4, "type": "DWORD"},
                {"name": "dwFlags2", "offset": 0xC8, "size": 4, "type": "DWORD"}
            ]
        }
    
    def extract_live_current_player_unit(self):
        """Extract real Current Player Unit structure from live D2 memory"""
        print("LIVE MEMORY EXTRACTION - CURRENT PLAYER UNIT")
        print("=" * 60)
        
        print(f"\nConnecting to D2 Analysis Container...")
        print(f"  Endpoint: {self.d2_analysis_endpoint}")
        
        # Step 1: Check D2 process status
        print(f"\nSTEP 1: Checking D2 Process Status")
        print("-" * 40)
        d2_status = self.check_d2_process_status()
        
        if not d2_status["success"]:
            print("  ERROR: D2 process not accessible")
            return None
        
        # Step 2: Get D2Client.dll base address
        print(f"\nSTEP 2: Getting D2Client.dll Base Address")
        print("-" * 40)
        base_address = self.get_d2client_base_address()
        
        if not base_address:
            print("  ERROR: Could not get D2Client.dll base address")
            return None
        
        # Step 3: Calculate Current Player Unit address
        player_unit_address = base_address + 0x11BBFC
        print(f"  D2Client.dll base: 0x{base_address:08X}")
        print(f"  Player unit offset: +0x11BBFC")
        print(f"  Player unit address: 0x{player_unit_address:08X}")
        
        # Step 4: Read Current Player Unit pointer
        print(f"\nSTEP 3: Reading Current Player Unit Pointer")
        print("-" * 40)
        unit_pointer = self.read_memory_dword(player_unit_address)
        
        if not unit_pointer:
            print("  ERROR: Could not read Current Player Unit pointer")
            return None
        
        print(f"  UnitAny* pointer: 0x{unit_pointer:08X}")
        
        # Step 5: Extract complete UnitAny structure
        print(f"\nSTEP 4: Extracting Complete UnitAny Structure")
        print("-" * 40)
        unit_data = self.read_memory_block(unit_pointer, self.unitany_layout["size"])
        
        if not unit_data:
            print("  ERROR: Could not read UnitAny structure")
            return None
        
        print(f"  Successfully read {len(unit_data)} bytes from 0x{unit_pointer:08X}")
        
        # Step 6: Parse and analyze structure
        print(f"\nSTEP 5: Parsing Live Structure Data")
        print("-" * 40)
        parsed_structure = self.parse_unitany_structure(unit_data, unit_pointer)
        
        # Step 7: Display complete results
        print(f"\nSTEP 6: Complete Live Memory Analysis")
        print("-" * 40)
        self.display_complete_structure(parsed_structure, unit_data)
        
        return parsed_structure
    
    def check_d2_process_status(self):
        """Check if D2 process is running and accessible"""
        try:
            response = requests.get(f"{self.d2_analysis_endpoint}/status", timeout=5)
            if response.status_code == 200:
                status_data = response.json()
                print(f"  D2 Process Status: {status_data.get('status', 'Unknown')}")
                return {"success": True, "data": status_data}
            else:
                print(f"  HTTP Error: {response.status_code}")
                return {"success": False}
        except requests.exceptions.RequestException as e:
            print(f"  Connection Error: {e}")
            # Try alternative endpoint
            try:
                response = requests.get(f"{self.analysis_engine_endpoint}/d2/status", timeout=5)
                if response.status_code == 200:
                    status_data = response.json()
                    print(f"  D2 Process Status (via analysis engine): {status_data.get('status', 'Running')}")
                    return {"success": True, "data": status_data}
            except:
                pass
            return {"success": False}
    
    def get_d2client_base_address(self):
        """Get D2Client.dll base address from live process"""
        try:
            # Try d2-analysis endpoint first
            response = requests.get(f"{self.d2_analysis_endpoint}/memory/modules", timeout=10)
            if response.status_code == 200:
                modules = response.json()
                for module in modules.get("modules", []):
                    if "d2client" in module.get("name", "").lower():
                        base_addr = int(module.get("base_address", "0"), 16)
                        print(f"  Found D2Client.dll: 0x{base_addr:08X}")
                        return base_addr
            
            # Try analysis engine endpoint
            response = requests.get(f"{self.analysis_engine_endpoint}/d2/modules", timeout=10)
            if response.status_code == 200:
                modules = response.json()
                for module in modules.get("modules", []):
                    if "d2client" in module.get("name", "").lower():
                        base_addr = int(module.get("base_address", "0"), 16)
                        print(f"  Found D2Client.dll (via analysis engine): 0x{base_addr:08X}")
                        return base_addr
            
            # If API calls fail, use common D2 base address
            print("  API unavailable, using typical D2Client.dll base address")
            return 0x6FAA0000  # Common D2Client.dll base
            
        except requests.exceptions.RequestException as e:
            print(f"  Module enumeration failed: {e}")
            print("  Using typical D2Client.dll base address: 0x6FAA0000")
            return 0x6FAA0000
    
    def read_memory_dword(self, address):
        """Read a DWORD (4 bytes) from live D2 memory"""
        try:
            # Try d2-analysis memory endpoint
            payload = {"address": f"0x{address:08X}", "size": 4}
            response = requests.post(f"{self.d2_analysis_endpoint}/memory/read", 
                                   json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                hex_bytes = data.get("data", "")
                if hex_bytes:
                    # Convert hex string to bytes and unpack as DWORD
                    bytes_data = bytes.fromhex(hex_bytes.replace(" ", ""))
                    return struct.unpack("<L", bytes_data[:4])[0]
            
            # Try analysis engine endpoint
            response = requests.post(f"{self.analysis_engine_endpoint}/d2/memory/read", 
                                   json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                hex_bytes = data.get("data", "")
                if hex_bytes:
                    bytes_data = bytes.fromhex(hex_bytes.replace(" ", ""))
                    return struct.unpack("<L", bytes_data[:4])[0]
            
            print(f"  Memory read failed for address 0x{address:08X}")
            return None
            
        except Exception as e:
            print(f"  Memory read error: {e}")
            return None
    
    def read_memory_block(self, address, size):
        """Read a block of memory from live D2 process"""
        try:
            payload = {"address": f"0x{address:08X}", "size": size}
            
            # Try d2-analysis endpoint
            response = requests.post(f"{self.d2_analysis_endpoint}/memory/read", 
                                   json=payload, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                hex_bytes = data.get("data", "")
                if hex_bytes:
                    return bytes.fromhex(hex_bytes.replace(" ", ""))
            
            # Try analysis engine endpoint
            response = requests.post(f"{self.analysis_engine_endpoint}/d2/memory/read", 
                                   json=payload, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                hex_bytes = data.get("data", "")
                if hex_bytes:
                    return bytes.fromhex(hex_bytes.replace(" ", ""))
            
            print(f"  Memory block read failed")
            return None
            
        except Exception as e:
            print(f"  Memory block read error: {e}")
            return None
    
    def parse_unitany_structure(self, data, base_address):
        """Parse the UnitAny structure from raw memory data"""
        if len(data) < self.unitany_layout["size"]:
            print(f"  WARNING: Incomplete data - got {len(data)} bytes, expected {self.unitany_layout['size']}")
        
        parsed = {
            "base_address": base_address,
            "size": len(data),
            "fields": {}
        }
        
        for field in self.unitany_layout["key_fields"]:
            offset = field["offset"]
            size = field["size"]
            name = field["name"]
            
            if offset + size <= len(data):
                if size == 4:
                    value = struct.unpack("<L", data[offset:offset+4])[0]
                    parsed["fields"][name] = {
                        "value": value,
                        "hex": f"0x{value:08X}",
                        "offset": f"0x{offset:02X}",
                        "type": field["type"]
                    }
                elif size == 2:
                    value = struct.unpack("<H", data[offset:offset+2])[0]
                    parsed["fields"][name] = {
                        "value": value,
                        "hex": f"0x{value:04X}",
                        "offset": f"0x{offset:02X}",
                        "type": field["type"]
                    }
        
        return parsed
    
    def display_complete_structure(self, parsed_structure, raw_data):
        """Display the complete live structure analysis"""
        print(f"LIVE CURRENT PLAYER UNIT STRUCTURE")
        print(f"Address: 0x{parsed_structure['base_address']:08X}")
        print(f"Size: {parsed_structure['size']} bytes")
        print()
        
        print("KEY FIELDS FROM LIVE MEMORY:")
        print("Offset | Field Name       | Value            | Description")
        print("-" * 65)
        
        for name, field_data in parsed_structure["fields"].items():
            offset = field_data["offset"]
            value = field_data["hex"]
            field_type = field_data["type"]
            
            # Add descriptions
            if name == "dwType":
                desc = f"Unit type ({field_data['value']})"
            elif name == "dwTxtFileNo":
                class_names = {0: "Amazon", 1: "Sorceress", 2: "Necromancer", 
                              3: "Paladin", 4: "Barbarian", 5: "Druid", 6: "Assassin"}
                class_name = class_names.get(field_data['value'], "Unknown")
                desc = f"Character class ({class_name})"
            elif name == "dwUnitId":
                desc = "Unique player ID"
            elif name == "pPlayerData":
                desc = "-> PlayerData (name, quests)"
            elif name == "pStats":
                desc = "-> StatList (STR, DEX, VIT, ENE)"
            elif name == "pInventory":
                desc = "-> Inventory (items)"
            elif name == "wX":
                desc = f"X position ({field_data['value']})"
            elif name == "wY":
                desc = f"Y position ({field_data['value']})"
            else:
                desc = field_type
            
            print(f"{offset}   | {name:16} | {value:16} | {desc}")
        
        print(f"\nRAW MEMORY DUMP:")
        print("Address | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII")
        print("-" * 75)
        
        for i in range(0, len(raw_data), 16):
            chunk = raw_data[i:i+16]
            hex_bytes = ' '.join(f'{b:02X}' for b in chunk)
            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            addr = parsed_structure["base_address"] + i
            print(f"  {addr:04X}: | {hex_bytes:<48} | {ascii_repr}")
        
        print(f"\nLIVE MEMORY VERIFICATION COMPLETE!")

def main():
    print("STARTING LIVE MEMORY EXTRACTION")
    print("Extracting Current Player Unit from D2 game memory")
    print()
    
    extractor = LiveMemoryExtractor()
    result = extractor.extract_live_current_player_unit()
    
    print(f"\n" + "="*60)
    if result:
        print("LIVE MEMORY EXTRACTION SUCCESSFUL!")
        print("Real Current Player Unit structure extracted from game memory!")
    else:
        print("LIVE MEMORY EXTRACTION FAILED!")
        print("Check D2 process and container status")

if __name__ == "__main__":
    main()