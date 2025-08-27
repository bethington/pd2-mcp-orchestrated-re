#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Current Player Unit Structure Demonstration
Shows the complete UnitAny structure data at D2Client.dll+0x11BBFC
"""

import struct
from typing import Dict, Any

class CurrentPlayerUnitDemo:
    def __init__(self):
        # UnitAny structure layout from D2Structs.h
        self.unitany_layout = {
            "name": "UnitAny (Current Player Unit)",
            "size": 0xEC,  # 236 bytes
            "static_offset": "D2Client.dll+0x11BBFC",
            "fields": [
                {"name": "dwType", "offset": 0x00, "size": 4, "type": "DWORD"},
                {"name": "dwTxtFileNo", "offset": 0x04, "size": 4, "type": "DWORD"},
                {"name": "dwUnitId", "offset": 0x0C, "size": 4, "type": "DWORD"},
                {"name": "dwMode", "offset": 0x10, "size": 4, "type": "DWORD"},
                {"name": "pPlayerData", "offset": 0x14, "size": 4, "type": "PlayerData*"},
                {"name": "dwAct", "offset": 0x18, "size": 4, "type": "DWORD"},
                {"name": "pAct", "offset": 0x1C, "size": 4, "type": "Act*"},
                {"name": "pPath", "offset": 0x2C, "size": 4, "type": "Path*"},
                {"name": "dwGfxFrame", "offset": 0x44, "size": 4, "type": "DWORD"},
                {"name": "dwFrameRemain", "offset": 0x48, "size": 4, "type": "DWORD"},
                {"name": "wFrameRate", "offset": 0x4C, "size": 2, "type": "WORD"},
                {"name": "pGfxInfo", "offset": 0x54, "size": 4, "type": "GfxInfo*"},
                {"name": "pStats", "offset": 0x5C, "size": 4, "type": "StatList*"},
                {"name": "pInventory", "offset": 0x60, "size": 4, "type": "Inventory*"},
                {"name": "wX", "offset": 0x8C, "size": 2, "type": "WORD"},
                {"name": "wY", "offset": 0x8E, "size": 2, "type": "WORD"},
                {"name": "pInfo", "offset": 0xA8, "size": 4, "type": "Info*"},
                {"name": "dwFlags", "offset": 0xC4, "size": 4, "type": "DWORD"},
                {"name": "dwFlags2", "offset": 0xC8, "size": 4, "type": "DWORD"},
                {"name": "pNext", "offset": 0xE8, "size": 4, "type": "UnitAny*"}
            ]
        }
        
        # Demonstration values for a real player character
        self.demo_player_data = {
            "character_name": "Xerzes",
            "character_class": "Sorceress",
            "level": 85,
            "act": 1,
            "area": "Rogue Encampment",
            "x_position": 25104,
            "y_position": 5144,
            "current_hp": 1250,
            "max_hp": 1250,
            "current_mana": 980,
            "max_mana": 980,
            "strength": 10,
            "energy": 35,
            "dexterity": 25,
            "vitality": 10
        }
    
    def demonstrate_current_player_unit(self):
        """Show complete Current Player Unit structure analysis"""
        print("CURRENT PLAYER UNIT STRUCTURE ANALYSIS")
        print("=" * 60)
        
        print(f"\nSTATIC MEMORY ACCESS:")
        print(f"   Location: {self.unitany_layout['static_offset']}")
        print(f"   Structure: {self.unitany_layout['name']}")
        print(f"   Size: {self.unitany_layout['size']} bytes (0x{self.unitany_layout['size']:02X})")
        print(f"   Fields: {len(self.unitany_layout['fields'])}")
        
        print(f"\nPHASE 1: Core Unit Information")
        print("-" * 50)
        self.show_core_unit_info()
        
        print(f"\nPHASE 2: Player Data Access")
        print("-" * 50)
        self.show_player_data_access()
        
        print(f"\nPHASE 3: Statistics System")
        print("-" * 50)
        self.show_statistics_system()
        
        print(f"\nPHASE 4: World Position & Context")
        print("-" * 50)
        self.show_world_context()
        
        print(f"\nPHASE 5: Complete Structure Layout")
        print("-" * 50)
        self.show_complete_structure()
        
        print(f"\nPHASE 6: Security Analysis Points")
        print("-" * 50)
        self.show_security_analysis()
    
    def show_core_unit_info(self):
        """Show core unit identification data"""
        print("  Core Unit Identification:")
        print(f"    dwType = 0x00000000 (Player Unit)")
        print(f"    dwTxtFileNo = 0x00000001 (Sorceress class)")
        print(f"    dwUnitId = 0x12345678 (Unique player ID)")
        print(f"    dwMode = 0x00000008 (Standing/Town mode)")
        
        print(f"\n  Unit Type Meanings:")
        print(f"    0 = Player, 1 = NPC/Monster, 2 = Object")
        print(f"    3 = Missile, 4 = Item, 5 = Tile")
    
    def show_player_data_access(self):
        """Show PlayerData pointer and accessible data"""
        print("  PlayerData Pointer Access:")
        print(f"    pPlayerData = 0x6FAB1000 (Pointer to PlayerData structure)")
        print(f"    -> szName = '{self.demo_player_data['character_name']}'")
        print(f"    -> pNormalQuest = 0x6FAB2000 (Quest completion data)")
        print(f"    -> pNormalWaypoint = 0x6FAB3000 (Waypoint activation data)")
        
        print(f"\n  Character Information:")
        print(f"    Name: {self.demo_player_data['character_name']}")
        print(f"    Class: {self.demo_player_data['character_class']}")
        print(f"    Level: {self.demo_player_data['level']}")
    
    def show_statistics_system(self):
        """Show StatList pointer and character statistics"""
        print("  Statistics System Access:")
        print(f"    pStats = 0x6FAB4000 (Pointer to StatList structure)")
        
        print(f"\n  Character Statistics:")
        print(f"    Strength: {self.demo_player_data['strength']}")
        print(f"    Energy: {self.demo_player_data['energy']}")
        print(f"    Dexterity: {self.demo_player_data['dexterity']}")
        print(f"    Vitality: {self.demo_player_data['vitality']}")
        
        print(f"\n  Life & Mana:")
        print(f"    Current HP: {self.demo_player_data['current_hp']}")
        print(f"    Maximum HP: {self.demo_player_data['max_hp']}")
        print(f"    Current Mana: {self.demo_player_data['current_mana']}")
        print(f"    Maximum Mana: {self.demo_player_data['max_mana']}")
    
    def show_world_context(self):
        """Show world position and context data"""
        print("  World Context & Position:")
        print(f"    dwAct = 0x00000000 (Act {self.demo_player_data['act']})")
        print(f"    pAct = 0x6FAB5000 (Pointer to Act structure)")
        print(f"    wX = {self.demo_player_data['x_position']} (World X coordinate)")
        print(f"    wY = {self.demo_player_data['y_position']} (World Y coordinate)")
        
        print(f"\n  Location Information:")
        print(f"    Current Act: {self.demo_player_data['act']}")
        print(f"    Current Area: {self.demo_player_data['area']}")
        print(f"    Position: ({self.demo_player_data['x_position']}, {self.demo_player_data['y_position']})")
        
        print(f"\n  Additional Pointers:")
        print(f"    pPath = 0x6FAB6000 (Movement & pathfinding data)")
        print(f"    pInventory = 0x6FAB7000 (Equipment & inventory items)")
        print(f"    pInfo = 0x6FAB8000 (Skills & abilities data)")
    
    def show_complete_structure(self):
        """Show complete field-by-field structure layout"""
        print("  Complete UnitAny Structure Layout:")
        print("  Offset | Field Name      | Type        | Description")
        print("  " + "-" * 60)
        
        structure_data = self.generate_realistic_unitany_data()
        
        for field in self.unitany_layout['fields']:
            offset = field['offset']
            name = field['name']
            field_type = field['type']
            size = field['size']
            
            # Get field value from generated data
            if size == 4:
                if field_type.endswith('*'):
                    value = f"0x{struct.unpack('<L', structure_data[offset:offset+4])[0]:08X}"
                else:
                    value = f"0x{struct.unpack('<L', structure_data[offset:offset+4])[0]:08X}"
            elif size == 2:
                value = f"0x{struct.unpack('<H', structure_data[offset:offset+2])[0]:04X}"
            else:
                value = "..."
            
            print(f"  0x{offset:02X}   | {name:15} | {field_type:11} | {value}")
        
        print(f"\n  Raw Memory Dump (first 64 bytes):")
        for i in range(0, min(64, len(structure_data)), 16):
            hex_bytes = ' '.join(f'{b:02X}' for b in structure_data[i:i+16])
            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in structure_data[i:i+16])
            print(f"    {i:04X}: {hex_bytes:<48} |{ascii_repr}|")
    
    def show_security_analysis(self):
        """Show security analysis and validation points"""
        print("  Critical Security Validation Points:")
        print("    1. Unit Type Validation:")
        print("       - dwType must equal 0 (Player)")
        print("       - Detect invalid unit type modifications")
        
        print(f"\n    2. Position Bounds Checking:")
        print(f"       - X/Y coordinates within valid map bounds")
        print(f"       - Detect teleportation/speed hacks")
        
        print(f"\n    3. Statistics Validation:")
        print(f"       - Stats within legitimate ranges for character level")
        print(f"       - HP/Mana values don't exceed maximum")
        
        print(f"\n    4. Pointer Validation:")
        print(f"       - All pointer values in valid memory ranges")
        print(f"       - Detect memory corruption or injection")
        
        print(f"\n    5. Mode State Verification:")
        print(f"       - dwMode matches legitimate game states")
        print(f"       - Detect impossible animation/action states")
        
        print(f"\n  Memory Access Pattern:")
        print(f"    HMODULE d2client = GetModuleHandle(\"D2Client.dll\");")
        print(f"    UnitAny** player_ptr = (UnitAny**)(d2client + 0x11BBFC);")
        print(f"    UnitAny* player_unit = *player_ptr;")
        print(f"    // Access all player data through player_unit->")
    
    def generate_realistic_unitany_data(self):
        """Generate realistic UnitAny structure data"""
        data = bytearray(236)  # 0xEC bytes
        
        # Core unit info
        struct.pack_into('<L', data, 0x00, 0x00000000)  # dwType (Player)
        struct.pack_into('<L', data, 0x04, 0x00000001)  # dwTxtFileNo (Sorceress)
        struct.pack_into('<L', data, 0x0C, 0x12345678)  # dwUnitId
        struct.pack_into('<L', data, 0x10, 0x00000008)  # dwMode (Standing)
        
        # Pointer fields
        struct.pack_into('<L', data, 0x14, 0x6FAB1000)  # pPlayerData
        struct.pack_into('<L', data, 0x18, 0x00000000)  # dwAct
        struct.pack_into('<L', data, 0x1C, 0x6FAB5000)  # pAct
        struct.pack_into('<L', data, 0x2C, 0x6FAB6000)  # pPath
        struct.pack_into('<L', data, 0x54, 0x6FAB9000)  # pGfxInfo
        struct.pack_into('<L', data, 0x5C, 0x6FAB4000)  # pStats
        struct.pack_into('<L', data, 0x60, 0x6FAB7000)  # pInventory
        struct.pack_into('<L', data, 0xA8, 0x6FAB8000)  # pInfo
        
        # Position
        struct.pack_into('<H', data, 0x8C, 25104)  # wX
        struct.pack_into('<H', data, 0x8E, 5144)   # wY
        
        # Flags
        struct.pack_into('<L', data, 0xC4, 0x00000001)  # dwFlags
        struct.pack_into('<L', data, 0xC8, 0x00000000)  # dwFlags2
        
        # Next pointer (NULL for single player)
        struct.pack_into('<L', data, 0xE8, 0x00000000)  # pNext
        
        return bytes(data)

def main():
    print("STARTING CURRENT PLAYER UNIT ANALYSIS")
    print("Analyzing structure at D2Client.dll+0x11BBFC")
    print()
    
    demo = CurrentPlayerUnitDemo()
    demo.demonstrate_current_player_unit()
    
    print(f"\n" + "="*60)
    print("CURRENT PLAYER UNIT ANALYSIS COMPLETE!")
    print("Structure successfully analyzed and demonstrated!")

if __name__ == "__main__":
    main()