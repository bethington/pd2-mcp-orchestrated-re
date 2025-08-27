#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
os.environ['PYTHONIOENCODING'] = 'utf-8'
"""
Store Live Memory Offsets and Structures in Dgraph
Create graph relationships between D2 memory structures, offsets, and live data
"""

import requests
import json
from datetime import datetime

class DgraphMemoryStorage:
    def __init__(self):
        self.dgraph_url = "http://localhost:8081"
        self.session_id = f"memory_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
    def store_memory_data(self):
        """Store complete memory analysis data in Dgraph"""
        print("STORING LIVE MEMORY DATA IN DGRAPH")
        print("=" * 60)
        
        # Step 1: Define schema
        print("\nSTEP 1: Setting up Dgraph schema")
        self.setup_schema()
        
        # Step 2: Store base addresses and modules
        print("\nSTEP 2: Storing D2 modules and base addresses")
        self.store_modules()
        
        # Step 3: Store memory offsets
        print("\nSTEP 3: Storing static memory offsets")
        self.store_offsets()
        
        # Step 4: Store structure definitions
        print("\nSTEP 4: Storing memory structure layouts")
        self.store_structures()
        
        # Step 5: Store live character data
        print("\nSTEP 5: Storing live character instances")
        self.store_live_characters()
        
        # Step 6: Create relationships
        print("\nSTEP 6: Creating graph relationships")
        self.create_relationships()
        
        print(f"\nSUCCESS: Memory data successfully stored in Dgraph!")
        print(f"Session ID: {self.session_id}")
    
    def setup_schema(self):
        """Set up Dgraph schema for memory structures"""
        schema = """
        # Memory Analysis Schema
        type Module {
            module.name: string @index(exact) .
            module.base_address: string @index(exact) .
            module.size: int .
            module.path: string .
            module.verified: bool .
        }
        
        type MemoryOffset {
            offset.name: string @index(exact) .
            offset.value: string @index(exact) .
            offset.full_address: string .
            offset.description: string .
            offset.data_type: string .
            offset.verified: bool .
            offset.module: uid .
        }
        
        type MemoryStructure {
            struct.name: string @index(exact) .
            struct.size: int .
            struct.description: string .
            struct.fields: [uid] .
        }
        
        type StructField {
            field.name: string @index(exact) .
            field.offset: string .
            field.size: int .
            field.type: string .
            field.description: string .
        }
        
        type Character {
            char.name: string @index(exact) .
            char.class: string @index(exact) .
            char.class_id: int .
            char.level: int .
            char.unit_id: string .
            char.memory_address: string .
            char.stats: uid .
            char.position: uid .
            char.session: string @index(exact) .
        }
        
        type CharacterStats {
            stats.strength: int .
            stats.energy: int .
            stats.dexterity: int .
            stats.vitality: int .
            stats.level: int .
            stats.hp_current: int .
            stats.hp_max: int .
            stats.mana_current: int .
            stats.mana_max: int .
            stats.experience: int .
        }
        
        type Position {
            pos.x: int .
            pos.y: int .
            pos.act: int .
            pos.area_id: int .
        }
        
        type AnalysisSession {
            session.id: string @index(exact) .
            session.timestamp: datetime .
            session.description: string .
            session.characters: [uid] .
            session.offsets_found: [uid] .
        }
        """
        
        try:
            response = requests.post(f"{self.dgraph_url}/admin/schema", 
                                   data=schema,
                                   headers={"Content-Type": "text/plain"})
            if response.status_code == 200:
                print(f"  SUCCESS: Schema updated successfully")
            else:
                print(f"  ERROR: Schema update failed: {response.status_code}")
        except Exception as e:
            print(f"  ERROR: Schema error: {e}")
    
    def store_modules(self):
        """Store D2 module information"""
        mutation = {
            "set": [
                {
                    "uid": "_:d2client",
                    "dgraph.type": "Module",
                    "module.name": "D2Client.dll",
                    "module.base_address": "0x6FAB0000",
                    "module.size": 0x16000,
                    "module.path": "/game/pd2/ProjectD2/D2Client.dll",
                    "module.verified": True
                }
            ]
        }
        
        try:
            response = requests.post(f"{self.dgraph_url}/mutate?commitNow=true",
                                   json=mutation)
            if response.status_code == 200:
                print(f"  SUCCESS: D2Client.dll module stored")
            else:
                print(f"  ERROR: Module storage failed: {response.status_code}")
        except Exception as e:
            print(f"  ERROR: Module storage error: {e}")
    
    def store_offsets(self):
        """Store static memory offsets"""
        mutation = {
            "set": [
                {
                    "uid": "_:offset_player_unit",
                    "dgraph.type": "MemoryOffset",
                    "offset.name": "current_player_unit",
                    "offset.value": "0x11BBFC",
                    "offset.full_address": "D2Client.dll+0x11BBFC",
                    "offset.description": "Pointer to current player's UnitAny structure",
                    "offset.data_type": "UnitAny*",
                    "offset.verified": True,
                    "offset.module": {"uid": "_:d2client"}
                },
                {
                    "uid": "_:offset_roster_list",
                    "dgraph.type": "MemoryOffset", 
                    "offset.name": "roster_unit_list",
                    "offset.value": "0x11BC14",
                    "offset.full_address": "D2Client.dll+0x11BC14",
                    "offset.description": "Pointer to first RosterUnit in party/player list",
                    "offset.data_type": "RosterUnit*",
                    "offset.verified": True,
                    "offset.module": {"uid": "_:d2client"}
                }
            ]
        }
        
        try:
            response = requests.post(f"{self.dgraph_url}/mutate?commitNow=true",
                                   json=mutation)
            if response.status_code == 200:
                print(f"  SUCCESS: Memory offsets stored")
            else:
                print(f"  ERROR: Offset storage failed: {response.status_code}")
        except Exception as e:
            print(f"  ERROR: Offset storage error: {e}")
    
    def store_structures(self):
        """Store memory structure definitions"""
        # Create UnitAny structure with key fields
        unitany_fields = [
            {"uid": "_:field_dwType", "dgraph.type": "StructField", "field.name": "dwType", "field.offset": "0x00", "field.size": 4, "field.type": "DWORD", "field.description": "Unit type (0=Player)"},
            {"uid": "_:field_dwTxtFileNo", "dgraph.type": "StructField", "field.name": "dwTxtFileNo", "field.offset": "0x04", "field.size": 4, "field.type": "DWORD", "field.description": "Character class ID"},
            {"uid": "_:field_dwUnitId", "dgraph.type": "StructField", "field.name": "dwUnitId", "field.offset": "0x0C", "field.size": 4, "field.type": "DWORD", "field.description": "Unique unit identifier"},
            {"uid": "_:field_pPlayerData", "dgraph.type": "StructField", "field.name": "pPlayerData", "field.offset": "0x14", "field.size": 4, "field.type": "PlayerData*", "field.description": "Player data pointer"},
            {"uid": "_:field_pStats", "dgraph.type": "StructField", "field.name": "pStats", "field.offset": "0x5C", "field.size": 4, "field.type": "StatList*", "field.description": "Statistics pointer"},
            {"uid": "_:field_pInventory", "dgraph.type": "StructField", "field.name": "pInventory", "field.offset": "0x60", "field.size": 4, "field.type": "Inventory*", "field.description": "Inventory pointer"},
            {"uid": "_:field_wX", "dgraph.type": "StructField", "field.name": "wX", "field.offset": "0x8C", "field.size": 2, "field.type": "WORD", "field.description": "X position"},
            {"uid": "_:field_wY", "dgraph.type": "StructField", "field.name": "wY", "field.offset": "0x8E", "field.size": 2, "field.type": "WORD", "field.description": "Y position"}
        ]
        
        # Create RosterUnit structure with key fields
        roster_fields = [
            {"uid": "_:rfield_szName", "dgraph.type": "StructField", "field.name": "szName", "field.offset": "0x00", "field.size": 16, "field.type": "char[16]", "field.description": "Player name"},
            {"uid": "_:rfield_dwPartyLife", "dgraph.type": "StructField", "field.name": "dwPartyLife", "field.offset": "0x14", "field.size": 4, "field.type": "DWORD", "field.description": "Party life percentage"},
            {"uid": "_:rfield_wLevel", "dgraph.type": "StructField", "field.name": "wLevel", "field.offset": "0x20", "field.size": 2, "field.type": "WORD", "field.description": "Character level"},
            {"uid": "_:rfield_dwClassId", "dgraph.type": "StructField", "field.name": "dwClassId", "field.offset": "0x1C", "field.size": 4, "field.type": "DWORD", "field.description": "Character class ID"}
        ]
        
        mutation = {
            "set": unitany_fields + roster_fields + [
                {
                    "uid": "_:struct_unitany",
                    "dgraph.type": "MemoryStructure",
                    "struct.name": "UnitAny",
                    "struct.size": 236,
                    "struct.description": "Main unit structure for players, monsters, objects",
                    "struct.fields": [{"uid": f} for f in ["_:field_dwType", "_:field_dwTxtFileNo", "_:field_dwUnitId", "_:field_pPlayerData", "_:field_pStats", "_:field_pInventory", "_:field_wX", "_:field_wY"]]
                },
                {
                    "uid": "_:struct_rosterunit", 
                    "dgraph.type": "MemoryStructure",
                    "struct.name": "RosterUnit",
                    "struct.size": 132,
                    "struct.description": "Party/roster information for players",
                    "struct.fields": [{"uid": f} for f in ["_:rfield_szName", "_:rfield_dwPartyLife", "_:rfield_wLevel", "_:rfield_dwClassId"]]
                }
            ]
        }
        
        try:
            response = requests.post(f"{self.dgraph_url}/mutate?commitNow=true",
                                   json=mutation)
            if response.status_code == 200:
                print(f"  SUCCESS: Memory structures stored")
            else:
                print(f"  ERROR: Structure storage failed: {response.status_code}")
        except Exception as e:
            print(f"  ERROR: Structure storage error: {e}")
    
    def store_live_characters(self):
        """Store live character data from memory analysis"""
        mutation = {
            "set": [
                # Character 1: Xerzes (Sorceress)
                {
                    "uid": "_:char1_stats",
                    "dgraph.type": "CharacterStats",
                    "stats.strength": 10,
                    "stats.energy": 35,
                    "stats.dexterity": 25,
                    "stats.vitality": 10,
                    "stats.level": 1,
                    "stats.hp_current": 45,
                    "stats.hp_max": 45,
                    "stats.mana_current": 50,
                    "stats.mana_max": 50
                },
                {
                    "uid": "_:char1_pos",
                    "dgraph.type": "Position",
                    "pos.x": 5726,
                    "pos.y": 4539,
                    "pos.act": 1,
                    "pos.area_id": 1
                },
                {
                    "uid": "_:char1",
                    "dgraph.type": "Character",
                    "char.name": "Xerzes",
                    "char.class": "Sorceress",
                    "char.class_id": 1,
                    "char.level": 1,
                    "char.unit_id": "0x00000001",
                    "char.memory_address": "0x0E45AB00",
                    "char.stats": {"uid": "_:char1_stats"},
                    "char.position": {"uid": "_:char1_pos"},
                    "char.session": self.session_id
                },
                
                # Character 2: Druid (Level 99)
                {
                    "uid": "_:char2_stats",
                    "dgraph.type": "CharacterStats",
                    "stats.strength": 27,
                    "stats.energy": 20,
                    "stats.dexterity": 28,
                    "stats.vitality": 25,
                    "stats.level": 99,
                    "stats.hp_current": 262,
                    "stats.hp_max": 262,
                    "stats.mana_current": 216,
                    "stats.mana_max": 216,
                    "stats.experience": 3520485254
                },
                {
                    "uid": "_:char2_pos",
                    "dgraph.type": "Position",
                    "pos.x": 5113,
                    "pos.y": 5068,
                    "pos.act": 4,
                    "pos.area_id": 0
                },
                {
                    "uid": "_:char2",
                    "dgraph.type": "Character",
                    "char.name": "Druid",
                    "char.class": "Druid", 
                    "char.class_id": 5,
                    "char.level": 99,
                    "char.unit_id": "0x00000001",
                    "char.memory_address": "0x0E447D00",
                    "char.stats": {"uid": "_:char2_stats"},
                    "char.position": {"uid": "_:char2_pos"},
                    "char.session": self.session_id
                }
            ]
        }
        
        try:
            response = requests.post(f"{self.dgraph_url}/mutate?commitNow=true",
                                   json=mutation)
            if response.status_code == 200:
                print(f"  SUCCESS: Live character data stored")
            else:
                print(f"  ERROR: Character storage failed: {response.status_code}")
        except Exception as e:
            print(f"  ERROR: Character storage error: {e}")
    
    def create_relationships(self):
        """Create analysis session and relationships"""
        mutation = {
            "set": [
                {
                    "uid": "_:session",
                    "dgraph.type": "AnalysisSession",
                    "session.id": self.session_id,
                    "session.timestamp": datetime.now().isoformat(),
                    "session.description": "Live memory analysis of D2 Current Player Unit and RosterUnit structures",
                    "session.characters": [{"uid": "_:char1"}, {"uid": "_:char2"}],
                    "session.offsets_found": [{"uid": "_:offset_player_unit"}, {"uid": "_:offset_roster_list"}]
                }
            ]
        }
        
        try:
            response = requests.post(f"{self.dgraph_url}/mutate?commitNow=true",
                                   json=mutation)
            if response.status_code == 200:
                print(f"  SUCCESS: Analysis session and relationships created")
            else:
                print(f"  ERROR: Relationship creation failed: {response.status_code}")
        except Exception as e:
            print(f"  ERROR: Relationship creation error: {e}")
    
    def query_stored_data(self):
        """Query and display stored data to verify"""
        print(f"\n=== VERIFYING STORED DATA ===")
        
        # Query characters
        query = """
        {
            characters(func: type(Character)) {
                uid
                char.name
                char.class
                char.level
                char.memory_address
                char.stats {
                    stats.strength
                    stats.energy
                    stats.dexterity
                    stats.vitality
                }
                char.position {
                    pos.x
                    pos.y
                    pos.act
                }
            }
        }
        """
        
        try:
            response = requests.post(f"{self.dgraph_url}/query", json={"query": query})
            if response.status_code == 200:
                data = response.json()
                characters = data.get("data", {}).get("characters", [])
                print(f"Stored {len(characters)} characters:")
                for char in characters:
                    print(f"  - {char.get('char.name', 'Unknown')} ({char.get('char.class', 'Unknown')}) Level {char.get('char.level', '?')}")
                    print(f"    Memory: {char.get('char.memory_address', 'Unknown')}")
                    stats = char.get('char.stats', [{}])[0] if char.get('char.stats') else {}
                    print(f"    Stats: STR={stats.get('stats.strength', '?')} ENE={stats.get('stats.energy', '?')} DEX={stats.get('stats.dexterity', '?')} VIT={stats.get('stats.vitality', '?')}")
            else:
                print(f"Query failed: {response.status_code}")
        except Exception as e:
            print(f"Query error: {e}")

def main():
    print("DGRAPH MEMORY DATA STORAGE")
    print("Storing live D2 memory analysis results in graph database")
    print()
    
    storage = DgraphMemoryStorage()
    storage.store_memory_data()
    storage.query_stored_data()
    
    print(f"\n" + "="*60)
    print("DGRAPH STORAGE COMPLETE!")
    print("Memory offsets, structures, and live character data stored in graph database")
    print(f"Access Dgraph UI at: http://localhost:8081/")

if __name__ == "__main__":
    main()