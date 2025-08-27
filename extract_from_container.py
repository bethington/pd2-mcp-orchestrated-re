#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extract Current Player Unit directly from container
Run memory analyzer inside the D2 analysis container
"""

import subprocess
import json
import time

class ContainerMemoryExtractor:
    def __init__(self):
        self.container_name = "d2-analysis"
        
    def extract_live_player_unit(self):
        """Extract Current Player Unit by executing memory analyzer inside container"""
        print("CONTAINER MEMORY EXTRACTION - CURRENT PLAYER UNIT")
        print("=" * 70)
        
        print(f"\nExecuting memory analyzer inside {self.container_name} container...")
        
        # Create Python script to run inside container
        extraction_script = '''
import sys
sys.path.append("/app")
sys.path.append("/app/src")

try:
    from src.analysis.memory.analyzer import MemoryAnalyzer, PlayerStats, PlayerPosition, GameMemoryState
    import json
    
    print("Memory analyzer imported successfully")
    
    # Initialize and connect to Game.exe
    analyzer = MemoryAnalyzer()
    print("Connecting to Game.exe process...")
    
    connected = analyzer.connect_to_game("Game.exe")
    if connected:
        print("Successfully connected to Game.exe!")
        
        # Get complete game state
        game_state = analyzer.get_game_state()
        
        if game_state.is_valid:
            print("\\n=== LIVE CURRENT PLAYER UNIT DATA ===")
            print(f"Player Name: {game_state.player_name}")
            print(f"Is Valid: {game_state.is_valid}")
            
            # Character stats
            stats = game_state.stats
            print("\\n=== CHARACTER STATISTICS ===")
            print(f"Strength: {stats.strength}")
            print(f"Energy: {stats.energy}")
            print(f"Dexterity: {stats.dexterity}")
            print(f"Vitality: {stats.vitality}")
            print(f"Level: {stats.level}")
            print(f"Hit Points: {stats.hitpoints}/{stats.max_hp}")
            print(f"Mana: {stats.mana_points}/{stats.max_mana}")
            print(f"Gold: {stats.gold}")
            
            # Position data
            pos = game_state.position
            print("\\n=== POSITION DATA ===")
            print(f"X: {pos.x}")
            print(f"Y: {pos.y}")
            print(f"Area ID: {pos.area_id}")
            
            # Debug info
            debug = analyzer.get_debug_info()
            print("\\n=== MEMORY DEBUG INFO ===")
            for key, value in debug.items():
                print(f"{key}: {value}")
            
            # Get raw player unit address for structure analysis
            if analyzer.connected:
                player_unit_addr = analyzer._get_player_unit_address()
                if player_unit_addr:
                    print(f"\\n=== UNITANY STRUCTURE INFO ===")
                    print(f"Player Unit Address: 0x{player_unit_addr:08X}")
                    print(f"D2Client Base: {debug.get('d2client_base')}")
                    print(f"Static Offset: D2Client.dll+0x11BBFC")
                    
                    # Try to read some key UnitAny fields directly
                    try:
                        # Read dwType (should be 0 for player)
                        dwType = analyzer._read_safe(player_unit_addr + 0x00, 4, 'uint')
                        print(f"dwType (0x00): {dwType} (should be 0 for player)")
                        
                        # Read dwTxtFileNo (character class)
                        dwTxtFileNo = analyzer._read_safe(player_unit_addr + 0x04, 4, 'uint')
                        class_names = {0: "Amazon", 1: "Sorceress", 2: "Necromancer", 3: "Paladin", 4: "Barbarian", 5: "Druid", 6: "Assassin"}
                        class_name = class_names.get(dwTxtFileNo, f"Unknown ({dwTxtFileNo})")
                        print(f"dwTxtFileNo (0x04): {dwTxtFileNo} ({class_name})")
                        
                        # Read dwUnitId
                        dwUnitId = analyzer._read_safe(player_unit_addr + 0x0C, 4, 'uint')
                        print(f"dwUnitId (0x0C): 0x{dwUnitId:08X}")
                        
                        # Read pPlayerData pointer
                        pPlayerData = analyzer._read_safe(player_unit_addr + 0x14, 4, 'uint')
                        print(f"pPlayerData (0x14): 0x{pPlayerData:08X}")
                        
                        # Read pStats pointer
                        pStats = analyzer._read_safe(player_unit_addr + 0x5C, 4, 'uint')
                        print(f"pStats (0x5C): 0x{pStats:08X}")
                        
                        # Read position
                        wX = analyzer._read_safe(player_unit_addr + 0x8C, 2, 'ushort')
                        wY = analyzer._read_safe(player_unit_addr + 0x8E, 2, 'ushort')
                        print(f"Position (0x8C,0x8E): ({wX}, {wY})")
                        
                        print("\\n*** REAL LIVE MEMORY DATA EXTRACTED ***")
                        print("This is actual data from the running Game.exe process!")
                        
                    except Exception as e:
                        print(f"Error reading UnitAny structure: {e}")
            
        else:
            print(f"Game state invalid: {game_state.error_message}")
            
        analyzer.disconnect()
    else:
        print("Failed to connect to Game.exe process")
        print("Checking if process exists...")
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            if 'game' in proc.info['name'].lower():
                print(f"Found process: {proc.info}")
        
except ImportError as e:
    print(f"Import error: {e}")
    print("Memory analyzer modules not available")
    
except Exception as e:
    print(f"Execution error: {e}")
    import traceback
    traceback.print_exc()
'''
        
        # Write the script to a temporary file in container
        script_path = "/tmp/extract_memory.py"
        
        try:
            # Copy script into container
            cmd_write = f'docker exec {self.container_name} sh -c "cat > {script_path}" <<\'EOF\'\n{extraction_script}\nEOF'
            
            result_write = subprocess.run(cmd_write, shell=True, capture_output=True, text=True)
            if result_write.returncode != 0:
                print(f"Error writing script: {result_write.stderr}")
                return False
            
            print(f"Script written to {script_path}")
            
            # Execute the script inside container
            cmd_exec = f'docker exec {self.container_name} python3 {script_path}'
            
            print(f"Executing: {cmd_exec}")
            result_exec = subprocess.run(cmd_exec, shell=True, capture_output=True, text=True, timeout=30)
            
            print(f"\n" + "="*70)
            print("CONTAINER EXECUTION OUTPUT:")
            print("="*70)
            
            if result_exec.stdout:
                print(result_exec.stdout)
            
            if result_exec.stderr:
                print("STDERR:")
                print(result_exec.stderr)
            
            if result_exec.returncode == 0:
                print(f"\n{'='*70}")
                print("CONTAINER MEMORY EXTRACTION SUCCESSFUL!")
                return True
            else:
                print(f"\nExecution failed with return code: {result_exec.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            print("Script execution timed out (30 seconds)")
            return False
        except Exception as e:
            print(f"Error executing script in container: {e}")
            return False

def main():
    print("STARTING CONTAINER-BASED MEMORY EXTRACTION")
    print("Executing memory analyzer directly inside D2 analysis container")
    print()
    
    extractor = ContainerMemoryExtractor()
    success = extractor.extract_live_player_unit()
    
    print(f"\n" + "="*70)
    if success:
        print("MEMORY EXTRACTION COMPLETE!")
        print("Successfully extracted live Current Player Unit data!")
    else:
        print("MEMORY EXTRACTION FAILED!")
        print("Check container status and memory analyzer setup")

if __name__ == "__main__":
    main()