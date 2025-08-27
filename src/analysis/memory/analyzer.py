"""
Diablo 2 Memory Analyzer

This module provides memory reading capabilities for extracting game state information
from a running Diablo 2 process using memory offsets defined in d2-memory-offsets.xml.

Memory Structure Overview:
- Player Unit Reference: D2Client.dll+0x11BBFC
- UnitPlayer structure with pPlayerData (offset 20) and pStats (offset 92)
- StatList structure with stat arrays for character attributes
- Individual Stat structures with index/value pairs

Based on Cheat Engine XML memory offset definitions for Project Diablo 2.
"""

import struct
import logging
from typing import Dict, Optional, List, Any
from dataclasses import dataclass
import pymem
import pymem.process

logger = logging.getLogger(__name__)

# Diablo 2 Stat Indices (common values from game analysis)
STAT_INDICES = {
    'STRENGTH': 0,
    'ENERGY': 1,
    'DEXTERITY': 2,
    'VITALITY': 3,
    'STATPOINTS': 4,
    'SKILLPOINTS': 5,
    'HITPOINTS': 6,
    'MAXHP': 7,
    'MANAPOINTS': 8,
    'MAXMANA': 9,
    'STAMINA': 10,
    'MAXSTAMINA': 11,
    'LEVEL': 12,
    'EXPERIENCE': 13,
    'GOLD': 14,
    'GOLDBANK': 15,
}

@dataclass
class PlayerStats:
    """Container for player character statistics"""
    strength: int = 0
    energy: int = 0
    dexterity: int = 0
    vitality: int = 0
    stat_points: int = 0
    skill_points: int = 0
    hitpoints: int = 0
    max_hp: int = 0
    mana_points: int = 0
    max_mana: int = 0
    stamina: int = 0
    max_stamina: int = 0
    level: int = 0
    experience: int = 0
    gold: int = 0
    gold_bank: int = 0

@dataclass
class PlayerPosition:
    """Container for player position and world data"""
    x: int = 0
    y: int = 0
    area_id: int = 0
    level_no: int = 0

@dataclass
class GameMemoryState:
    """Complete game memory state snapshot"""
    stats: PlayerStats
    position: PlayerPosition
    player_name: Optional[str] = None
    is_valid: bool = False
    error_message: Optional[str] = None

class MemoryAnalyzer:
    """
    Diablo 2 memory analyzer for extracting game state information.
    
    Uses memory offsets from d2-memory-offsets.xml to read character data,
    position information, and game state from a running D2 process.
    """
    
    def __init__(self):
        self.pm: Optional[pymem.Pymem] = None
        self.d2client_base: Optional[int] = None
        self.player_unit_ptr: Optional[int] = None
        self.connected = False
        
        # Memory offsets from D2Structs.h analysis
        self.PLAYER_UNIT_OFFSET = 0x11BBFC  # D2Client.dll+0x11BBFC
        
        # UnitAny structure offsets (from D2Structs.h)
        self.UNITANY_OFFSETS = {
            'dwType': 0x00,
            'dwTxtFileNo': 0x04,
            'dwUnitId': 0x0C,
            'dwMode': 0x10,
            'pPlayerData': 0x14,    # union with pItemData, pMonsterData, etc.
            'dwAct': 0x18,
            'pAct': 0x1C,
            'pStats': 0x5C,         # StatList *pStats
            'pInventory': 0x60,     # Inventory *pInventory
            'wX': 0x8C,             # WORD wX
            'wY': 0x8E,             # WORD wY
            'dwOwnerType': 0x94,
            'dwOwnerId': 0x98,
            'dwFlags': 0xC4,
            'dwFlags2': 0xC8,
        }
        
        # StatList structure offsets (from D2Structs.h)
        self.STATLIST_OFFSETS = {
            'pStat': 0x24,          # Stat *pStat
            'wStatCount1': 0x28,    # WORD wStatCount1
            'wStatCount2': 0x2A,    # WORD wStatCount2
            'pNext': 0x3C,          # StatList *pNext
        }
        
        # Stat structure offsets (from D2Structs.h)
        self.STAT_OFFSETS = {
            'wSubIndex': 0x00,      # WORD wSubIndex
            'wStatIndex': 0x02,     # WORD wStatIndex
            'dwStatValue': 0x04,    # DWORD dwStatValue
        }
        
        # PlayerData structure offsets (from D2Structs.h)
        self.PLAYERDATA_OFFSETS = {
            'szName': 0x00,         # char szName[0x10]
            'pNormalQuest': 0x10,   # QuestInfo *pNormalQuest
            'pNightmareQuest': 0x14,
            'pHellQuest': 0x18,
            'pNormalWaypoint': 0x1C,
            'pNightmareWaypoint': 0x20,
            'pHellWaypoint': 0x24,
        }
    
    def connect_to_game(self, process_name: str = "Game.exe") -> bool:
        """
        Connect to the Diablo 2 game process.
        
        Args:
            process_name: Name of the D2 process executable
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Find and attach to the Diablo 2 process
            self.pm = pymem.Pymem(process_name)
            
            # Get D2Client.dll base address
            d2client_module = None
            for module in self.pm.list_modules():
                if "d2client.dll" in module.name.lower():
                    d2client_module = module
                    break
            
            if not d2client_module:
                logger.error("D2Client.dll not found in process modules")
                return False
            
            self.d2client_base = d2client_module.lpBaseOfDll
            logger.info(f"D2Client.dll base address: 0x{self.d2client_base:X}")
            
            # Calculate player unit pointer address
            player_unit_addr = self.d2client_base + self.PLAYER_UNIT_OFFSET
            self.player_unit_ptr = self.pm.read_uint(player_unit_addr)
            
            if not self.player_unit_ptr:
                logger.warning("Player unit pointer is null - player may not be in game")
                return False
            
            self.connected = True
            logger.info(f"Successfully connected to {process_name}")
            return True
            
        except pymem.exception.ProcessNotFound:
            logger.error(f"Process {process_name} not found")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to game process: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the game process"""
        if self.pm:
            try:
                self.pm.close_process()
            except:
                pass
            self.pm = None
        
        self.d2client_base = None
        self.player_unit_ptr = None
        self.connected = False
        logger.info("Disconnected from game process")
    
    def _read_safe(self, address: int, size: int, data_type: str = 'uint') -> Optional[Any]:
        """
        Safely read memory with error handling.
        
        Args:
            address: Memory address to read
            size: Number of bytes to read
            data_type: Type of data ('uint', 'ushort', 'bytes')
            
        Returns:
            Read value or None if failed
        """
        try:
            if not self.pm or not address:
                return None
            
            if data_type == 'uint':
                return self.pm.read_uint(address)
            elif data_type == 'ushort':
                return self.pm.read_ushort(address)
            elif data_type == 'bytes':
                return self.pm.read_bytes(address, size)
            else:
                return None
                
        except Exception as e:
            logger.debug(f"Failed to read memory at 0x{address:X}: {e}")
            return None
    
    def _get_player_unit_address(self) -> Optional[int]:
        """Get the current player unit address"""
        if not self.connected or not self.d2client_base:
            return None
        
        try:
            # Read player unit pointer from D2Client.dll+0x11BBFC
            player_unit_addr = self.d2client_base + self.PLAYER_UNIT_OFFSET
            player_unit_ptr = self._read_safe(player_unit_addr, 4, 'uint')
            
            if not player_unit_ptr:
                logger.debug("Player unit pointer is null")
                return None
            
            return player_unit_ptr
            
        except Exception as e:
            logger.error(f"Failed to get player unit address: {e}")
            return None
    
    def _read_stat_list(self, stat_list_ptr: int) -> Dict[int, int]:
        """
        Read statistics from a StatList structure.
        
        Args:
            stat_list_ptr: Pointer to StatList structure
            
        Returns:
            Dictionary mapping stat indices to values
        """
        stats = {}
        
        if not stat_list_ptr:
            return stats
        
        try:
            # Read pStat pointer and stat count from StatList
            pStat = self._read_safe(stat_list_ptr + self.STATLIST_OFFSETS['pStat'], 4, 'uint')
            stat_count = self._read_safe(stat_list_ptr + self.STATLIST_OFFSETS['wStatCount1'], 2, 'ushort')
            
            if not pStat or not stat_count:
                return stats
            
            # Read individual stat entries
            for i in range(min(stat_count, 64)):  # Limit to prevent excessive reads
                stat_addr = pStat + (i * 8)  # Each Stat structure is 8 bytes
                
                stat_index = self._read_safe(stat_addr + self.STAT_OFFSETS['wStatIndex'], 2, 'ushort')
                stat_value = self._read_safe(stat_addr + self.STAT_OFFSETS['dwStatValue'], 4, 'uint')
                
                if stat_index is not None and stat_value is not None:
                    stats[stat_index] = stat_value
            
        except Exception as e:
            logger.error(f"Failed to read stat list: {e}")
        
        return stats
    
    def read_player_stats(self) -> Optional[PlayerStats]:
        """
        Read player character statistics from memory.
        
        Returns:
            PlayerStats object with current character stats or None if failed
        """
        player_unit = self._get_player_unit_address()
        if not player_unit:
            return None

        try:
            # Get pStats pointer from UnitAny structure
            pStats = self._read_safe(player_unit + self.UNITANY_OFFSETS['pStats'], 4, 'uint')
            
            if not pStats:
                logger.debug("pStats pointer is null")
                return None
            
            # Read stat list
            raw_stats = self._read_stat_list(pStats)
            
            if not raw_stats:
                logger.debug("No stats found in stat list")
                return None
            
            # Map raw stat indices to PlayerStats fields
            stats = PlayerStats()
            for stat_name, stat_index in STAT_INDICES.items():
                if stat_index in raw_stats:
                    value = raw_stats[stat_index]
                    
                    # Map to PlayerStats attributes
                    if stat_name == 'STRENGTH':
                        stats.strength = value
                    elif stat_name == 'ENERGY':
                        stats.energy = value
                    elif stat_name == 'DEXTERITY':
                        stats.dexterity = value
                    elif stat_name == 'VITALITY':
                        stats.vitality = value
                    elif stat_name == 'STATPOINTS':
                        stats.stat_points = value
                    elif stat_name == 'SKILLPOINTS':
                        stats.skill_points = value
                    elif stat_name == 'HITPOINTS':
                        stats.hitpoints = value
                    elif stat_name == 'MAXHP':
                        stats.max_hp = value
                    elif stat_name == 'MANAPOINTS':
                        stats.mana_points = value
                    elif stat_name == 'MAXMANA':
                        stats.max_mana = value
                    elif stat_name == 'STAMINA':
                        stats.stamina = value
                    elif stat_name == 'MAXSTAMINA':
                        stats.max_stamina = value
                    elif stat_name == 'LEVEL':
                        stats.level = value
                    elif stat_name == 'EXPERIENCE':
                        stats.experience = value
                    elif stat_name == 'GOLD':
                        stats.gold = value
                    elif stat_name == 'GOLDBANK':
                        stats.gold_bank = value
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to read player stats: {e}")
            return None
    
    def read_player_position(self) -> Optional[PlayerPosition]:
        """
        Read player position and world information from memory.
        
        Returns:
            PlayerPosition object with current position data or None if failed
        """
        player_unit = self._get_player_unit_address()
        if not player_unit:
            return None

        try:
            # Read position from UnitAny structure
            x = self._read_safe(player_unit + self.UNITANY_OFFSETS['wX'], 2, 'ushort')
            y = self._read_safe(player_unit + self.UNITANY_OFFSETS['wY'], 2, 'ushort')
            
            # Read area ID from D2Client.dll (if available)
            area_id = 0
            if self.d2client_base:
                # This would need the specific offset for current area ID
                # For now, we'll set it to 0
                pass
            
            if x is not None and y is not None:
                return PlayerPosition(
                    x=x,
                    y=y,
                    area_id=area_id,
                    level_no=0  # Would need specific offset for level number
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to read player position: {e}")
            return None
    
    def read_player_name(self) -> Optional[str]:
        """
        Read player character name from memory.
        
        Returns:
            Player name string or None if failed
        """
        player_unit = self._get_player_unit_address()
        if not player_unit:
            return None

        try:
            # Get pPlayerData pointer from UnitAny structure
            pPlayerData = self._read_safe(player_unit + self.UNITANY_OFFSETS['pPlayerData'], 4, 'uint')
            
            if not pPlayerData:
                logger.debug("pPlayerData pointer is null")
                return None
            
            # Read character name from PlayerData structure (16 bytes)
            name_bytes = self._read_safe(pPlayerData + self.PLAYERDATA_OFFSETS['szName'], 16, 'bytes')
            
            if name_bytes:
                # Convert bytes to string, stopping at null terminator
                name = name_bytes.decode('ascii', errors='ignore').split('\x00')[0]
                return name if name else None
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to read player name: {e}")
            return None
    
    def get_game_state(self) -> GameMemoryState:
        """
        Get complete game memory state snapshot.
        
        Returns:
            GameMemoryState with all available game information
        """
        if not self.connected:
            return GameMemoryState(
                stats=PlayerStats(),
                position=PlayerPosition(),
                player_name=None,
                is_valid=False,
                error_message="Not connected to game process"
            )
        
        try:
            stats = self.read_player_stats()
            position = self.read_player_position()
            player_name = self.read_player_name()
            
            if stats is None and position is None and player_name is None:
                return GameMemoryState(
                    stats=PlayerStats(),
                    position=PlayerPosition(),
                    player_name=None,
                    is_valid=False,
                    error_message="Unable to read any game data"
                )
            
            return GameMemoryState(
                stats=stats or PlayerStats(),
                position=position or PlayerPosition(),
                player_name=player_name,
                is_valid=True
            )
            
        except Exception as e:
            logger.error(f"Failed to get game state: {e}")
            return GameMemoryState(
                stats=PlayerStats(),
                position=PlayerPosition(),
                player_name=None,
                is_valid=False,
                error_message=str(e)
            )
    
    def is_in_game(self) -> bool:
        """
        Check if player is currently in game.
        
        Returns:
            True if player unit is available and valid
        """
        if not self.connected:
            return False
        
        player_unit = self._get_player_unit_address()
        return player_unit is not None
    
    def get_debug_info(self) -> Dict[str, Any]:
        """
        Get debugging information about memory state.
        
        Returns:
            Dictionary with debug information
        """
        info = {
            'connected': self.connected,
            'd2client_base': f"0x{self.d2client_base:X}" if self.d2client_base else None,
            'player_unit_ptr': f"0x{self.player_unit_ptr:X}" if self.player_unit_ptr else None,
            'process_attached': self.pm is not None,
        }
        
        if self.connected:
            player_unit = self._get_player_unit_address()
            info['current_player_unit'] = f"0x{player_unit:X}" if player_unit else None
            info['in_game'] = self.is_in_game()
        
        return info


# Export main classes
__all__ = ['MemoryAnalyzer', 'PlayerStats', 'PlayerPosition', 'GameMemoryState']
