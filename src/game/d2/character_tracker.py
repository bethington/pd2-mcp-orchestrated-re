#!/usr/bin/env python3
"""
Diablo 2 Character Tracker

Monitors character statistics, experience, health/mana, and detects anomalies
that could indicate cheating, botting, or exploits.
"""

import time
import psutil
import pymem
import logging
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class CharacterStats:
    """Character statistics structure"""
    level: int = 1
    experience: int = 0
    health: int = 0
    max_health: int = 0
    mana: int = 0
    max_mana: int = 0
    strength: int = 0
    dexterity: int = 0
    vitality: int = 0
    energy: int = 0
    character_class: str = "Unknown"
    character_name: str = ""
    timestamp: float = 0.0

@dataclass
class CharacterAnomalies:
    """Detected character anomalies"""
    rapid_level_gain: bool = False
    impossible_stats: bool = False
    health_mana_anomaly: bool = False
    suspicious_experience_gain: bool = False
    timestamp: float = 0.0

class CharacterTracker:
    """
    Tracks Diablo 2 character state and detects anomalies
    """
    
    def __init__(self):
        self.process_name = "Game.exe"
        self.process = None
        self.pymem = None
        
        # Memory offsets for Project Diablo 2 (these need to be updated for specific version)
        self.memory_offsets = {
            'character_level': 0x00000000,  # Placeholder - needs actual offset
            'character_experience': 0x00000000,  # Placeholder
            'character_health': 0x00000000,  # Placeholder
            'character_max_health': 0x00000000,  # Placeholder
            'character_mana': 0x00000000,  # Placeholder
            'character_max_mana': 0x00000000,  # Placeholder
            'character_strength': 0x00000000,  # Placeholder
            'character_dexterity': 0x00000000,  # Placeholder
            'character_vitality': 0x00000000,  # Placeholder
            'character_energy': 0x00000000,  # Placeholder
            'character_class': 0x00000000,  # Placeholder
            'character_name': 0x00000000,  # Placeholder
        }
        
        self.previous_stats = CharacterStats()
        self.stats_history: List[CharacterStats] = []
        self.max_history = 1000  # Keep last 1000 readings
        
        # Anomaly detection thresholds
        self.level_gain_threshold = 5  # levels per minute
        self.experience_multiplier_threshold = 100  # suspicious if exp gain too high
        
        self.is_monitoring = False
        
    def connect_to_game(self) -> bool:
        """Connect to the Diablo 2 game process"""
        try:
            # Find the game process
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == self.process_name:
                    self.process = proc
                    logger.info(f"Found game process: PID {proc.info['pid']}")
                    
                    # Connect with pymem
                    try:
                        self.pymem = pymem.Pymem(self.process_name)
                        logger.info("Successfully connected to game process memory")
                        return True
                    except Exception as e:
                        logger.error(f"Failed to connect to process memory: {e}")
                        return False
                        
            logger.warning("Game process not found")
            return False
            
        except Exception as e:
            logger.error(f"Error connecting to game: {e}")
            return False
    
    def read_memory_value(self, offset: int, data_type: str = "int") -> Any:
        """Read a value from game memory"""
        if not self.pymem:
            return None
            
        try:
            if data_type == "int":
                return self.pymem.read_int(offset)
            elif data_type == "uint":
                return self.pymem.read_uint(offset)
            elif data_type == "float":
                return self.pymem.read_float(offset)
            elif data_type == "string":
                return self.pymem.read_string(offset, 32)  # Read up to 32 characters
            else:
                logger.warning(f"Unknown data type: {data_type}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to read memory at offset {hex(offset)}: {e}")
            return None
    
    def get_current_stats(self) -> Optional[CharacterStats]:
        """Get current character statistics"""
        if not self.pymem:
            if not self.connect_to_game():
                return None
        
        try:
            stats = CharacterStats()
            stats.timestamp = time.time()
            
            # Read memory values (these offsets need to be determined through reverse engineering)
            stats.level = self.read_memory_value(self.memory_offsets['character_level']) or 1
            stats.experience = self.read_memory_value(self.memory_offsets['character_experience']) or 0
            stats.health = self.read_memory_value(self.memory_offsets['character_health']) or 0
            stats.max_health = self.read_memory_value(self.memory_offsets['character_max_health']) or 0
            stats.mana = self.read_memory_value(self.memory_offsets['character_mana']) or 0
            stats.max_mana = self.read_memory_value(self.memory_offsets['character_max_mana']) or 0
            stats.strength = self.read_memory_value(self.memory_offsets['character_strength']) or 0
            stats.dexterity = self.read_memory_value(self.memory_offsets['character_dexterity']) or 0
            stats.vitality = self.read_memory_value(self.memory_offsets['character_vitality']) or 0
            stats.energy = self.read_memory_value(self.memory_offsets['character_energy']) or 0
            
            # Read character name and class (string values)
            stats.character_name = self.read_memory_value(self.memory_offsets['character_name'], "string") or ""
            
            # Character class determination (this might be an enum/index)
            class_id = self.read_memory_value(self.memory_offsets['character_class']) or 0
            stats.character_class = self._get_character_class_name(class_id)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting character stats: {e}")
            return None
    
    def _get_character_class_name(self, class_id: int) -> str:
        """Convert character class ID to name"""
        class_names = {
            0: "Amazon",
            1: "Sorceress", 
            2: "Necromancer",
            3: "Paladin",
            4: "Barbarian",
            5: "Druid",
            6: "Assassin"
        }
        return class_names.get(class_id, "Unknown")
    
    def detect_anomalies(self, current_stats: CharacterStats) -> CharacterAnomalies:
        """Detect potential cheating/botting anomalies"""
        anomalies = CharacterAnomalies()
        anomalies.timestamp = time.time()
        
        if not self.previous_stats or not current_stats:
            return anomalies
        
        time_delta = current_stats.timestamp - self.previous_stats.timestamp
        if time_delta <= 0:
            return anomalies
        
        # Check for rapid level gain
        level_delta = current_stats.level - self.previous_stats.level
        if level_delta > 0:
            levels_per_minute = level_delta / (time_delta / 60.0)
            if levels_per_minute > self.level_gain_threshold:
                anomalies.rapid_level_gain = True
                logger.warning(f"Rapid level gain detected: {levels_per_minute:.2f} levels/minute")
        
        # Check for impossible stats (basic validation)
        if (current_stats.health > current_stats.max_health * 1.1 or  # Allow 10% variance
            current_stats.mana > current_stats.max_mana * 1.1):
            anomalies.health_mana_anomaly = True
            logger.warning("Health/Mana anomaly detected")
        
        # Check for suspicious experience gain
        exp_delta = current_stats.experience - self.previous_stats.experience
        if exp_delta > 0 and time_delta > 0:
            exp_per_second = exp_delta / time_delta
            # This threshold would need to be calibrated based on legitimate gameplay
            if exp_per_second > 10000:  # Placeholder threshold
                anomalies.suspicious_experience_gain = True
                logger.warning(f"Suspicious experience gain: {exp_per_second:.0f} exp/second")
        
        # Check for impossible stat values (basic bounds checking)
        max_reasonable_stat = 500  # Adjust based on game knowledge
        if (current_stats.strength > max_reasonable_stat or
            current_stats.dexterity > max_reasonable_stat or
            current_stats.vitality > max_reasonable_stat or
            current_stats.energy > max_reasonable_stat):
            anomalies.impossible_stats = True
            logger.warning("Impossible character stats detected")
        
        return anomalies
    
    def start_monitoring(self, interval: float = 1.0):
        """Start continuous character monitoring"""
        if not self.connect_to_game():
            logger.error("Cannot start monitoring - failed to connect to game")
            return False
        
        self.is_monitoring = True
        logger.info("Started character monitoring")
        
        while self.is_monitoring:
            try:
                stats = self.get_current_stats()
                if stats:
                    # Detect anomalies
                    anomalies = self.detect_anomalies(stats)
                    
                    # Store in history
                    self.stats_history.append(stats)
                    if len(self.stats_history) > self.max_history:
                        self.stats_history.pop(0)
                    
                    # Update previous stats
                    self.previous_stats = stats
                    
                    # Log significant changes
                    if (len(self.stats_history) > 1 and 
                        stats.level != self.stats_history[-2].level):
                        logger.info(f"Level up: {stats.character_name} reached level {stats.level}")
                    
                    # Report anomalies
                    if any(asdict(anomalies).values()):
                        logger.warning(f"Anomalies detected: {asdict(anomalies)}")
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error during monitoring: {e}")
                time.sleep(interval)
        
        return True
    
    def stop_monitoring(self):
        """Stop character monitoring"""
        self.is_monitoring = False
        logger.info("Stopped character monitoring")
    
    def get_stats_history(self) -> List[Dict]:
        """Get character statistics history"""
        return [asdict(stats) for stats in self.stats_history]
    
    def get_current_character_info(self) -> Optional[Dict]:
        """Get current character information"""
        stats = self.get_current_stats()
        return asdict(stats) if stats else None
    
    def calibrate_memory_offsets(self) -> Dict[str, int]:
        """
        Calibrate memory offsets for the current game version.
        This would need to be implemented with actual reverse engineering techniques.
        """
        # This is a placeholder - actual implementation would involve:
        # 1. Pattern scanning for known byte sequences
        # 2. Dynamic analysis of memory changes
        # 3. Signature matching against known game structures
        
        logger.info("Memory offset calibration not yet implemented")
        return self.memory_offsets
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if self.is_monitoring:
            self.stop_monitoring()
        
        if self.pymem:
            try:
                self.pymem.close_process()
            except:
                pass
