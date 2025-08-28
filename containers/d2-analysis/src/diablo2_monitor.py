#!/usr/bin/env python3
"""
Diablo 2 Memory and Game State Monitor
"""

import time
import json
import psutil
import logging
import os
from typing import Dict, List, Optional, Any
import struct
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class D2ProcessMonitor:
    def __init__(self):
        self.process_name = "Game.exe"
        self.process = None
        self.memory_snapshots = []
        self.game_state = {}
        # Check environment variable, default to False (disabled)
        self.enable_memory_dumps = os.getenv('ENABLE_MEMORY_DUMPS', 'false').lower() == 'true'
        if self.enable_memory_dumps:
            logger.info("Memory dumps ENABLED via environment variable")
        else:
            logger.info("Memory dumps DISABLED (default or via environment variable)")
        
    def find_d2_process(self) -> Optional[psutil.Process]:
        """Find the running Diablo 2 process"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and self.process_name.lower() in proc.info['name'].lower():
                    return psutil.Process(proc.info['pid'])
        except Exception as e:
            logger.error(f"Error finding process: {e}")
        return None
    
    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory information from D2 process"""
        if not self.process:
            return {}
            
        try:
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            return {
                "rss": memory_info.rss,  # Resident Set Size
                "vms": memory_info.vms,  # Virtual Memory Size
                "percent": memory_percent,
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"Error getting memory info: {e}")
            return {}
    
    def read_character_stats(self) -> Dict[str, Any]:
        """Attempt to read character stats from memory"""
        # Mock character stats - in production would use actual memory reading
        return {
            "name": "TestCharacter",
            "level": 85,
            "experience": 1234567890,
            "class": "Sorceress",
            "life": {"current": 1250, "max": 1250},
            "mana": {"current": 890, "max": 890},
            "stats": {
                "strength": 156,
                "dexterity": 187,
                "vitality": 245,
                "energy": 298
            },
            "skills": [
                {"name": "Fireball", "level": 20},
                {"name": "Meteor", "level": 20},
                {"name": "Fire Mastery", "level": 20}
            ],
            "position": {"x": 1234, "y": 5678, "area": "Act 1 - Rogue Encampment"}
        }
    
    def read_inventory_data(self) -> List[Dict[str, Any]]:
        """Attempt to read inventory from memory"""
        # Mock inventory data
        return [
            {
                "slot": 0,
                "item_name": "Shako",
                "item_type": "helm",
                "quality": "unique",
                "stats": ["+2 to All Skills", "+1-99 Life", "+1-99 Mana"]
            },
            {
                "slot": 1,
                "item_name": "Enigma Mage Plate",
                "item_type": "armor",
                "quality": "runeword",
                "stats": ["+2 to All Skills", "Teleport", "+750-775 Defense"]
            },
            {
                "slot": 2,
                "item_name": "Heart of the Oak Flail",
                "item_type": "weapon",
                "quality": "runeword",
                "stats": ["+3 to All Skills", "+40% FCR", "+75% Damage to Demons"]
            }
        ]
    
    def detect_behavioral_patterns(self) -> Dict[str, Any]:
        """Detect behavioral patterns that might indicate automation"""
        # Mock behavioral analysis
        return {
            "movement_pattern": "human-like",
            "click_timing": "variable",
            "reaction_time": "normal",
            "repetitive_actions": False,
            "suspicious_activity": False,
            "confidence": 0.95
        }
    
    def take_memory_snapshot(self) -> Dict[str, Any]:
        """Take a snapshot of current game state"""
        if not self.process:
            return {}
            
        snapshot = {
            "timestamp": time.time(),
            "memory_info": self.get_memory_info(),
            "character": self.read_character_stats(),
            "inventory": self.read_inventory_data(),
            "behavior": self.detect_behavioral_patterns()
        }
        
        self.memory_snapshots.append(snapshot)
        
        # Keep only last 100 snapshots
        if len(self.memory_snapshots) > 100:
            self.memory_snapshots = self.memory_snapshots[-100:]
            
        return snapshot
    
    def save_snapshot_to_file(self, snapshot: Dict[str, Any], filepath: str):
        """Save snapshot to file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(snapshot, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving snapshot: {e}")
    
    def monitor_loop(self):
        """Main monitoring loop"""
        logger.info("Starting D2 monitoring loop...")
        
        while True:
            try:
                # Find D2 process if not found
                if not self.process:
                    self.process = self.find_d2_process()
                    if not self.process:
                        logger.info("Waiting for Diablo 2 process...")
                        time.sleep(5)
                        continue
                    else:
                        logger.info(f"Found D2 process: PID {self.process.pid}")
                
                # Check if process is still running
                if not self.process.is_running():
                    logger.info("D2 process is no longer running")
                    self.process = None
                    continue
                
                # Take snapshot
                snapshot = self.take_memory_snapshot()
                
                # Log interesting findings
                if snapshot.get("behavior", {}).get("suspicious_activity"):
                    logger.warning("Suspicious behavior detected!")
                
                # Save periodic snapshots (only if enabled)
                if self.enable_memory_dumps and len(self.memory_snapshots) % 10 == 0:
                    timestamp = int(time.time())
                    filepath = f"/memory_dumps/snapshot_{timestamp}.json"
                    self.save_snapshot_to_file(snapshot, filepath)
                    logger.info(f"Saved snapshot to {filepath}")
                elif not self.enable_memory_dumps and len(self.memory_snapshots) % 10 == 0:
                    logger.debug("Memory dumps disabled - skipping snapshot save")
                
                time.sleep(1)  # Monitor every second
                
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Wait before retrying

def main():
    """Main entry point"""
    monitor = D2ProcessMonitor()
    
    # Start monitoring
    try:
        monitor.monitor_loop()
    except KeyboardInterrupt:
        logger.info("Monitoring stopped")
    except Exception as e:
        logger.error(f"Monitor error: {e}")

if __name__ == "__main__":
    main()
