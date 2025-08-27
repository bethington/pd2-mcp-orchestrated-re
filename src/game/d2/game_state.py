#!/usr/bin/env python3
"""
Diablo 2 Game State Manager

Provides a unified interface to monitor overall game state including
character, inventory, world state, and game session information.
"""

import time
import logging
import threading
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, asdict
from datetime import datetime

from .character_tracker import CharacterTracker, CharacterStats
from .inventory_manager import InventoryManager, InventorySnapshot

logger = logging.getLogger(__name__)

@dataclass
class GameSession:
    """Overall game session information"""
    session_id: str = ""
    character_name: str = ""
    character_class: str = ""
    game_mode: str = "unknown"  # single_player, battle_net, open_battle_net
    difficulty: str = "normal"  # normal, nightmare, hell
    current_act: int = 1
    current_area: str = ""
    session_start: float = 0.0
    total_playtime: float = 0.0
    deaths: int = 0
    last_update: float = 0.0

@dataclass
class WorldState:
    """Current world/area state information"""
    area_id: int = 0
    area_name: str = ""
    area_level: int = 1
    players_in_game: int = 1
    monsters_nearby: int = 0
    npcs_nearby: int = 0
    last_update: float = 0.0

@dataclass
class GameStateSnapshot:
    """Complete game state at a point in time"""
    session: GameSession = None
    character: CharacterStats = None
    inventory: InventorySnapshot = None
    world: WorldState = None
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if self.session is None:
            self.session = GameSession()
        if self.character is None:
            self.character = CharacterStats()
        if self.inventory is None:
            self.inventory = InventorySnapshot()
        if self.world is None:
            self.world = WorldState()

class GameState:
    """
    Unified game state manager that coordinates character tracking,
    inventory monitoring, and world state detection.
    """
    
    def __init__(self):
        self.character_tracker = CharacterTracker()
        self.inventory_manager = InventoryManager()
        
        self.current_session = GameSession()
        self.current_world = WorldState()
        
        self.state_history: List[GameStateSnapshot] = []
        self.max_history = 1000
        
        self.is_monitoring = False
        self.monitor_thread = None
        self.monitor_interval = 1.0
        
        # Game-specific memory offsets (placeholders)
        self.memory_offsets = {
            'current_area_id': 0x00000000,
            'difficulty_level': 0x00000000,
            'players_in_game': 0x00000000,
            'game_mode': 0x00000000,
            'character_deaths': 0x00000000,
            'session_time': 0x00000000,
        }
        
        # Area ID to name mapping (partial)
        self.area_names = {
            1: "Rogue Encampment",
            2: "Blood Moor",
            3: "Cold Plains",
            4: "Stony Field",
            5: "Dark Wood",
            6: "Black Marsh",
            7: "Tamoe Highland",
            8: "Den of Evil",
            9: "Cave Level 1",
            10: "Underground Passage Level 1",
            # ... many more areas would be added
            40: "Lut Gholein",
            74: "Kurast Docks",
            103: "The Pandemonium Fortress",
            109: "Harrogath",
        }
        
        logger.info("GameState manager initialized")
    
    def connect_to_game(self) -> bool:
        """Connect to game process"""
        char_connected = self.character_tracker.connect_to_game()
        inv_connected = self.inventory_manager.connect_to_game()
        
        if char_connected and inv_connected:
            logger.info("Successfully connected to game process")
            return True
        else:
            logger.error("Failed to connect to game process")
            return False
    
    def read_world_state(self) -> WorldState:
        """Read current world state from memory"""
        world = WorldState()
        world.last_update = time.time()
        
        # This would require actual memory reading implementation
        try:
            if self.character_tracker.pymem:
                pymem = self.character_tracker.pymem
                
                # Read area information
                world.area_id = pymem.read_int(self.memory_offsets['current_area_id']) or 0
                world.area_name = self.area_names.get(world.area_id, f"Unknown Area {world.area_id}")
                
                # Read difficulty
                difficulty_id = pymem.read_int(self.memory_offsets['difficulty_level']) or 0
                difficulty_names = {0: "normal", 1: "nightmare", 2: "hell"}
                world.area_level = difficulty_id + 1  # Simplified level calculation
                
                # Read player count
                world.players_in_game = pymem.read_int(self.memory_offsets['players_in_game']) or 1
                
                logger.debug(f"World state updated: {world.area_name}")
                
        except Exception as e:
            logger.error(f"Error reading world state: {e}")
        
        return world
    
    def update_session_info(self):
        """Update game session information"""
        try:
            if self.character_tracker.pymem:
                pymem = self.character_tracker.pymem
                
                # Read session data
                self.current_session.deaths = pymem.read_int(self.memory_offsets['character_deaths']) or 0
                session_time = pymem.read_float(self.memory_offsets['session_time']) or 0.0
                self.current_session.total_playtime = session_time
                
                # Get character info
                char_stats = self.character_tracker.get_current_stats()
                if char_stats:
                    self.current_session.character_name = char_stats.character_name
                    self.current_session.character_class = char_stats.character_class
                
                self.current_session.last_update = time.time()
                
        except Exception as e:
            logger.error(f"Error updating session info: {e}")
    
    def take_state_snapshot(self) -> GameStateSnapshot:
        """Take a complete game state snapshot"""
        snapshot = GameStateSnapshot()
        snapshot.timestamp = time.time()
        
        try:
            # Get character state
            snapshot.character = self.character_tracker.get_current_stats()
            
            # Get inventory state
            snapshot.inventory = self.inventory_manager.take_inventory_snapshot()
            
            # Get world state
            snapshot.world = self.read_world_state()
            self.current_world = snapshot.world
            
            # Update and get session info
            self.update_session_info()
            snapshot.session = self.current_session
            
        except Exception as e:
            logger.error(f"Error taking state snapshot: {e}")
        
        return snapshot
    
    def start_monitoring(self, interval: float = 1.0):
        """Start comprehensive game state monitoring"""
        if self.is_monitoring:
            logger.warning("Monitoring already active")
            return
        
        if not self.connect_to_game():
            logger.error("Cannot start monitoring - failed to connect to game")
            return False
        
        self.monitor_interval = interval
        self.is_monitoring = True
        
        # Initialize session
        self.current_session.session_id = f"session_{int(time.time())}"
        self.current_session.session_start = time.time()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Start component monitoring
        char_thread = threading.Thread(target=self.character_tracker.start_monitoring, args=(interval,), daemon=True)
        inv_thread = threading.Thread(target=self.inventory_manager.start_monitoring, args=(interval * 2,), daemon=True)
        
        char_thread.start()
        inv_thread.start()
        
        logger.info("Started comprehensive game state monitoring")
        return True
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Take periodic snapshots
                snapshot = self.take_state_snapshot()
                
                # Store in history
                self.state_history.append(snapshot)
                if len(self.state_history) > self.max_history:
                    self.state_history.pop(0)
                
                # Log significant events
                if len(self.state_history) >= 2:
                    prev_snapshot = self.state_history[-2]
                    
                    # Area changes
                    if (snapshot.world.area_id != prev_snapshot.world.area_id):
                        logger.info(f"Area changed: {prev_snapshot.world.area_name} -> {snapshot.world.area_name}")
                    
                    # Death detection
                    if (snapshot.session.deaths > prev_snapshot.session.deaths):
                        logger.info(f"Character death detected! Total deaths: {snapshot.session.deaths}")
                    
                    # Level up detection
                    if (snapshot.character.level > prev_snapshot.character.level):
                        logger.info(f"Level up! {snapshot.character.character_name} reached level {snapshot.character.level}")
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitor_interval)
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        self.is_monitoring = False
        
        # Stop component monitoring
        self.character_tracker.stop_monitoring()
        self.inventory_manager.stop_monitoring()
        
        # Wait for monitor thread to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        
        logger.info("Stopped game state monitoring")
    
    def get_current_state(self) -> Dict:
        """Get current complete game state"""
        snapshot = self.take_state_snapshot()
        return asdict(snapshot)
    
    def get_state_history(self) -> List[Dict]:
        """Get game state history"""
        return [asdict(snapshot) for snapshot in self.state_history]
    
    def get_session_summary(self) -> Dict:
        """Get session summary statistics"""
        if not self.state_history:
            return {}
        
        current_time = time.time()
        session_duration = current_time - self.current_session.session_start
        
        # Calculate statistics from history
        level_changes = 0
        area_changes = 0
        total_experience_gained = 0
        
        if len(self.state_history) >= 2:
            first_snapshot = self.state_history[0]
            last_snapshot = self.state_history[-1]
            
            level_changes = last_snapshot.character.level - first_snapshot.character.level
            total_experience_gained = last_snapshot.character.experience - first_snapshot.character.experience
            
            # Count area changes
            prev_area = first_snapshot.world.area_id
            for snapshot in self.state_history[1:]:
                if snapshot.world.area_id != prev_area:
                    area_changes += 1
                    prev_area = snapshot.world.area_id
        
        return {
            'session_id': self.current_session.session_id,
            'character_name': self.current_session.character_name,
            'character_class': self.current_session.character_class,
            'session_duration': session_duration,
            'current_area': self.current_world.area_name,
            'current_level': self.state_history[-1].character.level if self.state_history else 1,
            'levels_gained': level_changes,
            'areas_visited': area_changes,
            'experience_gained': total_experience_gained,
            'deaths': self.current_session.deaths,
            'snapshots_taken': len(self.state_history)
        }
    
    def search_history(self, criteria: Dict) -> List[Dict]:
        """Search state history based on criteria"""
        results = []
        
        for snapshot in self.state_history:
            match = True
            
            # Check various criteria
            if 'area_name' in criteria:
                if criteria['area_name'].lower() not in snapshot.world.area_name.lower():
                    match = False
            
            if 'min_level' in criteria:
                if snapshot.character.level < criteria['min_level']:
                    match = False
            
            if 'max_level' in criteria:
                if snapshot.character.level > criteria['max_level']:
                    match = False
            
            if 'time_range' in criteria:
                start_time, end_time = criteria['time_range']
                if not (start_time <= snapshot.timestamp <= end_time):
                    match = False
            
            if match:
                results.append(asdict(snapshot))
        
        return results
    
    def export_session_data(self, filepath: str):
        """Export session data to JSON file"""
        import json
        
        session_data = {
            'session_info': asdict(self.current_session),
            'session_summary': self.get_session_summary(),
            'state_history': self.get_state_history(),
            'character_history': self.character_tracker.get_stats_history(),
            'inventory_history': self.inventory_manager.get_inventory_history(),
            'item_events': self.inventory_manager.get_item_events()
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(session_data, f, indent=2, default=str)
            logger.info(f"Session data exported to {filepath}")
        except Exception as e:
            logger.error(f"Failed to export session data: {e}")
    
    def get_performance_metrics(self) -> Dict:
        """Get performance metrics of the monitoring system"""
        return {
            'monitoring_active': self.is_monitoring,
            'monitor_interval': self.monitor_interval,
            'state_snapshots': len(self.state_history),
            'character_history_size': len(self.character_tracker.stats_history),
            'inventory_history_size': len(self.inventory_manager.inventory_history),
            'item_events_count': len(self.inventory_manager.item_events),
            'memory_connected': self.character_tracker.pymem is not None,
            'last_update': max(
                self.current_session.last_update,
                self.current_world.last_update,
                self.state_history[-1].timestamp if self.state_history else 0
            )
        }
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if self.is_monitoring:
            self.stop_monitoring()
