#!/usr/bin/env python3
"""
Diablo 2 Inventory Manager

Monitors character inventory, stash, and item transactions.
Detects potential item duplication, impossible items, and trading anomalies.
"""

import time
import logging
import pymem
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class ItemQuality(Enum):
    """Item quality levels in Diablo 2"""
    NORMAL = 0
    MAGIC = 1
    SET = 2
    RARE = 3
    UNIQUE = 4
    CRAFTED = 5

class ItemType(Enum):
    """Basic item type categories"""
    WEAPON = "weapon"
    ARMOR = "armor"
    MISC = "misc"
    CONSUMABLE = "consumable"
    CHARM = "charm"
    JEWEL = "jewel"
    RUNE = "rune"
    GEM = "gem"

@dataclass
class GameItem:
    """Represents a single item in the game"""
    item_id: str = ""
    item_code: str = ""  # Internal game code (e.g., "rin" for ring)
    item_name: str = ""
    item_type: ItemType = ItemType.MISC
    quality: ItemQuality = ItemQuality.NORMAL
    level: int = 0
    position_x: int = 0
    position_y: int = 0
    location: str = "unknown"  # inventory, stash, ground, etc.
    properties: Dict[str, Any] = None
    socket_count: int = 0
    identified: bool = True
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.properties is None:
            self.properties = {}
        if self.timestamp == 0.0:
            self.timestamp = time.time()

@dataclass
class InventorySnapshot:
    """Complete inventory state at a point in time"""
    inventory_items: List[GameItem] = None
    stash_items: List[GameItem] = None
    equipped_items: List[GameItem] = None
    belt_items: List[GameItem] = None
    cube_items: List[GameItem] = None
    total_gold: int = 0
    stash_gold: int = 0
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.inventory_items is None:
            self.inventory_items = []
        if self.stash_items is None:
            self.stash_items = []
        if self.equipped_items is None:
            self.equipped_items = []
        if self.belt_items is None:
            self.belt_items = []
        if self.cube_items is None:
            self.cube_items = []
        if self.timestamp == 0.0:
            self.timestamp = time.time()

@dataclass
class ItemEvent:
    """Represents an item-related event (pickup, drop, trade, etc.)"""
    event_type: str = ""  # pickup, drop, trade, craft, socket, etc.
    item: GameItem = None
    location_from: str = ""
    location_to: str = ""
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

class InventoryManager:
    """
    Manages and monitors Diablo 2 character inventory and item transactions
    """
    
    def __init__(self):
        self.process_name = "Game.exe"
        self.process = None
        self.pymem = None
        
        # Memory offsets for item data (placeholders - need actual reverse engineering)
        self.memory_offsets = {
            'inventory_start': 0x00000000,
            'inventory_size': 40,  # 10x4 grid
            'stash_start': 0x00000000,
            'stash_size': 48,  # 12x4 grid (basic stash)
            'equipped_start': 0x00000000,
            'belt_start': 0x00000000,
            'cube_start': 0x00000000,
            'gold_inventory': 0x00000000,
            'gold_stash': 0x00000000,
        }
        
        self.current_inventory = InventorySnapshot()
        self.inventory_history: List[InventorySnapshot] = []
        self.item_events: List[ItemEvent] = []
        self.max_history = 500
        
        # Item code database (partial - would need complete database)
        self.item_codes = {
            'rin': 'Ring',
            'amu': 'Amulet', 
            'jew': 'Jewel',
            'cm1': 'Small Charm',
            'cm2': 'Large Charm',
            'cm3': 'Grand Charm',
            'r01': 'El Rune',
            'r02': 'Eld Rune',
            'r03': 'Tir Rune',
            # ... many more item codes would be added
        }
        
        # Known unique/set items for validation
        self.unique_items = {
            'The Stone of Jordan': {'base_type': 'rin', 'level_req': 29},
            'Shako': {'base_type': 'cap', 'level_req': 62},
            # ... more unique items
        }
        
        self.is_monitoring = False
    
    def connect_to_game(self) -> bool:
        """Connect to game process memory"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == self.process_name:
                    self.process = proc
                    logger.info(f"Connected to game process: PID {proc.info['pid']}")
                    
                    try:
                        self.pymem = pymem.Pymem(self.process_name)
                        return True
                    except Exception as e:
                        logger.error(f"Failed to connect to process memory: {e}")
                        return False
            
            logger.warning("Game process not found")
            return False
            
        except Exception as e:
            logger.error(f"Error connecting to game: {e}")
            return False
    
    def read_item_data(self, base_address: int, slot_index: int) -> Optional[GameItem]:
        """Read item data from a specific inventory slot"""
        if not self.pymem:
            return None
        
        try:
            # Calculate slot address (each item slot is typically 32 bytes)
            slot_address = base_address + (slot_index * 32)
            
            # Read basic item data
            item_code_bytes = self.pymem.read_bytes(slot_address, 4)
            item_code = item_code_bytes.decode('ascii', errors='ignore').strip('\x00')
            
            if not item_code or item_code == '\x00\x00\x00\x00':
                return None  # Empty slot
            
            item = GameItem()
            item.item_code = item_code
            item.item_name = self.item_codes.get(item_code, f"Unknown({item_code})")
            
            # Read item properties (offsets are placeholders)
            item.quality = ItemQuality(self.pymem.read_uchar(slot_address + 4))
            item.level = self.pymem.read_uchar(slot_address + 5)
            item.position_x = self.pymem.read_uchar(slot_address + 6)
            item.position_y = self.pymem.read_uchar(slot_address + 7)
            item.socket_count = self.pymem.read_uchar(slot_address + 8)
            item.identified = bool(self.pymem.read_uchar(slot_address + 9))
            
            # Generate unique item ID based on memory address and properties
            item.item_id = f"{slot_address:08x}_{item_code}_{int(time.time())}"
            
            return item
            
        except Exception as e:
            logger.error(f"Error reading item data at slot {slot_index}: {e}")
            return None
    
    def scan_inventory(self) -> List[GameItem]:
        """Scan character inventory for items"""
        items = []
        if not self.pymem:
            return items
        
        try:
            base_addr = self.memory_offsets['inventory_start']
            for i in range(self.memory_offsets['inventory_size']):
                item = self.read_item_data(base_addr, i)
                if item:
                    item.location = "inventory"
                    items.append(item)
            
            logger.debug(f"Found {len(items)} items in inventory")
            return items
            
        except Exception as e:
            logger.error(f"Error scanning inventory: {e}")
            return items
    
    def scan_stash(self) -> List[GameItem]:
        """Scan character stash for items"""
        items = []
        if not self.pymem:
            return items
        
        try:
            base_addr = self.memory_offsets['stash_start']
            for i in range(self.memory_offsets['stash_size']):
                item = self.read_item_data(base_addr, i)
                if item:
                    item.location = "stash"
                    items.append(item)
            
            logger.debug(f"Found {len(items)} items in stash")
            return items
            
        except Exception as e:
            logger.error(f"Error scanning stash: {e}")
            return items
    
    def scan_equipped_items(self) -> List[GameItem]:
        """Scan equipped items"""
        items = []
        # Equipment slots: helmet, armor, belt, gloves, boots, weapon1, weapon2, shield, ring1, ring2, amulet
        equipment_slots = ['helmet', 'armor', 'belt', 'gloves', 'boots', 
                          'weapon1', 'weapon2', 'shield', 'ring1', 'ring2', 'amulet']
        
        try:
            base_addr = self.memory_offsets['equipped_start']
            for i, slot_name in enumerate(equipment_slots):
                item = self.read_item_data(base_addr, i)
                if item:
                    item.location = f"equipped_{slot_name}"
                    items.append(item)
            
            logger.debug(f"Found {len(items)} equipped items")
            return items
            
        except Exception as e:
            logger.error(f"Error scanning equipped items: {e}")
            return items
    
    def get_gold_amounts(self) -> Tuple[int, int]:
        """Get inventory and stash gold amounts"""
        try:
            if not self.pymem:
                return 0, 0
            
            inventory_gold = self.pymem.read_uint(self.memory_offsets['gold_inventory'])
            stash_gold = self.pymem.read_uint(self.memory_offsets['gold_stash'])
            
            return inventory_gold, stash_gold
            
        except Exception as e:
            logger.error(f"Error reading gold amounts: {e}")
            return 0, 0
    
    def take_inventory_snapshot(self) -> InventorySnapshot:
        """Take a complete snapshot of current inventory state"""
        snapshot = InventorySnapshot()
        snapshot.timestamp = time.time()
        
        if not self.pymem and not self.connect_to_game():
            return snapshot
        
        try:
            snapshot.inventory_items = self.scan_inventory()
            snapshot.stash_items = self.scan_stash()
            snapshot.equipped_items = self.scan_equipped_items()
            
            # Get gold amounts
            snapshot.total_gold, snapshot.stash_gold = self.get_gold_amounts()
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Error taking inventory snapshot: {e}")
            return snapshot
    
    def detect_item_changes(self, previous: InventorySnapshot, current: InventorySnapshot) -> List[ItemEvent]:
        """Detect changes between two inventory snapshots"""
        events = []
        
        if not previous or not current:
            return events
        
        # Compare inventories
        prev_inv_ids = {item.item_id for item in previous.inventory_items}
        curr_inv_ids = {item.item_id for item in current.inventory_items}
        
        # Items added to inventory
        for item in current.inventory_items:
            if item.item_id not in prev_inv_ids:
                event = ItemEvent(
                    event_type="item_pickup",
                    item=item,
                    location_to="inventory",
                    timestamp=current.timestamp
                )
                events.append(event)
        
        # Items removed from inventory
        for item in previous.inventory_items:
            if item.item_id not in curr_inv_ids:
                event = ItemEvent(
                    event_type="item_drop",
                    item=item,
                    location_from="inventory",
                    timestamp=current.timestamp
                )
                events.append(event)
        
        # Gold changes
        if current.total_gold != previous.total_gold:
            gold_diff = current.total_gold - previous.total_gold
            event_type = "gold_gain" if gold_diff > 0 else "gold_loss"
            
            # Create a "virtual" gold item for the event
            gold_item = GameItem(
                item_code="gld",
                item_name="Gold",
                item_type=ItemType.MISC,
                properties={"amount": abs(gold_diff)}
            )
            
            event = ItemEvent(
                event_type=event_type,
                item=gold_item,
                timestamp=current.timestamp
            )
            events.append(event)
        
        return events
    
    def validate_item(self, item: GameItem) -> List[str]:
        """Validate an item for potential anomalies"""
        issues = []
        
        # Check if item code is known
        if item.item_code not in self.item_codes:
            issues.append(f"Unknown item code: {item.item_code}")
        
        # Check unique items
        if item.item_name in self.unique_items:
            unique_data = self.unique_items[item.item_name]
            if item.item_code != unique_data['base_type']:
                issues.append(f"Unique item {item.item_name} has wrong base type")
        
        # Basic validation checks
        if item.level < 0 or item.level > 99:
            issues.append(f"Invalid item level: {item.level}")
        
        if item.socket_count < 0 or item.socket_count > 6:
            issues.append(f"Invalid socket count: {item.socket_count}")
        
        # Position validation (depends on item location)
        if item.location == "inventory":
            if item.position_x < 0 or item.position_x > 9 or item.position_y < 0 or item.position_y > 3:
                issues.append(f"Invalid inventory position: ({item.position_x}, {item.position_y})")
        
        return issues
    
    def start_monitoring(self, interval: float = 2.0):
        """Start continuous inventory monitoring"""
        if not self.connect_to_game():
            logger.error("Cannot start inventory monitoring - failed to connect to game")
            return False
        
        self.is_monitoring = True
        logger.info("Started inventory monitoring")
        
        # Take initial snapshot
        self.current_inventory = self.take_inventory_snapshot()
        self.inventory_history.append(self.current_inventory)
        
        while self.is_monitoring:
            try:
                time.sleep(interval)
                
                # Take new snapshot
                new_snapshot = self.take_inventory_snapshot()
                
                # Detect changes
                events = self.detect_item_changes(self.current_inventory, new_snapshot)
                
                # Process events
                for event in events:
                    self.item_events.append(event)
                    logger.info(f"Item event: {event.event_type} - {event.item.item_name}")
                    
                    # Validate items
                    if event.item:
                        issues = self.validate_item(event.item)
                        if issues:
                            logger.warning(f"Item validation issues for {event.item.item_name}: {issues}")
                
                # Update current state
                self.current_inventory = new_snapshot
                self.inventory_history.append(new_snapshot)
                
                # Limit history size
                if len(self.inventory_history) > self.max_history:
                    self.inventory_history.pop(0)
                
                if len(self.item_events) > self.max_history * 2:
                    self.item_events = self.item_events[-self.max_history:]
                
            except Exception as e:
                logger.error(f"Error during inventory monitoring: {e}")
                time.sleep(interval)
        
        return True
    
    def stop_monitoring(self):
        """Stop inventory monitoring"""
        self.is_monitoring = False
        logger.info("Stopped inventory monitoring")
    
    def get_current_inventory(self) -> Dict:
        """Get current inventory state"""
        return asdict(self.current_inventory)
    
    def get_inventory_history(self) -> List[Dict]:
        """Get inventory history"""
        return [asdict(snapshot) for snapshot in self.inventory_history]
    
    def get_item_events(self) -> List[Dict]:
        """Get item event history"""
        return [asdict(event) for event in self.item_events]
    
    def search_items(self, query: str) -> List[GameItem]:
        """Search for items by name or code"""
        results = []
        query_lower = query.lower()
        
        # Search in current inventory
        all_items = (self.current_inventory.inventory_items + 
                    self.current_inventory.stash_items + 
                    self.current_inventory.equipped_items)
        
        for item in all_items:
            if (query_lower in item.item_name.lower() or 
                query_lower in item.item_code.lower()):
                results.append(item)
        
        return results
    
    def get_item_statistics(self) -> Dict:
        """Get inventory statistics"""
        all_items = (self.current_inventory.inventory_items + 
                    self.current_inventory.stash_items + 
                    self.current_inventory.equipped_items)
        
        stats = {
            'total_items': len(all_items),
            'inventory_items': len(self.current_inventory.inventory_items),
            'stash_items': len(self.current_inventory.stash_items),
            'equipped_items': len(self.current_inventory.equipped_items),
            'total_gold': self.current_inventory.total_gold,
            'stash_gold': self.current_inventory.stash_gold,
            'item_quality_distribution': {},
            'item_type_distribution': {},
            'recent_events': len([e for e in self.item_events 
                                if e.timestamp > time.time() - 3600])  # Last hour
        }
        
        # Quality distribution
        for item in all_items:
            quality_name = item.quality.name
            stats['item_quality_distribution'][quality_name] = \
                stats['item_quality_distribution'].get(quality_name, 0) + 1
        
        # Type distribution
        for item in all_items:
            type_name = item.item_type.value
            stats['item_type_distribution'][type_name] = \
                stats['item_type_distribution'].get(type_name, 0) + 1
        
        return stats
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if self.is_monitoring:
            self.stop_monitoring()
        
        if self.pymem:
            try:
                self.pymem.close_process()
            except:
                pass
