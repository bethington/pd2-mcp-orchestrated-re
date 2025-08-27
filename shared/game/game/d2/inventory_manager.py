"""
Inventory Management for Diablo 2 Analysis
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import structlog

logger = structlog.get_logger()

class Item:
    def __init__(self, item_data: Dict[str, Any]):
        self.item_id = item_data.get("id", "unknown")
        self.name = item_data.get("name", "Unknown Item")
        self.item_type = item_data.get("type", "unknown")
        self.quality = item_data.get("quality", "normal")
        self.level_req = item_data.get("level_req", 1)
        self.position = item_data.get("position", {"x": 0, "y": 0})
        self.equipped = item_data.get("equipped", False)
        self.properties = item_data.get("properties", [])
        self.rarity = item_data.get("rarity", "common")
        self.value = item_data.get("value", 0)
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "name": self.name,
            "type": self.item_type,
            "quality": self.quality,
            "level_req": self.level_req,
            "position": self.position,
            "equipped": self.equipped,
            "properties": self.properties,
            "rarity": self.rarity,
            "value": self.value
        }

class InventoryManager:
    def __init__(self):
        self.current_inventory = {}
        self.equipped_items = {}
        self.stash_items = {}
        self.item_history = []
        logger.info("Inventory manager initialized")
        
    def manage_inventory(self):
        """Legacy method for compatibility"""
        return asyncio.create_task(self.monitor_inventory())
        
    async def get_full_inventory(self) -> Dict[str, Any]:
        """Get complete inventory state"""
        try:
            # Read inventory from game memory
            inventory_data = await self._read_inventory_memory()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "inventory": inventory_data.get("inventory", []),
                "equipped": inventory_data.get("equipped", []),
                "stash": inventory_data.get("stash", []),
                "belt": inventory_data.get("belt", []),
                "mercenary": inventory_data.get("mercenary", []),
                "cube": inventory_data.get("cube", []),
                "total_items": len(inventory_data.get("inventory", [])) + len(inventory_data.get("equipped", [])),
                "total_value": self._calculate_total_value(inventory_data)
            }
            
        except Exception as e:
            logger.error("Error getting inventory", error=str(e))
            return {"error": str(e)}
            
    async def _read_inventory_memory(self) -> Dict[str, Any]:
        """Read inventory data from game memory"""
        # Mock inventory data for development
        import random
        
        items = []
        equipped = []
        
        # Generate mock inventory items
        item_names = ["Sword", "Shield", "Potion", "Gem", "Ring", "Amulet", "Armor"]
        rarities = ["normal", "magic", "rare", "unique", "set"]
        
        for i in range(random.randint(10, 30)):
            item = {
                "id": f"item_{i}",
                "name": random.choice(item_names),
                "type": "weapon" if "Sword" in item_names[0] else "misc",
                "quality": random.choice(rarities),
                "level_req": random.randint(1, 80),
                "position": {"x": random.randint(0, 9), "y": random.randint(0, 3)},
                "equipped": False,
                "properties": [],
                "rarity": random.choice(rarities),
                "value": random.randint(100, 10000)
            }
            items.append(item)
            
        # Generate equipped items
        equipment_slots = ["helmet", "armor", "weapon", "shield", "boots", "gloves", "belt", "amulet", "ring1", "ring2"]
        for slot in equipment_slots[:random.randint(3, 8)]:
            item = {
                "id": f"equipped_{slot}",
                "name": f"{slot.capitalize()} of Power",
                "type": slot,
                "quality": random.choice(rarities),
                "level_req": random.randint(1, 80),
                "position": {"slot": slot},
                "equipped": True,
                "properties": [f"+{random.randint(1, 20)} to something"],
                "rarity": random.choice(rarities),
                "value": random.randint(500, 50000)
            }
            equipped.append(item)
            
        return {
            "inventory": items,
            "equipped": equipped,
            "stash": [],  # Would be populated from stash memory
            "belt": [],   # Would be populated from belt memory
            "mercenary": [],  # Would be populated from mercenary memory
            "cube": []    # Would be populated from cube memory
        }
        
    async def monitor_inventory(self, callback=None):
        """Monitor inventory changes"""
        previous_inventory = {}
        
        while True:
            try:
                current_inventory = await self.get_full_inventory()
                
                if current_inventory and "error" not in current_inventory:
                    # Check for changes
                    changes = await self._detect_inventory_changes(previous_inventory, current_inventory)
                    
                    if changes and callback:
                        await callback("inventory_changed", changes)
                        
                    # Store in history
                    self.item_history.append({
                        "timestamp": datetime.now().isoformat(),
                        "changes": changes
                    })
                    
                    # Keep only recent history
                    if len(self.item_history) > 100:
                        self.item_history = self.item_history[-50:]
                    
                    previous_inventory = current_inventory
                    
                await asyncio.sleep(2.0)  # Check every 2 seconds
                
            except Exception as e:
                logger.error("Error in inventory monitoring", error=str(e))
                await asyncio.sleep(5.0)
                
    async def _detect_inventory_changes(self, old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        """Detect changes between inventory states"""
        changes = {
            "items_added": [],
            "items_removed": [],
            "items_moved": [],
            "items_equipped": [],
            "items_unequipped": []
        }
        
        if not old:
            return changes
            
        # Compare inventory items
        old_items = {item["id"]: item for item in old.get("inventory", [])}
        new_items = {item["id"]: item for item in new.get("inventory", [])}
        
        # Find added items
        for item_id, item in new_items.items():
            if item_id not in old_items:
                changes["items_added"].append(item)
                
        # Find removed items
        for item_id, item in old_items.items():
            if item_id not in new_items:
                changes["items_removed"].append(item)
                
        # Find moved items
        for item_id in old_items.keys() & new_items.keys():
            old_pos = old_items[item_id].get("position")
            new_pos = new_items[item_id].get("position")
            if old_pos != new_pos:
                changes["items_moved"].append({
                    "item": new_items[item_id],
                    "old_position": old_pos,
                    "new_position": new_pos
                })
                
        return changes
        
    def _calculate_total_value(self, inventory_data: Dict[str, Any]) -> int:
        """Calculate total value of all items"""
        total = 0
        
        for section in ["inventory", "equipped", "stash", "belt", "cube"]:
            items = inventory_data.get(section, [])
            for item in items:
                total += item.get("value", 0)
                
        return total
        
    async def analyze_item_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in item acquisition/usage"""
        analysis = {
            "most_common_items": {},
            "rarest_items": [],
            "value_trends": [],
            "acquisition_rate": 0,
            "suspicious_items": []
        }
        
        try:
            # Analyze item history
            if self.item_history:
                # Count item types
                item_counts = {}
                total_added = 0
                
                for entry in self.item_history:
                    changes = entry.get("changes", {})
                    for item in changes.get("items_added", []):
                        item_type = item.get("type", "unknown")
                        item_counts[item_type] = item_counts.get(item_type, 0) + 1
                        total_added += 1
                        
                analysis["most_common_items"] = dict(sorted(item_counts.items(), key=lambda x: x[1], reverse=True)[:10])
                
                # Calculate acquisition rate (items per minute)
                if len(self.item_history) > 1:
                    time_span = len(self.item_history) * 2 / 60  # 2 second intervals
                    analysis["acquisition_rate"] = total_added / time_span if time_span > 0 else 0
                    
        except Exception as e:
            logger.error("Error analyzing item patterns", error=str(e))
            
        return analysis
        
    async def detect_suspicious_activity(self) -> List[Dict[str, Any]]:
        """Detect suspicious inventory activity"""
        suspicious = []
        
        try:
            current_inventory = await self.get_full_inventory()
            if "error" in current_inventory:
                return suspicious
                
            # Check for impossible items
            for item in current_inventory.get("inventory", []) + current_inventory.get("equipped", []):
                # Check for items with impossible properties
                if item.get("value", 0) > 100000:  # Very high value items
                    suspicious.append({
                        "type": "high_value_item",
                        "item": item,
                        "description": f"Item '{item.get('name')}' has unusually high value",
                        "severity": "medium"
                    })
                    
                # Check for low level character with high level items
                if item.get("level_req", 0) > 80:  # Would need character level check
                    suspicious.append({
                        "type": "high_level_item",
                        "item": item,
                        "description": f"High level requirement item: {item.get('name')}",
                        "severity": "low"
                    })
                    
            # Check acquisition patterns
            patterns = await self.analyze_item_patterns()
            if patterns.get("acquisition_rate", 0) > 10:  # More than 10 items per minute
                suspicious.append({
                    "type": "rapid_acquisition",
                    "description": f"Very high item acquisition rate: {patterns['acquisition_rate']:.2f} items/min",
                    "severity": "high"
                })
                
        except Exception as e:
            logger.error("Error detecting suspicious activity", error=str(e))
            
        return suspicious
