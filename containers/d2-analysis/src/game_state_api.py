#!/usr/bin/env python3

"""
Game State API Server for D2 Game Runner Container

Provides REST API endpoints to query Diablo 2 game state, process information,
and coordinate with external analysis tools.
"""

import asyncio
import json
import logging
import os
import psutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="D2 Game State API", version="1.0.0")

# Import D2 interface modules if available
try:
    import sys
    sys.path.append('/home/wine/d2_interface')
    from character_tracker import CharacterTracker
    from game_state import GameStateMonitor
    from inventory_manager import InventoryManager
    D2_INTERFACE_AVAILABLE = True
    logger.info("D2 interface modules loaded successfully")
except ImportError as e:
    logger.warning(f"D2 interface modules not available: {e}")
    D2_INTERFACE_AVAILABLE = False

class GameProcess(BaseModel):
    pid: int
    name: str
    memory_mb: float
    cpu_percent: float
    status: str
    create_time: datetime

class GameState(BaseModel):
    is_running: bool
    processes: List[GameProcess]
    wine_processes: List[GameProcess]
    uptime_seconds: float
    
class CharacterInfo(BaseModel):
    name: Optional[str]
    level: Optional[int]
    class_name: Optional[str]
    experience: Optional[int]
    hitpoints: Optional[int]
    mana: Optional[int]
    position: Optional[Dict[str, float]]

# Global state
game_monitor = None
character_tracker = None
inventory_manager = None
start_time = time.time()

if D2_INTERFACE_AVAILABLE:
    try:
        game_monitor = GameStateMonitor()
        character_tracker = CharacterTracker()
        inventory_manager = InventoryManager()
        logger.info("D2 monitoring components initialized")
    except Exception as e:
        logger.error(f"Failed to initialize D2 components: {e}")

@app.on_startup
async def startup():
    """Initialize the game state monitoring"""
    logger.info("Game State API server starting up...")
    
    if game_monitor:
        await game_monitor.start_monitoring()
        logger.info("Game state monitoring started")

@app.on_shutdown  
async def shutdown():
    """Cleanup on shutdown"""
    logger.info("Game State API server shutting down...")
    
    if game_monitor:
        await game_monitor.stop_monitoring()
        logger.info("Game state monitoring stopped")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": time.time() - start_time,
        "d2_interface_available": D2_INTERFACE_AVAILABLE
    }

@app.get("/game/processes", response_model=GameState)
async def get_game_processes():
    """Get information about running game processes"""
    try:
        all_processes = []
        wine_processes = []
        is_game_running = False
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent', 'status', 'create_time']):
            try:
                info = proc.info
                process_data = GameProcess(
                    pid=info['pid'],
                    name=info['name'],
                    memory_mb=info['memory_info'].rss / 1024 / 1024,
                    cpu_percent=info['cpu_percent'],
                    status=info['status'],
                    create_time=datetime.fromtimestamp(info['create_time'])
                )
                
                if any(game_name in info['name'].lower() for game_name in ['game.exe', 'diablo', 'd2']):
                    is_game_running = True
                    all_processes.append(process_data)
                    
                if 'wine' in info['name'].lower():
                    wine_processes.append(process_data)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return GameState(
            is_running=is_game_running,
            processes=all_processes,
            wine_processes=wine_processes,
            uptime_seconds=time.time() - start_time
        )
        
    except Exception as e:
        logger.error(f"Error getting game processes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/game/character", response_model=CharacterInfo)
async def get_character_info():
    """Get current character information"""
    if not character_tracker:
        raise HTTPException(status_code=503, detail="Character tracking not available")
    
    try:
        char_data = await character_tracker.get_current_character()
        if not char_data:
            return CharacterInfo(
                name=None, level=None, class_name=None,
                experience=None, hitpoints=None, mana=None, position=None
            )
        
        return CharacterInfo(
            name=char_data.get('name'),
            level=char_data.get('level'),
            class_name=char_data.get('character_class'),
            experience=char_data.get('experience'),
            hitpoints=char_data.get('hitpoints'),
            mana=char_data.get('mana'),
            position=char_data.get('position')
        )
        
    except Exception as e:
        logger.error(f"Error getting character info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/game/inventory")
async def get_inventory():
    """Get current inventory state"""
    if not inventory_manager:
        raise HTTPException(status_code=503, detail="Inventory tracking not available")
    
    try:
        inventory = await inventory_manager.get_inventory()
        return {"inventory": inventory}
        
    except Exception as e:
        logger.error(f"Error getting inventory: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/game/state")
async def get_game_state():
    """Get comprehensive game state information"""
    try:
        # Get process information
        processes_info = await get_game_processes()
        
        # Get character information if available
        character_info = None
        if character_tracker:
            try:
                character_info = await get_character_info()
            except:
                pass
        
        # Get inventory information if available  
        inventory_info = None
        if inventory_manager:
            try:
                inventory_response = await get_inventory()
                inventory_info = inventory_response.get('inventory')
            except:
                pass
        
        # Get additional game state if monitor is available
        game_state_data = None
        if game_monitor:
            try:
                game_state_data = await game_monitor.get_current_state()
            except:
                pass
        
        return {
            "timestamp": datetime.now().isoformat(),
            "processes": processes_info.dict(),
            "character": character_info.dict() if character_info else None,
            "inventory": inventory_info,
            "game_state": game_state_data
        }
        
    except Exception as e:
        logger.error(f"Error getting game state: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/game/action/{action}")
async def execute_game_action(action: str, parameters: dict = None):
    """Execute a game action (for automation/testing)"""
    # This would be used for automated testing or bot actions
    # Implementation depends on the specific automation needs
    logger.info(f"Game action requested: {action} with parameters: {parameters}")
    
    # Placeholder for game action execution
    return {
        "action": action,
        "parameters": parameters,
        "status": "queued",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/memory/info")
async def get_memory_info():
    """Get memory usage information for the container"""
    try:
        memory = psutil.virtual_memory()
        return {
            "total_mb": memory.total / 1024 / 1024,
            "available_mb": memory.available / 1024 / 1024,
            "used_mb": memory.used / 1024 / 1024,
            "percent": memory.percent
        }
    except Exception as e:
        logger.error(f"Error getting memory info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    logger.info("Starting Game State API server...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8765,
        log_level="info"
    )
