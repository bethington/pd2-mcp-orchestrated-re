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
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import D2 specific modules - graceful fallback if not available
try:
    import sys
    sys.path.append('/app')
    sys.path.append('/app/src')
    from src.game.d2.character_tracker import CharacterTracker
    from src.game.d2.inventory_manager import InventoryManager
    from src.game.d2.game_state import GameState
    HAS_D2_MODULES = True
    logger.info("D2 modules loaded successfully")
except ImportError as e:
    logger.warning(f"D2 interface modules not available: {e}")
    HAS_D2_MODULES = False
    CharacterTracker = None
    InventoryManager = None
    GameState = None

# Global variables
game_monitor = None
character_tracker = None
inventory_manager = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Game State API server starting up...")
    
    global game_monitor, character_tracker, inventory_manager
    
    if HAS_D2_MODULES:
        try:
            character_tracker = CharacterTracker()
            inventory_manager = InventoryManager()
            logger.info("D2 monitoring components initialized")
        except Exception as e:
            logger.error(f"Failed to initialize D2 components: {e}")
    
    yield
    
    # Shutdown
    logger.info("Game State API server shutting down...")

# Create FastAPI app with lifespan
app = FastAPI(
    title="Diablo 2 Game State API",
    description="REST API for querying Diablo 2 game state and process information",
    version="1.0.0",
    lifespan=lifespan
)

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "running",
        "service": "d2-game-state-api",
        "timestamp": datetime.now().isoformat(),
        "d2_modules_available": HAS_D2_MODULES
    }

@app.get("/health")
async def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "uptime": time.time(),
        "d2_modules": HAS_D2_MODULES,
        "processes": len(psutil.pids())
    }

@app.get("/processes")
async def get_processes():
    """Get current running processes"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return {"processes": processes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/game/status")
async def get_game_status():
    """Get Diablo 2 game status"""
    try:
        # Look for wine/game processes
        game_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if any(keyword in str(proc.info['cmdline']).lower() 
                      for keyword in ['game.exe', 'diablo', 'wine']):
                    game_processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return {
            "game_running": len(game_processes) > 0,
            "processes": game_processes,
            "d2_modules_enabled": HAS_D2_MODULES
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/system/info")
async def get_system_info():
    """Get system information"""
    try:
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": dict(psutil.virtual_memory()._asdict()),
            "disk": dict(psutil.disk_usage('/')._asdict()),
            "boot_time": psutil.boot_time()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3001)
