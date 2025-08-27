#!/usr/bin/env python3
"""
MCP Coordinator - Central orchestration service for all MCP servers
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel
import aiohttp
import structlog

# Import platform modules
import sys
sys.path.append('/app')
from src.core.session_manager import SessionManager
from src.core.event_bus import EventBus
from claude.orchestrator import ClaudeOrchestrator

logger = structlog.get_logger()

class MCPCoordinator:
    def __init__(self):
        self.app = FastAPI(title="MCP Coordinator", version="1.0.0")
        self.session_manager = SessionManager()
        self.event_bus = EventBus()
        self.claude_orchestrator = ClaudeOrchestrator()
        
        self.registered_servers = {}
        self.active_sessions = {}
        self.websocket_connections = []
        
        self.setup_routes()
        self.setup_cors()
        
    def setup_cors(self):
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
    def setup_routes(self):
        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "registered_servers": len(self.registered_servers),
                "active_sessions": len(self.active_sessions)
            }
            
        @self.app.post("/api/v1/register_server")
        async def register_server(server_info: dict):
            """Register a new MCP server"""
            server_id = server_info.get("server_id")
            if not server_id:
                raise HTTPException(status_code=400, detail="server_id required")
                
            self.registered_servers[server_id] = server_info
            logger.info(f"Registered MCP server: {server_id}")
            
            # Notify Claude orchestrator
            await self.claude_orchestrator.on_server_registered(server_info)
            
            return {"status": "registered", "server_id": server_id}
            
        @self.app.post("/api/v1/sessions/{session_id}/analyze")
        async def trigger_analysis(session_id: str, analysis_request: dict):
            """Trigger Claude-orchestrated analysis"""
            try:
                result = await self.claude_orchestrator.analyze_session(
                    session_id, analysis_request
                )
                return {"status": "success", "result": result}
            except Exception as e:
                logger.error(f"Analysis failed for session {session_id}", error=str(e))
                raise HTTPException(status_code=500, detail=str(e))
                
        @self.app.websocket("/ws/events")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket for real-time events"""
            await websocket.accept()
            self.websocket_connections.append(websocket)
            
            try:
                while True:
                    # Keep connection alive and handle incoming messages
                    data = await websocket.receive_text()
                    message = json.loads(data)
                    
                    if message.get("type") == "subscribe":
                        # Handle subscriptions
                        pass
                    elif message.get("type") == "analysis_request":
                        # Handle real-time analysis requests
                        await self.handle_realtime_analysis(websocket, message)
                        
            except Exception as e:
                logger.error("WebSocket error", error=str(e))
            finally:
                self.websocket_connections.remove(websocket)
                
        @self.app.get("/api/v1/servers")
        async def list_servers():
            """List all registered MCP servers"""
            return {"servers": self.registered_servers}
            
    async def handle_realtime_analysis(self, websocket: WebSocket, message: dict):
        """Handle real-time analysis requests via WebSocket"""
        try:
            session_id = message.get("session_id")
            analysis_type = message.get("analysis_type", "general")
            
            # Stream analysis results back to client
            async for update in self.claude_orchestrator.stream_analysis(session_id, analysis_type):
                await websocket.send_text(json.dumps({
                    "type": "analysis_update",
                    "session_id": session_id,
                    "update": update
                }))
                
        except Exception as e:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": str(e)
            }))
            
    async def broadcast_event(self, event: dict):
        """Broadcast event to all connected WebSocket clients"""
        if not self.websocket_connections:
            return
            
        message = json.dumps(event)
        disconnected = []
        
        for ws in self.websocket_connections:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
                
        # Clean up disconnected clients
        for ws in disconnected:
            self.websocket_connections.remove(ws)
            
    async def start_background_tasks(self):
        """Start background monitoring tasks"""
        asyncio.create_task(self.health_check_loop())
        asyncio.create_task(self.event_processing_loop())
        
    async def health_check_loop(self):
        """Periodically check health of registered servers"""
        while True:
            for server_id, server_info in self.registered_servers.copy().items():
                try:
                    health_url = f"{server_info['base_url']}/health"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(health_url, timeout=5) as resp:
                            if resp.status != 200:
                                logger.warning(f"Server {server_id} health check failed")
                except Exception as e:
                    logger.error(f"Health check failed for {server_id}", error=str(e))
                    
            await asyncio.sleep(30)  # Check every 30 seconds
            
    async def event_processing_loop(self):
        """Process events from the event bus"""
        while True:
            try:
                # Process events and broadcast to WebSocket clients
                await asyncio.sleep(1)
            except Exception as e:
                logger.error("Event processing error", error=str(e))

async def main():
    coordinator = MCPCoordinator()
    
    # Start background tasks
    await coordinator.start_background_tasks()
    
    # Run the FastAPI server
    config = uvicorn.Config(
        coordinator.app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info"
    )
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
