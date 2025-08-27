"""
MCP client implementation for communicating with MCP servers
"""

import asyncio
import json
import logging
import aiohttp
import websockets
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger()

class MCPMessageType(Enum):
    """MCP message types"""
    REQUEST = "request"
    RESPONSE = "response" 
    NOTIFICATION = "notification"
    ERROR = "error"

@dataclass
class MCPMessage:
    """MCP message structure"""
    type: MCPMessageType
    id: Optional[str]
    method: Optional[str]
    params: Optional[Dict[str, Any]]
    result: Optional[Any]
    error: Optional[Dict[str, Any]]

class MCPClient:
    """Client for communicating with MCP servers"""
    
    def __init__(self, server_url: str, server_id: str = "default"):
        self.server_url = server_url
        self.server_id = server_id
        self.session = None
        self.websocket = None
        self.request_id_counter = 0
        self.pending_requests = {}
        self.event_handlers = {}
        self.connected = False
        
    async def connect(self):
        """Connect to the MCP server"""
        try:
            if self.server_url.startswith("ws"):
                # WebSocket connection
                self.websocket = await websockets.connect(self.server_url)
                self.connected = True
                # Start message handling loop
                asyncio.create_task(self._handle_websocket_messages())
            else:
                # HTTP connection
                self.session = aiohttp.ClientSession()
                self.connected = True
                
            logger.info(f"Connected to MCP server: {self.server_id}")
            
        except Exception as e:
            logger.error(f"Failed to connect to MCP server {self.server_id}: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from the MCP server"""
        self.connected = False
        
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
            
        if self.session:
            await self.session.close()
            self.session = None
            
        logger.info(f"Disconnected from MCP server: {self.server_id}")
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Call a tool on the MCP server"""
        if not self.connected:
            await self.connect()
        
        message = MCPMessage(
            type=MCPMessageType.REQUEST,
            id=self._next_request_id(),
            method="tools/call",
            params={
                "name": tool_name,
                "arguments": arguments
            },
            result=None,
            error=None
        )
        
        try:
            response = await self._send_request(message)
            
            if response.error:
                raise Exception(f"Tool call failed: {response.error}")
            
            return response.result or []
            
        except Exception as e:
            logger.error(f"Failed to call tool {tool_name}: {e}")
            raise
    
    async def read_resource(self, resource_uri: str) -> Dict[str, Any]:
        """Read a resource from the MCP server"""
        if not self.connected:
            await self.connect()
        
        message = MCPMessage(
            type=MCPMessageType.REQUEST,
            id=self._next_request_id(),
            method="resources/read",
            params={"uri": resource_uri},
            result=None,
            error=None
        )
        
        try:
            response = await self._send_request(message)
            
            if response.error:
                raise Exception(f"Resource read failed: {response.error}")
            
            return response.result
            
        except Exception as e:
            logger.error(f"Failed to read resource {resource_uri}: {e}")
            raise
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools on the MCP server"""
        if not self.connected:
            await self.connect()
        
        message = MCPMessage(
            type=MCPMessageType.REQUEST,
            id=self._next_request_id(),
            method="tools/list",
            params={},
            result=None,
            error=None
        )
        
        try:
            response = await self._send_request(message)
            
            if response.error:
                raise Exception(f"List tools failed: {response.error}")
            
            return response.result.get("tools", [])
            
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            raise
    
    async def list_resources(self) -> List[Dict[str, Any]]:
        """List available resources on the MCP server"""
        if not self.connected:
            await self.connect()
        
        message = MCPMessage(
            type=MCPMessageType.REQUEST,
            id=self._next_request_id(),
            method="resources/list",
            params={},
            result=None,
            error=None
        )
        
        try:
            response = await self._send_request(message)
            
            if response.error:
                raise Exception(f"List resources failed: {response.error}")
            
            return response.result.get("resources", [])
            
        except Exception as e:
            logger.error(f"Failed to list resources: {e}")
            raise
    
    async def subscribe_to_events(self, event_types: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        """Subscribe to events from the MCP server"""
        if not self.websocket:
            raise Exception("WebSocket connection required for event subscription")
        
        # Send subscription request
        message = MCPMessage(
            type=MCPMessageType.REQUEST,
            id=self._next_request_id(),
            method="events/subscribe",
            params={"event_types": event_types},
            result=None,
            error=None
        )
        
        await self._send_websocket_message(message)
        
        # Yield events as they arrive
        while self.connected:
            try:
                # Events will be handled by the message handler
                # This is a placeholder for event streaming
                await asyncio.sleep(0.1)
                
                # Check for new events in queue (implementation specific)
                if hasattr(self, '_event_queue') and not self._event_queue.empty():
                    event = await self._event_queue.get()
                    yield event
                    
            except Exception as e:
                logger.error(f"Error in event subscription: {e}")
                break
    
    def add_event_handler(self, event_type: str, handler: callable):
        """Add an event handler for a specific event type"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    async def _send_request(self, message: MCPMessage) -> MCPMessage:
        """Send a request and wait for response"""
        if self.websocket:
            return await self._send_websocket_request(message)
        elif self.session:
            return await self._send_http_request(message)
        else:
            raise Exception("No connection available")
    
    async def _send_websocket_request(self, message: MCPMessage) -> MCPMessage:
        """Send request via WebSocket"""
        request_id = message.id
        future = asyncio.Future()
        self.pending_requests[request_id] = future
        
        try:
            await self._send_websocket_message(message)
            
            # Wait for response with timeout
            response = await asyncio.wait_for(future, timeout=30.0)
            return response
            
        except asyncio.TimeoutError:
            raise Exception(f"Request {request_id} timed out")
        finally:
            self.pending_requests.pop(request_id, None)
    
    async def _send_http_request(self, message: MCPMessage) -> MCPMessage:
        """Send request via HTTP"""
        url = f"{self.server_url}/mcp"
        
        payload = {
            "jsonrpc": "2.0",
            "id": message.id,
            "method": message.method,
            "params": message.params
        }
        
        try:
            async with self.session.post(url, json=payload) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: {await response.text()}")
                
                data = await response.json()
                
                return MCPMessage(
                    type=MCPMessageType.RESPONSE,
                    id=data.get("id"),
                    method=None,
                    params=None,
                    result=data.get("result"),
                    error=data.get("error")
                )
                
        except Exception as e:
            logger.error(f"HTTP request failed: {e}")
            raise
    
    async def _send_websocket_message(self, message: MCPMessage):
        """Send message via WebSocket"""
        if not self.websocket:
            raise Exception("WebSocket not connected")
        
        payload = {
            "jsonrpc": "2.0",
            "id": message.id,
            "method": message.method,
            "params": message.params
        }
        
        if message.type == MCPMessageType.RESPONSE:
            payload = {
                "jsonrpc": "2.0", 
                "id": message.id,
                "result": message.result,
                "error": message.error
            }
        
        await self.websocket.send(json.dumps(payload))
    
    async def _handle_websocket_messages(self):
        """Handle incoming WebSocket messages"""
        try:
            async for message_data in self.websocket:
                try:
                    data = json.loads(message_data)
                    await self._process_message(data)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse WebSocket message: {e}")
                except Exception as e:
                    logger.error(f"Error processing WebSocket message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info("WebSocket connection closed")
            self.connected = False
        except Exception as e:
            logger.error(f"WebSocket message handler error: {e}")
            self.connected = False
    
    async def _process_message(self, data: Dict[str, Any]):
        """Process an incoming message"""
        message_id = data.get("id")
        
        if "result" in data or "error" in data:
            # This is a response to a request
            if message_id in self.pending_requests:
                future = self.pending_requests[message_id]
                
                response = MCPMessage(
                    type=MCPMessageType.RESPONSE,
                    id=message_id,
                    method=None,
                    params=None,
                    result=data.get("result"),
                    error=data.get("error")
                )
                
                future.set_result(response)
        
        elif "method" in data:
            # This is a notification or request from server
            method = data["method"]
            params = data.get("params", {})
            
            # Handle notifications
            if method.startswith("notifications/"):
                await self._handle_notification(method, params)
    
    async def _handle_notification(self, method: str, params: Dict[str, Any]):
        """Handle server notifications"""
        event_type = method.replace("notifications/", "")
        
        # Call registered event handlers
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    await handler(params)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")
        
        # Add to event queue if exists
        if hasattr(self, '_event_queue'):
            await self._event_queue.put({
                "type": event_type,
                "data": params
            })
    
    def _next_request_id(self) -> str:
        """Generate next request ID"""
        self.request_id_counter += 1
        return f"{self.server_id}_{self.request_id_counter}"

class MCPClientPool:
    """Pool of MCP clients for managing multiple server connections"""
    
    def __init__(self):
        self.clients = {}
        self.default_client_id = None
    
    def add_client(self, client_id: str, server_url: str, is_default: bool = False):
        """Add a client to the pool"""
        client = MCPClient(server_url, client_id)
        self.clients[client_id] = client
        
        if is_default or self.default_client_id is None:
            self.default_client_id = client_id
    
    def get_client(self, client_id: Optional[str] = None) -> MCPClient:
        """Get a client from the pool"""
        if client_id is None:
            client_id = self.default_client_id
        
        if client_id not in self.clients:
            raise Exception(f"Client {client_id} not found in pool")
        
        return self.clients[client_id]
    
    async def connect_all(self):
        """Connect all clients in the pool"""
        for client in self.clients.values():
            try:
                await client.connect()
            except Exception as e:
                logger.error(f"Failed to connect client {client.server_id}: {e}")
    
    async def disconnect_all(self):
        """Disconnect all clients in the pool"""
        for client in self.clients.values():
            try:
                await client.disconnect()
            except Exception as e:
                logger.error(f"Failed to disconnect client {client.server_id}: {e}")
    
    async def broadcast_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on all connected clients"""
        results = {}
        
        for client_id, client in self.clients.items():
            try:
                if client.connected:
                    result = await client.call_tool(tool_name, arguments)
                    results[client_id] = result
            except Exception as e:
                results[client_id] = {"error": str(e)}
        
        return results
