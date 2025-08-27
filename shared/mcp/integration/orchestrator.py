#!/usr/bin/env python3
"""
MCP Integration Orchestrator

Coordinates the entire dynamic discovery and integration pipeline,
connecting discovery engine, tool registry, data mapping, and function execution.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

from ..discovery.discovery_engine import DiscoveryEngine, DiscoveryResult
from ..tools.dynamic_registry import DynamicToolRegistry, ToolDefinition
from ..data.structure_mapper import StructureMapper, DataStructure
from ..execution.function_proxy import (
    FunctionCallProxy, FunctionSignature, ExecutionContext, 
    ParameterType, MCPFunctionAdapter
)

logger = logging.getLogger(__name__)

class IntegrationStatus(Enum):
    """Status of integration pipeline"""
    IDLE = "idle"
    DISCOVERING = "discovering"
    PROCESSING = "processing"
    REGISTERING = "registering"
    READY = "ready"
    ERROR = "error"

@dataclass
class IntegrationMetrics:
    """Metrics for integration pipeline performance"""
    discoveries_processed: int = 0
    tools_registered: int = 0
    functions_integrated: int = 0
    data_structures_mapped: int = 0
    processing_time: float = 0.0
    success_rate: float = 0.0
    last_update: float = field(default_factory=time.time)

@dataclass
class PipelineConfig:
    """Configuration for integration pipeline"""
    auto_register_tools: bool = True
    max_concurrent_processing: int = 5
    confidence_threshold: float = 0.7
    risk_level_threshold: int = 2
    enable_function_execution: bool = True
    discovery_interval: float = 30.0
    data_retention_hours: int = 24

class MCPIntegrationOrchestrator:
    """
    Main orchestrator for MCP dynamic integration pipeline.
    
    Coordinates discovery, mapping, registration, and execution of
    dynamically discovered game analysis capabilities.
    """
    
    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self.status = IntegrationStatus.IDLE
        self.metrics = IntegrationMetrics()
        
        # Core components
        self.discovery_engine = DiscoveryEngine()
        self.tool_registry = DynamicToolRegistry()
        self.structure_mapper = StructureMapper()
        self.function_proxy = FunctionCallProxy()
        self.mcp_adapter = MCPFunctionAdapter(self.function_proxy)
        
        # Integration state
        self.processed_discoveries: Set[str] = set()
        self.active_tools: Dict[str, ToolDefinition] = {}
        self.mapped_structures: Dict[str, DataStructure] = {}
        self.registered_functions: Dict[str, FunctionSignature] = {}
        
        # Background tasks
        self.background_tasks: Set[asyncio.Task] = set()
        self.discovery_task: Optional[asyncio.Task] = None
        self.processing_task: Optional[asyncio.Task] = None
        
        logger.info("MCP Integration Orchestrator initialized")
    
    async def start(self):
        """Start the integration orchestrator"""
        if self.status != IntegrationStatus.IDLE:
            logger.warning("Orchestrator already running")
            return
            
        logger.info("Starting MCP Integration Orchestrator...")
        self.status = IntegrationStatus.READY
        
        # Start background discovery
        if self.config.discovery_interval > 0:
            self.discovery_task = asyncio.create_task(self._discovery_loop())
            self.background_tasks.add(self.discovery_task)
        
        # Start processing pipeline
        self.processing_task = asyncio.create_task(self._processing_loop())
        self.background_tasks.add(self.processing_task)
        
        logger.info("MCP Integration Orchestrator started")
    
    async def stop(self):
        """Stop the integration orchestrator"""
        logger.info("Stopping MCP Integration Orchestrator...")
        self.status = IntegrationStatus.IDLE
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        self.background_tasks.clear()
        self.discovery_task = None
        self.processing_task = None
        
        logger.info("MCP Integration Orchestrator stopped")
    
    async def _discovery_loop(self):
        """Background discovery loop"""
        logger.info("Discovery loop started")
        
        while self.status != IntegrationStatus.IDLE:
            try:
                self.status = IntegrationStatus.DISCOVERING
                
                # Discover new capabilities
                discoveries = await self.discovery_engine.discover_new_capabilities()
                
                if discoveries:
                    logger.info(f"Found {len(discoveries)} new discoveries")
                    for discovery in discoveries:
                        await self._queue_discovery_for_processing(discovery)
                
                self.status = IntegrationStatus.READY
                await asyncio.sleep(self.config.discovery_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in discovery loop: {e}")
                self.status = IntegrationStatus.ERROR
                await asyncio.sleep(10.0)  # Error backoff
    
    async def _processing_loop(self):
        """Background processing loop"""
        logger.info("Processing loop started")
        
        while self.status != IntegrationStatus.IDLE:
            try:
                self.status = IntegrationStatus.PROCESSING
                
                # Process queued discoveries
                await self._process_pending_discoveries()
                
                self.status = IntegrationStatus.READY
                await asyncio.sleep(1.0)  # Process every second
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                self.status = IntegrationStatus.ERROR
                await asyncio.sleep(5.0)  # Error backoff
    
    async def _queue_discovery_for_processing(self, discovery: DiscoveryResult):
        """Queue discovery for processing"""
        discovery_id = f"{discovery.type}_{discovery.name}_{discovery.timestamp}"
        
        if discovery_id not in self.processed_discoveries:
            # Add to discovery engine queue for validation
            await self.discovery_engine.queue_for_validation(discovery)
            logger.debug(f"Queued discovery for processing: {discovery.name}")
    
    async def _process_pending_discoveries(self):
        """Process all pending discoveries"""
        # Get validated discoveries
        validated = await self.discovery_engine.get_validated_discoveries()
        
        # Process up to max_concurrent_processing items
        semaphore = asyncio.Semaphore(self.config.max_concurrent_processing)
        tasks = []
        
        for discovery in validated[:self.config.max_concurrent_processing]:
            task = self._process_single_discovery(discovery, semaphore)
            tasks.append(asyncio.create_task(task))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _process_single_discovery(self, discovery: DiscoveryResult, 
                                       semaphore: asyncio.Semaphore):
        """Process a single discovery through the integration pipeline"""
        async with semaphore:
            start_time = time.time()
            discovery_id = f"{discovery.type}_{discovery.name}_{discovery.timestamp}"
            
            try:
                logger.info(f"Processing discovery: {discovery.name}")
                
                # Skip if already processed
                if discovery_id in self.processed_discoveries:
                    return
                
                # Check confidence threshold
                if discovery.confidence < self.config.confidence_threshold:
                    logger.debug(f"Discovery {discovery.name} below confidence threshold")
                    return
                
                # Process based on discovery type
                if discovery.type == "data_structure":
                    await self._integrate_data_structure(discovery)
                elif discovery.type == "function":
                    await self._integrate_function(discovery)
                elif discovery.type == "api_endpoint":
                    await self._integrate_api_endpoint(discovery)
                else:
                    logger.warning(f"Unknown discovery type: {discovery.type}")
                    return
                
                # Mark as processed
                self.processed_discoveries.add(discovery_id)
                self.metrics.discoveries_processed += 1
                
                processing_time = time.time() - start_time
                self.metrics.processing_time += processing_time
                self.metrics.last_update = time.time()
                
                logger.info(f"Successfully processed discovery: {discovery.name} "
                           f"in {processing_time:.2f}s")
                
            except Exception as e:
                logger.error(f"Error processing discovery {discovery.name}: {e}")
                # Don't mark as processed so it can be retried
    
    async def _integrate_data_structure(self, discovery: DiscoveryResult):
        """Integrate discovered data structure"""
        logger.debug(f"Integrating data structure: {discovery.name}")
        
        # Map data structure
        structure = await self.structure_mapper.map_structure(
            discovery.name, discovery.metadata
        )
        
        if structure:
            self.mapped_structures[discovery.name] = structure
            self.metrics.data_structures_mapped += 1
            
            # Register as MCP resource if configured
            if self.config.auto_register_tools:
                resource_def = {
                    'name': f"structure_{discovery.name}",
                    'description': f"Data structure: {discovery.name}",
                    'data': structure.to_dict(),
                    'schema': structure.get_json_schema()
                }
                
                await self.tool_registry.register_resource(resource_def)
                logger.info(f"Registered data structure resource: {discovery.name}")
    
    async def _integrate_function(self, discovery: DiscoveryResult):
        """Integrate discovered function"""
        logger.debug(f"Integrating function: {discovery.name}")
        
        # Create function signature from discovery
        signature = self._create_function_signature(discovery)
        
        # Register function with proxy
        if self.function_proxy.register_function(signature):
            self.registered_functions[discovery.name] = signature
            self.metrics.functions_integrated += 1
            
            # Create MCP tool if configured
            if self.config.auto_register_tools and signature.is_safe:
                tool_def = self.mcp_adapter.create_mcp_tool_definition(signature)
                
                # Register with tool registry
                registered_tool = await self.tool_registry.register_tool(
                    tool_def['name'], tool_def
                )
                
                if registered_tool:
                    self.active_tools[discovery.name] = registered_tool
                    self.metrics.tools_registered += 1
                    logger.info(f"Registered MCP tool for function: {discovery.name}")
    
    async def _integrate_api_endpoint(self, discovery: DiscoveryResult):
        """Integrate discovered API endpoint"""
        logger.debug(f"Integrating API endpoint: {discovery.name}")
        
        # Create tool for API endpoint
        tool_def = {
            'name': f"api_{discovery.name}",
            'description': discovery.metadata.get('description', f"API endpoint: {discovery.name}"),
            'inputSchema': {
                'type': 'object',
                'properties': discovery.metadata.get('parameters', {}),
                'required': discovery.metadata.get('required_params', [])
            },
            'endpoint': discovery.metadata.get('url'),
            'method': discovery.metadata.get('method', 'GET')
        }
        
        if self.config.auto_register_tools:
            registered_tool = await self.tool_registry.register_tool(
                tool_def['name'], tool_def
            )
            
            if registered_tool:
                self.active_tools[discovery.name] = registered_tool
                self.metrics.tools_registered += 1
                logger.info(f"Registered API endpoint tool: {discovery.name}")
    
    def _create_function_signature(self, discovery: DiscoveryResult) -> FunctionSignature:
        """Create function signature from discovery result"""
        metadata = discovery.metadata
        
        # Extract parameters
        parameters = []
        for param in metadata.get('parameters', []):
            parameters.append({
                'name': param.get('name', 'param'),
                'type': self._map_parameter_type(param.get('type', 'unknown')),
                'required': param.get('required', False),
                'description': param.get('description', '')
            })
        
        # Determine execution context
        context = ExecutionContext.FILE_ANALYSIS
        if 'memory' in discovery.name.lower():
            context = ExecutionContext.GAME_MEMORY
        elif 'network' in discovery.name.lower() or 'packet' in discovery.name.lower():
            context = ExecutionContext.NETWORK_HANDLER
        elif 'behavior' in discovery.name.lower():
            context = ExecutionContext.BEHAVIORAL_ANALYSIS
        elif 'security' in discovery.name.lower():
            context = ExecutionContext.SECURITY_ANALYSIS
        
        # Determine risk level
        risk_level = metadata.get('risk_level', 2)
        if any(dangerous in discovery.name.lower() 
               for dangerous in ['write', 'delete', 'exec', 'system']):
            risk_level = 4
        
        return FunctionSignature(
            name=discovery.name,
            module=metadata.get('module', 'discovered'),
            address=metadata.get('address'),
            parameters=parameters,
            return_type=metadata.get('return_type'),
            context=context,
            risk_level=risk_level,
            description=metadata.get('description', f"Discovered function: {discovery.name}")
        )
    
    def _map_parameter_type(self, type_str: str) -> str:
        """Map discovered parameter type to ParameterType"""
        type_mapping = {
            'int': ParameterType.INTEGER.value,
            'integer': ParameterType.INTEGER.value,
            'float': ParameterType.FLOAT.value,
            'double': ParameterType.FLOAT.value,
            'str': ParameterType.STRING.value,
            'string': ParameterType.STRING.value,
            'bool': ParameterType.BOOLEAN.value,
            'boolean': ParameterType.BOOLEAN.value,
            'bytes': ParameterType.BYTES.value,
            'ptr': ParameterType.POINTER.value,
            'pointer': ParameterType.POINTER.value,
            'struct': ParameterType.STRUCT.value,
            'array': ParameterType.ARRAY.value,
            'list': ParameterType.ARRAY.value
        }
        return type_mapping.get(type_str.lower(), ParameterType.STRING.value)
    
    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a registered MCP tool"""
        if tool_name not in self.active_tools:
            return {
                'success': False,
                'error': f"Tool {tool_name} not found"
            }
        
        # Check if it's a function tool
        if tool_name in self.registered_functions:
            return await self.mcp_adapter.execute_mcp_tool(tool_name, arguments)
        
        # Handle other tool types (API endpoints, resources)
        tool_def = self.active_tools[tool_name]
        if hasattr(tool_def, 'endpoint'):
            return await self._execute_api_tool(tool_def, arguments)
        
        return {
            'success': False,
            'error': f"Tool type not supported for execution: {tool_name}"
        }
    
    async def _execute_api_tool(self, tool_def: ToolDefinition, 
                               arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute API endpoint tool"""
        # This would integrate with HTTP client to make actual API calls
        # For now, return mock response
        return {
            'success': True,
            'result': f"API call to {tool_def.name} executed",
            'arguments': arguments,
            'endpoint': getattr(tool_def, 'endpoint', 'unknown')
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status"""
        return {
            'status': self.status.value,
            'metrics': {
                'discoveries_processed': self.metrics.discoveries_processed,
                'tools_registered': self.metrics.tools_registered,
                'functions_integrated': self.metrics.functions_integrated,
                'data_structures_mapped': self.metrics.data_structures_mapped,
                'processing_time': self.metrics.processing_time,
                'last_update': self.metrics.last_update
            },
            'active_tools': list(self.active_tools.keys()),
            'registered_functions': list(self.registered_functions.keys()),
            'mapped_structures': list(self.mapped_structures.keys()),
            'config': {
                'auto_register_tools': self.config.auto_register_tools,
                'confidence_threshold': self.config.confidence_threshold,
                'risk_level_threshold': self.config.risk_level_threshold,
                'discovery_interval': self.config.discovery_interval
            }
        }
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Get list of all available MCP tools"""
        tools = []
        
        # Add function tools
        for name, signature in self.registered_functions.items():
            tools.append(self.mcp_adapter.create_mcp_tool_definition(signature))
        
        # Add other tool types
        for name, tool_def in self.active_tools.items():
            if name not in self.registered_functions:
                tools.append({
                    'name': tool_def.name,
                    'description': tool_def.description,
                    'type': 'resource' if hasattr(tool_def, 'data') else 'api',
                    'schema': getattr(tool_def, 'inputSchema', {})
                })
        
        return tools
    
    async def cleanup_old_data(self):
        """Cleanup old discoveries and data based on retention policy"""
        cutoff_time = time.time() - (self.config.data_retention_hours * 3600)
        
        # Cleanup old discoveries
        await self.discovery_engine.cleanup_old_discoveries(cutoff_time)
        
        # Remove old processed discovery IDs
        old_ids = {did for did in self.processed_discoveries 
                  if float(did.split('_')[-1]) < cutoff_time}
        self.processed_discoveries -= old_ids
        
        logger.info(f"Cleaned up {len(old_ids)} old discovery records")
    
    async def manual_discovery_trigger(self, source_path: Optional[str] = None) -> List[DiscoveryResult]:
        """Manually trigger discovery process"""
        logger.info("Manual discovery triggered")
        
        if source_path:
            discoveries = await self.discovery_engine.discover_from_path(Path(source_path))
        else:
            discoveries = await self.discovery_engine.discover_new_capabilities()
        
        # Queue for processing
        for discovery in discoveries:
            await self._queue_discovery_for_processing(discovery)
        
        logger.info(f"Manual discovery found {len(discoveries)} items")
        return discoveries