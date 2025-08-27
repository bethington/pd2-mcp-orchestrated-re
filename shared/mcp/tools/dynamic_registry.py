"""
Dynamic MCP Tool Registration Framework

This framework allows for runtime registration and management of MCP tools
discovered through analysis, enabling the platform to expose new functionality
as it discovers new data structures and functions.
"""

import asyncio
import inspect
import json
import logging
from typing import Dict, List, Any, Callable, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import structlog

from ..core.event_bus import EventBus
from ..discovery.discovery_engine import Discovery, DiscoveryType

logger = structlog.get_logger()


class ToolCategory(Enum):
    """Categories of MCP tools"""
    DATA_ACCESS = "data_access"
    FUNCTION_CALL = "function_call"
    MEMORY_ANALYSIS = "memory_analysis"
    PATTERN_MATCHING = "pattern_matching"
    NETWORK_ANALYSIS = "network_analysis"
    BEHAVIOR_ANALYSIS = "behavior_analysis"
    UTILITY = "utility"


@dataclass
class ToolMetadata:
    """Metadata for a registered MCP tool"""
    name: str
    description: str
    category: ToolCategory
    parameters: Dict[str, Any]
    return_schema: Dict[str, Any]
    confidence: float
    source_discovery_id: Optional[str] = None
    created_at: datetime = None
    last_used: datetime = None
    usage_count: int = 0
    enabled: bool = True
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


class DynamicToolRegistry:
    """Registry for dynamically discovered and generated MCP tools"""
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        
        # Tool storage
        self.tools: Dict[str, Callable] = {}
        self.metadata: Dict[str, ToolMetadata] = {}
        self.tool_schemas: Dict[str, Dict[str, Any]] = {}
        
        # Categories and indexing
        self.tools_by_category: Dict[ToolCategory, List[str]] = {
            category: [] for category in ToolCategory
        }
        self.tools_by_discovery: Dict[str, List[str]] = {}
        
        # Tool generation templates
        self.tool_templates = {}
        self._setup_tool_templates()
        
        # Performance tracking
        self.performance_metrics: Dict[str, Dict[str, Any]] = {}
        
    async def register_tool(self, tool_name: str, tool_function: Callable, 
                          metadata: ToolMetadata, schema: Dict[str, Any] = None) -> bool:
        """Register a new MCP tool"""
        try:
            # Validate tool function
            if not callable(tool_function):
                raise ValueError("Tool function must be callable")
            
            # Generate schema if not provided
            if schema is None:
                schema = self._generate_tool_schema(tool_function, metadata)
            
            # Store tool and metadata
            self.tools[tool_name] = tool_function
            self.metadata[tool_name] = metadata
            self.tool_schemas[tool_name] = schema
            
            # Update category index
            self.tools_by_category[metadata.category].append(tool_name)
            
            # Update discovery index
            if metadata.source_discovery_id:
                if metadata.source_discovery_id not in self.tools_by_discovery:
                    self.tools_by_discovery[metadata.source_discovery_id] = []
                self.tools_by_discovery[metadata.source_discovery_id].append(tool_name)
            
            # Initialize performance tracking
            self.performance_metrics[tool_name] = {
                "total_calls": 0,
                "total_execution_time": 0.0,
                "average_execution_time": 0.0,
                "success_count": 0,
                "error_count": 0,
                "last_call_time": None
            }
            
            logger.info(f"Registered MCP tool: {tool_name} (category: {metadata.category.value})")
            
            # Publish registration event
            await self.event_bus.publish("tool_registered", {
                "tool_name": tool_name,
                "category": metadata.category.value,
                "discovery_id": metadata.source_discovery_id
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to register tool {tool_name}: {e}")
            return False
    
    async def unregister_tool(self, tool_name: str) -> bool:
        """Unregister an MCP tool"""
        if tool_name not in self.tools:
            return False
        
        try:
            metadata = self.metadata[tool_name]
            
            # Remove from indexes
            self.tools_by_category[metadata.category].remove(tool_name)
            
            if metadata.source_discovery_id:
                discovery_tools = self.tools_by_discovery.get(metadata.source_discovery_id, [])
                if tool_name in discovery_tools:
                    discovery_tools.remove(tool_name)
            
            # Remove tool data
            del self.tools[tool_name]
            del self.metadata[tool_name]
            del self.tool_schemas[tool_name]
            del self.performance_metrics[tool_name]
            
            logger.info(f"Unregistered MCP tool: {tool_name}")
            
            # Publish unregistration event
            await self.event_bus.publish("tool_unregistered", {
                "tool_name": tool_name
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister tool {tool_name}: {e}")
            return False
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a registered MCP tool"""
        if tool_name not in self.tools:
            return {"error": f"Tool not found: {tool_name}"}
        
        metadata = self.metadata[tool_name]
        
        if not metadata.enabled:
            return {"error": f"Tool disabled: {tool_name}"}
        
        tool_function = self.tools[tool_name]
        metrics = self.performance_metrics[tool_name]
        
        start_time = datetime.now()
        
        try:
            # Validate arguments against schema
            validation_result = self._validate_arguments(tool_name, arguments)
            if not validation_result["valid"]:
                return {"error": f"Invalid arguments: {validation_result['errors']}"}
            
            # Call the tool function
            if inspect.iscoroutinefunction(tool_function):
                result = await tool_function(**arguments)
            else:
                result = tool_function(**arguments)
            
            # Update performance metrics
            execution_time = (datetime.now() - start_time).total_seconds()
            self._update_performance_metrics(tool_name, execution_time, True)
            
            # Update metadata
            metadata.last_used = datetime.now()
            metadata.usage_count += 1
            
            logger.debug(f"Tool executed successfully: {tool_name} ({execution_time:.3f}s)")
            
            return {
                "success": True,
                "result": result,
                "execution_time": execution_time,
                "tool_metadata": {
                    "name": tool_name,
                    "category": metadata.category.value,
                    "confidence": metadata.confidence
                }
            }
            
        except Exception as e:
            # Update error metrics
            execution_time = (datetime.now() - start_time).total_seconds()
            self._update_performance_metrics(tool_name, execution_time, False)
            
            logger.error(f"Tool execution failed: {tool_name}: {e}")
            
            return {
                "success": False,
                "error": str(e),
                "execution_time": execution_time
            }
    
    def get_tool_list(self, category: ToolCategory = None, 
                     discovery_id: str = None, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """Get list of registered tools with optional filtering"""
        tools = []
        
        for tool_name, metadata in self.metadata.items():
            # Apply filters
            if enabled_only and not metadata.enabled:
                continue
            
            if category and metadata.category != category:
                continue
            
            if discovery_id and metadata.source_discovery_id != discovery_id:
                continue
            
            # Include schema and performance data
            tool_info = {
                "name": tool_name,
                "description": metadata.description,
                "category": metadata.category.value,
                "confidence": metadata.confidence,
                "usage_count": metadata.usage_count,
                "last_used": metadata.last_used.isoformat() if metadata.last_used else None,
                "schema": self.tool_schemas[tool_name],
                "performance": self.performance_metrics.get(tool_name, {})
            }
            
            if metadata.source_discovery_id:
                tool_info["source_discovery_id"] = metadata.source_discovery_id
            
            tools.append(tool_info)
        
        return sorted(tools, key=lambda t: t["usage_count"], reverse=True)
    
    def get_tool_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get schema for a specific tool"""
        return self.tool_schemas.get(tool_name)
    
    def get_tool_metadata(self, tool_name: str) -> Optional[ToolMetadata]:
        """Get metadata for a specific tool"""
        return self.metadata.get(tool_name)
    
    async def enable_tool(self, tool_name: str) -> bool:
        """Enable a tool"""
        if tool_name in self.metadata:
            self.metadata[tool_name].enabled = True
            return True
        return False
    
    async def disable_tool(self, tool_name: str) -> bool:
        """Disable a tool"""
        if tool_name in self.metadata:
            self.metadata[tool_name].enabled = False
            return True
        return False
    
    def get_performance_statistics(self) -> Dict[str, Any]:
        """Get overall performance statistics"""
        total_tools = len(self.tools)
        enabled_tools = sum(1 for m in self.metadata.values() if m.enabled)
        total_calls = sum(m["total_calls"] for m in self.performance_metrics.values())
        total_errors = sum(m["error_count"] for m in self.performance_metrics.values())
        
        category_stats = {}
        for category in ToolCategory:
            category_tools = self.tools_by_category[category]
            category_stats[category.value] = {
                "tool_count": len(category_tools),
                "total_calls": sum(
                    self.performance_metrics.get(tool, {}).get("total_calls", 0) 
                    for tool in category_tools
                ),
                "average_confidence": sum(
                    self.metadata.get(tool, ToolMetadata("", "", category, {}, {}, 0.0)).confidence
                    for tool in category_tools
                ) / len(category_tools) if category_tools else 0
            }
        
        return {
            "total_tools": total_tools,
            "enabled_tools": enabled_tools,
            "total_calls": total_calls,
            "total_errors": total_errors,
            "success_rate": (total_calls - total_errors) / total_calls if total_calls > 0 else 0,
            "category_stats": category_stats,
            "discovery_coverage": len(self.tools_by_discovery)
        }
    
    def _generate_tool_schema(self, tool_function: Callable, metadata: ToolMetadata) -> Dict[str, Any]:
        """Generate JSON schema for a tool based on its function signature"""
        try:
            signature = inspect.signature(tool_function)
            parameters = {}
            required = []
            
            for param_name, param in signature.parameters.items():
                # Skip 'self' parameter
                if param_name == 'self':
                    continue
                
                param_schema = {"type": "string"}  # Default type
                
                # Try to infer type from annotation
                if param.annotation != inspect.Parameter.empty:
                    if param.annotation == int:
                        param_schema["type"] = "integer"
                    elif param.annotation == float:
                        param_schema["type"] = "number"
                    elif param.annotation == bool:
                        param_schema["type"] = "boolean"
                    elif param.annotation == list:
                        param_schema["type"] = "array"
                    elif param.annotation == dict:
                        param_schema["type"] = "object"
                
                # Check if parameter is required (no default value)
                if param.default == inspect.Parameter.empty:
                    required.append(param_name)
                else:
                    param_schema["default"] = param.default
                
                parameters[param_name] = param_schema
            
            schema = {
                "type": "object",
                "properties": parameters,
                "required": required,
                "description": metadata.description
            }
            
            return schema
            
        except Exception as e:
            logger.warning(f"Failed to generate schema for tool: {e}")
            return {
                "type": "object",
                "properties": {},
                "required": [],
                "description": metadata.description
            }
    
    def _validate_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Validate tool arguments against schema"""
        schema = self.tool_schemas.get(tool_name)
        if not schema:
            return {"valid": True, "errors": []}
        
        errors = []
        
        # Check required parameters
        required = schema.get("required", [])
        for req_param in required:
            if req_param not in arguments:
                errors.append(f"Missing required parameter: {req_param}")
        
        # Check parameter types (basic validation)
        properties = schema.get("properties", {})
        for param_name, param_value in arguments.items():
            if param_name in properties:
                expected_type = properties[param_name].get("type")
                if expected_type == "integer" and not isinstance(param_value, int):
                    errors.append(f"Parameter {param_name} must be integer")
                elif expected_type == "number" and not isinstance(param_value, (int, float)):
                    errors.append(f"Parameter {param_name} must be number")
                elif expected_type == "boolean" and not isinstance(param_value, bool):
                    errors.append(f"Parameter {param_name} must be boolean")
                elif expected_type == "array" and not isinstance(param_value, list):
                    errors.append(f"Parameter {param_name} must be array")
                elif expected_type == "object" and not isinstance(param_value, dict):
                    errors.append(f"Parameter {param_name} must be object")
        
        return {"valid": len(errors) == 0, "errors": errors}
    
    def _update_performance_metrics(self, tool_name: str, execution_time: float, success: bool):
        """Update performance metrics for a tool"""
        metrics = self.performance_metrics[tool_name]
        
        metrics["total_calls"] += 1
        metrics["total_execution_time"] += execution_time
        metrics["average_execution_time"] = metrics["total_execution_time"] / metrics["total_calls"]
        metrics["last_call_time"] = datetime.now().isoformat()
        
        if success:
            metrics["success_count"] += 1
        else:
            metrics["error_count"] += 1
    
    def _setup_tool_templates(self):
        """Setup templates for generating tools from discoveries"""
        self.tool_templates = {
            DiscoveryType.DATA_STRUCTURE: self._create_data_structure_tool_template,
            DiscoveryType.FUNCTION_CALL: self._create_function_call_tool_template,
            DiscoveryType.MEMORY_PATTERN: self._create_pattern_tool_template
        }
    
    def _create_data_structure_tool_template(self, discovery: Discovery) -> Dict[str, Any]:
        """Create tool template for data structure access"""
        signature = discovery.signature
        
        async def structure_access_tool(session_id: str, address: str = None, 
                                      fields: List[str] = None) -> Dict[str, Any]:
            """Access discovered data structure"""
            # This would be implemented to actually read from memory
            result = {
                "structure_name": discovery.name,
                "address": address,
                "size": signature.get("size", 0),
                "fields": {}
            }
            
            # Read specific fields if requested
            target_fields = fields or [f.get("name") for f in signature.get("fields", [])]
            
            for field_info in signature.get("fields", []):
                field_name = field_info.get("name")
                if field_name and (not fields or field_name in target_fields):
                    result["fields"][field_name] = {
                        "type": field_info.get("type", "unknown"),
                        "offset": field_info.get("offset", 0),
                        "size": field_info.get("size", 0),
                        "value": None  # Would read actual value
                    }
            
            return result
        
        metadata = ToolMetadata(
            name=f"get_{discovery.name.lower()}_data",
            description=f"Access {discovery.name} data structure ({signature.get('size', 0)} bytes)",
            category=ToolCategory.DATA_ACCESS,
            parameters={
                "session_id": {"type": "string", "required": True},
                "address": {"type": "string", "required": False},
                "fields": {"type": "array", "required": False}
            },
            return_schema={
                "type": "object",
                "properties": {
                    "structure_name": {"type": "string"},
                    "address": {"type": "string"},
                    "size": {"type": "integer"},
                    "fields": {"type": "object"}
                }
            },
            confidence=discovery.confidence,
            source_discovery_id=discovery.id
        )
        
        return {
            "tool_function": structure_access_tool,
            "metadata": metadata
        }
    
    def _create_function_call_tool_template(self, discovery: Discovery) -> Dict[str, Any]:
        """Create tool template for function calls"""
        signature = discovery.signature
        
        async def function_call_tool(session_id: str, **kwargs) -> Dict[str, Any]:
            """Call discovered function"""
            result = {
                "function_name": discovery.name,
                "address": signature.get("address"),
                "parameters_passed": kwargs,
                "return_value": None,  # Would contain actual return value
                "execution_success": True
            }
            
            return result
        
        # Build parameter schema from discovered function signature
        parameters = {"session_id": {"type": "string", "required": True}}
        for param in signature.get("parameters", []):
            param_name = param.get("name", f"param_{param.get('index', 0)}")
            param_type = param.get("type", "string")
            
            # Map C types to JSON schema types
            if param_type in ["int", "uint32", "int32"]:
                parameters[param_name] = {"type": "integer"}
            elif param_type in ["float", "double"]:
                parameters[param_name] = {"type": "number"}
            elif param_type in ["bool"]:
                parameters[param_name] = {"type": "boolean"}
            else:
                parameters[param_name] = {"type": "string"}
        
        metadata = ToolMetadata(
            name=f"call_{discovery.name.lower()}",
            description=f"Call {discovery.name} function at {signature.get('address')}",
            category=ToolCategory.FUNCTION_CALL,
            parameters=parameters,
            return_schema={
                "type": "object",
                "properties": {
                    "function_name": {"type": "string"},
                    "address": {"type": "string"},
                    "return_value": {},
                    "execution_success": {"type": "boolean"}
                }
            },
            confidence=discovery.confidence,
            source_discovery_id=discovery.id
        )
        
        return {
            "tool_function": function_call_tool,
            "metadata": metadata
        }
    
    def _create_pattern_tool_template(self, discovery: Discovery) -> Dict[str, Any]:
        """Create tool template for pattern matching"""
        signature = discovery.signature
        
        async def pattern_matching_tool(session_id: str, search_range: str = None,
                                      max_matches: int = 10) -> Dict[str, Any]:
            """Find memory pattern matches"""
            result = {
                "pattern_name": discovery.name,
                "pattern_type": signature.get("pattern_type"),
                "search_range": search_range,
                "matches": [],  # Would contain actual matches
                "total_matches_found": 0
            }
            
            return result
        
        metadata = ToolMetadata(
            name=f"find_{discovery.name.lower()}_pattern",
            description=f"Find {discovery.name} pattern in memory",
            category=ToolCategory.PATTERN_MATCHING,
            parameters={
                "session_id": {"type": "string", "required": True},
                "search_range": {"type": "string", "required": False},
                "max_matches": {"type": "integer", "required": False, "default": 10}
            },
            return_schema={
                "type": "object",
                "properties": {
                    "pattern_name": {"type": "string"},
                    "matches": {"type": "array"},
                    "total_matches_found": {"type": "integer"}
                }
            },
            confidence=discovery.confidence,
            source_discovery_id=discovery.id
        )
        
        return {
            "tool_function": pattern_matching_tool,
            "metadata": metadata
        }
    
    async def create_tool_from_discovery(self, discovery: Discovery) -> bool:
        """Create and register a tool from a discovery"""
        try:
            # Get appropriate template
            template_func = self.tool_templates.get(discovery.type)
            if not template_func:
                logger.warning(f"No template for discovery type: {discovery.type}")
                return False
            
            # Generate tool from template
            tool_data = template_func(discovery)
            tool_function = tool_data["tool_function"]
            metadata = tool_data["metadata"]
            
            # Register the tool
            return await self.register_tool(metadata.name, tool_function, metadata)
            
        except Exception as e:
            logger.error(f"Failed to create tool from discovery {discovery.id}: {e}")
            return False