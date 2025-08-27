"""
Dynamic Discovery Engine for MCP Integration

This engine automatically discovers new data structures and function calls
during analysis and integrates them into the MCP protocol ecosystem.
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import structlog

from ..core.event_bus import EventBus
from ..data.models import DataStructure, FunctionSignature, DiscoveryResult

logger = structlog.get_logger()


class DiscoveryType(Enum):
    """Types of discoveries that can be made"""
    DATA_STRUCTURE = "data_structure"
    FUNCTION_CALL = "function_call"
    MEMORY_PATTERN = "memory_pattern"
    NETWORK_PROTOCOL = "network_protocol"
    API_ENDPOINT = "api_endpoint"
    BEHAVIOR_PATTERN = "behavior_pattern"


@dataclass
class Discovery:
    """Represents a discovered element"""
    id: str
    type: DiscoveryType
    name: str
    description: str
    signature: Dict[str, Any]
    confidence: float
    discovered_at: datetime
    source: str  # Which analysis tool discovered it
    session_id: str
    validation_status: str = "pending"  # pending, validated, rejected
    integration_status: str = "pending"  # pending, integrated, failed
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class DiscoveryEngine:
    """Main engine for discovering and integrating new structures/functions"""
    
    def __init__(self, event_bus: EventBus, mcp_orchestrator):
        self.event_bus = event_bus
        self.mcp_orchestrator = mcp_orchestrator
        
        # Discovery storage
        self.discoveries: Dict[str, Discovery] = {}
        self.integration_queue = asyncio.Queue()
        self.validation_queue = asyncio.Queue()
        
        # Discovery patterns and validators
        self.structure_patterns = {}
        self.function_patterns = {}
        self.validators: Dict[DiscoveryType, Callable] = {}
        self.integrators: Dict[DiscoveryType, Callable] = {}
        
        # Integration tracking
        self.active_integrations: Set[str] = set()
        self.integration_history: List[Dict[str, Any]] = []
        
        # Configuration
        self.min_confidence_threshold = 0.7
        self.auto_integrate_threshold = 0.9
        self.max_discoveries_per_session = 100
        
        self._setup_default_patterns()
        self._setup_validators()
        self._setup_integrators()
        
    async def start(self):
        """Start the discovery engine"""
        logger.info("Starting discovery engine...")
        
        # Subscribe to analysis events
        await self.event_bus.subscribe("memory_analysis_result", self._handle_memory_analysis)
        await self.event_bus.subscribe("function_discovered", self._handle_function_discovery)
        await self.event_bus.subscribe("network_pattern_found", self._handle_network_discovery)
        await self.event_bus.subscribe("behavior_pattern_detected", self._handle_behavior_discovery)
        
        # Start processing queues
        asyncio.create_task(self._validation_worker())
        asyncio.create_task(self._integration_worker())
        
        logger.info("Discovery engine started")
    
    async def process_analysis_result(self, analysis_result: Dict[str, Any]) -> List[Discovery]:
        """Process analysis results and extract discoveries"""
        session_id = analysis_result.get("session_id", "unknown")
        source = analysis_result.get("source", "unknown")
        
        discoveries = []
        
        # Check for data structure discoveries
        if "structures" in analysis_result:
            for struct_data in analysis_result["structures"]:
                discovery = await self._create_structure_discovery(
                    struct_data, session_id, source
                )
                if discovery:
                    discoveries.append(discovery)
        
        # Check for function call discoveries
        if "functions" in analysis_result:
            for func_data in analysis_result["functions"]:
                discovery = await self._create_function_discovery(
                    func_data, session_id, source
                )
                if discovery:
                    discoveries.append(discovery)
        
        # Check for memory pattern discoveries
        if "patterns" in analysis_result:
            for pattern_data in analysis_result["patterns"]:
                discovery = await self._create_pattern_discovery(
                    pattern_data, session_id, source
                )
                if discovery:
                    discoveries.append(discovery)
        
        # Store discoveries and queue for processing
        for discovery in discoveries:
            self.discoveries[discovery.id] = discovery
            
            # Queue for validation
            await self.validation_queue.put(discovery)
            
            # Publish discovery event
            await self.event_bus.publish("discovery_made", {
                "discovery_id": discovery.id,
                "type": discovery.type.value,
                "name": discovery.name,
                "confidence": discovery.confidence,
                "session_id": session_id
            })
        
        logger.info(f"Processed analysis result: {len(discoveries)} discoveries found")
        return discoveries
    
    async def _create_structure_discovery(self, struct_data: Dict[str, Any], 
                                        session_id: str, source: str) -> Optional[Discovery]:
        """Create a data structure discovery"""
        try:
            # Extract structure information
            name = struct_data.get("name", f"struct_{struct_data.get('address', 'unknown')}")
            size = struct_data.get("size", 0)
            fields = struct_data.get("fields", [])
            
            # Calculate confidence based on structure completeness
            confidence = self._calculate_structure_confidence(struct_data)
            
            if confidence < self.min_confidence_threshold:
                return None
            
            # Create signature
            signature = {
                "name": name,
                "size": size,
                "fields": fields,
                "alignment": struct_data.get("alignment", 4),
                "address": struct_data.get("address"),
                "access_pattern": struct_data.get("access_pattern", {}),
                "type_hints": struct_data.get("type_hints", {})
            }
            
            discovery_id = f"struct_{session_id}_{name}_{int(datetime.now().timestamp())}"
            
            return Discovery(
                id=discovery_id,
                type=DiscoveryType.DATA_STRUCTURE,
                name=name,
                description=f"Data structure with {len(fields)} fields ({size} bytes)",
                signature=signature,
                confidence=confidence,
                discovered_at=datetime.now(),
                source=source,
                session_id=session_id,
                metadata={
                    "analysis_context": struct_data.get("context", {}),
                    "related_functions": struct_data.get("related_functions", []),
                    "usage_frequency": struct_data.get("usage_frequency", 0)
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to create structure discovery: {e}")
            return None
    
    async def _create_function_discovery(self, func_data: Dict[str, Any],
                                       session_id: str, source: str) -> Optional[Discovery]:
        """Create a function call discovery"""
        try:
            # Extract function information
            name = func_data.get("name", f"func_{func_data.get('address', 'unknown')}")
            address = func_data.get("address")
            parameters = func_data.get("parameters", [])
            return_type = func_data.get("return_type", "unknown")
            
            # Calculate confidence
            confidence = self._calculate_function_confidence(func_data)
            
            if confidence < self.min_confidence_threshold:
                return None
            
            # Create signature
            signature = {
                "name": name,
                "address": address,
                "parameters": parameters,
                "return_type": return_type,
                "calling_convention": func_data.get("calling_convention", "unknown"),
                "stack_frame_size": func_data.get("stack_frame_size", 0),
                "is_exported": func_data.get("is_exported", False),
                "analysis_confidence": confidence
            }
            
            discovery_id = f"func_{session_id}_{name}_{int(datetime.now().timestamp())}"
            
            return Discovery(
                id=discovery_id,
                type=DiscoveryType.FUNCTION_CALL,
                name=name,
                description=f"Function with {len(parameters)} parameters -> {return_type}",
                signature=signature,
                confidence=confidence,
                discovered_at=datetime.now(),
                source=source,
                session_id=session_id,
                metadata={
                    "call_frequency": func_data.get("call_frequency", 0),
                    "call_sites": func_data.get("call_sites", []),
                    "cross_references": func_data.get("cross_references", [])
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to create function discovery: {e}")
            return None
    
    async def _create_pattern_discovery(self, pattern_data: Dict[str, Any],
                                      session_id: str, source: str) -> Optional[Discovery]:
        """Create a memory/behavior pattern discovery"""
        try:
            pattern_type = pattern_data.get("type", "unknown")
            name = pattern_data.get("name", f"pattern_{pattern_type}")
            
            confidence = pattern_data.get("confidence", 0.5)
            
            if confidence < self.min_confidence_threshold:
                return None
            
            signature = {
                "pattern_type": pattern_type,
                "pattern_data": pattern_data.get("pattern", {}),
                "occurrence_count": pattern_data.get("occurrence_count", 1),
                "locations": pattern_data.get("locations", []),
                "correlation_data": pattern_data.get("correlations", {})
            }
            
            discovery_id = f"pattern_{session_id}_{pattern_type}_{int(datetime.now().timestamp())}"
            
            return Discovery(
                id=discovery_id,
                type=DiscoveryType.MEMORY_PATTERN,
                name=name,
                description=f"{pattern_type} pattern ({pattern_data.get('occurrence_count', 1)} occurrences)",
                signature=signature,
                confidence=confidence,
                discovered_at=datetime.now(),
                source=source,
                session_id=session_id,
                metadata=pattern_data.get("metadata", {})
            )
            
        except Exception as e:
            logger.error(f"Failed to create pattern discovery: {e}")
            return None
    
    async def _validation_worker(self):
        """Worker to validate discoveries"""
        while True:
            try:
                discovery = await self.validation_queue.get()
                
                # Validate the discovery
                is_valid = await self._validate_discovery(discovery)
                
                if is_valid:
                    discovery.validation_status = "validated"
                    logger.info(f"Discovery validated: {discovery.id}")
                    
                    # Queue for integration if confidence is high enough
                    if discovery.confidence >= self.auto_integrate_threshold:
                        await self.integration_queue.put(discovery)
                    
                    await self.event_bus.publish("discovery_validated", {
                        "discovery_id": discovery.id,
                        "type": discovery.type.value
                    })
                else:
                    discovery.validation_status = "rejected"
                    logger.warning(f"Discovery rejected: {discovery.id}")
                
                self.validation_queue.task_done()
                
            except Exception as e:
                logger.error(f"Validation worker error: {e}")
                await asyncio.sleep(1)
    
    async def _integration_worker(self):
        """Worker to integrate validated discoveries into MCP"""
        while True:
            try:
                discovery = await self.integration_queue.get()
                
                if discovery.validation_status != "validated":
                    continue
                
                # Integrate the discovery
                success = await self._integrate_discovery(discovery)
                
                if success:
                    discovery.integration_status = "integrated"
                    logger.info(f"Discovery integrated: {discovery.id}")
                    
                    await self.event_bus.publish("discovery_integrated", {
                        "discovery_id": discovery.id,
                        "type": discovery.type.value,
                        "name": discovery.name
                    })
                else:
                    discovery.integration_status = "failed"
                    logger.error(f"Discovery integration failed: {discovery.id}")
                
                # Record integration history
                self.integration_history.append({
                    "discovery_id": discovery.id,
                    "type": discovery.type.value,
                    "name": discovery.name,
                    "success": success,
                    "timestamp": datetime.now().isoformat()
                })
                
                self.integration_queue.task_done()
                
            except Exception as e:
                logger.error(f"Integration worker error: {e}")
                await asyncio.sleep(1)
    
    def _calculate_structure_confidence(self, struct_data: Dict[str, Any]) -> float:
        """Calculate confidence score for a data structure discovery"""
        score = 0.0
        
        # Base score for having basic structure info
        if "size" in struct_data and struct_data["size"] > 0:
            score += 0.3
        
        # Score for having field information
        fields = struct_data.get("fields", [])
        if fields:
            score += 0.4
            # Bonus for detailed field info
            detailed_fields = sum(1 for f in fields if "type" in f and "offset" in f)
            if detailed_fields > 0:
                score += 0.2 * (detailed_fields / len(fields))
        
        # Score for usage context
        if "access_pattern" in struct_data:
            score += 0.1
        
        # Score for type hints
        if "type_hints" in struct_data and struct_data["type_hints"]:
            score += 0.1
        
        # Score for related functions
        if "related_functions" in struct_data and struct_data["related_functions"]:
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_function_confidence(self, func_data: Dict[str, Any]) -> float:
        """Calculate confidence score for a function discovery"""
        score = 0.0
        
        # Base score for having address
        if "address" in func_data:
            score += 0.2
        
        # Score for having parameters
        params = func_data.get("parameters", [])
        if params:
            score += 0.3
            # Bonus for typed parameters
            typed_params = sum(1 for p in params if "type" in p)
            if typed_params > 0:
                score += 0.2 * (typed_params / len(params))
        
        # Score for return type
        if "return_type" in func_data and func_data["return_type"] != "unknown":
            score += 0.2
        
        # Score for calling convention
        if "calling_convention" in func_data and func_data["calling_convention"] != "unknown":
            score += 0.1
        
        # Score for cross-references
        if "cross_references" in func_data and func_data["cross_references"]:
            score += 0.1
        
        # Score for call frequency (indicates actual usage)
        call_freq = func_data.get("call_frequency", 0)
        if call_freq > 0:
            score += min(0.1, call_freq / 100)  # Cap at 0.1
        
        return min(score, 1.0)
    
    def _setup_default_patterns(self):
        """Setup default patterns for discovery"""
        # Common D2 data structures
        self.structure_patterns = {
            "player_data": {
                "size_range": (1000, 5000),
                "required_fields": ["level", "experience", "stats"],
                "field_patterns": {
                    "level": {"type": "uint32", "range": (1, 99)},
                    "experience": {"type": "uint32", "range": (0, 2000000000)}
                }
            },
            "item_data": {
                "size_range": (50, 500),
                "required_fields": ["id", "type", "properties"],
                "field_patterns": {
                    "id": {"type": "uint32"},
                    "type": {"type": "uint32"}
                }
            }
        }
        
        # Common function patterns
        self.function_patterns = {
            "game_api": {
                "name_patterns": ["Get.*", "Set.*", "Update.*"],
                "parameter_count_range": (0, 10),
                "common_types": ["uint32", "int32", "void*", "char*"]
            }
        }
    
    def _setup_validators(self):
        """Setup validators for different discovery types"""
        self.validators[DiscoveryType.DATA_STRUCTURE] = self._validate_data_structure
        self.validators[DiscoveryType.FUNCTION_CALL] = self._validate_function_call
        self.validators[DiscoveryType.MEMORY_PATTERN] = self._validate_memory_pattern
    
    def _setup_integrators(self):
        """Setup integrators for different discovery types"""
        self.integrators[DiscoveryType.DATA_STRUCTURE] = self._integrate_data_structure
        self.integrators[DiscoveryType.FUNCTION_CALL] = self._integrate_function_call
        self.integrators[DiscoveryType.MEMORY_PATTERN] = self._integrate_memory_pattern
    
    async def _validate_discovery(self, discovery: Discovery) -> bool:
        """Validate a discovery using appropriate validator"""
        validator = self.validators.get(discovery.type)
        if validator:
            return await validator(discovery)
        return False
    
    async def _integrate_discovery(self, discovery: Discovery) -> bool:
        """Integrate a discovery using appropriate integrator"""
        integrator = self.integrators.get(discovery.type)
        if integrator:
            return await integrator(discovery)
        return False
    
    async def _validate_data_structure(self, discovery: Discovery) -> bool:
        """Validate a data structure discovery"""
        signature = discovery.signature
        
        # Check basic requirements
        if not signature.get("size") or signature["size"] <= 0:
            return False
        
        fields = signature.get("fields", [])
        if not fields:
            return False
        
        # Check field consistency
        total_field_size = 0
        for field in fields:
            if "size" not in field or "offset" not in field:
                return False
            
            total_field_size += field["size"]
        
        # Size should be reasonable compared to fields
        if total_field_size > signature["size"] * 2:  # Allow some padding
            return False
        
        return True
    
    async def _validate_function_call(self, discovery: Discovery) -> bool:
        """Validate a function call discovery"""
        signature = discovery.signature
        
        # Check basic requirements
        if not signature.get("address"):
            return False
        
        # Validate parameters
        parameters = signature.get("parameters", [])
        for param in parameters:
            if "type" not in param:
                return False
        
        return True
    
    async def _validate_memory_pattern(self, discovery: Discovery) -> bool:
        """Validate a memory pattern discovery"""
        signature = discovery.signature
        
        # Check pattern data exists
        if not signature.get("pattern_data"):
            return False
        
        # Check occurrence count is reasonable
        occurrence_count = signature.get("occurrence_count", 0)
        if occurrence_count < 1:
            return False
        
        return True
    
    async def _integrate_data_structure(self, discovery: Discovery) -> bool:
        """Integrate a data structure discovery into MCP"""
        try:
            # Create MCP tool for accessing this structure
            tool_name = f"get_{discovery.name.lower()}_data"
            
            # Generate tool function
            tool_function = self._generate_structure_accessor_tool(discovery)
            
            # Register with MCP orchestrator
            await self.mcp_orchestrator.register_dynamic_tool(
                tool_name, tool_function, discovery.signature
            )
            
            logger.info(f"Integrated data structure as MCP tool: {tool_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to integrate data structure {discovery.id}: {e}")
            return False
    
    async def _integrate_function_call(self, discovery: Discovery) -> bool:
        """Integrate a function call discovery into MCP"""
        try:
            # Create MCP tool for calling this function
            tool_name = f"call_{discovery.name.lower()}"
            
            # Generate tool function
            tool_function = self._generate_function_call_tool(discovery)
            
            # Register with MCP orchestrator
            await self.mcp_orchestrator.register_dynamic_tool(
                tool_name, tool_function, discovery.signature
            )
            
            logger.info(f"Integrated function call as MCP tool: {tool_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to integrate function call {discovery.id}: {e}")
            return False
    
    async def _integrate_memory_pattern(self, discovery: Discovery) -> bool:
        """Integrate a memory pattern discovery into MCP"""
        try:
            # Create MCP tool for pattern matching
            tool_name = f"find_{discovery.name.lower()}_pattern"
            
            # Generate tool function
            tool_function = self._generate_pattern_finder_tool(discovery)
            
            # Register with MCP orchestrator
            await self.mcp_orchestrator.register_dynamic_tool(
                tool_name, tool_function, discovery.signature
            )
            
            logger.info(f"Integrated memory pattern as MCP tool: {tool_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to integrate memory pattern {discovery.id}: {e}")
            return False
    
    def _generate_structure_accessor_tool(self, discovery: Discovery) -> Callable:
        """Generate MCP tool function for accessing a data structure"""
        signature = discovery.signature
        
        async def structure_accessor_tool(session_id: str, address: str = None) -> Dict[str, Any]:
            """Dynamically generated tool for accessing discovered data structure"""
            try:
                # Implementation would interact with memory analysis tools
                # to read the structure at the given address
                result = {
                    "structure_name": discovery.name,
                    "size": signature["size"],
                    "fields": {},
                    "source_discovery": discovery.id,
                    "address": address
                }
                
                # Read field values (placeholder implementation)
                for field in signature.get("fields", []):
                    field_name = field.get("name", f"field_{field.get('offset', 0)}")
                    result["fields"][field_name] = {
                        "type": field.get("type", "unknown"),
                        "value": "placeholder",  # Would read actual value
                        "offset": field.get("offset", 0)
                    }
                
                return result
                
            except Exception as e:
                return {"error": f"Failed to read structure: {str(e)}"}
        
        return structure_accessor_tool
    
    def _generate_function_call_tool(self, discovery: Discovery) -> Callable:
        """Generate MCP tool function for calling a discovered function"""
        signature = discovery.signature
        
        async def function_call_tool(session_id: str, **kwargs) -> Dict[str, Any]:
            """Dynamically generated tool for calling discovered function"""
            try:
                # Implementation would set up function call with discovered signature
                result = {
                    "function_name": discovery.name,
                    "address": signature["address"],
                    "parameters_passed": kwargs,
                    "source_discovery": discovery.id,
                    "call_result": "placeholder"  # Would contain actual result
                }
                
                return result
                
            except Exception as e:
                return {"error": f"Failed to call function: {str(e)}"}
        
        return function_call_tool
    
    def _generate_pattern_finder_tool(self, discovery: Discovery) -> Callable:
        """Generate MCP tool function for finding memory patterns"""
        signature = discovery.signature
        
        async def pattern_finder_tool(session_id: str, search_range: str = None) -> Dict[str, Any]:
            """Dynamically generated tool for finding memory patterns"""
            try:
                result = {
                    "pattern_name": discovery.name,
                    "pattern_type": signature["pattern_type"],
                    "matches_found": [],  # Would contain actual matches
                    "source_discovery": discovery.id,
                    "search_range": search_range
                }
                
                return result
                
            except Exception as e:
                return {"error": f"Failed to find pattern: {str(e)}"}
        
        return pattern_finder_tool
    
    # Event handlers
    async def _handle_memory_analysis(self, event_data: Dict[str, Any]):
        """Handle memory analysis results"""
        await self.process_analysis_result(event_data)
    
    async def _handle_function_discovery(self, event_data: Dict[str, Any]):
        """Handle function discovery events"""
        await self.process_analysis_result(event_data)
    
    async def _handle_network_discovery(self, event_data: Dict[str, Any]):
        """Handle network pattern discovery events"""
        await self.process_analysis_result(event_data)
    
    async def _handle_behavior_discovery(self, event_data: Dict[str, Any]):
        """Handle behavior pattern discovery events"""  
        await self.process_analysis_result(event_data)
    
    # Public API methods
    async def get_discoveries(self, session_id: str = None, 
                            discovery_type: DiscoveryType = None) -> List[Discovery]:
        """Get discoveries with optional filtering"""
        discoveries = list(self.discoveries.values())
        
        if session_id:
            discoveries = [d for d in discoveries if d.session_id == session_id]
        
        if discovery_type:
            discoveries = [d for d in discoveries if d.type == discovery_type]
        
        return sorted(discoveries, key=lambda d: d.discovered_at, reverse=True)
    
    async def force_integrate(self, discovery_id: str) -> bool:
        """Force integration of a specific discovery"""
        discovery = self.discoveries.get(discovery_id)
        if not discovery:
            return False
        
        if discovery.validation_status != "validated":
            # Validate first
            is_valid = await self._validate_discovery(discovery)
            if not is_valid:
                return False
            discovery.validation_status = "validated"
        
        # Queue for integration
        await self.integration_queue.put(discovery)
        return True
    
    async def get_integration_statistics(self) -> Dict[str, Any]:
        """Get statistics about discovery and integration"""
        total_discoveries = len(self.discoveries)
        validated = len([d for d in self.discoveries.values() 
                        if d.validation_status == "validated"])
        integrated = len([d for d in self.discoveries.values() 
                         if d.integration_status == "integrated"])
        
        type_breakdown = {}
        for discovery_type in DiscoveryType:
            count = len([d for d in self.discoveries.values() if d.type == discovery_type])
            type_breakdown[discovery_type.value] = count
        
        return {
            "total_discoveries": total_discoveries,
            "validated": validated,
            "integrated": integrated,
            "validation_rate": validated / total_discoveries if total_discoveries > 0 else 0,
            "integration_rate": integrated / validated if validated > 0 else 0,
            "type_breakdown": type_breakdown,
            "recent_integrations": self.integration_history[-10:]  # Last 10
        }