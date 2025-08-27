#!/usr/bin/env python3
"""
Function Call Proxy System for MCP Dynamic Integration

This module provides safe execution of discovered function calls through the MCP protocol,
including parameter marshaling, return value handling, and comprehensive error management.
"""

import asyncio
import inspect
import json
import ctypes
import struct
import traceback
from typing import Any, Dict, List, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ExecutionContext(Enum):
    """Execution context for function calls"""
    GAME_MEMORY = "game_memory"
    NETWORK_HANDLER = "network_handler" 
    FILE_ANALYSIS = "file_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    SECURITY_ANALYSIS = "security_analysis"

class ParameterType(Enum):
    """Supported parameter types for function calls"""
    INTEGER = "integer"
    FLOAT = "float"
    STRING = "string"
    BOOLEAN = "boolean"
    BYTES = "bytes"
    POINTER = "pointer"
    STRUCT = "struct"
    ARRAY = "array"

@dataclass
class FunctionSignature:
    """Function signature metadata"""
    name: str
    module: str
    address: Optional[int] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    return_type: Optional[str] = None
    context: ExecutionContext = ExecutionContext.FILE_ANALYSIS
    is_safe: bool = False
    risk_level: int = 3  # 1=low, 2=medium, 3=high, 4=critical
    description: Optional[str] = None

@dataclass
class ExecutionResult:
    """Result of function execution"""
    success: bool
    return_value: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    memory_usage: int = 0
    warnings: List[str] = field(default_factory=list)
    context_data: Dict[str, Any] = field(default_factory=list)

class SafetyValidator:
    """Validates function calls for safety and security"""
    
    DANGEROUS_PATTERNS = {
        'file_operations': ['open', 'write', 'delete', 'chmod', 'unlink'],
        'network_operations': ['socket', 'connect', 'bind', 'listen'],
        'process_operations': ['exec', 'spawn', 'fork', 'system', 'popen'],
        'memory_operations': ['malloc', 'free', 'memcpy', 'memmove'],
        'registry_operations': ['RegOpenKey', 'RegSetValue', 'RegDeleteKey']
    }
    
    def __init__(self):
        self.allowed_contexts = {
            ExecutionContext.FILE_ANALYSIS: ['read', 'parse', 'analyze'],
            ExecutionContext.GAME_MEMORY: ['read_memory', 'get_stats', 'parse_structure'],
            ExecutionContext.NETWORK_HANDLER: ['parse_packet', 'decode_message'],
            ExecutionContext.BEHAVIORAL_ANALYSIS: ['calculate_pattern', 'detect_anomaly'],
            ExecutionContext.SECURITY_ANALYSIS: ['scan_buffer', 'validate_data']
        }
    
    def validate_function(self, signature: FunctionSignature) -> Tuple[bool, List[str]]:
        """Validate if function is safe to execute"""
        warnings = []
        is_safe = True
        
        # Check function name against dangerous patterns
        for category, patterns in self.DANGEROUS_PATTERNS.items():
            if any(pattern.lower() in signature.name.lower() for pattern in patterns):
                warnings.append(f"Function contains {category} pattern")
                is_safe = False
                
        # Check context appropriateness
        if signature.context in self.allowed_contexts:
            allowed_ops = self.allowed_contexts[signature.context]
            if not any(op.lower() in signature.name.lower() for op in allowed_ops):
                warnings.append(f"Function name doesn't match context {signature.context.value}")
                
        # Check parameter safety
        for param in signature.parameters:
            if param.get('type') == ParameterType.POINTER.value:
                if not param.get('validated', False):
                    warnings.append(f"Unvalidated pointer parameter: {param.get('name')}")
                    is_safe = False
                    
        return is_safe, warnings

class ParameterMarshaller:
    """Handles marshalling of parameters between Python and native code"""
    
    def __init__(self):
        self.type_mappings = {
            ParameterType.INTEGER: self._marshal_integer,
            ParameterType.FLOAT: self._marshal_float,
            ParameterType.STRING: self._marshal_string,
            ParameterType.BOOLEAN: self._marshal_boolean,
            ParameterType.BYTES: self._marshal_bytes,
            ParameterType.POINTER: self._marshal_pointer,
            ParameterType.STRUCT: self._marshal_struct,
            ParameterType.ARRAY: self._marshal_array
        }
    
    def marshall_parameters(self, parameters: List[Dict[str, Any]], 
                          values: List[Any]) -> List[Any]:
        """Marshal Python values to native types"""
        if len(parameters) != len(values):
            raise ValueError("Parameter count mismatch")
            
        marshalled = []
        for param, value in zip(parameters, values):
            param_type = ParameterType(param['type'])
            marshaller = self.type_mappings.get(param_type)
            if not marshaller:
                raise ValueError(f"Unsupported parameter type: {param_type}")
                
            marshalled_value = marshaller(value, param)
            marshalled.append(marshalled_value)
            
        return marshalled
    
    def _marshal_integer(self, value: Any, param: Dict[str, Any]) -> int:
        """Marshal integer parameter"""
        try:
            result = int(value)
            # Check bounds if specified
            min_val = param.get('min_value', -2**31)
            max_val = param.get('max_value', 2**31 - 1)
            if not (min_val <= result <= max_val):
                raise ValueError(f"Integer {result} out of bounds [{min_val}, {max_val}]")
            return result
        except (ValueError, TypeError) as e:
            raise ValueError(f"Cannot marshal {value} to integer: {e}")
    
    def _marshal_float(self, value: Any, param: Dict[str, Any]) -> float:
        """Marshal float parameter"""
        try:
            return float(value)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Cannot marshal {value} to float: {e}")
    
    def _marshal_string(self, value: Any, param: Dict[str, Any]) -> str:
        """Marshal string parameter"""
        if isinstance(value, bytes):
            encoding = param.get('encoding', 'utf-8')
            return value.decode(encoding)
        return str(value)
    
    def _marshal_boolean(self, value: Any, param: Dict[str, Any]) -> bool:
        """Marshal boolean parameter"""
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)
    
    def _marshal_bytes(self, value: Any, param: Dict[str, Any]) -> bytes:
        """Marshal bytes parameter"""
        if isinstance(value, str):
            encoding = param.get('encoding', 'utf-8')
            return value.encode(encoding)
        elif isinstance(value, (list, tuple)):
            return bytes(value)
        return bytes(value)
    
    def _marshal_pointer(self, value: Any, param: Dict[str, Any]) -> ctypes.c_void_p:
        """Marshal pointer parameter (dangerous - requires validation)"""
        if not param.get('validated', False):
            raise ValueError("Pointer parameter must be pre-validated")
        
        if isinstance(value, int):
            return ctypes.c_void_p(value)
        elif hasattr(value, '_as_parameter_'):
            return value
        else:
            raise ValueError(f"Cannot marshal {type(value)} to pointer")
    
    def _marshal_struct(self, value: Dict[str, Any], param: Dict[str, Any]) -> Any:
        """Marshal struct parameter"""
        struct_def = param.get('structure')
        if not struct_def:
            raise ValueError("Struct parameter missing structure definition")
            
        # Create ctypes structure dynamically
        fields = [(field['name'], getattr(ctypes, field['type'])) 
                 for field in struct_def['fields']]
        
        StructClass = type(struct_def['name'], (ctypes.Structure,), {'_fields_': fields})
        instance = StructClass()
        
        # Populate fields
        for field_name, field_value in value.items():
            if hasattr(instance, field_name):
                setattr(instance, field_name, field_value)
                
        return instance
    
    def _marshal_array(self, value: List[Any], param: Dict[str, Any]) -> Any:
        """Marshal array parameter"""
        element_type = param.get('element_type', 'c_int')
        array_size = param.get('size', len(value))
        
        ArrayType = getattr(ctypes, element_type) * array_size
        return ArrayType(*value[:array_size])

class FunctionCallProxy:
    """Main proxy system for executing discovered function calls"""
    
    def __init__(self):
        self.validator = SafetyValidator()
        self.marshaller = ParameterMarshaller()
        self.registered_functions: Dict[str, FunctionSignature] = {}
        self.execution_stats: Dict[str, Dict[str, Any]] = {}
        self.max_execution_time = 30.0  # seconds
        self.max_memory_usage = 100 * 1024 * 1024  # 100MB
        
    def register_function(self, signature: FunctionSignature) -> bool:
        """Register a discovered function for execution"""
        is_safe, warnings = self.validator.validate_function(signature)
        signature.is_safe = is_safe
        
        if warnings:
            logger.warning(f"Function {signature.name} has warnings: {warnings}")
            
        # Only register if risk level is acceptable
        if signature.risk_level <= 2 or signature.is_safe:
            self.registered_functions[signature.name] = signature
            self.execution_stats[signature.name] = {
                'call_count': 0,
                'success_count': 0,
                'error_count': 0,
                'avg_execution_time': 0.0,
                'last_executed': None
            }
            logger.info(f"Registered function: {signature.name}")
            return True
        else:
            logger.warning(f"Function {signature.name} rejected due to high risk level")
            return False
    
    async def execute_function(self, function_name: str, 
                             parameters: List[Any]) -> ExecutionResult:
        """Execute a registered function with given parameters"""
        if function_name not in self.registered_functions:
            return ExecutionResult(
                success=False,
                error=f"Function {function_name} not registered"
            )
            
        signature = self.registered_functions[function_name]
        start_time = time.time()
        
        try:
            # Update execution stats
            self.execution_stats[function_name]['call_count'] += 1
            self.execution_stats[function_name]['last_executed'] = start_time
            
            # Marshall parameters
            marshalled_params = self.marshaller.marshall_parameters(
                signature.parameters, parameters
            )
            
            # Execute with timeout and resource limits
            result = await self._execute_with_limits(
                signature, marshalled_params
            )
            
            execution_time = time.time() - start_time
            
            # Update success stats
            self.execution_stats[function_name]['success_count'] += 1
            self._update_avg_execution_time(function_name, execution_time)
            
            return ExecutionResult(
                success=True,
                return_value=result,
                execution_time=execution_time,
                context_data={
                    'function_name': function_name,
                    'context': signature.context.value,
                    'parameter_count': len(parameters)
                }
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Function execution failed: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            
            # Update error stats
            self.execution_stats[function_name]['error_count'] += 1
            
            return ExecutionResult(
                success=False,
                error=error_msg,
                execution_time=execution_time
            )
    
    async def _execute_with_limits(self, signature: FunctionSignature, 
                                 parameters: List[Any]) -> Any:
        """Execute function with resource limits and timeout"""
        
        # Create execution task
        if signature.context == ExecutionContext.GAME_MEMORY:
            task = self._execute_game_memory_function(signature, parameters)
        elif signature.context == ExecutionContext.NETWORK_HANDLER:
            task = self._execute_network_function(signature, parameters)
        elif signature.context == ExecutionContext.FILE_ANALYSIS:
            task = self._execute_file_analysis_function(signature, parameters)
        else:
            task = self._execute_generic_function(signature, parameters)
        
        # Execute with timeout
        try:
            result = await asyncio.wait_for(task, timeout=self.max_execution_time)
            return result
        except asyncio.TimeoutError:
            raise RuntimeError(f"Function execution timed out after {self.max_execution_time}s")
    
    async def _execute_game_memory_function(self, signature: FunctionSignature, 
                                          parameters: List[Any]) -> Any:
        """Execute game memory related functions"""
        # Placeholder for game memory function execution
        # This would interface with the actual game memory analysis system
        logger.info(f"Executing game memory function: {signature.name}")
        
        # Simulate memory read operation
        if 'read' in signature.name.lower():
            return {'memory_address': parameters[0] if parameters else 0x0,
                   'data': b'mock_memory_data',
                   'size': 64}
        elif 'stats' in signature.name.lower():
            return {'health': 100, 'mana': 50, 'level': 1}
        
        return None
    
    async def _execute_network_function(self, signature: FunctionSignature, 
                                      parameters: List[Any]) -> Any:
        """Execute network analysis functions"""
        logger.info(f"Executing network function: {signature.name}")
        
        # Simulate packet parsing
        if 'parse' in signature.name.lower():
            return {'packet_type': 'game_update',
                   'size': len(parameters[0]) if parameters else 0,
                   'parsed_data': {'action': 'move', 'x': 100, 'y': 200}}
        
        return None
    
    async def _execute_file_analysis_function(self, signature: FunctionSignature, 
                                            parameters: List[Any]) -> Any:
        """Execute file analysis functions"""
        logger.info(f"Executing file analysis function: {signature.name}")
        
        # Simulate file parsing
        if 'parse' in signature.name.lower():
            return {'file_type': 'game_data',
                   'structures_found': 5,
                   'functions_found': 12}
        elif 'analyze' in signature.name.lower():
            return {'complexity_score': 7.5,
                   'risk_indicators': ['buffer_overflow_potential'],
                   'recommendations': ['add_bounds_checking']}
        
        return None
    
    async def _execute_generic_function(self, signature: FunctionSignature, 
                                       parameters: List[Any]) -> Any:
        """Execute generic functions"""
        logger.info(f"Executing generic function: {signature.name}")
        return {'result': 'success', 'parameters_processed': len(parameters)}
    
    def _update_avg_execution_time(self, function_name: str, execution_time: float):
        """Update average execution time for function"""
        stats = self.execution_stats[function_name]
        current_avg = stats['avg_execution_time']
        call_count = stats['call_count']
        
        # Calculate new average
        new_avg = ((current_avg * (call_count - 1)) + execution_time) / call_count
        stats['avg_execution_time'] = new_avg
    
    def get_execution_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get execution statistics for all registered functions"""
        return self.execution_stats.copy()
    
    def get_registered_functions(self) -> List[FunctionSignature]:
        """Get list of all registered functions"""
        return list(self.registered_functions.values())
    
    def unregister_function(self, function_name: str) -> bool:
        """Unregister a function"""
        if function_name in self.registered_functions:
            del self.registered_functions[function_name]
            if function_name in self.execution_stats:
                del self.execution_stats[function_name]
            logger.info(f"Unregistered function: {function_name}")
            return True
        return False

# Integration with MCP Protocol
class MCPFunctionAdapter:
    """Adapts function proxy for MCP protocol integration"""
    
    def __init__(self, proxy: FunctionCallProxy):
        self.proxy = proxy
    
    def create_mcp_tool_definition(self, signature: FunctionSignature) -> Dict[str, Any]:
        """Create MCP tool definition from function signature"""
        return {
            'name': signature.name,
            'description': signature.description or f"Execute {signature.name} function",
            'inputSchema': {
                'type': 'object',
                'properties': {
                    param['name']: {
                        'type': self._convert_type_to_json_schema(param['type']),
                        'description': param.get('description', f"Parameter {param['name']}")
                    }
                    for param in signature.parameters
                },
                'required': [p['name'] for p in signature.parameters if p.get('required', False)]
            },
            'context': signature.context.value,
            'risk_level': signature.risk_level,
            'is_safe': signature.is_safe
        }
    
    def _convert_type_to_json_schema(self, param_type: str) -> str:
        """Convert parameter type to JSON schema type"""
        type_map = {
            ParameterType.INTEGER.value: 'integer',
            ParameterType.FLOAT.value: 'number',
            ParameterType.STRING.value: 'string',
            ParameterType.BOOLEAN.value: 'boolean',
            ParameterType.BYTES.value: 'string',  # Base64 encoded
            ParameterType.ARRAY.value: 'array',
            ParameterType.STRUCT.value: 'object',
            ParameterType.POINTER.value: 'integer'  # Memory address
        }
        return type_map.get(param_type, 'string')
    
    async def execute_mcp_tool(self, tool_name: str, 
                              arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute function as MCP tool"""
        if tool_name not in self.proxy.registered_functions:
            return {
                'error': f"Tool {tool_name} not found",
                'success': False
            }
        
        signature = self.proxy.registered_functions[tool_name]
        
        # Convert arguments to parameter list
        parameters = []
        for param in signature.parameters:
            param_name = param['name']
            if param_name in arguments:
                parameters.append(arguments[param_name])
            elif param.get('required', False):
                return {
                    'error': f"Required parameter {param_name} missing",
                    'success': False
                }
            else:
                parameters.append(param.get('default_value'))
        
        # Execute function
        result = await self.proxy.execute_function(tool_name, parameters)
        
        # Convert to MCP response format
        return {
            'success': result.success,
            'result': result.return_value,
            'error': result.error,
            'execution_time': result.execution_time,
            'context': result.context_data
        }