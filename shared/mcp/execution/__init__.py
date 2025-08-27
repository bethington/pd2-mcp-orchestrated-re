"""
MCP Execution Module

Function call proxy system for safe execution of discovered functions
through the Model Context Protocol.
"""

from .function_proxy import (
    FunctionCallProxy,
    FunctionSignature,
    ExecutionResult,
    ExecutionContext,
    ParameterType,
    SafetyValidator,
    ParameterMarshaller,
    MCPFunctionAdapter
)

__all__ = [
    'FunctionCallProxy',
    'FunctionSignature', 
    'ExecutionResult',
    'ExecutionContext',
    'ParameterType',
    'SafetyValidator',
    'ParameterMarshaller',
    'MCPFunctionAdapter'
]