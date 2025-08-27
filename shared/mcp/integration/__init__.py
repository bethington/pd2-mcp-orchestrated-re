"""
MCP Integration Module

Complete orchestration system for dynamic discovery and integration
of game analysis capabilities through the Model Context Protocol.
"""

from .orchestrator import (
    MCPIntegrationOrchestrator,
    IntegrationStatus,
    IntegrationMetrics,
    PipelineConfig
)

__all__ = [
    'MCPIntegrationOrchestrator',
    'IntegrationStatus', 
    'IntegrationMetrics',
    'PipelineConfig'
]