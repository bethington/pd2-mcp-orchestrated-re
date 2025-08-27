"""
MCP Platform Shared Libraries

This package contains shared utilities, models, and components used across
the MCP-orchestrated reverse engineering platform.

Modules:
    mcp: Model Context Protocol implementations
    analysis: Analysis utilities and algorithms
    game: Game-specific logic and interfaces  
    data: Data models and storage abstractions
    security: Security utilities and authentication
    testing: Shared testing utilities and fixtures
"""

__version__ = "1.0.0"
__author__ = "MCP Platform Team"

# Package-level imports for convenience
from . import mcp, analysis, game, data

__all__ = ["mcp", "analysis", "game", "data"]