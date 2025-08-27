#!/bin/bash
set -e

echo "🚀 Starting Live MCP Integration Server..."

# Create necessary directories
mkdir -p /app/logs
mkdir -p /app/data

# Set Python path
export PYTHONPATH="/app:/app/shared:$PYTHONPATH"

echo "📁 Python path: $PYTHONPATH"
echo "📊 System info:"
python3 --version
pip --version

# Install any missing dependencies
echo "📦 Installing dependencies..."
pip install --no-cache-dir fastapi uvicorn structlog aiohttp

# Check if shared modules are available
echo "🔍 Checking shared modules..."
ls -la /app/shared/ || echo "⚠️  Shared modules not found - running in standalone mode"

echo "🎯 Starting Live MCP Integration Server on port 8000..."

# Run the live integration server
cd /app
python3 src/mcp_integration_server.py
