#!/usr/bin/env python3
"""
MCP Dynamic Integration Example

Demonstrates how to use the complete MCP integration system to:
1. Discover new data structures and functions from game analysis
2. Dynamically register them as MCP tools
3. Execute them through the MCP protocol

This example shows the full pipeline from discovery to execution.
"""

import asyncio
import json
import time
from pathlib import Path
import logging

# Import our MCP integration system
from shared.mcp.integration import (
    MCPIntegrationOrchestrator, 
    PipelineConfig, 
    IntegrationStatus
)
from shared.mcp.discovery import DiscoveryEngine, DiscoveryResult
from shared.mcp.execution import ExecutionContext, ParameterType

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MCPIntegrationDemo:
    """Demonstration of the complete MCP integration system"""
    
    def __init__(self):
        # Configure the integration pipeline
        self.config = PipelineConfig(
            auto_register_tools=True,
            max_concurrent_processing=3,
            confidence_threshold=0.6,
            risk_level_threshold=2,
            enable_function_execution=True,
            discovery_interval=15.0,  # Discover every 15 seconds for demo
            data_retention_hours=1    # Short retention for demo
        )
        
        self.orchestrator = MCPIntegrationOrchestrator(self.config)
        
    async def run_demo(self):
        """Run the complete integration demo"""
        logger.info("🚀 Starting MCP Dynamic Integration Demo")
        
        try:
            # Step 1: Start the orchestrator
            await self.orchestrator.start()
            logger.info("✅ Integration orchestrator started")
            
            # Step 2: Simulate some discoveries
            await self._simulate_discoveries()
            
            # Step 3: Wait for processing
            await self._wait_for_processing()
            
            # Step 4: Show available tools
            await self._show_available_tools()
            
            # Step 5: Execute some tools
            await self._execute_tools()
            
            # Step 6: Show final status
            await self._show_final_status()
            
        except KeyboardInterrupt:
            logger.info("Demo interrupted by user")
        except Exception as e:
            logger.error(f"Demo error: {e}")
        finally:
            await self.orchestrator.stop()
            logger.info("🛑 Integration orchestrator stopped")
    
    async def _simulate_discoveries(self):
        """Simulate discovering new game analysis capabilities"""
        logger.info("🔍 Simulating discovery of new capabilities...")
        
        # Simulate discovering a character stats function
        character_stats_discovery = DiscoveryResult(
            type="function",
            name="get_character_stats",
            confidence=0.85,
            timestamp=time.time(),
            source_file="game_memory_analysis.exe",
            metadata={
                'description': 'Retrieves current character statistics from game memory',
                'module': 'character_module',
                'address': 0x00401000,
                'parameters': [
                    {
                        'name': 'character_id',
                        'type': 'integer',
                        'required': True,
                        'description': 'Unique character identifier'
                    }
                ],
                'return_type': 'struct',
                'risk_level': 1  # Low risk - read-only
            }
        )
        
        # Simulate discovering a inventory data structure
        inventory_structure_discovery = DiscoveryResult(
            type="data_structure",
            name="InventorySlot",
            confidence=0.92,
            timestamp=time.time(),
            source_file="game_structures.h",
            metadata={
                'description': 'Game inventory slot structure',
                'size': 64,
                'fields': [
                    {'name': 'item_id', 'type': 'c_uint32', 'offset': 0},
                    {'name': 'quantity', 'type': 'c_uint16', 'offset': 4},
                    {'name': 'durability', 'type': 'c_uint16', 'offset': 6},
                    {'name': 'enchantments', 'type': 'c_uint32', 'offset': 8, 'array_size': 8}
                ],
                'alignment': 4
            }
        )
        
        # Simulate discovering a packet parsing function
        packet_parser_discovery = DiscoveryResult(
            type="function",
            name="parse_game_packet",
            confidence=0.78,
            timestamp=time.time(),
            source_file="network_analysis.dll",
            metadata={
                'description': 'Parses incoming game network packets',
                'module': 'network_module',
                'parameters': [
                    {
                        'name': 'packet_data',
                        'type': 'bytes',
                        'required': True,
                        'description': 'Raw packet data'
                    },
                    {
                        'name': 'packet_size',
                        'type': 'integer',
                        'required': True,
                        'description': 'Size of packet data'
                    }
                ],
                'return_type': 'struct',
                'risk_level': 1
            }
        )
        
        # Simulate discovering an API endpoint
        api_discovery = DiscoveryResult(
            type="api_endpoint",
            name="game_session_status",
            confidence=0.88,
            timestamp=time.time(),
            source_file="web_interface.py",
            metadata={
                'description': 'Get current game session status',
                'url': 'http://localhost:8765/game/session',
                'method': 'GET',
                'parameters': {
                    'session_id': {
                        'type': 'string',
                        'description': 'Game session identifier'
                    }
                },
                'required_params': []
            }
        )
        
        # Queue discoveries for processing
        discoveries = [
            character_stats_discovery,
            inventory_structure_discovery, 
            packet_parser_discovery,
            api_discovery
        ]
        
        for discovery in discoveries:
            await self.orchestrator._queue_discovery_for_processing(discovery)
            logger.info(f"   📋 Queued discovery: {discovery.name} ({discovery.type})")
        
        logger.info(f"✅ Simulated {len(discoveries)} discoveries")
    
    async def _wait_for_processing(self):
        """Wait for discoveries to be processed"""
        logger.info("⏳ Waiting for discovery processing...")
        
        # Wait up to 30 seconds for processing
        for i in range(30):
            status = self.orchestrator.get_status()
            
            if status['metrics']['discoveries_processed'] >= 4:
                logger.info("✅ All discoveries processed!")
                break
            
            if i % 5 == 0:  # Log every 5 seconds
                logger.info(f"   Processing status: {status['status']}, "
                           f"processed: {status['metrics']['discoveries_processed']}/4")
            
            await asyncio.sleep(1)
        
        # Show processing results
        status = self.orchestrator.get_status()
        metrics = status['metrics']
        logger.info(f"📊 Processing Results:")
        logger.info(f"   • Discoveries processed: {metrics['discoveries_processed']}")
        logger.info(f"   • Tools registered: {metrics['tools_registered']}")
        logger.info(f"   • Functions integrated: {metrics['functions_integrated']}")
        logger.info(f"   • Data structures mapped: {metrics['data_structures_mapped']}")
    
    async def _show_available_tools(self):
        """Show all available MCP tools"""
        logger.info("🔧 Available MCP Tools:")
        
        tools = self.orchestrator.get_available_tools()
        
        if not tools:
            logger.info("   No tools available yet")
            return
        
        for i, tool in enumerate(tools, 1):
            logger.info(f"   {i}. {tool['name']}")
            logger.info(f"      Description: {tool['description']}")
            logger.info(f"      Type: {tool.get('type', 'function')}")
            
            # Show input schema if available
            schema = tool.get('inputSchema', {})
            if schema.get('properties'):
                logger.info(f"      Parameters:")
                for param_name, param_info in schema['properties'].items():
                    required = " (required)" if param_name in schema.get('required', []) else ""
                    logger.info(f"        - {param_name}: {param_info.get('type', 'unknown')}{required}")
            logger.info("")
    
    async def _execute_tools(self):
        """Execute some of the available tools"""
        logger.info("🎯 Executing MCP Tools...")
        
        # Try to execute character stats function
        result = await self.orchestrator.execute_tool(
            "get_character_stats",
            {"character_id": 12345}
        )
        
        if result['success']:
            logger.info("✅ get_character_stats execution result:")
            logger.info(f"   Result: {json.dumps(result['result'], indent=2)}")
            logger.info(f"   Execution time: {result.get('execution_time', 0):.3f}s")
        else:
            logger.error(f"❌ get_character_stats failed: {result.get('error')}")
        
        # Try to execute packet parser
        test_packet_data = b"\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08"
        result = await self.orchestrator.execute_tool(
            "parse_game_packet",
            {
                "packet_data": test_packet_data.hex(),  # Send as hex string
                "packet_size": len(test_packet_data)
            }
        )
        
        if result['success']:
            logger.info("✅ parse_game_packet execution result:")
            logger.info(f"   Result: {json.dumps(result['result'], indent=2)}")
        else:
            logger.error(f"❌ parse_game_packet failed: {result.get('error')}")
        
        # Try to execute API endpoint tool
        result = await self.orchestrator.execute_tool(
            "api_game_session_status",
            {"session_id": "demo_session_001"}
        )
        
        if result['success']:
            logger.info("✅ api_game_session_status execution result:")
            logger.info(f"   Result: {json.dumps(result['result'], indent=2)}")
        else:
            logger.error(f"❌ api_game_session_status failed: {result.get('error')}")
    
    async def _show_final_status(self):
        """Show final status and statistics"""
        logger.info("📈 Final Integration Status:")
        
        status = self.orchestrator.get_status()
        
        logger.info(f"   Status: {status['status']}")
        logger.info(f"   Active Tools: {len(status['active_tools'])}")
        logger.info(f"   Registered Functions: {len(status['registered_functions'])}")
        logger.info(f"   Mapped Structures: {len(status['mapped_structures'])}")
        
        metrics = status['metrics']
        logger.info(f"   Total Processing Time: {metrics['processing_time']:.2f}s")
        
        # Show function execution stats
        execution_stats = self.orchestrator.function_proxy.get_execution_stats()
        if execution_stats:
            logger.info("📊 Function Execution Statistics:")
            for func_name, stats in execution_stats.items():
                success_rate = (stats['success_count'] / stats['call_count'] * 100) if stats['call_count'] > 0 else 0
                logger.info(f"   {func_name}:")
                logger.info(f"     Calls: {stats['call_count']}, "
                           f"Success Rate: {success_rate:.1f}%, "
                           f"Avg Time: {stats['avg_execution_time']:.3f}s")

async def main():
    """Run the MCP integration demonstration"""
    demo = MCPIntegrationDemo()
    await demo.run_demo()

if __name__ == "__main__":
    print("🎮 MCP Dynamic Integration Demo")
    print("=====================================")
    print("This demo shows how new game analysis capabilities")
    print("are automatically discovered and integrated as MCP tools.")
    print()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"\n💥 Demo crashed: {e}")
        import traceback
        traceback.print_exc()