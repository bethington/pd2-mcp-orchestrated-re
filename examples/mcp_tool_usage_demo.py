#!/usr/bin/env python3
"""
MCP Tool Usage Demo

Demonstrates how the discovered D2 character structure would be used as MCP tools
in real Claude Code interaction scenarios.
"""

import asyncio
import json
import time
from typing import Dict, List, Any
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MCPToolSimulator:
    """Simulates how MCP tools would be used in Claude Code"""
    
    def __init__(self):
        # Simulated D2 character data from our discovered structure
        self.character_data = {
            'dwClassId': 1,           # Sorceress
            'szCharName': 'FireMage',
            'wLevel': 87,
            'dwExperience': 2156789320,
            'wStrength': 156,
            'wDexterity': 185,
            'wVitality': 241,
            'wEnergy': 350,           # High energy for Sorceress
            'wMaxLife': 1246,
            'wCurrentLife': 1246,
            'wMaxMana': 1650,         # High mana for Sorceress  
            'wCurrentMana': 1650,
            'wMaxStamina': 241,
            'wCurrentStamina': 241,
            'dwGold': 2500000,
            'dwGoldStash': 2500000,
            'wPlayerX': 25116,
            'wPlayerY': 5144,
            'dwGameSeed': 0x12345678,
            'bDifficulty': 2          # Hell difficulty
        }
        
        # Track tool usage
        self.tool_calls = []
        
    async def execute_mcp_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate executing an MCP tool"""
        start_time = time.time()
        
        # Log the tool call
        self.tool_calls.append({
            'tool': tool_name,
            'parameters': parameters,
            'timestamp': start_time
        })
        
        logger.info(f"🔧 Executing MCP Tool: {tool_name}")
        logger.info(f"   Parameters: {json.dumps(parameters, indent=2)}")
        
        # Route to appropriate handler
        if tool_name == "d2_get_character_stats":
            result = await self._get_character_stats(parameters)
        elif tool_name == "d2_get_character_info":
            result = await self._get_character_info(parameters)
        elif tool_name == "d2_get_combat_stats":
            result = await self._get_combat_stats(parameters)
        elif tool_name == "d2_get_location":
            result = await self._get_location(parameters)
        elif tool_name == "d2_monitor_health":
            result = await self._monitor_health(parameters)
        elif tool_name == "d2_analyze_build":
            result = await self._analyze_build(parameters)
        else:
            result = {'error': f'Unknown tool: {tool_name}', 'success': False}
        
        execution_time = time.time() - start_time
        result['execution_time'] = execution_time
        
        logger.info(f"✅ Tool Result: {json.dumps(result, indent=2)}")
        return result
    
    async def _get_character_stats(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get basic character statistics"""
        return {
            'success': True,
            'character': {
                'name': self.character_data['szCharName'],
                'level': self.character_data['wLevel'],
                'class': self._get_class_name(self.character_data['dwClassId']),
                'experience': self.character_data['dwExperience'],
                'attributes': {
                    'strength': self.character_data['wStrength'],
                    'dexterity': self.character_data['wDexterity'],
                    'vitality': self.character_data['wVitality'],
                    'energy': self.character_data['wEnergy']
                }
            }
        }
    
    async def _get_character_info(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed character information"""
        class_name = self._get_class_name(self.character_data['dwClassId'])
        difficulty = ['Normal', 'Nightmare', 'Hell'][self.character_data['bDifficulty']]
        
        return {
            'success': True,
            'character_info': {
                'name': self.character_data['szCharName'],
                'class': class_name,
                'level': self.character_data['wLevel'],
                'difficulty': difficulty,
                'gold_inventory': self.character_data['dwGold'],
                'gold_stash': self.character_data['dwGoldStash'],
                'game_seed': f"0x{self.character_data['dwGameSeed']:08X}",
                'total_experience': self.character_data['dwExperience'],
                'next_level_exp': self._calculate_next_level_exp(self.character_data['wLevel'])
            }
        }
    
    async def _get_combat_stats(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get combat-related statistics"""
        return {
            'success': True,
            'combat_stats': {
                'life': {
                    'current': self.character_data['wCurrentLife'],
                    'maximum': self.character_data['wMaxLife'],
                    'percentage': round((self.character_data['wCurrentLife'] / self.character_data['wMaxLife']) * 100, 1)
                },
                'mana': {
                    'current': self.character_data['wCurrentMana'],
                    'maximum': self.character_data['wMaxMana'],
                    'percentage': round((self.character_data['wCurrentMana'] / self.character_data['wMaxMana']) * 100, 1)
                },
                'stamina': {
                    'current': self.character_data['wCurrentStamina'],
                    'maximum': self.character_data['wMaxStamina'],
                    'percentage': round((self.character_data['wCurrentStamina'] / self.character_data['wMaxStamina']) * 100, 1)
                }
            }
        }
    
    async def _get_location(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get character location information"""
        return {
            'success': True,
            'location': {
                'x': self.character_data['wPlayerX'],
                'y': self.character_data['wPlayerY'],
                'coordinates': f"({self.character_data['wPlayerX']}, {self.character_data['wPlayerY']})",
                'area': self._get_area_from_coordinates(self.character_data['wPlayerX'], self.character_data['wPlayerY'])
            }
        }
    
    async def _monitor_health(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor character health status"""
        current_life = self.character_data['wCurrentLife']
        max_life = self.character_data['wMaxLife']
        life_percentage = (current_life / max_life) * 100
        
        # Determine health status
        if life_percentage >= 80:
            status = "healthy"
            warning = None
        elif life_percentage >= 50:
            status = "injured"
            warning = "Character health below 80%"
        elif life_percentage >= 25:
            status = "critical"
            warning = "Character health critically low!"
        else:
            status = "near_death"
            warning = "CHARACTER NEAR DEATH - IMMEDIATE ACTION REQUIRED!"
        
        return {
            'success': True,
            'health_monitor': {
                'status': status,
                'current_life': current_life,
                'max_life': max_life,
                'percentage': round(life_percentage, 1),
                'warning': warning,
                'recommendation': self._get_health_recommendation(life_percentage)
            }
        }
    
    async def _analyze_build(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze character build and provide recommendations"""
        class_id = self.character_data['dwClassId']
        class_name = self._get_class_name(class_id)
        
        # Analyze attribute distribution
        total_base_stats = 60  # Base stats for all classes
        invested_stats = (self.character_data['wStrength'] + 
                         self.character_data['wDexterity'] + 
                         self.character_data['wVitality'] + 
                         self.character_data['wEnergy'] - total_base_stats)
        
        stat_points_used = invested_stats
        
        analysis = {
            'class': class_name,
            'level': self.character_data['wLevel'],
            'stat_distribution': {
                'strength': self.character_data['wStrength'],
                'dexterity': self.character_data['wDexterity'],
                'vitality': self.character_data['wVitality'],
                'energy': self.character_data['wEnergy']
            },
            'total_stat_points_used': stat_points_used,
            'build_analysis': self._analyze_stat_distribution(class_id),
            'recommendations': self._get_build_recommendations(class_id)
        }
        
        return {
            'success': True,
            'build_analysis': analysis
        }
    
    def _get_class_name(self, class_id: int) -> str:
        """Get class name from class ID"""
        classes = {
            0: "Amazon",
            1: "Sorceress", 
            2: "Necromancer",
            3: "Paladin",
            4: "Barbarian",
            5: "Druid",
            6: "Assassin"
        }
        return classes.get(class_id, f"Unknown ({class_id})")
    
    def _calculate_next_level_exp(self, level: int) -> int:
        """Calculate experience needed for next level (simplified)"""
        if level >= 99:
            return 0
        # Simplified exp table - in reality this would be more complex
        return (level + 1) * 1000000
    
    def _get_area_from_coordinates(self, x: int, y: int) -> str:
        """Get area name from coordinates (simplified)"""
        # This would normally use a proper area lookup table
        if 25000 <= x <= 26000 and 5000 <= y <= 6000:
            return "Rogue Encampment"
        else:
            return f"Unknown Area (coords: {x}, {y})"
    
    def _get_health_recommendation(self, life_percentage: float) -> str:
        """Get health recommendation based on current life"""
        if life_percentage >= 80:
            return "Character is healthy"
        elif life_percentage >= 50:
            return "Consider using health potions"
        elif life_percentage >= 25:
            return "Use health potions immediately"
        else:
            return "URGENT: Use full rejuvenation potion or town portal to safety"
    
    def _analyze_stat_distribution(self, class_id: int) -> str:
        """Analyze character stat distribution for the class"""
        str_val = self.character_data['wStrength']
        dex_val = self.character_data['wDexterity'] 
        vit_val = self.character_data['wVitality']
        eng_val = self.character_data['wEnergy']
        
        if class_id == 1:  # Sorceress
            if eng_val > 200:
                return "High energy build - excellent for casting spells"
            else:
                return "Moderate energy build - balanced caster"
        else:
            return "Build analysis not available for this class"
    
    def _get_build_recommendations(self, class_id: int) -> List[str]:
        """Get build recommendations based on class and stats"""
        if class_id == 1:  # Sorceress
            return [
                "Energy build is good for spell casting",
                "Consider investing more in Vitality for survivability",
                "Strength looks adequate for equipment requirements",
                "Dexterity is sufficient for blocking"
            ]
        else:
            return ["Build recommendations not available for this class"]

class MCPUsageDemo:
    """Demonstrates practical MCP tool usage scenarios"""
    
    def __init__(self):
        self.tool_simulator = MCPToolSimulator()
        
    async def run_usage_scenarios(self):
        """Run various MCP tool usage scenarios"""
        logger.info("🎯 MCP Tool Usage Scenarios")
        logger.info("=" * 50)
        
        scenarios = [
            ("Basic Character Info", self._scenario_basic_info),
            ("Combat Status Check", self._scenario_combat_status),
            ("Health Monitoring", self._scenario_health_monitoring),
            ("Location Tracking", self._scenario_location_tracking),
            ("Build Analysis", self._scenario_build_analysis),
            ("Combined Analysis", self._scenario_combined_analysis)
        ]
        
        for scenario_name, scenario_func in scenarios:
            logger.info(f"\n📋 Scenario: {scenario_name}")
            logger.info("-" * 30)
            await scenario_func()
            await asyncio.sleep(0.5)  # Brief pause between scenarios
        
        await self._show_usage_summary()
    
    async def _scenario_basic_info(self):
        """Scenario: Getting basic character information"""
        logger.info("User asks: 'What's my character's current level and stats?'")
        
        result = await self.tool_simulator.execute_mcp_tool(
            "d2_get_character_stats", 
            {}
        )
        
        if result['success']:
            char = result['character']
            logger.info(f"🎮 Claude Response: Your character '{char['name']}' is a level {char['level']} {char['class']}.")
            logger.info(f"   Your attributes are: STR {char['attributes']['strength']}, DEX {char['attributes']['dexterity']}, VIT {char['attributes']['vitality']}, ENG {char['attributes']['energy']}")
    
    async def _scenario_combat_status(self):
        """Scenario: Checking combat readiness"""
        logger.info("User asks: 'Am I ready for combat? Check my life and mana.'")
        
        result = await self.tool_simulator.execute_mcp_tool(
            "d2_get_combat_stats",
            {}
        )
        
        if result['success']:
            combat = result['combat_stats']
            life_pct = combat['life']['percentage']
            mana_pct = combat['mana']['percentage']
            
            logger.info(f"🛡️ Claude Response: Your combat status:")
            logger.info(f"   Life: {combat['life']['current']}/{combat['life']['maximum']} ({life_pct}%)")
            logger.info(f"   Mana: {combat['mana']['current']}/{combat['mana']['maximum']} ({mana_pct}%)")
            
            if life_pct == 100 and mana_pct == 100:
                logger.info("   ✅ You're fully ready for combat!")
            else:
                logger.info("   ⚠️ Consider resting or using potions before combat.")
    
    async def _scenario_health_monitoring(self):
        """Scenario: Monitoring health during gameplay"""
        logger.info("User asks: 'Monitor my health status and warn me if I'm in danger.'")
        
        result = await self.tool_simulator.execute_mcp_tool(
            "d2_monitor_health",
            {}
        )
        
        if result['success']:
            health = result['health_monitor']
            logger.info(f"❤️ Claude Response: Health Status - {health['status'].upper()}")
            logger.info(f"   Life: {health['current_life']}/{health['max_life']} ({health['percentage']}%)")
            
            if health['warning']:
                logger.info(f"   ⚠️ WARNING: {health['warning']}")
            
            logger.info(f"   💡 Recommendation: {health['recommendation']}")
    
    async def _scenario_location_tracking(self):
        """Scenario: Tracking character location"""
        logger.info("User asks: 'Where am I currently located in the game?'")
        
        result = await self.tool_simulator.execute_mcp_tool(
            "d2_get_location",
            {}
        )
        
        if result['success']:
            location = result['location']
            logger.info(f"📍 Claude Response: You're currently at coordinates {location['coordinates']}")
            logger.info(f"   Area: {location['area']}")
    
    async def _scenario_build_analysis(self):
        """Scenario: Analyzing character build"""
        logger.info("User asks: 'Analyze my character build and give me recommendations.'")
        
        result = await self.tool_simulator.execute_mcp_tool(
            "d2_analyze_build",
            {}
        )
        
        if result['success']:
            analysis = result['build_analysis']
            logger.info(f"🏗️ Claude Response: Build Analysis for {analysis['class']} (Level {analysis['level']})")
            
            stats = analysis['stat_distribution']
            logger.info(f"   Stats: STR {stats['strength']}, DEX {stats['dexterity']}, VIT {stats['vitality']}, ENG {stats['energy']}")
            logger.info(f"   Analysis: {analysis['build_analysis']}")
            
            logger.info("   📝 Recommendations:")
            for i, rec in enumerate(analysis['recommendations'], 1):
                logger.info(f"      {i}. {rec}")
    
    async def _scenario_combined_analysis(self):
        """Scenario: Combined analysis using multiple tools"""
        logger.info("User asks: 'Give me a complete status report of my character.'")
        
        # Get character info
        char_info = await self.tool_simulator.execute_mcp_tool("d2_get_character_info", {})
        combat_stats = await self.tool_simulator.execute_mcp_tool("d2_get_combat_stats", {})
        location = await self.tool_simulator.execute_mcp_tool("d2_get_location", {})
        
        logger.info("📊 Claude Response: Complete Character Status Report")
        
        if char_info['success']:
            info = char_info['character_info']
            logger.info(f"   🎮 Character: {info['name']} ({info['class']}, Level {info['level']})")
            logger.info(f"   🎯 Difficulty: {info['difficulty']}")
            logger.info(f"   💰 Gold: {info['gold_inventory']:,} (Stash: {info['gold_stash']:,})")
        
        if combat_stats['success']:
            combat = combat_stats['combat_stats']
            logger.info(f"   ❤️ Life: {combat['life']['current']}/{combat['life']['maximum']} ({combat['life']['percentage']}%)")
            logger.info(f"   💙 Mana: {combat['mana']['current']}/{combat['mana']['maximum']} ({combat['mana']['percentage']}%)")
        
        if location['success']:
            loc = location['location']
            logger.info(f"   📍 Location: {loc['area']} at {loc['coordinates']}")
    
    async def _show_usage_summary(self):
        """Show summary of tool usage"""
        logger.info(f"\n📈 Usage Summary")
        logger.info("=" * 30)
        
        total_calls = len(self.tool_simulator.tool_calls)
        logger.info(f"✅ Total MCP Tool Calls: {total_calls}")
        
        # Count unique tools used
        unique_tools = set(call['tool'] for call in self.tool_simulator.tool_calls)
        logger.info(f"🔧 Unique Tools Used: {len(unique_tools)}")
        
        # Show tool usage frequency
        tool_frequency = {}
        for call in self.tool_simulator.tool_calls:
            tool = call['tool']
            tool_frequency[tool] = tool_frequency.get(tool, 0) + 1
        
        logger.info("📊 Tool Usage Frequency:")
        for tool, count in sorted(tool_frequency.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"   • {tool}: {count} times")
        
        logger.info("\n✨ MCP Integration Success!")
        logger.info("The discovered D2 character structure enables:")
        logger.info("  • Real-time character monitoring")
        logger.info("  • Automated health and status alerts") 
        logger.info("  • Build analysis and optimization")
        logger.info("  • Location and progress tracking")
        logger.info("  • Comprehensive gameplay assistance")

async def main():
    """Run the MCP tool usage demonstration"""
    demo = MCPUsageDemo()
    await demo.run_usage_scenarios()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"\n💥 Demo crashed: {e}")
        import traceback
        traceback.print_exc()