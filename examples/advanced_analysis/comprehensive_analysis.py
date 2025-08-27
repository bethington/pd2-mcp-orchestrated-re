#!/usr/bin/env python3
"""
Example: Comprehensive D2 analysis with Claude orchestration
"""

import asyncio
import json
from datetime import datetime
import sys
import os

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.core.session_manager import SessionManager
from src.game.d2.character_tracker import CharacterTracker
from src.game.d2.inventory_manager import InventoryManager
from src.analysis.memory.analyzer import MemoryAnalyzer

class D2AnalysisSession:
    def __init__(self):
        self.session_manager = SessionManager()
        self.character_tracker = CharacterTracker()
        self.inventory_manager = InventoryManager()
        self.memory_analyzer = MemoryAnalyzer()
        self.session_id = None
        self.findings = []
        
    async def start_comprehensive_analysis(self):
        """Start comprehensive D2 analysis session"""
        print("🤖 Starting comprehensive Diablo 2 analysis...")
        
        # Initialize session
        self.session_id = await self.session_manager.create_session(
            binary_path="/game/pd2/ProjectD2/Game.exe",
            analysis_goals=["security", "performance", "cheat_detection", "protocol_analysis"]
        )
        
        print(f"✅ Analysis session started: {self.session_id}")
        
        # Start parallel analysis streams
        await asyncio.gather(
            self.monitor_gameplay_patterns(),
            self.analyze_memory_structures(), 
            self.monitor_inventory_changes(),
            self.detect_security_anomalies()
        )
        
    async def monitor_gameplay_patterns(self):
        """Monitor and analyze gameplay patterns"""
        print("📊 Monitoring gameplay patterns...")
        
        previous_state = None
        pattern_violations = 0
        
        for i in range(30):  # Monitor for 30 iterations (demo)
            try:
                # Get current game state
                character = await self.character_tracker.get_current_stats()
                
                if previous_state and "error" not in character:
                    # Simple pattern analysis
                    level_change = character.get("level", 0) - previous_state.get("level", 0)
                    exp_change = character.get("experience", 0) - previous_state.get("experience", 0)
                    
                    if level_change > 5:  # Rapid level gain
                        pattern_violations += 1
                        finding = {
                            "type": "rapid_level_gain",
                            "timestamp": datetime.now().isoformat(),
                            "description": f"Character gained {level_change} levels rapidly",
                            "confidence": "high",
                            "evidence": {
                                "old_level": previous_state.get("level"),
                                "new_level": character.get("level"),
                                "change": level_change
                            }
                        }
                        
                        self.findings.append(finding)
                        print(f"⚠️  Rapid level gain detected: {level_change} levels")
                        
                        if pattern_violations > 2:
                            print("🚨 Multiple suspicious patterns detected - recommending deeper analysis")
                            await self.escalate_analysis("rapid_progression")
                            
                previous_state = character
                await asyncio.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                print(f"Error in pattern monitoring: {e}")
                await asyncio.sleep(5)
                
    async def analyze_memory_structures(self):
        """Deep memory structure analysis"""
        print("🧠 Analyzing memory structures...")
        
        structures_to_analyze = ["character", "inventory"]
        
        for structure in structures_to_analyze:
            try:
                print(f"   Analyzing {structure} structure...")
                
                # Perform memory analysis
                analysis_result = await self.memory_analyzer.analyze_structure(
                    structure, "comprehensive"
                )
                
                if analysis_result and "error" not in analysis_result:
                    findings_count = len(analysis_result.get("findings", []))
                    anomalies_count = len(analysis_result.get("anomalies", []))
                    
                    print(f"   ✅ {structure}: {findings_count} findings, {anomalies_count} anomalies")
                    
                    if anomalies_count > 0:
                        print(f"   🚨 Anomalies found in {structure}:")
                        for anomaly in analysis_result["anomalies"]:
                            print(f"      - {anomaly['type']}: {anomaly['description']}")
                            
                        self.findings.extend(analysis_result["anomalies"])
                        
                    await self.session_manager.add_analysis_result(
                        self.session_id, f"memory_analysis_{structure}", analysis_result
                    )
                else:
                    print(f"   ❌ Failed to analyze {structure}: {analysis_result.get('error', 'Unknown error')}")
                        
            except Exception as e:
                print(f"Error analyzing {structure}: {e}")
                
            await asyncio.sleep(5)  # Pause between structure analyses
            
    async def monitor_inventory_changes(self):
        """Monitor and analyze inventory changes"""
        print("🎒 Monitoring inventory changes...")
        
        for i in range(10):  # Monitor for 10 iterations
            try:
                inventory = await self.inventory_manager.get_full_inventory()
                
                if inventory and "error" not in inventory:
                    total_items = inventory.get("total_items", 0)
                    total_value = inventory.get("total_value", 0)
                    
                    print(f"   📦 Inventory: {total_items} items, total value: {total_value}")
                    
                    # Check for suspicious patterns
                    suspicious = await self.inventory_manager.detect_suspicious_activity()
                    if suspicious:
                        print(f"   ⚠️  Suspicious inventory activity detected:")
                        for item in suspicious:
                            print(f"      - {item['type']}: {item['description']}")
                            
                        self.findings.extend(suspicious)
                        
                await asyncio.sleep(5)
                
            except Exception as e:
                print(f"Error in inventory monitoring: {e}")
                await asyncio.sleep(10)
                
    async def detect_security_anomalies(self):
        """Detect security anomalies and potential threats"""
        print("🔒 Detecting security anomalies...")
        
        for i in range(5):  # Run 5 security scans
            try:
                # Check character anomalies
                char_anomalies = await self.character_tracker.detect_anomalies()
                if char_anomalies:
                    print("🚨 Character anomalies detected:")
                    for anomaly in char_anomalies:
                        print(f"   - {anomaly['type']}: {anomaly['description']}")
                        
                    self.findings.extend(char_anomalies)
                    
                # Check inventory anomalies
                inv_anomalies = await self.inventory_manager.detect_suspicious_activity()
                if inv_anomalies:
                    print("🚨 Inventory anomalies detected:")
                    for anomaly in inv_anomalies:
                        print(f"   - {anomaly['type']}: {anomaly['description']}")
                        
                # Check memory anomalies
                memory_dump = await self.memory_analyzer.create_live_dump()
                if memory_dump and "error" not in memory_dump:
                    print(f"   ✅ Memory dump created: {len(memory_dump.get('structures', {}))} structures")
                    
                await asyncio.sleep(10)  # Security scan every 10 seconds
                
            except Exception as e:
                print(f"Error in security detection: {e}")
                await asyncio.sleep(15)
                
    async def escalate_analysis(self, reason: str):
        """Escalate analysis with additional investigation"""
        print(f"📈 Escalating analysis due to: {reason}")
        
        # Generate comprehensive report
        report = {
            "session_id": self.session_id,
            "escalation_reason": reason,
            "total_findings": len(self.findings),
            "findings_by_type": {},
            "recommendations": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Categorize findings
        for finding in self.findings:
            finding_type = finding.get("type", "unknown")
            if finding_type not in report["findings_by_type"]:
                report["findings_by_type"][finding_type] = 0
            report["findings_by_type"][finding_type] += 1
            
        # Generate recommendations
        if "rapid_level_gain" in [f.get("type") for f in self.findings]:
            report["recommendations"].append("Investigate experience gain mechanisms")
            
        if any("suspicious" in f.get("type", "") for f in self.findings):
            report["recommendations"].append("Perform detailed behavioral analysis")
            
        print("📋 ANALYSIS ESCALATION REPORT:")
        print(json.dumps(report, indent=2))
        
        # Save detailed report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"analysis_report_{timestamp}.json"
        
        try:
            with open(report_path, 'w') as f:
                json.dump({
                    "report": report,
                    "detailed_findings": self.findings
                }, f, indent=2)
                
            print(f"📄 Detailed report saved: {report_path}")
        except Exception as e:
            print(f"Failed to save report: {e}")

async def main():
    print("🎮 D2 Analysis Platform - Comprehensive Analysis Demo")
    print("=" * 60)
    
    session = D2AnalysisSession()
    try:
        await session.start_comprehensive_analysis()
        print("\n✅ Analysis completed successfully!")
        
    except KeyboardInterrupt:
        print("\n🛑 Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        
    print(f"\nFinal Summary:")
    print(f"- Session ID: {session.session_id}")
    print(f"- Total Findings: {len(session.findings)}")
    print(f"- Findings by Type:")
    
    finding_types = {}
    for finding in session.findings:
        ftype = finding.get("type", "unknown")
        finding_types[ftype] = finding_types.get(ftype, 0) + 1
        
    for ftype, count in finding_types.items():
        print(f"  - {ftype}: {count}")

if __name__ == "__main__":
    asyncio.run(main())
