"""
Automated Triage System
Intelligent prioritization and workflow automation for reverse engineering
"""

import asyncio
import structlog
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import json
import hashlib

logger = structlog.get_logger()

class PriorityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

class AnalysisStage(Enum):
    INTAKE = "intake"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    MEMORY_FORENSICS = "memory_forensics"
    AI_CLASSIFICATION = "ai_classification"
    MANUAL_REVIEW = "manual_review"
    COMPLETED = "completed"

@dataclass
class TriageDecision:
    priority: PriorityLevel
    recommended_tools: List[str]
    analysis_depth: str
    estimated_time: str
    resource_allocation: Dict[str, Any]
    reasoning: List[str]
    confidence: float

class AutomatedTriageEngine:
    """Intelligent triage and workflow automation system"""
    
    def __init__(self):
        self.triage_rules = {}
        self.workflow_templates = {}
        self.resource_limits = {
            "max_concurrent_analyses": 5,
            "cpu_cores_per_analysis": 2,
            "memory_gb_per_analysis": 4,
            "max_analysis_time_hours": 24
        }
        self.active_analyses = {}
        self._initialize_triage_rules()
        self._initialize_workflow_templates()
    
    def _initialize_triage_rules(self):
        """Initialize intelligent triage rules"""
        self.triage_rules = {
            "file_size_based": {
                "very_large": {"threshold": 100 * 1024 * 1024, "priority_modifier": 0.2},
                "large": {"threshold": 10 * 1024 * 1024, "priority_modifier": 0.1},
                "normal": {"threshold": 1 * 1024 * 1024, "priority_modifier": 0.0},
                "small": {"threshold": 0, "priority_modifier": -0.1}
            },
            
            "entropy_based": {
                "very_high": {"threshold": 7.8, "priority": PriorityLevel.HIGH, "weight": 0.3},
                "high": {"threshold": 7.0, "priority": PriorityLevel.MEDIUM, "weight": 0.2},
                "normal": {"threshold": 6.0, "priority": PriorityLevel.LOW, "weight": 0.0},
                "low": {"threshold": 0.0, "priority": PriorityLevel.MINIMAL, "weight": -0.1}
            },
            
            "api_pattern_based": {
                "malicious_apis": {
                    "apis": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
                    "priority": PriorityLevel.CRITICAL,
                    "weight": 0.4
                },
                "network_apis": {
                    "apis": ["WSAStartup", "InternetOpen", "HttpOpenRequest"],
                    "priority": PriorityLevel.HIGH,
                    "weight": 0.3
                },
                "crypto_apis": {
                    "apis": ["CryptEncrypt", "CryptDecrypt", "CryptHashData"],
                    "priority": PriorityLevel.MEDIUM,
                    "weight": 0.2
                }
            },
            
            "behavior_based": {
                "persistence_indicators": {
                    "indicators": ["registry_modification", "service_creation", "startup_modification"],
                    "priority": PriorityLevel.HIGH,
                    "weight": 0.3
                },
                "evasion_techniques": {
                    "indicators": ["packing", "obfuscation", "anti_debug"],
                    "priority": PriorityLevel.HIGH,
                    "weight": 0.35
                },
                "data_exfiltration": {
                    "indicators": ["network_communication", "file_access", "encryption"],
                    "priority": PriorityLevel.CRITICAL,
                    "weight": 0.4
                }
            }
        }
    
    def _initialize_workflow_templates(self):
        """Initialize automated workflow templates"""
        self.workflow_templates = {
            "quick_scan": {
                "stages": [AnalysisStage.STATIC_ANALYSIS],
                "tools": ["binary_analyzer", "yara_scanner"],
                "max_time": "15 minutes",
                "resource_usage": "minimal"
            },
            
            "standard_analysis": {
                "stages": [
                    AnalysisStage.STATIC_ANALYSIS,
                    AnalysisStage.DYNAMIC_ANALYSIS,
                    AnalysisStage.AI_CLASSIFICATION
                ],
                "tools": ["binary_analyzer", "ghidra_decompiler", "frida_tracer", "ai_classifier"],
                "max_time": "2 hours",
                "resource_usage": "medium"
            },
            
            "comprehensive_analysis": {
                "stages": [
                    AnalysisStage.STATIC_ANALYSIS,
                    AnalysisStage.DYNAMIC_ANALYSIS,
                    AnalysisStage.MEMORY_FORENSICS,
                    AnalysisStage.AI_CLASSIFICATION,
                    AnalysisStage.MANUAL_REVIEW
                ],
                "tools": [
                    "binary_analyzer", "ghidra_decompiler", "frida_tracer",
                    "memory_forensics", "ai_classifier", "pattern_matcher"
                ],
                "max_time": "8 hours",
                "resource_usage": "high"
            },
            
            "malware_focused": {
                "stages": [
                    AnalysisStage.STATIC_ANALYSIS,
                    AnalysisStage.DYNAMIC_ANALYSIS,
                    AnalysisStage.MEMORY_FORENSICS,
                    AnalysisStage.AI_CLASSIFICATION
                ],
                "tools": [
                    "binary_analyzer", "yara_scanner", "frida_tracer",
                    "memory_forensics", "threat_classifier", "behavior_analyzer"
                ],
                "max_time": "4 hours",
                "resource_usage": "high"
            },
            
            "game_specific": {
                "stages": [
                    AnalysisStage.STATIC_ANALYSIS,
                    AnalysisStage.MEMORY_FORENSICS,
                    AnalysisStage.AI_CLASSIFICATION
                ],
                "tools": [
                    "binary_analyzer", "game_structure_analyzer", 
                    "memory_forensics", "pattern_matcher"
                ],
                "max_time": "3 hours",
                "resource_usage": "medium"
            }
        }
    
    async def perform_intelligent_triage(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform intelligent triage analysis"""
        try:
            triage_result = {
                "sample_id": sample_data.get("sample_id", "unknown"),
                "triage_timestamp": datetime.now().isoformat(),
                "decision": None,
                "priority_factors": [],
                "recommended_workflow": None,
                "resource_allocation": {},
                "next_actions": [],
                "confidence_score": 0.0
            }
            
            # Extract sample characteristics
            characteristics = self._extract_sample_characteristics(sample_data)
            
            # Calculate priority score
            priority_result = self._calculate_priority_score(characteristics)
            triage_result["priority_factors"] = priority_result["factors"]
            
            # Determine analysis workflow
            workflow = self._determine_analysis_workflow(characteristics, priority_result)
            triage_result["recommended_workflow"] = workflow
            
            # Calculate resource allocation
            resources = self._calculate_resource_allocation(workflow, priority_result["priority"])
            triage_result["resource_allocation"] = resources
            
            # Generate triage decision
            decision = TriageDecision(
                priority=priority_result["priority"],
                recommended_tools=workflow["tools"],
                analysis_depth=workflow["depth"],
                estimated_time=workflow["estimated_time"],
                resource_allocation=resources,
                reasoning=priority_result["reasoning"],
                confidence=priority_result["confidence"]
            )
            triage_result["decision"] = self._serialize_decision(decision)
            
            # Generate next actions
            next_actions = self._generate_next_actions(decision, characteristics)
            triage_result["next_actions"] = next_actions
            
            triage_result["confidence_score"] = priority_result["confidence"]
            
            logger.info("Intelligent triage completed",
                       priority=decision.priority.value,
                       confidence=decision.confidence,
                       workflow=workflow["template"])
            
            return triage_result
            
        except Exception as e:
            logger.error("Intelligent triage failed", error=str(e))
            return {"error": str(e)}
    
    def _extract_sample_characteristics(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key characteristics from sample data"""
        characteristics = {
            "file_info": {},
            "static_indicators": {},
            "behavioral_indicators": {},
            "context_information": {}
        }
        
        # File information
        file_info = sample_data.get("file_info", {})
        characteristics["file_info"] = {
            "size": file_info.get("size", 0),
            "type": file_info.get("type", "unknown"),
            "entropy": file_info.get("entropy", 0.0),
            "name": file_info.get("name", ""),
            "hash": file_info.get("hash", "")
        }
        
        # Static analysis indicators
        static_analysis = sample_data.get("static_analysis", {})
        characteristics["static_indicators"] = {
            "imports": len(static_analysis.get("imports", {})),
            "exports": len(static_analysis.get("exports", [])),
            "sections": len(static_analysis.get("sections", [])),
            "strings": len(static_analysis.get("strings", [])),
            "api_calls": self._extract_api_calls(static_analysis.get("imports", {})),
            "suspicious_patterns": static_analysis.get("yara_matches", [])
        }
        
        # Behavioral indicators
        if "behavioral_analysis" in sample_data:
            behavioral = sample_data["behavioral_analysis"]
            characteristics["behavioral_indicators"] = {
                "network_activity": behavioral.get("network_connections", []),
                "file_operations": behavioral.get("file_operations", []),
                "registry_operations": behavioral.get("registry_operations", []),
                "process_operations": behavioral.get("process_operations", [])
            }
        
        # Context information
        characteristics["context_information"] = {
            "source": sample_data.get("source", "unknown"),
            "submission_time": sample_data.get("submission_time"),
            "analyst_notes": sample_data.get("analyst_notes", ""),
            "previous_analysis": sample_data.get("previous_analysis_results")
        }
        
        return characteristics
    
    def _extract_api_calls(self, imports: Dict[str, Any]) -> List[str]:
        """Extract API calls from imports"""
        api_calls = []
        for dll_name, functions in imports.items():
            if isinstance(functions, list):
                api_calls.extend(functions)
        return api_calls
    
    def _calculate_priority_score(self, characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate priority score based on characteristics"""
        priority_score = 0.0
        factors = []
        reasoning = []
        confidence = 0.0
        
        file_info = characteristics.get("file_info", {})
        static_indicators = characteristics.get("static_indicators", {})
        behavioral_indicators = characteristics.get("behavioral_indicators", {})
        
        # File size factor
        file_size = file_info.get("size", 0)
        size_factor = self._evaluate_file_size(file_size)
        priority_score += size_factor["score"]
        if size_factor["factor"]:
            factors.append(size_factor["factor"])
            reasoning.append(size_factor["reasoning"])
        
        # Entropy factor
        entropy = file_info.get("entropy", 0.0)
        entropy_factor = self._evaluate_entropy(entropy)
        priority_score += entropy_factor["score"]
        if entropy_factor["factor"]:
            factors.append(entropy_factor["factor"])
            reasoning.append(entropy_factor["reasoning"])
        
        # API pattern factor
        api_calls = static_indicators.get("api_calls", [])
        api_factor = self._evaluate_api_patterns(api_calls)
        priority_score += api_factor["score"]
        factors.extend(api_factor["factors"])
        reasoning.extend(api_factor["reasoning"])
        
        # Behavioral factor
        behavioral_factor = self._evaluate_behavioral_indicators(behavioral_indicators)
        priority_score += behavioral_factor["score"]
        factors.extend(behavioral_factor["factors"])
        reasoning.extend(behavioral_factor["reasoning"])
        
        # Suspicious pattern factor
        suspicious_patterns = static_indicators.get("suspicious_patterns", [])
        pattern_factor = self._evaluate_suspicious_patterns(suspicious_patterns)
        priority_score += pattern_factor["score"]
        if pattern_factor["factor"]:
            factors.append(pattern_factor["factor"])
            reasoning.append(pattern_factor["reasoning"])
        
        # Determine priority level
        if priority_score >= 0.8:
            priority = PriorityLevel.CRITICAL
            confidence = 0.9
        elif priority_score >= 0.6:
            priority = PriorityLevel.HIGH
            confidence = 0.8
        elif priority_score >= 0.4:
            priority = PriorityLevel.MEDIUM
            confidence = 0.7
        elif priority_score >= 0.2:
            priority = PriorityLevel.LOW
            confidence = 0.6
        else:
            priority = PriorityLevel.MINIMAL
            confidence = 0.5
        
        return {
            "priority": priority,
            "score": priority_score,
            "factors": factors,
            "reasoning": reasoning,
            "confidence": confidence
        }
    
    def _evaluate_file_size(self, file_size: int) -> Dict[str, Any]:
        """Evaluate file size impact on priority"""
        if file_size > 100 * 1024 * 1024:  # > 100MB
            return {
                "score": 0.2,
                "factor": "very_large_file",
                "reasoning": f"Very large file ({file_size / (1024*1024):.1f}MB) may require extended analysis"
            }
        elif file_size > 10 * 1024 * 1024:  # > 10MB
            return {
                "score": 0.1,
                "factor": "large_file",
                "reasoning": f"Large file ({file_size / (1024*1024):.1f}MB) may contain complex functionality"
            }
        elif file_size < 10 * 1024:  # < 10KB
            return {
                "score": -0.1,
                "factor": "very_small_file",
                "reasoning": f"Very small file ({file_size} bytes) likely has limited functionality"
            }
        
        return {"score": 0.0, "factor": None, "reasoning": None}
    
    def _evaluate_entropy(self, entropy: float) -> Dict[str, Any]:
        """Evaluate entropy impact on priority"""
        if entropy >= 7.8:
            return {
                "score": 0.3,
                "factor": "very_high_entropy",
                "reasoning": f"Very high entropy ({entropy:.2f}) strongly suggests packing/encryption"
            }
        elif entropy >= 7.0:
            return {
                "score": 0.2,
                "factor": "high_entropy",
                "reasoning": f"High entropy ({entropy:.2f}) suggests possible packing/obfuscation"
            }
        elif entropy <= 4.0:
            return {
                "score": -0.1,
                "factor": "low_entropy",
                "reasoning": f"Low entropy ({entropy:.2f}) suggests simple or debug code"
            }
        
        return {"score": 0.0, "factor": None, "reasoning": None}
    
    def _evaluate_api_patterns(self, api_calls: List[str]) -> Dict[str, Any]:
        """Evaluate API call patterns"""
        score = 0.0
        factors = []
        reasoning = []
        
        api_set = set(api_calls)
        
        # Check for malicious API patterns
        for pattern_name, pattern_data in self.triage_rules["api_pattern_based"].items():
            pattern_apis = set(pattern_data["apis"])
            matches = len(pattern_apis.intersection(api_set))
            
            if matches > 0:
                match_ratio = matches / len(pattern_apis)
                weight = pattern_data["weight"]
                contribution = match_ratio * weight
                score += contribution
                
                factors.append(f"{pattern_name}_apis")
                reasoning.append(
                    f"Contains {matches}/{len(pattern_apis)} {pattern_name} APIs "
                    f"(contribution: {contribution:.2f})"
                )
        
        return {
            "score": min(score, 0.5),  # Cap API contribution
            "factors": factors,
            "reasoning": reasoning
        }
    
    def _evaluate_behavioral_indicators(self, behavioral_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate behavioral indicators"""
        score = 0.0
        factors = []
        reasoning = []
        
        # Network activity
        network_activity = behavioral_indicators.get("network_activity", [])
        if len(network_activity) > 0:
            score += 0.2
            factors.append("network_communication")
            reasoning.append(f"Network activity detected ({len(network_activity)} connections)")
        
        # File operations
        file_operations = behavioral_indicators.get("file_operations", [])
        if len(file_operations) > 10:
            score += 0.15
            factors.append("extensive_file_operations")
            reasoning.append(f"Extensive file operations ({len(file_operations)} operations)")
        
        # Registry operations
        registry_operations = behavioral_indicators.get("registry_operations", [])
        if len(registry_operations) > 0:
            score += 0.1
            factors.append("registry_modification")
            reasoning.append(f"Registry modifications detected ({len(registry_operations)} operations)")
        
        # Process operations
        process_operations = behavioral_indicators.get("process_operations", [])
        if len(process_operations) > 0:
            score += 0.15
            factors.append("process_manipulation")
            reasoning.append(f"Process manipulation detected ({len(process_operations)} operations)")
        
        return {
            "score": score,
            "factors": factors,
            "reasoning": reasoning
        }
    
    def _evaluate_suspicious_patterns(self, suspicious_patterns: List[str]) -> Dict[str, Any]:
        """Evaluate suspicious patterns from YARA or other scanners"""
        if len(suspicious_patterns) > 0:
            score = min(len(suspicious_patterns) * 0.1, 0.4)  # Cap at 0.4
            return {
                "score": score,
                "factor": "suspicious_patterns_detected",
                "reasoning": f"Suspicious patterns detected: {', '.join(suspicious_patterns[:3])}"
            }
        
        return {"score": 0.0, "factor": None, "reasoning": None}
    
    def _determine_analysis_workflow(self, characteristics: Dict[str, Any], 
                                   priority_result: Dict[str, Any]) -> Dict[str, Any]:
        """Determine appropriate analysis workflow"""
        priority = priority_result["priority"]
        file_info = characteristics.get("file_info", {})
        
        # Select workflow template based on priority and characteristics
        if priority == PriorityLevel.CRITICAL:
            template = "comprehensive_analysis"
        elif priority == PriorityLevel.HIGH:
            # Check if it might be malware
            if any("malicious" in factor or "suspicious" in factor 
                   for factor in priority_result["factors"]):
                template = "malware_focused"
            else:
                template = "standard_analysis"
        elif priority == PriorityLevel.MEDIUM:
            # Check file type and context
            if file_info.get("type") == "game_executable":
                template = "game_specific"
            else:
                template = "standard_analysis"
        else:  # LOW or MINIMAL
            template = "quick_scan"
        
        workflow_config = self.workflow_templates[template].copy()
        workflow_config["template"] = template
        workflow_config["depth"] = self._determine_analysis_depth(priority)
        
        return workflow_config
    
    def _determine_analysis_depth(self, priority: PriorityLevel) -> str:
        """Determine analysis depth based on priority"""
        depth_mapping = {
            PriorityLevel.CRITICAL: "comprehensive",
            PriorityLevel.HIGH: "detailed",
            PriorityLevel.MEDIUM: "standard",
            PriorityLevel.LOW: "basic",
            PriorityLevel.MINIMAL: "minimal"
        }
        return depth_mapping.get(priority, "standard")
    
    def _calculate_resource_allocation(self, workflow: Dict[str, Any], 
                                     priority: PriorityLevel) -> Dict[str, Any]:
        """Calculate resource allocation for analysis"""
        resource_multipliers = {
            PriorityLevel.CRITICAL: 1.5,
            PriorityLevel.HIGH: 1.2,
            PriorityLevel.MEDIUM: 1.0,
            PriorityLevel.LOW: 0.8,
            PriorityLevel.MINIMAL: 0.5
        }
        
        multiplier = resource_multipliers.get(priority, 1.0)
        base_resources = self._get_base_resources(workflow["resource_usage"])
        
        return {
            "cpu_cores": int(base_resources["cpu_cores"] * multiplier),
            "memory_gb": int(base_resources["memory_gb"] * multiplier),
            "disk_gb": base_resources["disk_gb"],
            "max_time_hours": base_resources["max_time_hours"],
            "priority_weight": multiplier
        }
    
    def _get_base_resources(self, resource_usage: str) -> Dict[str, Any]:
        """Get base resource allocation by usage level"""
        resource_configs = {
            "minimal": {"cpu_cores": 1, "memory_gb": 2, "disk_gb": 5, "max_time_hours": 1},
            "medium": {"cpu_cores": 2, "memory_gb": 4, "disk_gb": 10, "max_time_hours": 4},
            "high": {"cpu_cores": 4, "memory_gb": 8, "disk_gb": 20, "max_time_hours": 12}
        }
        return resource_configs.get(resource_usage, resource_configs["medium"])
    
    def _generate_next_actions(self, decision: TriageDecision, 
                             characteristics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommended next actions"""
        actions = []
        
        # Always start with static analysis
        actions.append({
            "action": "static_analysis",
            "tool": "binary_analyzer",
            "priority": 1,
            "estimated_time": "10-15 minutes",
            "description": "Perform comprehensive static analysis"
        })
        
        # Add dynamic analysis for higher priority samples
        if decision.priority in [PriorityLevel.CRITICAL, PriorityLevel.HIGH]:
            actions.append({
                "action": "dynamic_analysis",
                "tool": "frida_tracer",
                "priority": 2,
                "estimated_time": "30-60 minutes",
                "description": "Monitor runtime behavior and API calls"
            })
        
        # Add specialized analysis based on characteristics
        if characteristics["file_info"].get("entropy", 0) > 7.0:
            actions.append({
                "action": "unpacking_analysis",
                "tool": "unpacker",
                "priority": 2,
                "estimated_time": "15-30 minutes",
                "description": "Attempt to unpack or decrypt binary"
            })
        
        # Add AI classification for all samples
        actions.append({
            "action": "ai_classification",
            "tool": "threat_classifier",
            "priority": 3,
            "estimated_time": "5-10 minutes",
            "description": "Classify threat type using AI models"
        })
        
        # Add manual review for critical samples
        if decision.priority == PriorityLevel.CRITICAL:
            actions.append({
                "action": "manual_review",
                "tool": "analyst_workstation",
                "priority": 4,
                "estimated_time": "2-4 hours",
                "description": "Expert manual analysis and verification"
            })
        
        return actions
    
    def _serialize_decision(self, decision: TriageDecision) -> Dict[str, Any]:
        """Serialize triage decision to dictionary"""
        return {
            "priority": decision.priority.value,
            "recommended_tools": decision.recommended_tools,
            "analysis_depth": decision.analysis_depth,
            "estimated_time": decision.estimated_time,
            "resource_allocation": decision.resource_allocation,
            "reasoning": decision.reasoning,
            "confidence": decision.confidence
        }
    
    async def update_triage_rules(self, new_rules: Dict[str, Any]) -> Dict[str, Any]:
        """Update triage rules based on feedback"""
        try:
            # Validate new rules
            if not self._validate_rules(new_rules):
                return {"error": "Invalid rule format"}
            
            # Merge with existing rules
            for rule_type, rule_data in new_rules.items():
                if rule_type in self.triage_rules:
                    self.triage_rules[rule_type].update(rule_data)
                else:
                    self.triage_rules[rule_type] = rule_data
            
            logger.info("Triage rules updated", rule_types=list(new_rules.keys()))
            return {"success": True, "updated_rules": list(new_rules.keys())}
            
        except Exception as e:
            logger.error("Failed to update triage rules", error=str(e))
            return {"error": str(e)}
    
    def _validate_rules(self, rules: Dict[str, Any]) -> bool:
        """Validate rule format and content"""
        # Basic validation - could be expanded
        required_fields = {"threshold", "priority", "weight"}
        
        for rule_type, rule_data in rules.items():
            if not isinstance(rule_data, dict):
                return False
            
            for rule_name, rule_config in rule_data.items():
                if isinstance(rule_config, dict):
                    # Check if it has expected fields
                    if not any(field in rule_config for field in required_fields):
                        continue  # Skip validation for non-standard rules
        
        return True
    
    def get_triage_statistics(self) -> Dict[str, Any]:
        """Get triage system statistics"""
        return {
            "active_analyses": len(self.active_analyses),
            "resource_limits": self.resource_limits,
            "workflow_templates": list(self.workflow_templates.keys()),
            "rule_categories": list(self.triage_rules.keys()),
            "system_status": "operational"
        }