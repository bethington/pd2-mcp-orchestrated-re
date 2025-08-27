"""
Advanced Pattern Recognition Engine
Sophisticated pattern matching and classification for binary analysis
"""

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
import structlog
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter

logger = structlog.get_logger()

class AdvancedPatternRecognizer:
    """Advanced pattern recognition for binary analysis"""
    
    def __init__(self):
        self.known_patterns = {}
        self.malware_families = {}
        self.api_patterns = {}
        self.string_patterns = {}
        self.control_flow_patterns = {}
        self.tfidf_vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(3, 8),
            max_features=10000
        )
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize known patterns and signatures"""
        
        # Common API call patterns for malware detection
        self.api_patterns = {
            "process_injection": [
                "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                "OpenProcess", "ResumeThread", "SetThreadContext"
            ],
            "persistence": [
                "RegCreateKeyEx", "RegSetValueEx", "CreateService",
                "StartServiceCtrlDispatcher", "SetWindowsHookEx"
            ],
            "network_communication": [
                "WSAStartup", "socket", "connect", "send", "recv",
                "InternetOpen", "HttpOpenRequest", "HttpSendRequest"
            ],
            "file_operations": [
                "CreateFile", "WriteFile", "ReadFile", "DeleteFile",
                "MoveFile", "CopyFile", "FindFirstFile"
            ],
            "crypto_operations": [
                "CryptCreateHash", "CryptHashData", "CryptEncrypt",
                "CryptDecrypt", "CryptGenKey", "CryptImportKey"
            ]
        }
        
        # Known malware family signatures
        self.malware_families = {
            "trojan_banker": {
                "api_calls": ["HttpOpenRequest", "RegSetValueEx", "CryptEncrypt"],
                "strings": ["bank", "credit", "password", "login"],
                "file_patterns": [r"\.exe$", r"temp"]
            },
            "ransomware": {
                "api_calls": ["CryptEncrypt", "FindFirstFile", "WriteFile"],
                "strings": ["encrypt", "ransom", "bitcoin", "payment"],
                "file_patterns": [r"\.(txt|html)$"]
            },
            "keylogger": {
                "api_calls": ["SetWindowsHookEx", "GetAsyncKeyState", "WriteFile"],
                "strings": ["key", "log", "capture"],
                "file_patterns": [r"log"]
            }
        }
        
        # Control flow patterns
        self.control_flow_patterns = {
            "packer_obfuscation": {
                "characteristics": ["high_entropy_sections", "unusual_entry_point", "import_table_manipulation"],
                "indicators": ["self_modifying_code", "dynamic_api_resolution"]
            },
            "anti_analysis": {
                "characteristics": ["debugger_detection", "vm_detection", "sandbox_evasion"],
                "indicators": ["timing_checks", "environment_queries"]
            }
        }
    
    async def analyze_binary_patterns(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive pattern analysis of binary"""
        try:
            results = {
                "pattern_matches": {},
                "malware_classification": {},
                "behavioral_patterns": {},
                "similarity_analysis": {},
                "anomaly_detection": {},
                "risk_assessment": {}
            }
            
            # Extract features for analysis
            features = self._extract_features(analysis_data)
            
            # API call pattern analysis
            api_patterns = self._analyze_api_patterns(features.get("api_calls", []))
            results["pattern_matches"]["api_patterns"] = api_patterns
            
            # String pattern analysis
            string_patterns = self._analyze_string_patterns(features.get("strings", []))
            results["pattern_matches"]["string_patterns"] = string_patterns
            
            # Control flow analysis
            cf_patterns = self._analyze_control_flow(features.get("control_flow", {}))
            results["pattern_matches"]["control_flow"] = cf_patterns
            
            # Malware family classification
            malware_class = self._classify_malware_family(features)
            results["malware_classification"] = malware_class
            
            # Behavioral pattern detection
            behavioral = self._detect_behavioral_patterns(features)
            results["behavioral_patterns"] = behavioral
            
            # Similarity analysis with known samples
            similarity = self._perform_similarity_analysis(features)
            results["similarity_analysis"] = similarity
            
            # Anomaly detection
            anomalies = self._detect_anomalies(features)
            results["anomaly_detection"] = anomalies
            
            # Risk assessment
            risk = self._assess_risk(results)
            results["risk_assessment"] = risk
            
            logger.info("Pattern analysis completed", 
                       total_patterns=len(results["pattern_matches"]),
                       risk_level=risk.get("risk_level"))
            
            return results
            
        except Exception as e:
            logger.error("Pattern analysis failed", error=str(e))
            return {"error": str(e)}
    
    def _extract_features(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant features from analysis data"""
        features = {
            "api_calls": [],
            "strings": [],
            "file_info": {},
            "imports": [],
            "exports": [],
            "sections": [],
            "control_flow": {},
            "entropy": {}
        }
        
        # Extract from static analysis
        static_analysis = analysis_data.get("static_analysis", {})
        
        if "imports" in static_analysis:
            features["imports"] = static_analysis["imports"]
            # Extract API calls from imports
            for dll_data in static_analysis["imports"].values():
                if isinstance(dll_data, list):
                    features["api_calls"].extend(dll_data)
        
        if "strings" in static_analysis:
            features["strings"] = static_analysis["strings"]
        
        if "file_info" in static_analysis:
            features["file_info"] = static_analysis["file_info"]
        
        if "sections" in static_analysis:
            features["sections"] = static_analysis["sections"]
        
        # Extract from dynamic analysis if available
        dynamic_analysis = analysis_data.get("dynamic_analysis", {})
        if "api_calls" in dynamic_analysis:
            features["api_calls"].extend(dynamic_analysis["api_calls"])
        
        return features
    
    def _analyze_api_patterns(self, api_calls: List[str]) -> Dict[str, Any]:
        """Analyze API call patterns"""
        results = {
            "suspicious_patterns": {},
            "api_frequency": {},
            "pattern_confidence": {}
        }
        
        # Count API call frequencies
        api_counter = Counter(api_calls)
        results["api_frequency"] = dict(api_counter.most_common(20))
        
        # Check against known suspicious patterns
        for pattern_name, pattern_apis in self.api_patterns.items():
            matches = sum(1 for api in pattern_apis if api in api_calls)
            if matches > 0:
                confidence = matches / len(pattern_apis)
                results["suspicious_patterns"][pattern_name] = {
                    "matches": matches,
                    "total_apis": len(pattern_apis),
                    "confidence": confidence,
                    "matched_apis": [api for api in pattern_apis if api in api_calls]
                }
                results["pattern_confidence"][pattern_name] = confidence
        
        return results
    
    def _analyze_string_patterns(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze string patterns for suspicious content"""
        results = {
            "suspicious_strings": [],
            "domains": [],
            "file_paths": [],
            "registry_keys": [],
            "ip_addresses": [],
            "crypto_indicators": []
        }
        
        # Regex patterns for different string types
        patterns = {
            "domains": r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
            "ip_addresses": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "file_paths": r"[A-Za-z]:\\[^<>:\"|?*\r\n]*",
            "registry_keys": r"HKEY_[A-Z_]+\\.*",
            "crypto_indicators": r"(encrypt|decrypt|cipher|hash|md5|sha|aes|rsa)"
        }
        
        for string in strings:
            if len(string) < 4:  # Skip very short strings
                continue
                
            # Check for different pattern types
            for pattern_type, pattern in patterns.items():
                matches = re.findall(pattern, string, re.IGNORECASE)
                if matches:
                    results[pattern_type].extend(matches)
            
            # Check for suspicious keywords
            suspicious_keywords = [
                "password", "admin", "root", "exploit", "payload",
                "backdoor", "trojan", "virus", "malware", "keylog"
            ]
            
            for keyword in suspicious_keywords:
                if keyword.lower() in string.lower():
                    results["suspicious_strings"].append({
                        "string": string,
                        "keyword": keyword,
                        "context": "suspicious_content"
                    })
        
        # Remove duplicates
        for key in results:
            if isinstance(results[key], list) and key != "suspicious_strings":
                results[key] = list(set(results[key]))
        
        return results
    
    def _analyze_control_flow(self, control_flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze control flow patterns"""
        results = {
            "complexity_metrics": {},
            "suspicious_patterns": [],
            "obfuscation_indicators": []
        }
        
        if not control_flow_data:
            return results
        
        # Calculate complexity metrics
        basic_blocks = control_flow_data.get("basic_blocks", 0)
        edges = control_flow_data.get("edges", 0)
        
        if basic_blocks > 0:
            cyclomatic_complexity = edges - basic_blocks + 2
            results["complexity_metrics"] = {
                "basic_blocks": basic_blocks,
                "edges": edges,
                "cyclomatic_complexity": cyclomatic_complexity
            }
            
            # Check for suspicious complexity patterns
            if cyclomatic_complexity > 50:
                results["suspicious_patterns"].append("high_cyclomatic_complexity")
            
            if basic_blocks > 1000:
                results["suspicious_patterns"].append("excessive_basic_blocks")
        
        # Check for obfuscation indicators
        if control_flow_data.get("indirect_jumps", 0) > 10:
            results["obfuscation_indicators"].append("excessive_indirect_jumps")
        
        if control_flow_data.get("self_modifying", False):
            results["obfuscation_indicators"].append("self_modifying_code")
        
        return results
    
    def _classify_malware_family(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classify potential malware family based on patterns"""
        results = {
            "family_scores": {},
            "top_matches": [],
            "confidence": 0.0
        }
        
        for family_name, family_patterns in self.malware_families.items():
            score = 0.0
            matched_indicators = []
            
            # Check API call patterns
            family_apis = family_patterns.get("api_calls", [])
            api_matches = sum(1 for api in family_apis if api in features.get("api_calls", []))
            if family_apis:
                api_score = api_matches / len(family_apis)
                score += api_score * 0.4
                if api_matches > 0:
                    matched_indicators.append(f"api_calls: {api_matches}/{len(family_apis)}")
            
            # Check string patterns
            family_strings = family_patterns.get("strings", [])
            string_matches = sum(1 for s in family_strings 
                               if any(s.lower() in string.lower() 
                                     for string in features.get("strings", [])))
            if family_strings:
                string_score = string_matches / len(family_strings)
                score += string_score * 0.3
                if string_matches > 0:
                    matched_indicators.append(f"strings: {string_matches}/{len(family_strings)}")
            
            # Check file patterns
            family_files = family_patterns.get("file_patterns", [])
            file_name = features.get("file_info", {}).get("name", "")
            file_matches = sum(1 for pattern in family_files if re.search(pattern, file_name))
            if family_files:
                file_score = file_matches / len(family_files)
                score += file_score * 0.3
                if file_matches > 0:
                    matched_indicators.append(f"file_patterns: {file_matches}/{len(family_files)}")
            
            results["family_scores"][family_name] = {
                "score": score,
                "matched_indicators": matched_indicators
            }
        
        # Get top matches
        sorted_families = sorted(results["family_scores"].items(), 
                               key=lambda x: x[1]["score"], reverse=True)
        results["top_matches"] = sorted_families[:3]
        
        if sorted_families:
            results["confidence"] = sorted_families[0][1]["score"]
        
        return results
    
    def _detect_behavioral_patterns(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect behavioral patterns"""
        results = {
            "behaviors": [],
            "risk_indicators": [],
            "capability_assessment": {}
        }
        
        api_calls = features.get("api_calls", [])
        strings = features.get("strings", [])
        
        # Network communication capability
        network_apis = ["WSAStartup", "socket", "connect", "InternetOpen"]
        if any(api in api_calls for api in network_apis):
            results["behaviors"].append("network_communication")
            results["capability_assessment"]["network"] = True
        
        # File manipulation capability
        file_apis = ["CreateFile", "WriteFile", "DeleteFile", "CopyFile"]
        if any(api in api_calls for api in file_apis):
            results["behaviors"].append("file_manipulation")
            results["capability_assessment"]["file_operations"] = True
        
        # Registry manipulation
        registry_apis = ["RegCreateKeyEx", "RegSetValueEx", "RegDeleteKey"]
        if any(api in api_calls for api in registry_apis):
            results["behaviors"].append("registry_modification")
            results["capability_assessment"]["registry_access"] = True
        
        # Process manipulation
        process_apis = ["CreateProcess", "OpenProcess", "TerminateProcess"]
        if any(api in api_calls for api in process_apis):
            results["behaviors"].append("process_manipulation")
            results["capability_assessment"]["process_control"] = True
        
        # Cryptographic operations
        crypto_apis = ["CryptEncrypt", "CryptDecrypt", "CryptHashData"]
        if any(api in api_calls for api in crypto_apis):
            results["behaviors"].append("cryptographic_operations")
            results["capability_assessment"]["cryptography"] = True
        
        # Check for high-risk behaviors
        high_risk_combinations = [
            (["network_communication", "file_manipulation"], "data_exfiltration_risk"),
            (["cryptographic_operations", "file_manipulation"], "encryption_malware_risk"),
            (["process_manipulation", "registry_modification"], "system_persistence_risk")
        ]
        
        for behavior_combo, risk_name in high_risk_combinations:
            if all(behavior in results["behaviors"] for behavior in behavior_combo):
                results["risk_indicators"].append(risk_name)
        
        return results
    
    def _perform_similarity_analysis(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform similarity analysis with known samples"""
        results = {
            "similar_samples": [],
            "feature_similarity": {},
            "clustering_results": {}
        }
        
        # This would typically compare against a database of known samples
        # For now, we'll simulate similarity analysis
        
        # Calculate feature hash for similarity matching
        feature_string = ""
        
        # Include API calls in feature string
        api_calls = sorted(features.get("api_calls", []))
        feature_string += "|".join(api_calls[:50])  # Limit to top 50
        
        # Include important strings
        strings = features.get("strings", [])
        important_strings = [s for s in strings if len(s) > 6 and s.isascii()]
        feature_string += "|" + "|".join(sorted(important_strings)[:20])
        
        # Calculate hash
        feature_hash = hashlib.md5(feature_string.encode()).hexdigest()
        
        results["feature_similarity"] = {
            "feature_hash": feature_hash,
            "api_call_count": len(api_calls),
            "string_count": len(important_strings)
        }
        
        return results
    
    def _detect_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalous patterns"""
        results = {
            "anomalies": [],
            "anomaly_scores": {},
            "suspicious_indicators": []
        }
        
        # Check for unusual import patterns
        imports = features.get("imports", {})
        total_imports = sum(len(dll_imports) for dll_imports in imports.values())
        
        if total_imports > 500:
            results["anomalies"].append("excessive_imports")
            results["anomaly_scores"]["import_count"] = min(1.0, total_imports / 1000)
        
        # Check for unusual string patterns
        strings = features.get("strings", [])
        if len(strings) > 1000:
            results["anomalies"].append("excessive_strings")
        
        # Check for high entropy sections (potential packing/encryption)
        sections = features.get("sections", [])
        high_entropy_sections = [s for s in sections 
                               if isinstance(s, dict) and s.get("entropy", 0) > 7.0]
        
        if high_entropy_sections:
            results["anomalies"].append("high_entropy_sections")
            results["suspicious_indicators"].append("potential_packing_or_encryption")
        
        # Check for unusual API call patterns
        api_calls = features.get("api_calls", [])
        api_counter = Counter(api_calls)
        
        # Look for APIs called excessively
        for api, count in api_counter.items():
            if count > 50:
                results["suspicious_indicators"].append(f"excessive_{api}_calls")
        
        return results
    
    def _assess_risk(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk level"""
        risk_score = 0.0
        risk_factors = []
        
        # Pattern match risk contribution
        pattern_matches = analysis_results.get("pattern_matches", {})
        api_patterns = pattern_matches.get("api_patterns", {})
        
        for pattern_name, pattern_data in api_patterns.get("suspicious_patterns", {}).items():
            confidence = pattern_data.get("confidence", 0)
            risk_score += confidence * 0.3
            if confidence > 0.5:
                risk_factors.append(f"suspicious_api_pattern_{pattern_name}")
        
        # Malware classification risk
        malware_class = analysis_results.get("malware_classification", {})
        max_family_score = malware_class.get("confidence", 0)
        risk_score += max_family_score * 0.4
        
        if max_family_score > 0.3:
            top_family = malware_class.get("top_matches", [])
            if top_family:
                risk_factors.append(f"malware_family_match_{top_family[0][0]}")
        
        # Behavioral risk
        behavioral = analysis_results.get("behavioral_patterns", {})
        risk_indicators = behavioral.get("risk_indicators", [])
        risk_score += len(risk_indicators) * 0.1
        risk_factors.extend(risk_indicators)
        
        # Anomaly risk
        anomalies = analysis_results.get("anomaly_detection", {})
        anomaly_count = len(anomalies.get("anomalies", []))
        risk_score += min(anomaly_count * 0.05, 0.2)
        
        # Normalize risk score
        risk_score = min(risk_score, 1.0)
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "critical"
        elif risk_score >= 0.6:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        elif risk_score >= 0.2:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": self._get_risk_recommendation(risk_level, risk_factors)
        }
    
    def _get_risk_recommendation(self, risk_level: str, risk_factors: List[str]) -> str:
        """Get recommendation based on risk assessment"""
        recommendations = {
            "critical": "Immediate quarantine and detailed manual analysis required",
            "high": "Isolation recommended, perform comprehensive analysis",
            "medium": "Monitor closely, consider additional analysis",
            "low": "Standard monitoring sufficient",
            "minimal": "Low priority, routine processing acceptable"
        }
        
        base_rec = recommendations.get(risk_level, "Unknown risk level")
        
        if risk_factors:
            factor_summary = ", ".join(risk_factors[:3])
            return f"{base_rec}. Primary concerns: {factor_summary}"
        
        return base_rec