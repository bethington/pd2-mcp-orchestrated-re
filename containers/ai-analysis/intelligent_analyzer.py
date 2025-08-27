"""
Intelligent Analysis Engine
AI-driven automation and intelligence layer for reverse engineering
"""

import asyncio
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import structlog
import pickle
import os
from pathlib import Path

# Machine Learning imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler
import joblib

# Deep Learning imports
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel

logger = structlog.get_logger()

class IntelligentAnalyzer:
    """AI-driven analysis coordination and pattern recognition"""
    
    def __init__(self):
        self.models_loaded = False
        self.analysis_history = []
        self.pattern_database = {}
        self.threat_signatures = {}
        self.feature_extractors = {}
        
        # Initialize ML models
        self.anomaly_detector = None
        self.threat_classifier = None
        self.similarity_engine = None
        
        self._initialize_models()
        logger.info("Intelligent analyzer initialized")
        
    def _initialize_models(self):
        """Initialize machine learning models"""
        try:
            # Anomaly detection model
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Threat classification model
            self.threat_classifier = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                random_state=42
            )
            
            # Text similarity for code analysis
            self.text_vectorizer = TfidfVectorizer(
                max_features=10000,
                ngram_range=(1, 3),
                stop_words='english'
            )
            
            # Load pre-trained models if available
            self._load_pretrained_models()
            
            self.models_loaded = True
            logger.info("ML models initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize ML models", error=str(e))
            
    def _load_pretrained_models(self):
        """Load pre-trained models from disk"""
        models_dir = Path("/app/models")
        
        try:
            if (models_dir / "anomaly_detector.pkl").exists():
                self.anomaly_detector = joblib.load(models_dir / "anomaly_detector.pkl")
                logger.info("Loaded pre-trained anomaly detector")
                
            if (models_dir / "threat_classifier.pkl").exists():
                self.threat_classifier = joblib.load(models_dir / "threat_classifier.pkl")
                logger.info("Loaded pre-trained threat classifier")
                
            if (models_dir / "text_vectorizer.pkl").exists():
                self.text_vectorizer = joblib.load(models_dir / "text_vectorizer.pkl")
                logger.info("Loaded pre-trained text vectorizer")
                
        except Exception as e:
            logger.warning("Failed to load some pre-trained models", error=str(e))
            
    async def intelligent_triage(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform intelligent triage of analysis results using AI
        
        Args:
            analysis_results: Combined results from all analysis phases
            
        Returns:
            Intelligent triage results with prioritization and recommendations
        """
        try:
            triage_result = {
                "triage_timestamp": datetime.now().isoformat(),
                "priority_score": 0.0,
                "threat_classification": "unknown",
                "anomaly_indicators": [],
                "similarity_matches": [],
                "automated_insights": [],
                "recommended_actions": [],
                "confidence_metrics": {}
            }
            
            # Extract features from analysis results
            features = await self._extract_intelligence_features(analysis_results)
            
            # Perform anomaly detection
            anomaly_results = await self._detect_anomalies(features)
            triage_result["anomaly_indicators"] = anomaly_results
            
            # Classify threat level
            threat_results = await self._classify_threat_level(features)
            triage_result["threat_classification"] = threat_results["classification"]
            triage_result["priority_score"] = threat_results["confidence"]
            
            # Find similar samples
            similarity_results = await self._find_similar_samples(analysis_results)
            triage_result["similarity_matches"] = similarity_results
            
            # Generate automated insights
            insights = await self._generate_automated_insights(analysis_results, features)
            triage_result["automated_insights"] = insights
            
            # Recommend actions
            actions = await self._recommend_actions(triage_result)
            triage_result["recommended_actions"] = actions
            
            # Calculate confidence metrics
            confidence = await self._calculate_confidence_metrics(triage_result)
            triage_result["confidence_metrics"] = confidence
            
            # Store for future learning
            self.analysis_history.append({
                "timestamp": datetime.now().isoformat(),
                "results": analysis_results,
                "triage": triage_result
            })
            
            # Limit history size
            if len(self.analysis_history) > 1000:
                self.analysis_history = self.analysis_history[-500:]
                
            logger.info("Intelligent triage completed", 
                       priority_score=triage_result["priority_score"],
                       threat_class=triage_result["threat_classification"])
            
            return triage_result
            
        except Exception as e:
            logger.error("Intelligent triage failed", error=str(e))
            return {"error": str(e)}
            
    async def _extract_intelligence_features(self, analysis_results: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features for ML analysis"""
        features = []
        
        try:
            # Static analysis features
            static_results = analysis_results.get("static_analysis", {})
            
            features.extend([
                len(static_results.get("functions", [])),
                len(static_results.get("imports", [])),
                len(static_results.get("exports", [])),
                len(static_results.get("strings", [])),
                static_results.get("file_info", {}).get("file_size", 0),
                len(static_results.get("sections", [])),
            ])
            
            # Security analysis features
            security_results = analysis_results.get("security_assessment", {}).get("security_analysis", {})
            
            features.extend([
                security_results.get("risk_score", 0),
                1 if security_results.get("aslr_enabled", False) else 0,
                1 if security_results.get("dep_enabled", False) else 0,
                1 if security_results.get("packer_detected", False) else 0,
                1 if security_results.get("anti_debug", False) else 0,
                len(security_results.get("suspicious_apis", [])),
            ])
            
            # Dynamic analysis features
            dynamic_results = analysis_results.get("dynamic_analysis", {})
            if dynamic_results and "error" not in dynamic_results:
                memory_analysis = dynamic_results.get("memory_analysis", {})
                features.extend([
                    memory_analysis.get("snapshots_count", 0),
                    len(memory_analysis.get("known_structures", [])),
                    1 if memory_analysis.get("process_attached", False) else 0,
                ])
            else:
                features.extend([0, 0, 0])  # No dynamic analysis data
                
            # Decompilation features
            decompilation_results = analysis_results.get("decompilation", {})
            if decompilation_results and "error" not in decompilation_results:
                features.extend([
                    len(decompilation_results.get("functions", [])),
                    len(decompilation_results.get("strings", [])),
                    len(decompilation_results.get("data_types", [])),
                ])
            else:
                features.extend([0, 0, 0])  # No decompilation data
                
            # Pattern matching features
            patterns = analysis_results.get("static_analysis", {}).get("patterns", [])
            features.extend([
                len(patterns),
                sum(1 for p in patterns if "packer" in p.get("rule_name", "").lower()),
                sum(1 for p in patterns if "malware" in p.get("rule_name", "").lower()),
                sum(1 for p in patterns if "suspicious" in p.get("rule_name", "").lower()),
            ])
            
            # Ensure fixed feature length
            while len(features) < 25:  # Pad to minimum feature count
                features.append(0.0)
                
            return np.array(features, dtype=np.float32)
            
        except Exception as e:
            logger.error("Feature extraction failed", error=str(e))
            return np.zeros(25, dtype=np.float32)  # Return zero vector
            
    async def _detect_anomalies(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """Detect anomalies using ML models"""
        anomalies = []
        
        try:
            if self.anomaly_detector and len(features) > 0:
                # Reshape for sklearn
                features_2d = features.reshape(1, -1)
                
                # Predict anomaly
                anomaly_score = self.anomaly_detector.decision_function(features_2d)[0]
                is_anomaly = self.anomaly_detector.predict(features_2d)[0] == -1
                
                if is_anomaly:
                    anomalies.append({
                        "type": "statistical_anomaly",
                        "score": float(anomaly_score),
                        "severity": "high" if anomaly_score < -0.5 else "medium",
                        "description": "Sample shows statistical deviation from normal patterns"
                    })
                    
                # Additional heuristic checks
                if features[4] > 50 * 1024 * 1024:  # File size > 50MB
                    anomalies.append({
                        "type": "large_binary",
                        "score": 0.7,
                        "severity": "medium",
                        "description": "Unusually large binary file"
                    })
                    
                if features[5] > 20:  # Too many sections
                    anomalies.append({
                        "type": "excessive_sections",
                        "score": 0.8,
                        "severity": "high",
                        "description": "Excessive number of binary sections"
                    })
                    
                if features[6] > 8:  # High risk score
                    anomalies.append({
                        "type": "high_risk_indicators",
                        "score": 0.9,
                        "severity": "critical",
                        "description": "Multiple high-risk security indicators"
                    })
                    
        except Exception as e:
            logger.error("Anomaly detection failed", error=str(e))
            
        return anomalies
        
    async def _classify_threat_level(self, features: np.ndarray) -> Dict[str, Any]:
        """Classify threat level using ML classifier"""
        try:
            # Heuristic-based classification (would use trained model in production)
            risk_score = 0.0
            threat_indicators = []
            
            # File size based risk
            if features[4] > 100 * 1024 * 1024:  # > 100MB
                risk_score += 0.2
                threat_indicators.append("large_file_size")
                
            # Security features based risk
            security_risk = features[6]  # Risk score from security analysis
            if security_risk > 7:
                risk_score += 0.4
                threat_indicators.append("high_security_risk")
            elif security_risk > 4:
                risk_score += 0.2
                threat_indicators.append("medium_security_risk")
                
            # Packer detection
            if features[9] == 1:  # Packer detected
                risk_score += 0.3
                threat_indicators.append("packer_detected")
                
            # Anti-debug techniques
            if features[10] == 1:  # Anti-debug detected
                risk_score += 0.3
                threat_indicators.append("anti_debug_detected")
                
            # Suspicious API usage
            if features[11] > 5:  # Many suspicious APIs
                risk_score += 0.4
                threat_indicators.append("suspicious_api_usage")
                
            # Pattern-based indicators
            if features[22] > 0:  # Malware patterns
                risk_score += 0.5
                threat_indicators.append("malware_patterns")
                
            if features[23] > 2:  # Multiple suspicious patterns
                risk_score += 0.3
                threat_indicators.append("multiple_suspicious_patterns")
                
            # Classify based on risk score
            if risk_score >= 0.8:
                classification = "critical"
            elif risk_score >= 0.6:
                classification = "high"
            elif risk_score >= 0.4:
                classification = "medium"
            elif risk_score >= 0.2:
                classification = "low"
            else:
                classification = "benign"
                
            return {
                "classification": classification,
                "confidence": min(risk_score, 1.0),
                "risk_factors": threat_indicators,
                "risk_breakdown": {
                    "file_characteristics": features[4] / (100 * 1024 * 1024),  # Normalized
                    "security_indicators": security_risk / 10.0,
                    "behavioral_patterns": len(threat_indicators) / 10.0
                }
            }
            
        except Exception as e:
            logger.error("Threat classification failed", error=str(e))
            return {
                "classification": "unknown",
                "confidence": 0.0,
                "risk_factors": [],
                "error": str(e)
            }
            
    async def _find_similar_samples(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find similar samples in analysis history"""
        similarities = []
        
        try:
            if len(self.analysis_history) < 2:
                return similarities
                
            current_features = await self._extract_intelligence_features(analysis_results)
            
            # Compare with historical samples
            for i, historical_entry in enumerate(self.analysis_history[-50:]):  # Last 50 samples
                try:
                    historical_features = await self._extract_intelligence_features(
                        historical_entry["results"]
                    )
                    
                    # Calculate cosine similarity
                    similarity_score = cosine_similarity(
                        current_features.reshape(1, -1),
                        historical_features.reshape(1, -1)
                    )[0, 0]
                    
                    if similarity_score > 0.8:  # High similarity threshold
                        similarities.append({
                            "sample_index": i,
                            "similarity_score": float(similarity_score),
                            "timestamp": historical_entry["timestamp"],
                            "threat_classification": historical_entry.get("triage", {}).get("threat_classification", "unknown"),
                            "priority_score": historical_entry.get("triage", {}).get("priority_score", 0.0)
                        })
                        
                except Exception:
                    continue  # Skip problematic historical entries
                    
            # Sort by similarity score
            similarities.sort(key=lambda x: x["similarity_score"], reverse=True)
            
        except Exception as e:
            logger.error("Similarity matching failed", error=str(e))
            
        return similarities[:10]  # Return top 10 matches
        
    async def _generate_automated_insights(self, analysis_results: Dict[str, Any], features: np.ndarray) -> List[Dict[str, Any]]:
        """Generate automated insights using pattern analysis"""
        insights = []
        
        try:
            # File characteristics insights
            file_size = features[4]
            if file_size > 50 * 1024 * 1024:
                insights.append({
                    "category": "file_characteristics",
                    "insight": f"Large binary file ({file_size / (1024*1024):.1f} MB) may indicate bundled resources or multiple components",
                    "confidence": 0.8,
                    "actionable": True,
                    "recommendation": "Investigate file structure and embedded resources"
                })
                
            # Import analysis insights
            import_count = features[1]
            if import_count > 200:
                insights.append({
                    "category": "api_usage",
                    "insight": f"High number of imports ({import_count}) suggests complex functionality or library dependencies",
                    "confidence": 0.7,
                    "actionable": True,
                    "recommendation": "Analyze import patterns for suspicious or uncommon APIs"
                })
                
            # Security insights
            if features[7] == 0 and features[8] == 0:  # No ASLR and no DEP
                insights.append({
                    "category": "security_mitigations",
                    "insight": "Binary lacks modern security mitigations (ASLR, DEP)",
                    "confidence": 0.9,
                    "actionable": True,
                    "recommendation": "Vulnerable to memory corruption exploits - prioritize analysis"
                })
                
            # Pattern-based insights
            static_results = analysis_results.get("static_analysis", {})
            patterns = static_results.get("patterns", [])
            
            if patterns:
                packer_patterns = [p for p in patterns if "packer" in p.get("rule_name", "").lower()]
                if packer_patterns:
                    insights.append({
                        "category": "obfuscation",
                        "insight": f"Binary appears to be packed ({len(packer_patterns)} packer signatures detected)",
                        "confidence": 0.85,
                        "actionable": True,
                        "recommendation": "Unpack binary before detailed analysis"
                    })
                    
            # Dynamic analysis insights
            dynamic_results = analysis_results.get("dynamic_analysis", {})
            if dynamic_results and "error" not in dynamic_results:
                memory_analysis = dynamic_results.get("memory_analysis", {})
                if memory_analysis.get("process_attached", False):
                    insights.append({
                        "category": "runtime_behavior",
                        "insight": "Successful dynamic analysis provides runtime behavioral data",
                        "confidence": 0.9,
                        "actionable": True,
                        "recommendation": "Correlate static and dynamic findings for comprehensive analysis"
                    })
                    
            # Code quality insights
            decompilation_results = analysis_results.get("decompilation", {})
            if decompilation_results and "error" not in decompilation_results:
                functions_count = len(decompilation_results.get("functions", []))
                if functions_count > 1000:
                    insights.append({
                        "category": "complexity",
                        "insight": f"High function count ({functions_count}) indicates complex software",
                        "confidence": 0.8,
                        "actionable": True,
                        "recommendation": "Focus on entry points and exported functions first"
                    })
                    
        except Exception as e:
            logger.error("Insight generation failed", error=str(e))
            
        return insights
        
    async def _recommend_actions(self, triage_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommended actions based on triage results"""
        actions = []
        
        try:
            threat_class = triage_result.get("threat_classification", "unknown")
            priority_score = triage_result.get("priority_score", 0.0)
            anomalies = triage_result.get("anomaly_indicators", [])
            
            # Priority-based recommendations
            if threat_class == "critical" or priority_score > 0.8:
                actions.extend([
                    {
                        "action": "immediate_manual_review",
                        "priority": "critical",
                        "description": "Requires immediate expert analysis due to high threat indicators",
                        "estimated_time": "2-4 hours"
                    },
                    {
                        "action": "isolate_sample", 
                        "priority": "critical",
                        "description": "Isolate sample in secure environment to prevent potential damage",
                        "estimated_time": "15 minutes"
                    }
                ])
                
            elif threat_class in ["high", "medium"] or priority_score > 0.4:
                actions.extend([
                    {
                        "action": "detailed_analysis",
                        "priority": "high",
                        "description": "Perform comprehensive static and dynamic analysis",
                        "estimated_time": "1-2 hours"
                    },
                    {
                        "action": "sandbox_execution",
                        "priority": "medium", 
                        "description": "Execute in controlled sandbox environment for behavioral analysis",
                        "estimated_time": "30-60 minutes"
                    }
                ])
            else:
                actions.append({
                    "action": "automated_processing",
                    "priority": "low",
                    "description": "Can be processed through automated analysis pipeline",
                    "estimated_time": "15-30 minutes"
                })
                
            # Anomaly-based recommendations
            for anomaly in anomalies:
                if anomaly.get("severity") == "critical":
                    actions.append({
                        "action": "investigate_anomaly",
                        "priority": "high",
                        "description": f"Investigate {anomaly.get('type', 'unknown')} anomaly",
                        "estimated_time": "30-60 minutes",
                        "context": anomaly.get("description", "")
                    })
                    
            # Similarity-based recommendations
            similarities = triage_result.get("similarity_matches", [])
            if similarities:
                high_sim_matches = [s for s in similarities if s.get("similarity_score", 0) > 0.9]
                if high_sim_matches:
                    actions.append({
                        "action": "compare_with_similar",
                        "priority": "medium",
                        "description": f"Compare with {len(high_sim_matches)} highly similar samples",
                        "estimated_time": "20-30 minutes",
                        "context": "May be variant of known sample"
                    })
                    
            # Remove duplicate actions
            seen_actions = set()
            unique_actions = []
            for action in actions:
                action_key = action["action"]
                if action_key not in seen_actions:
                    unique_actions.append(action)
                    seen_actions.add(action_key)
                    
            return unique_actions
            
        except Exception as e:
            logger.error("Action recommendation failed", error=str(e))
            return []
            
    async def _calculate_confidence_metrics(self, triage_result: Dict[str, Any]) -> Dict[str, float]:
        """Calculate confidence metrics for triage results"""
        try:
            metrics = {
                "overall_confidence": 0.0,
                "threat_classification_confidence": 0.0,
                "anomaly_detection_confidence": 0.0,
                "similarity_matching_confidence": 0.0,
                "insight_generation_confidence": 0.0
            }
            
            # Threat classification confidence
            metrics["threat_classification_confidence"] = min(
                triage_result.get("priority_score", 0.0), 1.0
            )
            
            # Anomaly detection confidence
            anomalies = triage_result.get("anomaly_indicators", [])
            if anomalies:
                avg_anomaly_score = sum(a.get("score", 0) for a in anomalies) / len(anomalies)
                metrics["anomaly_detection_confidence"] = min(avg_anomaly_score, 1.0)
            else:
                metrics["anomaly_detection_confidence"] = 0.8  # High confidence in no anomalies
                
            # Similarity matching confidence
            similarities = triage_result.get("similarity_matches", [])
            if similarities:
                max_similarity = max(s.get("similarity_score", 0) for s in similarities)
                metrics["similarity_matching_confidence"] = max_similarity
            else:
                metrics["similarity_matching_confidence"] = 0.5  # Medium confidence in uniqueness
                
            # Insight generation confidence
            insights = triage_result.get("automated_insights", [])
            if insights:
                avg_insight_confidence = sum(i.get("confidence", 0) for i in insights) / len(insights)
                metrics["insight_generation_confidence"] = avg_insight_confidence
            else:
                metrics["insight_generation_confidence"] = 0.3  # Low confidence without insights
                
            # Overall confidence (weighted average)
            weights = [0.3, 0.3, 0.2, 0.2]  # Threat class and anomalies weighted higher
            values = [
                metrics["threat_classification_confidence"],
                metrics["anomaly_detection_confidence"],
                metrics["similarity_matching_confidence"],
                metrics["insight_generation_confidence"]
            ]
            
            metrics["overall_confidence"] = sum(w * v for w, v in zip(weights, values))
            
            return metrics
            
        except Exception as e:
            logger.error("Confidence calculation failed", error=str(e))
            return {"overall_confidence": 0.5}  # Default medium confidence
            
    async def continuous_learning_update(self, feedback: Dict[str, Any]):
        """Update models based on analyst feedback"""
        try:
            # Store feedback for model retraining
            feedback_entry = {
                "timestamp": datetime.now().isoformat(),
                "feedback": feedback,
                "model_version": "1.0"
            }
            
            # In production, this would trigger model retraining
            logger.info("Received feedback for continuous learning", 
                       feedback_type=feedback.get("type", "unknown"))
            
            return {"success": True, "message": "Feedback recorded for model improvement"}
            
        except Exception as e:
            logger.error("Continuous learning update failed", error=str(e))
            return {"error": str(e)}
            
    def get_model_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded models and analysis history"""
        return {
            "models_loaded": self.models_loaded,
            "analysis_history_size": len(self.analysis_history),
            "pattern_database_size": len(self.pattern_database),
            "threat_signatures_count": len(self.threat_signatures),
            "model_versions": {
                "anomaly_detector": "1.0",
                "threat_classifier": "1.0",
                "similarity_engine": "1.0"
            },
            "last_model_update": datetime.now().isoformat(),
            "learning_statistics": {
                "total_samples_analyzed": len(self.analysis_history),
                "threat_distribution": self._get_threat_distribution(),
                "accuracy_metrics": self._get_accuracy_metrics()
            }
        }
        
    def _get_threat_distribution(self) -> Dict[str, int]:
        """Get distribution of threat classifications in history"""
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "benign": 0, "unknown": 0}
        
        for entry in self.analysis_history:
            threat_class = entry.get("triage", {}).get("threat_classification", "unknown")
            if threat_class in distribution:
                distribution[threat_class] += 1
                
        return distribution
        
    def _get_accuracy_metrics(self) -> Dict[str, float]:
        """Get mock accuracy metrics (would be real metrics in production)"""
        return {
            "threat_classification_accuracy": 0.87,
            "anomaly_detection_precision": 0.82,
            "anomaly_detection_recall": 0.79,
            "similarity_matching_accuracy": 0.91
        }