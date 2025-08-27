"""
AI-Powered Threat Classification System
Advanced threat classification using machine learning models
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow import keras
import structlog
import joblib
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import pickle

logger = structlog.get_logger()

class ThreatClassifier:
    """Advanced AI-powered threat classification system"""
    
    def __init__(self):
        self.rf_classifier = None
        self.isolation_forest = None
        self.deep_classifier = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000)
        self.models_trained = False
        self.feature_names = []
        self.threat_categories = [
            'benign', 'malware', 'trojan', 'ransomware', 'spyware', 
            'adware', 'rootkit', 'backdoor', 'worm', 'virus'
        ]
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models with default configurations"""
        try:
            # Random Forest for multi-class classification
            self.rf_classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            
            # Isolation Forest for anomaly detection
            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            
            # Deep neural network for complex pattern recognition
            self._build_deep_classifier()
            
            logger.info("Threat classification models initialized")
            
        except Exception as e:
            logger.error("Failed to initialize models", error=str(e))
            raise
    
    def _build_deep_classifier(self):
        """Build deep neural network for threat classification"""
        try:
            self.deep_classifier = keras.Sequential([
                keras.layers.Dense(512, activation='relu', input_shape=(None,)),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(256, activation='relu'),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(128, activation='relu'),
                keras.layers.Dropout(0.2),
                keras.layers.Dense(64, activation='relu'),
                keras.layers.Dense(len(self.threat_categories), activation='softmax')
            ])
            
            self.deep_classifier.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
        except Exception as e:
            logger.error("Failed to build deep classifier", error=str(e))
    
    async def classify_threat(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify threat using multiple ML models"""
        try:
            # Extract and prepare features
            features = self._extract_features(analysis_data)
            
            if not features:
                return {"error": "No features could be extracted for classification"}
            
            # Prepare feature vector
            feature_vector = self._prepare_feature_vector(features)
            
            results = {
                "classification": {},
                "anomaly_detection": {},
                "confidence_scores": {},
                "feature_importance": {},
                "model_predictions": {}
            }
            
            # Random Forest classification
            if self.models_trained:
                rf_prediction = await self._classify_with_rf(feature_vector)
                results["classification"]["random_forest"] = rf_prediction
            else:
                # Use rule-based classification as fallback
                rule_based = self._rule_based_classification(features)
                results["classification"]["rule_based"] = rule_based
            
            # Anomaly detection
            anomaly_result = await self._detect_anomaly(feature_vector)
            results["anomaly_detection"] = anomaly_result
            
            # Deep learning classification (if trained)
            if self.models_trained:
                deep_prediction = await self._classify_with_deep_model(feature_vector)
                results["classification"]["deep_learning"] = deep_prediction
            
            # Ensemble prediction combining all models
            ensemble_result = self._ensemble_prediction(results["classification"])
            results["final_prediction"] = ensemble_result
            
            # Feature importance analysis
            importance = self._analyze_feature_importance(features, ensemble_result)
            results["feature_importance"] = importance
            
            logger.info("Threat classification completed", 
                       prediction=ensemble_result.get("threat_type"),
                       confidence=ensemble_result.get("confidence"))
            
            return results
            
        except Exception as e:
            logger.error("Threat classification failed", error=str(e))
            return {"error": str(e)}
    
    def _extract_features(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant features for classification"""
        features = {
            # Static analysis features
            "file_size": 0,
            "entropy": 0.0,
            "section_count": 0,
            "import_count": 0,
            "export_count": 0,
            "string_count": 0,
            
            # API call features
            "api_call_count": 0,
            "suspicious_api_ratio": 0.0,
            "network_api_count": 0,
            "file_api_count": 0,
            "registry_api_count": 0,
            "crypto_api_count": 0,
            
            # Behavioral features
            "has_network_capability": False,
            "has_file_manipulation": False,
            "has_registry_access": False,
            "has_process_manipulation": False,
            "has_crypto_operations": False,
            
            # String analysis features
            "suspicious_string_count": 0,
            "url_count": 0,
            "ip_count": 0,
            "domain_count": 0,
            
            # Packing/obfuscation indicators
            "is_packed": False,
            "high_entropy_sections": 0,
            "unusual_entry_point": False,
            
            # Pattern matching results
            "yara_matches": 0,
            "signature_matches": 0
        }
        
        # Extract from static analysis
        static_analysis = analysis_data.get("static_analysis", {})
        
        # File information
        file_info = static_analysis.get("file_info", {})
        features["file_size"] = file_info.get("size", 0)
        features["entropy"] = file_info.get("entropy", 0.0)
        
        # Section information
        sections = static_analysis.get("sections", [])
        features["section_count"] = len(sections)
        features["high_entropy_sections"] = sum(1 for s in sections 
                                              if isinstance(s, dict) and s.get("entropy", 0) > 7.0)
        
        # Import/Export information
        imports = static_analysis.get("imports", {})
        features["import_count"] = sum(len(dll_imports) for dll_imports in imports.values())
        
        exports = static_analysis.get("exports", [])
        features["export_count"] = len(exports)
        
        # String analysis
        strings = static_analysis.get("strings", [])
        features["string_count"] = len(strings)
        
        # Count different types of strings
        features["suspicious_string_count"] = sum(1 for s in strings 
                                                if any(keyword in s.lower() 
                                                      for keyword in ["password", "admin", "exploit"]))
        
        import re
        url_pattern = r"https?://[^\s]+"
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        domain_pattern = r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"
        
        all_strings = " ".join(strings)
        features["url_count"] = len(re.findall(url_pattern, all_strings))
        features["ip_count"] = len(re.findall(ip_pattern, all_strings))
        features["domain_count"] = len(re.findall(domain_pattern, all_strings))
        
        # API call analysis
        api_calls = []
        for dll_imports in imports.values():
            if isinstance(dll_imports, list):
                api_calls.extend(dll_imports)
        
        features["api_call_count"] = len(api_calls)
        
        # Categorize API calls
        network_apis = {"WSAStartup", "socket", "connect", "InternetOpen", "HttpOpenRequest"}
        file_apis = {"CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile"}
        registry_apis = {"RegCreateKeyEx", "RegSetValueEx", "RegOpenKeyEx", "RegDeleteKey"}
        crypto_apis = {"CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptGenKey"}
        process_apis = {"CreateProcess", "OpenProcess", "TerminateProcess"}
        
        features["network_api_count"] = sum(1 for api in api_calls if api in network_apis)
        features["file_api_count"] = sum(1 for api in api_calls if api in file_apis)
        features["registry_api_count"] = sum(1 for api in api_calls if api in registry_apis)
        features["crypto_api_count"] = sum(1 for api in api_calls if api in crypto_apis)
        
        # Behavioral features
        features["has_network_capability"] = features["network_api_count"] > 0
        features["has_file_manipulation"] = features["file_api_count"] > 0
        features["has_registry_access"] = features["registry_api_count"] > 0
        features["has_process_manipulation"] = sum(1 for api in api_calls if api in process_apis) > 0
        features["has_crypto_operations"] = features["crypto_api_count"] > 0
        
        # Suspicious API ratio
        suspicious_apis = network_apis | crypto_apis | process_apis
        if features["api_call_count"] > 0:
            features["suspicious_api_ratio"] = sum(1 for api in api_calls if api in suspicious_apis) / features["api_call_count"]
        
        # Packing indicators
        features["is_packed"] = features["high_entropy_sections"] > 0 or features["entropy"] > 7.0
        
        # Pattern matching (if available)
        pattern_results = analysis_data.get("pattern_analysis", {})
        features["yara_matches"] = len(pattern_results.get("yara_matches", []))
        features["signature_matches"] = len(pattern_results.get("signature_matches", []))
        
        return features
    
    def _prepare_feature_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """Prepare feature vector for ML models"""
        # Define feature order for consistent vector creation
        if not self.feature_names:
            self.feature_names = [
                "file_size", "entropy", "section_count", "import_count", "export_count",
                "string_count", "api_call_count", "suspicious_api_ratio", "network_api_count",
                "file_api_count", "registry_api_count", "crypto_api_count", "suspicious_string_count",
                "url_count", "ip_count", "domain_count", "high_entropy_sections", "yara_matches",
                "signature_matches"
            ]
        
        # Create numerical feature vector
        feature_vector = []
        for feature_name in self.feature_names:
            value = features.get(feature_name, 0)
            if isinstance(value, bool):
                value = 1 if value else 0
            feature_vector.append(float(value))
        
        # Add boolean features as additional dimensions
        boolean_features = [
            "has_network_capability", "has_file_manipulation", "has_registry_access",
            "has_process_manipulation", "has_crypto_operations", "is_packed", "unusual_entry_point"
        ]
        
        for feature_name in boolean_features:
            value = features.get(feature_name, False)
            feature_vector.append(1.0 if value else 0.0)
        
        return np.array(feature_vector).reshape(1, -1)
    
    async def _classify_with_rf(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Classify using Random Forest model"""
        try:
            # Scale features
            scaled_features = self.scaler.transform(feature_vector)
            
            # Predict
            prediction = self.rf_classifier.predict(scaled_features)[0]
            probabilities = self.rf_classifier.predict_proba(scaled_features)[0]
            
            # Get class names
            classes = self.rf_classifier.classes_
            
            # Create probability dictionary
            class_probabilities = {
                classes[i]: float(probabilities[i]) 
                for i in range(len(classes))
            }
            
            return {
                "predicted_class": prediction,
                "confidence": float(max(probabilities)),
                "class_probabilities": class_probabilities,
                "model": "random_forest"
            }
            
        except Exception as e:
            logger.error("Random Forest classification failed", error=str(e))
            return {"error": str(e)}
    
    async def _classify_with_deep_model(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Classify using deep neural network"""
        try:
            # Scale features
            scaled_features = self.scaler.transform(feature_vector)
            
            # Predict
            predictions = self.deep_classifier.predict(scaled_features, verbose=0)
            predicted_class_idx = np.argmax(predictions[0])
            confidence = float(predictions[0][predicted_class_idx])
            
            # Create probability dictionary
            class_probabilities = {
                self.threat_categories[i]: float(predictions[0][i])
                for i in range(len(self.threat_categories))
            }
            
            return {
                "predicted_class": self.threat_categories[predicted_class_idx],
                "confidence": confidence,
                "class_probabilities": class_probabilities,
                "model": "deep_neural_network"
            }
            
        except Exception as e:
            logger.error("Deep learning classification failed", error=str(e))
            return {"error": str(e)}
    
    async def _detect_anomaly(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Detect anomalies using Isolation Forest"""
        try:
            if not self.models_trained:
                # Use simple threshold-based anomaly detection
                return self._threshold_based_anomaly_detection(feature_vector)
            
            # Scale features
            scaled_features = self.scaler.transform(feature_vector)
            
            # Predict anomaly
            anomaly_prediction = self.isolation_forest.predict(scaled_features)[0]
            anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]
            
            is_anomaly = anomaly_prediction == -1
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": float(anomaly_score),
                "threshold": 0.0,
                "model": "isolation_forest"
            }
            
        except Exception as e:
            logger.error("Anomaly detection failed", error=str(e))
            return {"error": str(e)}
    
    def _threshold_based_anomaly_detection(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Simple threshold-based anomaly detection"""
        features = feature_vector[0]
        
        anomaly_score = 0.0
        anomaly_indicators = []
        
        # Check various thresholds
        if len(features) > 0:
            # High entropy
            if features[1] > 7.5:  # entropy
                anomaly_score += 0.3
                anomaly_indicators.append("high_entropy")
            
            # Excessive API calls
            if features[6] > 500:  # api_call_count
                anomaly_score += 0.2
                anomaly_indicators.append("excessive_api_calls")
            
            # High suspicious API ratio
            if features[7] > 0.5:  # suspicious_api_ratio
                anomaly_score += 0.3
                anomaly_indicators.append("high_suspicious_api_ratio")
            
            # Many high entropy sections
            if len(features) > 16 and features[16] > 2:  # high_entropy_sections
                anomaly_score += 0.2
                anomaly_indicators.append("multiple_high_entropy_sections")
        
        is_anomaly = anomaly_score > 0.5
        
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "anomaly_indicators": anomaly_indicators,
            "threshold": 0.5,
            "model": "threshold_based"
        }
    
    def _rule_based_classification(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based threat classification as fallback"""
        score_weights = {
            'malware': 0.0,
            'trojan': 0.0,
            'ransomware': 0.0,
            'spyware': 0.0,
            'adware': 0.0,
            'benign': 0.1  # Default slight benign bias
        }
        
        # Network capability + crypto = potential ransomware/banking trojan
        if features.get("has_network_capability") and features.get("has_crypto_operations"):
            score_weights['ransomware'] += 0.4
            score_weights['trojan'] += 0.3
        
        # High entropy + packing = likely malware
        if features.get("is_packed") or features.get("entropy", 0) > 7.0:
            score_weights['malware'] += 0.3
            score_weights['trojan'] += 0.2
        
        # Process manipulation + registry = persistence mechanism
        if features.get("has_process_manipulation") and features.get("has_registry_access"):
            score_weights['trojan'] += 0.3
            score_weights['malware'] += 0.2
        
        # High suspicious API ratio
        if features.get("suspicious_api_ratio", 0) > 0.4:
            score_weights['malware'] += 0.3
        
        # Many suspicious strings
        if features.get("suspicious_string_count", 0) > 5:
            score_weights['malware'] += 0.2
        
        # Network indicators (URLs, IPs)
        if features.get("url_count", 0) + features.get("ip_count", 0) > 3:
            score_weights['spyware'] += 0.2
            score_weights['trojan'] += 0.2
        
        # Find highest scoring category
        predicted_class = max(score_weights, key=score_weights.get)
        confidence = score_weights[predicted_class]
        
        return {
            "predicted_class": predicted_class,
            "confidence": confidence,
            "class_probabilities": score_weights,
            "model": "rule_based"
        }
    
    def _ensemble_prediction(self, classifications: Dict[str, Any]) -> Dict[str, Any]:
        """Combine predictions from multiple models"""
        if not classifications:
            return {"error": "No classifications to ensemble"}
        
        # Weight different models
        model_weights = {
            "random_forest": 0.4,
            "deep_learning": 0.4,
            "rule_based": 0.2
        }
        
        # Collect all predictions and confidences
        class_votes = {}
        total_confidence = 0.0
        prediction_count = 0
        
        for model_name, classification in classifications.items():
            if "error" in classification:
                continue
                
            predicted_class = classification.get("predicted_class")
            confidence = classification.get("confidence", 0.0)
            weight = model_weights.get(model_name, 0.1)
            
            if predicted_class:
                if predicted_class not in class_votes:
                    class_votes[predicted_class] = 0.0
                
                weighted_score = confidence * weight
                class_votes[predicted_class] += weighted_score
                total_confidence += weighted_score
                prediction_count += 1
        
        if not class_votes:
            return {"error": "No valid predictions from any model"}
        
        # Find the class with highest weighted vote
        final_prediction = max(class_votes, key=class_votes.get)
        final_confidence = class_votes[final_prediction]
        
        # Normalize confidence
        if total_confidence > 0:
            final_confidence = final_confidence / total_confidence
        
        return {
            "threat_type": final_prediction,
            "confidence": final_confidence,
            "class_votes": class_votes,
            "models_used": list(classifications.keys()),
            "ensemble_method": "weighted_voting"
        }
    
    def _analyze_feature_importance(self, features: Dict[str, Any], prediction: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze which features contributed most to the classification"""
        important_features = []
        
        # Check which features have high values that could influence classification
        if features.get("suspicious_api_ratio", 0) > 0.3:
            important_features.append({
                "feature": "suspicious_api_ratio",
                "value": features["suspicious_api_ratio"],
                "importance": "high",
                "impact": "Strong indicator of malicious behavior"
            })
        
        if features.get("entropy", 0) > 7.0:
            important_features.append({
                "feature": "entropy",
                "value": features["entropy"],
                "importance": "high",
                "impact": "High entropy suggests packing or encryption"
            })
        
        if features.get("has_crypto_operations"):
            important_features.append({
                "feature": "crypto_operations",
                "value": True,
                "importance": "medium",
                "impact": "Cryptographic capabilities present"
            })
        
        if features.get("network_api_count", 0) > 5:
            important_features.append({
                "feature": "network_api_count",
                "value": features["network_api_count"],
                "importance": "medium",
                "impact": "Significant network communication capability"
            })
        
        return {
            "important_features": important_features,
            "feature_count": len(important_features),
            "analysis_method": "rule_based_importance"
        }
    
    async def train_models(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train ML models with provided training data"""
        try:
            if len(training_data) < 10:
                return {"error": "Insufficient training data (minimum 10 samples required)"}
            
            # Prepare training features and labels
            X = []
            y = []
            
            for sample in training_data:
                features = self._extract_features(sample["analysis_data"])
                feature_vector = self._prepare_feature_vector(features)
                X.append(feature_vector[0])
                y.append(sample["label"])
            
            X = np.array(X)
            y = np.array(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest
            self.rf_classifier.fit(X_train_scaled, y_train)
            rf_score = self.rf_classifier.score(X_test_scaled, y_test)
            
            # Train Isolation Forest for anomaly detection
            # Use only "benign" samples for training
            benign_mask = y_train == 'benign'
            if np.sum(benign_mask) > 5:
                self.isolation_forest.fit(X_train_scaled[benign_mask])
            
            # Train deep learning model
            y_train_encoded = self.label_encoder.fit_transform(y_train)
            y_test_encoded = self.label_encoder.transform(y_test)
            
            # Rebuild deep classifier with correct input shape
            input_dim = X_train_scaled.shape[1]
            self.deep_classifier = keras.Sequential([
                keras.layers.Dense(512, activation='relu', input_shape=(input_dim,)),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(256, activation='relu'),
                keras.layers.Dropout(0.3),
                keras.layers.Dense(128, activation='relu'),
                keras.layers.Dropout(0.2),
                keras.layers.Dense(64, activation='relu'),
                keras.layers.Dense(len(np.unique(y_train_encoded)), activation='softmax')
            ])
            
            self.deep_classifier.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
            # Train deep model
            history = self.deep_classifier.fit(
                X_train_scaled, y_train_encoded,
                epochs=50,
                batch_size=32,
                validation_data=(X_test_scaled, y_test_encoded),
                verbose=0
            )
            
            # Evaluate deep model
            deep_score = self.deep_classifier.evaluate(X_test_scaled, y_test_encoded, verbose=0)[1]
            
            self.models_trained = True
            
            training_results = {
                "success": True,
                "training_samples": len(training_data),
                "test_samples": len(y_test),
                "random_forest_accuracy": rf_score,
                "deep_learning_accuracy": deep_score,
                "feature_count": X.shape[1],
                "classes_trained": list(np.unique(y)),
                "training_timestamp": datetime.now().isoformat()
            }
            
            logger.info("Model training completed", 
                       rf_accuracy=rf_score,
                       dl_accuracy=deep_score)
            
            return training_results
            
        except Exception as e:
            logger.error("Model training failed", error=str(e))
            return {"error": str(e)}
    
    def save_models(self, model_path: str) -> Dict[str, Any]:
        """Save trained models to disk"""
        try:
            if not self.models_trained:
                return {"error": "No trained models to save"}
            
            # Save Random Forest
            joblib.dump(self.rf_classifier, f"{model_path}/rf_classifier.pkl")
            joblib.dump(self.isolation_forest, f"{model_path}/isolation_forest.pkl")
            joblib.dump(self.scaler, f"{model_path}/scaler.pkl")
            joblib.dump(self.label_encoder, f"{model_path}/label_encoder.pkl")
            
            # Save deep learning model
            self.deep_classifier.save(f"{model_path}/deep_classifier.h5")
            
            # Save metadata
            metadata = {
                "feature_names": self.feature_names,
                "threat_categories": self.threat_categories,
                "models_trained": self.models_trained,
                "save_timestamp": datetime.now().isoformat()
            }
            
            with open(f"{model_path}/metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("Models saved successfully", path=model_path)
            return {"success": True, "path": model_path}
            
        except Exception as e:
            logger.error("Failed to save models", error=str(e))
            return {"error": str(e)}
    
    def load_models(self, model_path: str) -> Dict[str, Any]:
        """Load trained models from disk"""
        try:
            # Load Random Forest and preprocessing
            self.rf_classifier = joblib.load(f"{model_path}/rf_classifier.pkl")
            self.isolation_forest = joblib.load(f"{model_path}/isolation_forest.pkl")
            self.scaler = joblib.load(f"{model_path}/scaler.pkl")
            self.label_encoder = joblib.load(f"{model_path}/label_encoder.pkl")
            
            # Load deep learning model
            self.deep_classifier = keras.models.load_model(f"{model_path}/deep_classifier.h5")
            
            # Load metadata
            with open(f"{model_path}/metadata.json", 'r') as f:
                metadata = json.load(f)
            
            self.feature_names = metadata["feature_names"]
            self.threat_categories = metadata["threat_categories"]
            self.models_trained = True
            
            logger.info("Models loaded successfully", path=model_path)
            return {"success": True, "metadata": metadata}
            
        except Exception as e:
            logger.error("Failed to load models", error=str(e))
            return {"error": str(e)}
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about current models"""
        return {
            "models_trained": self.models_trained,
            "feature_count": len(self.feature_names),
            "threat_categories": self.threat_categories,
            "models": {
                "random_forest": self.rf_classifier is not None,
                "isolation_forest": self.isolation_forest is not None,
                "deep_learning": self.deep_classifier is not None
            },
            "preprocessing": {
                "scaler": self.scaler is not None,
                "label_encoder": self.label_encoder is not None,
                "tfidf_vectorizer": self.tfidf_vectorizer is not None
            }
        }