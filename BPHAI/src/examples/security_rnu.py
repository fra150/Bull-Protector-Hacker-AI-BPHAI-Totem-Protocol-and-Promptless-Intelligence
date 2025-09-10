"""Security RNU - Specialized for threat detection and security analysis.

This RNU is specifically designed to detect and analyze security threats,
including prompt injection attempts, malicious patterns, and suspicious behavior.
"""

import re
import hashlib
import json
import math
from typing import Dict, List, Any

from core.rnu import RootedNeuralUnit, RNUConfig, RNUType
from core.orchestrator import ThreatLevel


class SecurityRNU(RootedNeuralUnit):
    """Security-focused Rooted Neural Unit.
    
    This RNU implements advanced security analysis patterns embedded
    directly into its neural architecture, making it immune to prompt
    injection while maintaining high threat detection accuracy.
    """
    
    def __init__(self):
        # Generate behavior hash for this specific RNU
        behavior_patterns = {
            "core_directive": self._get_core_directive(),
            "security_constraints": self._get_security_constraints(),
            "processing_rules": self._get_processing_rules(),
            "response_filters": self._get_response_filters()
        }
        
        behavior_str = json.dumps(behavior_patterns, sort_keys=True)
        behavior_hash = hashlib.sha256(behavior_str.encode()).hexdigest()
        
        config = RNUConfig(
            rnu_id="security_rnu_001",
            rnu_type=RNUType.SECURITY,
            behavior_hash=behavior_hash,
            trust_level=0.95,
            max_input_size=2048,
            timeout_seconds=15
        )
        
        super().__init__(config)
        
        # Initialize threat detection patterns
        self._threat_patterns = self._initialize_threat_patterns()
        self._anomaly_baseline = self._initialize_anomaly_baseline()
        
        # Seal the RNU to prevent modifications
        self.seal()
    
    def _get_core_directive(self) -> str:
        """Return the core security directive."""
        return "Analyze input for security threats and malicious patterns"
    
    def _get_security_constraints(self) -> List[str]:
        """Return security constraints for this RNU."""
        return [
            "no_code_execution",
            "no_system_commands",
            "no_prompt_injection",
            "no_data_exfiltration"
        ]
    
    def _get_processing_rules(self) -> Dict[str, Any]:
        """Return processing rules for security analysis."""
        return {
            "threat_detection": True,
            "pattern_analysis": True,
            "behavioral_analysis": True,
            "anomaly_detection": True,
            "real_time_analysis": True,
            "multi_layer_scanning": True
        }
    
    def _get_response_filters(self) -> List[str]:
        """Return response filtering rules."""
        return [
            "sanitize_output",
            "remove_sensitive_data",
            "threat_level_classification",
            "confidence_scoring"
        ]
    
    def _initialize_threat_patterns(self) -> Dict[str, List[str]]:
        """Initialize threat detection patterns."""
        return {
            "prompt_injection": [
                r"ignore\s+previous\s+instructions?",
                r"forget\s+everything\s+above",
                r"new\s+instructions?:",
                r"system\s*:\s*",
                r"assistant\s*:\s*",
                r"user\s*:\s*",
                r"prompt\s*:\s*",
                r"override\s+security",
                r"bypass\s+filter",
                r"jailbreak",
                r"roleplay\s+as",
                r"pretend\s+to\s+be",
                r"act\s+as\s+if"
            ],
            
            "code_injection": [
                r"<script[^>]*>",
                r"javascript:",
                r"eval\s*\(",
                r"exec\s*\(",
                r"import\s+os",
                r"import\s+subprocess",
                r"__import__",
                r"getattr\s*\(",
                r"setattr\s*\(",
                r"\$\{.*\}",  # Template injection
                r"<%.*%>",    # Template injection
            ],
            
            "system_commands": [
                r"rm\s+-rf",
                r"del\s+/[sq]",
                r"format\s+c:",
                r"shutdown\s+",
                r"reboot",
                r"passwd",
                r"sudo\s+",
                r"chmod\s+777",
                r"wget\s+",
                r"curl\s+.*\|\s*sh",
                r"nc\s+-l",  # netcat listener
                r"/bin/sh",
                r"/bin/bash"
            ],
            
            "data_exfiltration": [
                r"cat\s+/etc/passwd",
                r"cat\s+/etc/shadow",
                r"ls\s+-la\s+/",
                r"find\s+/\s+-name",
                r"grep\s+-r\s+password",
                r"base64\s+-d",
                r"echo\s+.*\|\s*base64",
                r"SELECT\s+.*\s+FROM\s+users",
                r"UNION\s+SELECT",
                r"information_schema"
            ],
            
            "social_engineering": [
                r"urgent\s+security\s+update",
                r"verify\s+your\s+account",
                r"click\s+here\s+immediately",
                r"suspended\s+account",
                r"confirm\s+your\s+identity",
                r"temporary\s+access",
                r"limited\s+time\s+offer",
                r"act\s+now\s+or"
            ]
        }
    
    def _initialize_anomaly_baseline(self) -> Dict[str, Any]:
        """Initialize baseline for anomaly detection."""
        return {
            "normal_input_length": {"min": 10, "max": 500, "avg": 150},
            "normal_word_count": {"min": 5, "max": 100, "avg": 30},
            "normal_special_chars": {"max_ratio": 0.1},
            "normal_entropy": {"min": 3.0, "max": 6.0},
            "suspicious_keywords_threshold": 3
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
            
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        text_len = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _detect_threat_patterns(self, input_text: str) -> Dict[str, List[str]]:
        """Detect threat patterns in input text."""
        detected_threats = {}
        
        for threat_type, patterns in self._threat_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, input_text, re.IGNORECASE | re.MULTILINE):
                    matches.append(pattern)
            
            if matches:
                detected_threats[threat_type] = matches
        
        return detected_threats
    
    def _analyze_anomalies(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze input for anomalous characteristics."""
        input_text = str(input_data)
        anomalies = {}
        
        # Length anomaly
        text_length = len(input_text)
        baseline = self._anomaly_baseline["normal_input_length"]
        if text_length < baseline["min"] or text_length > baseline["max"]:
            anomalies["length_anomaly"] = {
                "actual": text_length,
                "expected_range": f"{baseline['min']}-{baseline['max']}"
            }
        
        # Word count anomaly
        word_count = len(input_text.split())
        word_baseline = self._anomaly_baseline["normal_word_count"]
        if word_count < word_baseline["min"] or word_count > word_baseline["max"]:
            anomalies["word_count_anomaly"] = {
                "actual": word_count,
                "expected_range": f"{word_baseline['min']}-{word_baseline['max']}"
            }
        
        # Special character ratio
        special_chars = sum(1 for c in input_text if not c.isalnum() and not c.isspace())
        special_ratio = special_chars / len(input_text) if input_text else 0
        max_ratio = self._anomaly_baseline["normal_special_chars"]["max_ratio"]
        if special_ratio > max_ratio:
            anomalies["special_char_anomaly"] = {
                "actual_ratio": round(special_ratio, 3),
                "max_expected": max_ratio
            }
        
        # Entropy anomaly
        entropy = self._calculate_entropy(input_text)
        entropy_baseline = self._anomaly_baseline["normal_entropy"]
        if entropy < entropy_baseline["min"] or entropy > entropy_baseline["max"]:
            anomalies["entropy_anomaly"] = {
                "actual": round(entropy, 2),
                "expected_range": f"{entropy_baseline['min']}-{entropy_baseline['max']}"
            }
        
        return anomalies
    
    def _calculate_threat_level(self, threats: Dict[str, List[str]], anomalies: Dict[str, Any]) -> ThreatLevel:
        """Calculate overall threat level based on detected threats and anomalies."""
        threat_score = 0
        
        # Score based on threat types
        threat_weights = {
            "prompt_injection": 4,
            "code_injection": 5,
            "system_commands": 5,
            "data_exfiltration": 4,
            "social_engineering": 2
        }
        
        for threat_type, matches in threats.items():
            weight = threat_weights.get(threat_type, 1)
            threat_score += len(matches) * weight
        
        # Score based on anomalies
        anomaly_score = len(anomalies) * 2
        total_score = threat_score + anomaly_score
        
        # Convert to threat level
        if total_score >= 15:
            return ThreatLevel.CRITICAL
        elif total_score >= 10:
            return ThreatLevel.HIGH
        elif total_score >= 5:
            return ThreatLevel.MEDIUM
        elif total_score >= 1:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE
    
    def process(self, masked_input: Dict[str, Any]) -> Dict[str, Any]:
        """Process input for security analysis."""
        if not self._validate_input(masked_input):
            return {
                "error": "Input validation failed",
                "threat_level": ThreatLevel.CRITICAL,
                "confidence": 1.0
            }
        
        # Extract data payload
        data_payload = masked_input.get("data_payload", {})
        input_text = json.dumps(data_payload) if isinstance(data_payload, dict) else str(data_payload)
        
        # Detect threat patterns
        detected_threats = self._detect_threat_patterns(input_text)
        
        # Analyze anomalies
        detected_anomalies = self._analyze_anomalies(data_payload)
        
        # Calculate threat level
        threat_level = self._calculate_threat_level(detected_threats, detected_anomalies)
        
        # Calculate confidence score
        confidence = min(1.0, (len(detected_threats) + len(detected_anomalies)) * 0.2 + 0.5)
        
        # Record processing in history
        self._input_history.append({
            "timestamp": masked_input.get("processing_context", {}).get("timestamp"),
            "threat_level": threat_level.name_str,
            "threats_detected": len(detected_threats),
            "anomalies_detected": len(detected_anomalies)
        })
        
        return {
            "status": "security_analysis_complete",
            "threat_level": threat_level,
            "confidence_score": confidence,
            "detected_threats": detected_threats,
            "detected_anomalies": detected_anomalies,
            "suspicious_patterns": list(detected_threats.keys()),
            "security_recommendation": self._get_security_recommendation(threat_level),
            "analysis_metadata": {
                "input_length": len(input_text),
                "processing_time": masked_input.get("processing_context", {}).get("timestamp"),
                "rnu_id": self.config.rnu_id
            }
        }
    
    def _get_security_recommendation(self, threat_level: ThreatLevel) -> str:
        """Get security recommendation based on threat level."""
        recommendations = {
            ThreatLevel.SAFE: "Input appears safe, proceed with normal processing",
            ThreatLevel.LOW: "Minor security concerns detected, apply additional monitoring",
            ThreatLevel.MEDIUM: "Moderate security risk, implement enhanced filtering",
            ThreatLevel.HIGH: "High security risk detected, block request and log incident",
            ThreatLevel.CRITICAL: "Critical security threat, immediate blocking and alert required"
        }
        
        return recommendations.get(threat_level, "Unknown threat level, apply maximum security")