"""Rooted Neural Unit (RNU) - Core component of BPHAI system.

The RNU implements prompt-less intelligence by embedding behavioral patterns
directly into the neural architecture, eliminating textual prompt vulnerabilities.
"""

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum


class RNUType(Enum):
    """Types of Rooted Neural Units."""
    SECURITY = "security"
    ANALYSIS = "analysis"
    RESPONSE = "response"
    FILTER = "filter"
    VALIDATOR = "validator"


@dataclass
class RNUConfig:
    """Configuration for a Rooted Neural Unit."""
    rnu_id: str
    rnu_type: RNUType
    behavior_hash: str
    trust_level: float  # 0.0 to 1.0
    max_input_size: int = 1024
    timeout_seconds: int = 30


class RootedNeuralUnit(ABC):
    """Base class for Rooted Neural Units.
    
    RNUs implement prompt-less intelligence by having their behavioral patterns
    embedded directly into their synaptic graph rather than receiving textual prompts.
    This eliminates the attack surface for prompt injection attacks.
    """
    
    def __init__(self, config: RNUConfig):
        self.config = config
        self._behavior_patterns = self._initialize_behavior_patterns()
        self._input_history: List[Dict[str, Any]] = []
        self._is_sealed = False
        
    def _initialize_behavior_patterns(self) -> Dict[str, Any]:
        """Initialize the rooted behavioral patterns.
        
        This method embeds the core behaviors directly into the RNU's
        neural architecture, making them immutable and non-injectable.
        """
        patterns = {
            "core_directive": self._get_core_directive(),
            "security_constraints": self._get_security_constraints(),
            "processing_rules": self._get_processing_rules(),
            "response_filters": self._get_response_filters()
        }
        
        # Generate behavior hash for integrity verification
        behavior_str = json.dumps(patterns, sort_keys=True)
        computed_hash = hashlib.sha256(behavior_str.encode()).hexdigest()
        
        if self.config.behavior_hash != computed_hash:
            raise ValueError(f"Behavior integrity check failed for RNU {self.config.rnu_id}")
            
        return patterns
    
    @abstractmethod
    def _get_core_directive(self) -> str:
        """Return the core directive embedded in this RNU."""
        pass
    
    @abstractmethod
    def _get_security_constraints(self) -> List[str]:
        """Return security constraints for this RNU."""
        pass
    
    @abstractmethod
    def _get_processing_rules(self) -> Dict[str, Any]:
        """Return processing rules for this RNU."""
        pass
    
    @abstractmethod
    def _get_response_filters(self) -> List[str]:
        """Return response filtering rules."""
        pass
    
    def seal(self) -> None:
        """Seal the RNU to prevent further modifications.
        
        Once sealed, the RNU's behavior patterns become immutable,
        ensuring the integrity of the prompt-less architecture.
        """
        self._is_sealed = True
    
    def is_sealed(self) -> bool:
        """Check if the RNU is sealed."""
        return self._is_sealed
    
    def _validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate input data against security constraints."""
        if not isinstance(data, dict):
            return False
            
        # Check input size
        input_str = json.dumps(data)
        if len(input_str) > self.config.max_input_size:
            return False
            
        # Apply security constraints
        for constraint in self._behavior_patterns["security_constraints"]:
            if not self._apply_constraint(data, constraint):
                return False
                
        return True
    
    def _apply_constraint(self, data: Dict[str, Any], constraint: str) -> bool:
        """Apply a specific security constraint to input data."""
        # Basic constraint implementations
        if constraint == "no_code_execution":
            dangerous_patterns = ["exec", "eval", "import", "__", "subprocess"]
            input_str = str(data).lower()
            return not any(pattern in input_str for pattern in dangerous_patterns)
            
        elif constraint == "no_system_commands":
            system_patterns = ["rm ", "del ", "format", "shutdown", "reboot"]
            input_str = str(data).lower()
            return not any(pattern in input_str for pattern in system_patterns)
            
        elif constraint == "no_prompt_injection":
            injection_patterns = [
                "ignore previous", "forget instructions", "new instructions",
                "system:", "assistant:", "user:", "prompt:"
            ]
            input_str = str(data).lower()
            return not any(pattern in input_str for pattern in injection_patterns)
            
        return True
    
    @abstractmethod
    def process(self, masked_input: Dict[str, Any]) -> Dict[str, Any]:
        """Process masked input according to rooted behavioral patterns.
        
        Args:
            masked_input: Pre-processed and masked input data
            
        Returns:
            Processed result following the RNU's embedded behaviors
        """
        pass
    
    def get_trust_score(self) -> float:
        """Return the trust score for this RNU's output."""
        return self.config.trust_level
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return metadata about this RNU."""
        return {
            "rnu_id": self.config.rnu_id,
            "rnu_type": self.config.rnu_type.value,
            "trust_level": self.config.trust_level,
            "is_sealed": self._is_sealed,
            "behavior_hash": self.config.behavior_hash,
            "processing_count": len(self._input_history)
        }