"""BPHAI Orchestrator - Coordinates and aggregates RNU responses.

The orchestrator manages the flow of masked data through multiple RNUs
and intelligently aggregates their responses while maintaining security.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import time
import json

from core.rnu import RootedNeuralUnit, RNUType


class ThreatLevel(Enum):
    """Threat assessment levels."""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented
    
    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented
    
    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented
    
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented
    
    @property
    def name_str(self) -> str:
        """Get string representation of threat level."""
        return self.name.lower()


@dataclass
class RNUResponse:
    """Response from a single RNU."""
    rnu_id: str
    rnu_type: RNUType
    result: Dict[str, Any]
    trust_score: float
    processing_time: float
    threat_level: ThreatLevel
    metadata: Dict[str, Any]


@dataclass
class AggregatedResponse:
    """Final aggregated response from all RNUs."""
    final_result: Dict[str, Any]
    overall_threat_level: ThreatLevel
    confidence_score: float
    rnu_responses: List[RNUResponse]
    processing_summary: Dict[str, Any]
    timestamp: float
    status: str = "success"


class BPHAIOrchestrator:
    """Orchestrates the processing of input through multiple RNUs.
    
    The orchestrator ensures that:
    1. Input is properly masked before reaching RNUs
    2. RNU responses are aggregated intelligently
    3. Threat levels are assessed and handled appropriately
    4. System integrity is maintained throughout processing
    """
    
    def __init__(self, max_concurrent_rnus: int = 5):
        self.rnus: Dict[str, RootedNeuralUnit] = {}
        self.max_concurrent_rnus = max_concurrent_rnus
        self.logger = logging.getLogger(__name__)
        self._processing_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "blocked_requests": 0,
            "average_processing_time": 0.0
        }
    
    def register_rnu(self, rnu: RootedNeuralUnit) -> None:
        """Register a new RNU with the orchestrator."""
        if not rnu.is_sealed():
            raise ValueError(f"RNU {rnu.config.rnu_id} must be sealed before registration")
            
        self.rnus[rnu.config.rnu_id] = rnu
        self.logger.info(f"Registered RNU: {rnu.config.rnu_id} (type: {rnu.config.rnu_type.value})")
    
    def unregister_rnu(self, rnu_id: str) -> None:
        """Unregister an RNU from the orchestrator."""
        if rnu_id in self.rnus:
            del self.rnus[rnu_id]
            self.logger.info(f"Unregistered RNU: {rnu_id}")
    
    def get_registered_rnus(self) -> Dict[str, RootedNeuralUnit]:
        """Get all registered RNUs."""
        return self.rnus.copy()
    
    async def process_async(self, raw_input: Dict[str, Any]) -> AggregatedResponse:
        """Alias for process_request to maintain compatibility."""
        return await self.process_request(raw_input)
    
    def _mask_input(self, raw_input: Dict[str, Any]) -> Dict[str, Any]:
        """Apply input masking to protect RNUs from direct manipulation."""
        masked_input = {
            "data_payload": raw_input,
            "processing_context": {
                "timestamp": time.time(),
                "request_id": f"req_{int(time.time() * 1000000)}",
                "masking_applied": True
            },
            "metadata": {
                "input_size": len(json.dumps(raw_input)),
                "input_type": type(raw_input).__name__
            }
        }
        return masked_input
    
    def _assess_threat_level(self, rnu_responses: List[RNUResponse]) -> ThreatLevel:
        """Assess overall threat level based on RNU responses."""
        threat_scores = {
            ThreatLevel.SAFE: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        
        max_threat_score = 0
        weighted_threat = 0.0
        total_weight = 0.0
        
        for response in rnu_responses:
            threat_score = threat_scores[response.threat_level]
            weight = response.trust_score
            
            max_threat_score = max(max_threat_score, threat_score)
            weighted_threat += threat_score * weight
            total_weight += weight
        
        if total_weight == 0:
            return ThreatLevel.CRITICAL
        
        avg_threat = weighted_threat / total_weight
        
        # Convert back to threat level
        if avg_threat >= 3.5:
            return ThreatLevel.CRITICAL
        elif avg_threat >= 2.5:
            return ThreatLevel.HIGH
        elif avg_threat >= 1.5:
            return ThreatLevel.MEDIUM
        elif avg_threat >= 0.5:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE
    
    async def _process_with_rnu(self, rnu: RootedNeuralUnit, masked_input: Dict[str, Any]) -> RNUResponse:
        """Process input with a single RNU asynchronously."""
        start_time = time.time()
        
        try:
            # Process the masked input
            result = rnu.process(masked_input)
            
            # Determine threat level based on result
            threat_level = self._determine_threat_level(result, rnu.config.rnu_type)
            
            processing_time = time.time() - start_time
            
            return RNUResponse(
                rnu_id=rnu.config.rnu_id,
                rnu_type=rnu.config.rnu_type,
                result=result,
                trust_score=rnu.get_trust_score(),
                processing_time=processing_time,
                threat_level=threat_level,
                metadata=rnu.get_metadata()
            )
            
        except Exception as e:
            self.logger.error(f"Error processing with RNU {rnu.config.rnu_id}: {str(e)}")
            return RNUResponse(
                rnu_id=rnu.config.rnu_id,
                rnu_type=rnu.config.rnu_type,
                result={"error": str(e)},
                trust_score=0.0,
                processing_time=time.time() - start_time,
                threat_level=ThreatLevel.CRITICAL,
                metadata=rnu.get_metadata()
            )
    
    def _determine_threat_level(self, result: Dict[str, Any], rnu_type: RNUType) -> ThreatLevel:
        """Determine threat level based on RNU result and type."""
        if "error" in result:
            return ThreatLevel.HIGH
        
        if rnu_type == RNUType.SECURITY:
            # Security RNU results indicate threat levels directly
            return result.get("threat_level", ThreatLevel.MEDIUM)
        
        # For other RNU types, assess based on content
        if "suspicious_patterns" in result:
            pattern_count = len(result["suspicious_patterns"])
            if pattern_count >= 5:
                return ThreatLevel.HIGH
            elif pattern_count >= 3:
                return ThreatLevel.MEDIUM
            elif pattern_count >= 1:
                return ThreatLevel.LOW
        
        return ThreatLevel.SAFE
    
    def _aggregate_responses(self, rnu_responses: List[RNUResponse]) -> Dict[str, Any]:
        """Aggregate responses from multiple RNUs into a final result."""
        if not rnu_responses:
            return {"error": "No RNU responses to aggregate"}
        
        # Separate responses by type
        responses_by_type = {}
        for response in rnu_responses:
            rnu_type = response.rnu_type.value
            if rnu_type not in responses_by_type:
                responses_by_type[rnu_type] = []
            responses_by_type[rnu_type].append(response)
        
        # Aggregate based on trust scores
        final_result = {
            "status": "processed",
            "analysis": {},
            "recommendations": [],
            "confidence_factors": {}
        }
        
        for rnu_type, responses in responses_by_type.items():
            # Weight responses by trust score
            weighted_result = {}
            total_weight = sum(r.trust_score for r in responses)
            
            if total_weight > 0:
                for response in responses:
                    weight = response.trust_score / total_weight
                    for key, value in response.result.items():
                        if key not in weighted_result:
                            weighted_result[key] = value
                        # For numeric values, compute weighted average
                        elif isinstance(value, (int, float)) and isinstance(weighted_result[key], (int, float)):
                            weighted_result[key] = weighted_result[key] * (1 - weight) + value * weight
            
            final_result["analysis"][rnu_type] = weighted_result
        
        return final_result
    
    async def process_request(self, raw_input: Dict[str, Any]) -> AggregatedResponse:
        """Process a request through the BPHAI system."""
        start_time = time.time()
        self._processing_stats["total_requests"] += 1
        
        try:
            # Step 1: Mask the input
            masked_input = self._mask_input(raw_input)
            
            # Step 2: Process with all registered RNUs concurrently
            tasks = []
            for rnu in self.rnus.values():
                task = self._process_with_rnu(rnu, masked_input)
                tasks.append(task)
            
            # Limit concurrent processing
            if len(tasks) > self.max_concurrent_rnus:
                tasks = tasks[:self.max_concurrent_rnus]
            
            rnu_responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            valid_responses = [r for r in rnu_responses if isinstance(r, RNUResponse)]
            
            if not valid_responses:
                self._processing_stats["blocked_requests"] += 1
                return AggregatedResponse(
                    final_result={"error": "All RNUs failed to process request"},
                    overall_threat_level=ThreatLevel.CRITICAL,
                    confidence_score=0.0,
                    rnu_responses=[],
                    processing_summary={"error": "System failure"},
                    timestamp=time.time(),
                    status="error"
                )
            
            # Step 3: Assess threat level
            overall_threat_level = self._assess_threat_level(valid_responses)
            
            # Step 4: Aggregate responses
            final_result = self._aggregate_responses(valid_responses)
            
            # Step 5: Calculate confidence score
            confidence_score = sum(r.trust_score for r in valid_responses) / len(valid_responses)
            
            processing_time = time.time() - start_time
            self._processing_stats["successful_requests"] += 1
            
            # Update average processing time
            total_requests = self._processing_stats["successful_requests"]
            current_avg = self._processing_stats["average_processing_time"]
            self._processing_stats["average_processing_time"] = (
                (current_avg * (total_requests - 1) + processing_time) / total_requests
            )
            
            return AggregatedResponse(
                final_result=final_result,
                overall_threat_level=overall_threat_level,
                confidence_score=confidence_score,
                rnu_responses=valid_responses,
                processing_summary={
                    "processing_time": processing_time,
                    "rnus_used": len(valid_responses),
                    "threat_assessment": overall_threat_level.name_str
                },
                timestamp=time.time(),
                status="success"
            )
            
        except Exception as e:
            self.logger.error(f"Error in orchestrator processing: {str(e)}")
            self._processing_stats["blocked_requests"] += 1
            
            return AggregatedResponse(
                final_result={"error": f"Orchestrator error: {str(e)}"},
                overall_threat_level=ThreatLevel.CRITICAL,
                confidence_score=0.0,
                rnu_responses=[],
                processing_summary={"error": str(e)},
                timestamp=time.time(),
                status="error"
            )
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics."""
        return {
            "registered_rnus": len(self.rnus),
            "rnu_details": {rnu_id: rnu.get_metadata() for rnu_id, rnu in self.rnus.items()},
            "processing_stats": self._processing_stats.copy(),
            "system_health": "operational" if self.rnus else "no_rnus_registered"
        }