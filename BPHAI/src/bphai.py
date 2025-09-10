"""BPHAI - Behavioral Pattern Hardcoded AI System.

Main interface for the BPHAI system that provides prompt-less intelligence
through Rooted Neural Units (RNUs) with embedded behavioral patterns.
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass, asdict
from core.orchestrator import BPHAIOrchestrator, ThreatLevel, AggregatedResponse
from core.rnu import RootedNeuralUnit, RNUType, RNUConfig
from core.move_masking import MoveMasking, MaskingStrategy
from examples.security_rnu import SecurityRNU
from examples.analysis_rnu import AnalysisRNU
from examples.response_rnu import ResponseRNU


@dataclass
class BPHAIConfig:
    """Configuration for BPHAI system."""
    enable_security_rnu: bool = True
    enable_analysis_rnu: bool = True
    enable_response_rnu: bool = True
    default_masking_strategy: MaskingStrategy = MaskingStrategy.MODERATE
    max_processing_time: int = 30
    enable_logging: bool = True
    log_level: str = "INFO"
    threat_threshold: ThreatLevel = ThreatLevel.MEDIUM
    enable_move_masking: bool = True


@dataclass
class BPHAIResponse:
    """Response from BPHAI system."""
    success: bool
    content: str
    metadata: Dict[str, Any]
    threat_assessment: Dict[str, Any]
    processing_time: float
    timestamp: str
    warnings: List[str]
    rnu_results: Dict[str, Any]  # Keep for backward compatibility


class BPHAI:
    """Main BPHAI System Interface.
    
    This class provides the primary interface for interacting with the
    Behavioral Pattern Hardcoded AI system, managing RNUs and orchestrating
    secure AI responses.
    """
    
    def __init__(self, config: Optional[BPHAIConfig] = None):
        """Initialize BPHAI system.
        
        Args:
            config: Configuration for the BPHAI system
        """
        self.config = config or BPHAIConfig()
        self.orchestrator = BPHAIOrchestrator()
        self.move_masking = MoveMasking()
        self.logger = self._setup_logging()
        
        # Initialize RNUs based on configuration
        self._initialize_rnus()
        
        # System statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "blocked_requests": 0,
            "threats_detected": 0,
            "average_processing_time": 0.0,
            "start_time": datetime.now().isoformat()
        }
        
        self.logger.info("BPHAI system initialized successfully")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for BPHAI system."""
        logger = logging.getLogger("BPHAI")
        
        if self.config.enable_logging:
            logger.setLevel(getattr(logging, self.config.log_level.upper()))
            
            # Create console handler if not already exists
            if not logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                logger.addHandler(handler)
        else:
            logger.setLevel(logging.CRITICAL)
        
        return logger
    
    def _initialize_rnus(self) -> None:
        """Initialize and register RNUs based on configuration."""
        try:
            # Register Security RNU
            if self.config.enable_security_rnu:
                security_rnu = SecurityRNU()
                self.orchestrator.register_rnu(security_rnu)
                self.logger.info("Security RNU registered")
            
            # Register Analysis RNU
            if self.config.enable_analysis_rnu:
                analysis_rnu = AnalysisRNU()
                self.orchestrator.register_rnu(analysis_rnu)
                self.logger.info("Analysis RNU registered")
            
            # Register Response RNU
            if self.config.enable_response_rnu:
                response_rnu = ResponseRNU()
                self.orchestrator.register_rnu(response_rnu)
                self.logger.info("Response RNU registered")
            
            self.logger.info(f"Initialized {len(self.orchestrator.get_registered_rnus())} RNUs")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize RNUs: {str(e)}")
            raise
    
    def register_custom_rnu(self, rnu: RootedNeuralUnit) -> bool:
        """Register a custom RNU with the system.
        
        Args:
            rnu: Custom RNU to register
            
        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            success = self.orchestrator.register_rnu(rnu)
            if success:
                self.logger.info(f"Custom RNU {rnu.config.rnu_id} registered successfully")
            else:
                self.logger.warning(f"Failed to register custom RNU {rnu.config.rnu_id}")
            return success
        except Exception as e:
            self.logger.error(f"Error registering custom RNU: {str(e)}")
            return False
    
    def unregister_rnu(self, rnu_id: str) -> bool:
        """Unregister an RNU from the system.
        
        Args:
            rnu_id: ID of the RNU to unregister
            
        Returns:
            bool: True if unregistration successful, False otherwise
        """
        try:
            success = self.orchestrator.unregister_rnu(rnu_id)
            if success:
                self.logger.info(f"RNU {rnu_id} unregistered successfully")
            else:
                self.logger.warning(f"Failed to unregister RNU {rnu_id}")
            return success
        except Exception as e:
            self.logger.error(f"Error unregistering RNU: {str(e)}")
            return False
    
    async def process_async(self, 
                           input_data: Union[str, Dict[str, Any]], 
                           context: Optional[Dict[str, Any]] = None) -> BPHAIResponse:
        """Process input asynchronously through the BPHAI system.
        
        Args:
            input_data: Input data to process (string or dictionary)
            context: Optional context information
            
        Returns:
            BPHAIResponse: Processed response with metadata
        """
        start_time = datetime.now()
        self.stats["total_requests"] += 1
        
        try:
            # Prepare input for processing
            if isinstance(input_data, str):
                processed_input = {
                    "data_payload": {"message": input_data},
                    "processing_context": context or {}
                }
            else:
                processed_input = {
                    "data_payload": input_data,
                    "processing_context": context or {}
                }
            
            # Add timestamp to processing context
            processed_input["processing_context"]["timestamp"] = start_time.isoformat()
            processed_input["processing_context"]["request_id"] = f"req_{self.stats['total_requests']}"
            
            self.logger.debug(f"Processing request {processed_input['processing_context']['request_id']}")
            
            # Process through orchestrator
            result = await self.orchestrator.process_async(processed_input)
            
            # Handle different result types
            if result.status == "success":
                response_content = self._extract_response_content(result)
                threat_assessment = self._extract_threat_assessment(result)
                
                # Apply move masking if enabled and threat detected
                if (self.config.enable_move_masking and 
                    threat_assessment.get("threat_level", ThreatLevel.LOW) >= self.config.threat_threshold):
                    
                    masking_result = self.move_masking.apply_masking(
                        response_content,
                        self.config.default_masking_strategy,
                        threat_assessment
                    )
                    response_content = masking_result["masked_content"]
                    
                    self.logger.warning(f"Move masking applied due to threat level: {threat_assessment.get('threat_level')}")
                    self.stats["threats_detected"] += 1
                
                self.stats["successful_requests"] += 1
                
            elif result.status == "blocked":
                response_content = "I cannot process this request due to security concerns."
                threat_assessment = {"threat_level": ThreatLevel.HIGH, "blocked": True}
                self.stats["blocked_requests"] += 1
                self.logger.warning(f"Request blocked: {result.message}")
                
            else:  # error
                response_content = "I encountered an error while processing your request. Please try again."
                threat_assessment = {"threat_level": ThreatLevel.LOW, "error": True}
                self.logger.error(f"Processing error: {result.message}")
            
            # Calculate processing time
            end_time = datetime.now()
            processing_time = (end_time - start_time).total_seconds()
            
            # Update average processing time
            total_time = self.stats["average_processing_time"] * (self.stats["total_requests"] - 1)
            self.stats["average_processing_time"] = (total_time + processing_time) / self.stats["total_requests"]
            
            # Create response
            response = BPHAIResponse(
                success=result.status == "success",
                content=response_content,
                metadata={
                    "request_id": processed_input["processing_context"]["request_id"],
                    "processing_status": result.status,
                    "rnu_count": len(result.rnu_responses) if hasattr(result, 'rnu_responses') else 0,
                    "masking_applied": self.config.enable_move_masking and 
                                     threat_assessment.get("threat_level", ThreatLevel.LOW) >= self.config.threat_threshold,
                    "system_version": "1.0.0"
                },
                threat_assessment=threat_assessment,
                processing_time=processing_time,
                timestamp=end_time.isoformat(),
                warnings=result.warnings if hasattr(result, 'warnings') else [],
                rnu_results={rnu_resp.rnu_id: rnu_resp.result for rnu_resp in result.rnu_responses} if hasattr(result, 'rnu_responses') else {}
            )
            
            self.logger.info(f"Request processed successfully in {processing_time:.3f}s")
            return response
            
        except Exception as e:
            self.logger.error(f"Unexpected error during processing: {str(e)}")
            
            end_time = datetime.now()
            processing_time = (end_time - start_time).total_seconds()
            
            return BPHAIResponse(
                success=False,
                content="An unexpected error occurred. Please try again later.",
                metadata={
                    "error": str(e),
                    "processing_status": "error",
                    "system_version": "1.0.0"
                },
                threat_assessment={"threat_level": ThreatLevel.LOW, "error": True},
                processing_time=processing_time,
                timestamp=end_time.isoformat(),
                warnings=["Unexpected system error"],
                rnu_results={}
            )
    
    def process(self, 
               input_data: Union[str, Dict[str, Any]], 
               context: Optional[Dict[str, Any]] = None) -> BPHAIResponse:
        """Process input synchronously through the BPHAI system.
        
        Args:
            input_data: Input data to process (string or dictionary)
            context: Optional context information
            
        Returns:
            BPHAIResponse: Processed response with metadata
        """
        return asyncio.run(self.process_async(input_data, context))
    
    def _extract_response_content(self, result: AggregatedResponse) -> str:
        """Extract response content from processing result."""
        if hasattr(result, 'rnu_responses'):
            # Look for response from Response RNU first
            for rnu_response in result.rnu_responses:
                if "response_rnu" in rnu_response.rnu_id.lower() and "response_content" in rnu_response.result:
                    return rnu_response.result["response_content"]
            
            # Fallback to any available content
            for rnu_response in result.rnu_responses:
                if isinstance(rnu_response.result, dict):
                    if "content" in rnu_response.result:
                        return str(rnu_response.result["content"])
                    elif "message" in rnu_response.result:
                        return str(rnu_response.result["message"])
        
        return "Response generated successfully."
    
    def _extract_threat_assessment(self, result: AggregatedResponse) -> Dict[str, Any]:
        """Extract threat assessment from processing result."""
        threat_assessment = {
            "threat_level": ThreatLevel.LOW,
            "threats_detected": [],
            "confidence": 0.0
        }
        
        if hasattr(result, 'rnu_responses'):
            # Look for security assessment from Security RNU
            for rnu_response in result.rnu_responses:
                if "security_rnu" in rnu_response.rnu_id.lower() and isinstance(rnu_response.result, dict):
                    if "threat_level" in rnu_response.result:
                        threat_assessment["threat_level"] = rnu_response.result["threat_level"]
                    if "threats_detected" in rnu_response.result:
                        threat_assessment["threats_detected"] = rnu_response.result["threats_detected"]
                    if "confidence" in rnu_response.result:
                        threat_assessment["confidence"] = rnu_response.result["confidence"]
                    break
        
        return threat_assessment
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics.
        
        Returns:
            Dict containing system status information
        """
        orchestrator_status = self.orchestrator.get_system_status()
        
        return {
            "system_info": {
                "version": "1.0.0",
                "status": "operational",
                "uptime": (datetime.now() - datetime.fromisoformat(self.stats["start_time"])).total_seconds(),
                "configuration": asdict(self.config)
            },
            "system_health": "healthy",
            "statistics": self.stats.copy(),
            "orchestrator_status": orchestrator_status,
            "registered_rnus": [
                {
                    "rnu_id": rnu.config.rnu_id,
                    "rnu_type": rnu.config.rnu_type.value,
                    "trust_level": rnu.config.trust_level,
                    "is_sealed": rnu.is_sealed
                }
                for rnu in self.orchestrator.get_registered_rnus().values()
            ]
        }
    
    def get_rnu_info(self, rnu_id: Optional[str] = None) -> Dict[str, Any]:
        """Get information about registered RNUs.
        
        Args:
            rnu_id: Optional specific RNU ID to get info for
            
        Returns:
            Dict containing RNU information
        """
        registered_rnus = self.orchestrator.get_registered_rnus()
        
        if rnu_id:
            # Get specific RNU info
            for rnu_key, rnu in registered_rnus.items():
                if rnu.config.rnu_id == rnu_id:
                    return {
                        "rnu_id": rnu.config.rnu_id,
                        "rnu_type": rnu.config.rnu_type.value,
                        "behavior_hash": rnu.config.behavior_hash,
                        "trust_level": rnu.config.trust_level,
                        "max_input_size": rnu.config.max_input_size,
                        "timeout_seconds": rnu.config.timeout_seconds,
                        "is_sealed": rnu.is_sealed,
                        "metadata": rnu.get_metadata()
                    }
            return {"error": f"RNU {rnu_id} not found"}
        else:
            # Get all RNUs info
            return {
                "total_rnus": len(registered_rnus),
                "rnus": [
                    {
                        "rnu_id": rnu.config.rnu_id,
                        "rnu_type": rnu.config.rnu_type.value,
                        "trust_level": rnu.config.trust_level,
                        "is_sealed": rnu.is_sealed
                    }
                    for rnu in registered_rnus.values()
                ]
            }
    
    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """Update system configuration.
        
        Args:
            new_config: Dictionary with new configuration values
            
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            # Update configuration attributes
            for key, value in new_config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)
                    self.logger.info(f"Configuration updated: {key} = {value}")
                else:
                    self.logger.warning(f"Unknown configuration key: {key}")
            
            # Update logging level if changed
            if "log_level" in new_config and self.config.enable_logging:
                self.logger.setLevel(getattr(logging, self.config.log_level.upper()))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update configuration: {str(e)}")
            return False
    
    def reset_statistics(self) -> None:
        """Reset system statistics."""
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "blocked_requests": 0,
            "threats_detected": 0,
            "average_processing_time": 0.0,
            "start_time": datetime.now().isoformat()
        }
        self.logger.info("System statistics reset")
    
    def shutdown(self) -> None:
        """Gracefully shutdown the BPHAI system."""
        self.logger.info("Shutting down BPHAI system...")
        
        # Log final statistics
        self.logger.info(f"Final statistics: {self.stats}")
        
        # Clear registered RNUs
        for rnu in self.orchestrator.get_registered_rnus():
            self.orchestrator.unregister_rnu(rnu.config.rnu_id)
        
        self.logger.info("BPHAI system shutdown complete")


# Convenience functions for quick usage
def create_bphai_system(config: Optional[Dict[str, Any]] = None) -> BPHAI:
    """Create a BPHAI system with optional configuration.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        BPHAI: Initialized BPHAI system
    """
    if config:
        bphai_config = BPHAIConfig(**config)
    else:
        bphai_config = BPHAIConfig()
    
    return BPHAI(bphai_config)


def quick_process(input_data: Union[str, Dict[str, Any]], 
                 config: Optional[Dict[str, Any]] = None) -> str:
    """Quick processing function for simple use cases.
    
    Args:
        input_data: Input to process
        config: Optional system configuration
        
    Returns:
        str: Response content
    """
    bphai = create_bphai_system(config)
    response = bphai.process(input_data)
    return response.content