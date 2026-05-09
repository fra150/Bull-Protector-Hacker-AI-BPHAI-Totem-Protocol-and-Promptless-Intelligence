"""Response RNU - Specialized for secure response generation.

This RNU focuses on generating appropriate and secure responses
while maintaining strict adherence to safety protocols.
"""

import json
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from ..core.rnu import RootedNeuralUnit, RNUConfig, RNUType
from ..core.orchestrator import ThreatLevel


class ResponseRNU(RootedNeuralUnit):
    """Response Generation Rooted Neural Unit.
    
    This RNU implements secure response generation patterns
    embedded directly into its architecture for safe output.
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
            rnu_id="response_rnu_001",
            rnu_type=RNUType.RESPONSE,
            behavior_hash=behavior_hash,
            trust_level=0.90,
            max_input_size=8192,
            timeout_seconds=15
        )
        
        super().__init__(config)
        
        # Initialize response components
        self._response_templates = self._initialize_response_templates()
        self._safety_filters = self._initialize_safety_filters()
        self._tone_adjusters = self._initialize_tone_adjusters()
        self._content_validators = self._initialize_content_validators()
        
        # Seal the RNU
        self.seal()
    
    def _get_core_directive(self) -> str:
        """Return the core response generation directive."""
        return "Generate safe, helpful, and contextually appropriate responses"
    
    def _get_security_constraints(self) -> List[str]:
        """Return security constraints for response generation."""
        return [
            "no_harmful_content",
            "no_personal_data_exposure",
            "no_system_information_leak",
            "content_filtering",
            "output_sanitization"
        ]
    
    def _get_processing_rules(self) -> Dict[str, Any]:
        """Return processing rules for response generation."""
        return {
            "helpful_responses": True,
            "contextual_awareness": True,
            "safety_first": True,
            "professional_tone": True,
            "factual_accuracy": True,
            "length_optimization": True,
            "clarity_enhancement": True
        }
    
    def _get_response_filters(self) -> List[str]:
        """Return response filtering rules."""
        return [
            "content_sanitization",
            "safety_validation",
            "appropriateness_check",
            "length_optimization",
            "tone_consistency"
        ]
    
    def _initialize_response_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize response templates for different scenarios."""
        return {
            "informational": {
                "structure": ["introduction", "main_content", "conclusion"],
                "tone": "professional",
                "max_length": 1000,
                "include_sources": True
            },
            "instructional": {
                "structure": ["overview", "step_by_step", "tips", "conclusion"],
                "tone": "helpful",
                "max_length": 1500,
                "include_examples": True
            },
            "conversational": {
                "structure": ["acknowledgment", "response", "follow_up"],
                "tone": "friendly",
                "max_length": 800,
                "personalization": True
            },
            "analytical": {
                "structure": ["summary", "analysis", "insights", "recommendations"],
                "tone": "analytical",
                "max_length": 2000,
                "include_data": True
            },
            "error_handling": {
                "structure": ["acknowledgment", "explanation", "alternatives"],
                "tone": "apologetic_helpful",
                "max_length": 500,
                "provide_alternatives": True
            }
        }
    
    def _initialize_safety_filters(self) -> Dict[str, List[str]]:
        """Initialize safety filtering patterns."""
        return {
            "harmful_content": [
                r"\b(?:kill|murder|suicide|harm|violence|attack)\b",
                r"\b(?:bomb|weapon|explosive|dangerous)\b",
                r"\b(?:illegal|criminal|fraud|scam)\b"
            ],
            "personal_data": [
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b",  # Phone
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
                r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"  # Credit card pattern
            ],
            "system_info": [
                r"\b(?:password|token|key|secret|credential)\b",
                r"\b(?:server|database|admin|root|system)\b",
                r"\b(?:config|configuration|settings|environment)\b"
            ],
            "inappropriate_content": [
                r"\b(?:hate|discrimination|bias|prejudice)\b",
                r"\b(?:offensive|inappropriate|vulgar)\b"
            ]
        }
    
    def _initialize_tone_adjusters(self) -> Dict[str, Dict[str, Any]]:
        """Initialize tone adjustment patterns."""
        return {
            "professional": {
                "vocabulary": "formal",
                "sentence_structure": "complex",
                "personal_pronouns": "minimal",
                "contractions": False
            },
            "friendly": {
                "vocabulary": "casual",
                "sentence_structure": "varied",
                "personal_pronouns": "moderate",
                "contractions": True
            },
            "helpful": {
                "vocabulary": "clear",
                "sentence_structure": "simple",
                "personal_pronouns": "supportive",
                "contractions": True
            },
            "analytical": {
                "vocabulary": "technical",
                "sentence_structure": "structured",
                "personal_pronouns": "minimal",
                "contractions": False
            },
            "apologetic_helpful": {
                "vocabulary": "empathetic",
                "sentence_structure": "supportive",
                "personal_pronouns": "understanding",
                "contractions": True
            }
        }
    
    def _initialize_content_validators(self) -> Dict[str, Any]:
        """Initialize content validation rules."""
        return {
            "min_length": 10,
            "max_length": 2000,
            "required_elements": ["main_point", "context"],
            "forbidden_elements": ["personal_data", "harmful_content", "system_info"],
            "quality_metrics": {
                "clarity": 0.7,
                "relevance": 0.8,
                "safety": 1.0,
                "helpfulness": 0.7
            }
        }
    
    def _detect_response_type(self, context: Dict[str, Any]) -> str:
        """Detect the appropriate response type based on context."""
        # Analyze the input context to determine response type
        input_text = str(context.get("data_payload", "")).lower()
        
        # Check for question patterns
        if any(word in input_text for word in ["how", "what", "why", "when", "where", "?"]):
            if any(word in input_text for word in ["step", "guide", "tutorial", "instructions"]):
                return "instructional"
            else:
                return "informational"
        
        # Check for analysis requests
        if any(word in input_text for word in ["analyze", "compare", "evaluate", "assess"]):
            return "analytical"
        
        # Check for errors or problems
        if any(word in input_text for word in ["error", "problem", "issue", "help", "stuck"]):
            return "error_handling"
        
        # Default to conversational
        return "conversational"
    
    def _apply_safety_filters(self, content: str) -> Tuple[str, List[str]]:
        """Apply safety filters to content and return filtered content with warnings."""
        filtered_content = content
        warnings = []
        
        for filter_type, patterns in self._safety_filters.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    warnings.append(f"Detected {filter_type}: {len(matches)} instances")
                    # Replace sensitive content with placeholders
                    if filter_type == "personal_data":
                        filtered_content = re.sub(pattern, "[REDACTED]", filtered_content, flags=re.IGNORECASE)
                    elif filter_type == "system_info":
                        filtered_content = re.sub(pattern, "[SYSTEM_INFO_REMOVED]", filtered_content, flags=re.IGNORECASE)
                    elif filter_type == "harmful_content":
                        filtered_content = re.sub(pattern, "[CONTENT_FILTERED]", filtered_content, flags=re.IGNORECASE)
        
        return filtered_content, warnings
    
    def _adjust_tone(self, content: str, target_tone: str) -> str:
        """Adjust the tone of the content based on target tone."""
        tone_config = self._tone_adjusters.get(target_tone, self._tone_adjusters["professional"])
        
        # Apply tone adjustments (simplified implementation)
        adjusted_content = content
        
        # Handle contractions based on tone
        if not tone_config["contractions"]:
            # Expand contractions for formal tone
            contractions = {
                "can't": "cannot",
                "won't": "will not",
                "don't": "do not",
                "isn't": "is not",
                "aren't": "are not",
                "wasn't": "was not",
                "weren't": "were not",
                "haven't": "have not",
                "hasn't": "has not",
                "hadn't": "had not",
                "wouldn't": "would not",
                "shouldn't": "should not",
                "couldn't": "could not"
            }
            
            for contraction, expansion in contractions.items():
                adjusted_content = adjusted_content.replace(contraction, expansion)
                adjusted_content = adjusted_content.replace(contraction.capitalize(), expansion.capitalize())
        
        return adjusted_content
    
    def _validate_content_quality(self, content: str, response_type: str) -> Dict[str, Any]:
        """Validate the quality of generated content."""
        validation_results = {
            "is_valid": True,
            "quality_score": 0.0,
            "issues": [],
            "recommendations": []
        }
        
        # Check length requirements
        content_length = len(content)
        min_length = self._content_validators["min_length"]
        max_length = self._content_validators["max_length"]
        
        if content_length < min_length:
            validation_results["issues"].append(f"Content too short ({content_length} < {min_length})")
            validation_results["is_valid"] = False
        elif content_length > max_length:
            validation_results["issues"].append(f"Content too long ({content_length} > {max_length})")
            validation_results["recommendations"].append("Consider shortening the response")
        
        # Check for required elements (simplified)
        if not content.strip():
            validation_results["issues"].append("Empty content")
            validation_results["is_valid"] = False
        
        # Calculate quality score
        quality_factors = []
        
        # Length factor
        if min_length <= content_length <= max_length:
            length_factor = 1.0
        else:
            length_factor = max(0.0, 1.0 - abs(content_length - (min_length + max_length) / 2) / max_length)
        quality_factors.append(length_factor)
        
        # Clarity factor (based on sentence structure)
        sentences = re.split(r'[.!?]+', content)
        avg_sentence_length = sum(len(s.split()) for s in sentences if s.strip()) / max(len(sentences), 1)
        clarity_factor = max(0.0, min(1.0, 1.0 - abs(avg_sentence_length - 15) / 20))  # Optimal ~15 words per sentence
        quality_factors.append(clarity_factor)
        
        # Calculate overall quality score
        validation_results["quality_score"] = sum(quality_factors) / len(quality_factors)
        
        return validation_results
    
    def _generate_response_content(self, context: Dict[str, Any], response_type: str) -> str:
        """Generate response content based on context and type."""
        template = self._response_templates.get(response_type, self._response_templates["conversational"])
        
        # Extract relevant information from context
        data_payload = context.get("data_payload", {})
        processing_context = context.get("processing_context", {})
        
        # Generate content based on response type
        if response_type == "informational":
            content = self._generate_informational_response(data_payload, template)
        elif response_type == "instructional":
            content = self._generate_instructional_response(data_payload, template)
        elif response_type == "analytical":
            content = self._generate_analytical_response(data_payload, template)
        elif response_type == "error_handling":
            content = self._generate_error_response(data_payload, template)
        else:  # conversational
            content = self._generate_conversational_response(data_payload, template)
        
        return content
    
    def _generate_informational_response(self, data: Dict[str, Any], template: Dict[str, Any]) -> str:
        """Generate an informational response."""
        # Simplified informational response generation
        topic = str(data.get("topic", "the requested information"))
        
        response = f"Based on your inquiry about {topic}, here's what I can provide:\n\n"
        response += f"The information you're looking for relates to {topic}. "
        response += "This is a complex topic that requires careful consideration of multiple factors. "
        response += "I recommend reviewing reliable sources and consulting with experts when making important decisions.\n\n"
        response += "If you need more specific information, please feel free to ask with more details."
        
        return response
    
    def _generate_instructional_response(self, data: Dict[str, Any], template: Dict[str, Any]) -> str:
        """Generate an instructional response."""
        task = str(data.get("task", "the requested task"))
        
        response = f"Here's how to approach {task}:\n\n"
        response += "**Step-by-step approach:**\n"
        response += "1. First, gather all necessary information and resources\n"
        response += "2. Plan your approach carefully\n"
        response += "3. Execute the plan systematically\n"
        response += "4. Review and validate your results\n\n"
        response += "**Important tips:**\n"
        response += "- Take your time and don't rush\n"
        response += "- Double-check your work at each step\n"
        response += "- Ask for help if you encounter difficulties\n\n"
        response += "Feel free to ask if you need clarification on any of these steps."
        
        return response
    
    def _generate_analytical_response(self, data: Dict[str, Any], template: Dict[str, Any]) -> str:
        """Generate an analytical response."""
        subject = str(data.get("subject", "the provided data"))
        
        response = f"**Analysis of {subject}:**\n\n"
        response += "**Summary:**\n"
        response += f"The analysis of {subject} reveals several key patterns and insights. "
        response += "The data suggests multiple factors are at play, requiring a comprehensive approach.\n\n"
        response += "**Key Insights:**\n"
        response += "- Multiple variables influence the outcome\n"
        response += "- Patterns suggest both opportunities and challenges\n"
        response += "- Further investigation may be beneficial\n\n"
        response += "**Recommendations:**\n"
        response += "- Continue monitoring relevant metrics\n"
        response += "- Consider additional data sources\n"
        response += "- Implement gradual improvements based on findings\n\n"
        response += "This analysis provides a foundation for informed decision-making."
        
        return response
    
    def _generate_error_response(self, data: Dict[str, Any], template: Dict[str, Any]) -> str:
        """Generate an error handling response."""
        issue = str(data.get("issue", "the issue you're experiencing"))
        
        response = f"I understand you're experiencing {issue}. Let me help you resolve this.\n\n"
        response += "**Possible solutions:**\n"
        response += "1. Check if all requirements are met\n"
        response += "2. Verify your input data and format\n"
        response += "3. Try a different approach if the current one isn't working\n"
        response += "4. Consult documentation or help resources\n\n"
        response += "**Alternative approaches:**\n"
        response += "- Break down the problem into smaller parts\n"
        response += "- Seek assistance from relevant experts\n"
        response += "- Consider using different tools or methods\n\n"
        response += "If these suggestions don't help, please provide more details about the specific issue."
        
        return response
    
    def _generate_conversational_response(self, data: Dict[str, Any], template: Dict[str, Any]) -> str:
        """Generate a conversational response."""
        message = str(data.get("message", "your message"))
        
        response = f"Thank you for {message}. I appreciate you reaching out.\n\n"
        response += "I'm here to help with any questions or tasks you might have. "
        response += "Whether you need information, assistance with a project, or just want to have a conversation, "
        response += "I'm ready to provide helpful and accurate responses.\n\n"
        response += "What would you like to explore or discuss today?"
        
        return response
    
    def process(self, masked_input: Dict[str, Any]) -> Dict[str, Any]:
        """Process input to generate a safe and appropriate response."""
        if not self._validate_input(masked_input):
            return {
                "error": "Input validation failed",
                "response_status": "failed"
            }
        
        try:
            # Detect appropriate response type
            response_type = self._detect_response_type(masked_input)
            
            # Generate initial response content
            raw_content = self._generate_response_content(masked_input, response_type)
            
            # Apply safety filters
            filtered_content, safety_warnings = self._apply_safety_filters(raw_content)
            
            # Adjust tone based on response type
            template = self._response_templates[response_type]
            adjusted_content = self._adjust_tone(filtered_content, template["tone"])
            
            # Validate content quality
            validation_results = self._validate_content_quality(adjusted_content, response_type)
            
            # Ensure content length is within limits
            max_length = template["max_length"]
            if len(adjusted_content) > max_length:
                # Truncate content intelligently (at sentence boundary)
                sentences = re.split(r'(?<=[.!?])\s+', adjusted_content)
                truncated_content = ""
                for sentence in sentences:
                    if len(truncated_content + sentence) <= max_length - 3:
                        truncated_content += sentence + " "
                    else:
                        break
                adjusted_content = truncated_content.strip() + "..."
            
            # Record processing in history
            self._input_history.append({
                "timestamp": masked_input.get("processing_context", {}).get("timestamp"),
                "response_type": response_type,
                "content_length": len(adjusted_content),
                "safety_warnings": len(safety_warnings)
            })
            
            return {
                "status": "response_generated",
                "response_content": adjusted_content,
                "response_metadata": {
                    "response_type": response_type,
                    "tone": template["tone"],
                    "content_length": len(adjusted_content),
                    "safety_filtered": len(safety_warnings) > 0,
                    "quality_score": validation_results["quality_score"],
                    "generation_timestamp": datetime.now().isoformat()
                },
                "safety_report": {
                    "warnings": safety_warnings,
                    "filters_applied": len(safety_warnings),
                    "content_safe": validation_results["is_valid"]
                },
                "quality_assessment": {
                    "score": validation_results["quality_score"],
                    "issues": validation_results["issues"],
                    "recommendations": validation_results["recommendations"]
                },
                "processing_context": {
                    "rnu_id": self.config.rnu_id,
                    "processing_timestamp": masked_input.get("processing_context", {}).get("timestamp"),
                    "template_used": response_type
                }
            }
            
        except Exception as e:
            return {
                "error": f"Response generation failed: {str(e)}",
                "response_status": "error",
                "fallback_response": "I apologize, but I encountered an issue while generating a response. Please try rephrasing your request or contact support if the problem persists."
            }