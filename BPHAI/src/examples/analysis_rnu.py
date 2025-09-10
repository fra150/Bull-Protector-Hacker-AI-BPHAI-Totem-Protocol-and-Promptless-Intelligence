"""Analysis RNU - Specialized for content analysis and processing.

This RNU focuses on analyzing and understanding input content,
extractingmeaningful insights while maintaining security boundaries.
"""

import json
import hashlib
import re
from typing import Dict, List, Any, Tuple
from collections import Counter

from core.rnu import RootedNeuralUnit, RNUConfig, RNUType
from core.orchestrator import ThreatLevel


class AnalysisRNU(RootedNeuralUnit):
    """Content Analysis Rooted Neural Unit.
    
    This RNU implements sophisticated content analysis patterns
    embedded directly into its architecture for secure processing.
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
            rnu_id="analysis_rnu_001",
            rnu_type=RNUType.ANALYSIS,
            behavior_hash=behavior_hash,
            trust_level=0.85,
            max_input_size=4096,
            timeout_seconds=20
        )
        
        super().__init__(config)
        
        # Initialize analysis components
        self._sentiment_lexicon = self._initialize_sentiment_lexicon()
        self._topic_keywords = self._initialize_topic_keywords()
        self._entity_patterns = self._initialize_entity_patterns()
        
        # Seal the RNU
        self.seal()
    
    def _get_core_directive(self) -> str:
        """Return the core analysis directive."""
        return "Analyze content structure, sentiment, and extract insights"
    
    def _get_security_constraints(self) -> List[str]:
        """Return security constraints for analysis."""
        return [
            "no_code_execution",
            "no_prompt_injection",
            "content_boundary_respect",
            "privacy_preservation"
        ]
    
    def _get_processing_rules(self) -> Dict[str, Any]:
        """Return processing rules for content analysis."""
        return {
            "content_analysis": True,
            "sentiment_analysis": True,
            "entity_extraction": True,
            "topic_classification": True,
            "language_detection": True,
            "statistical_analysis": True,
            "pattern_recognition": True
        }
    
    def _get_response_filters(self) -> List[str]:
        """Return response filtering rules."""
        return [
            "sanitize_extracted_data",
            "remove_personal_info",
            "confidence_scoring",
            "anonymize_sensitive_content"
        ]
    
    def _initialize_sentiment_lexicon(self) -> Dict[str, float]:
        """Initialize sentiment analysis lexicon."""
        return {
            # Positive words
            "excellent": 0.9, "amazing": 0.8, "great": 0.7, "good": 0.6, "nice": 0.5,
            "wonderful": 0.8, "fantastic": 0.9, "awesome": 0.8, "brilliant": 0.8,
            "outstanding": 0.9, "superb": 0.8, "perfect": 0.9, "love": 0.7,
            "like": 0.4, "enjoy": 0.6, "happy": 0.7, "pleased": 0.6, "satisfied": 0.6,
            
            # Negative words
            "terrible": -0.9, "awful": -0.8, "bad": -0.6, "poor": -0.5, "horrible": -0.9,
            "disgusting": -0.8, "hate": -0.8, "dislike": -0.5, "angry": -0.7,
            "frustrated": -0.6, "disappointed": -0.6, "sad": -0.6, "upset": -0.6,
            "annoyed": -0.5, "irritated": -0.5, "worst": -0.9, "fail": -0.7,
            
            # Neutral/modifier words
            "very": 0.0, "quite": 0.0, "rather": 0.0, "somewhat": 0.0, "slightly": 0.0,
            "extremely": 0.0, "incredibly": 0.0, "really": 0.0, "truly": 0.0
        }
    
    def _initialize_topic_keywords(self) -> Dict[str, List[str]]:
        """Initialize topic classification keywords."""
        return {
            "technology": [
                "software", "hardware", "computer", "programming", "code", "algorithm",
                "database", "network", "security", "AI", "machine learning", "data",
                "cloud", "server", "application", "system", "digital", "cyber"
            ],
            "business": [
                "company", "market", "sales", "revenue", "profit", "customer", "client",
                "strategy", "management", "finance", "investment", "growth", "budget",
                "corporate", "enterprise", "startup", "entrepreneur", "commerce"
            ],
            "science": [
                "research", "study", "experiment", "hypothesis", "theory", "analysis",
                "data", "results", "conclusion", "methodology", "scientific", "evidence",
                "discovery", "innovation", "laboratory", "academic", "publication"
            ],
            "health": [
                "medical", "health", "doctor", "patient", "treatment", "medicine", "therapy",
                "diagnosis", "symptom", "disease", "wellness", "fitness", "nutrition",
                "hospital", "clinic", "pharmaceutical", "healthcare", "recovery"
            ],
            "education": [
                "school", "university", "student", "teacher", "learning", "education",
                "course", "curriculum", "degree", "academic", "knowledge", "skill",
                "training", "instruction", "classroom", "lecture", "study", "exam"
            ]
        }
    
    def _initialize_entity_patterns(self) -> Dict[str, str]:
        """Initialize entity recognition patterns."""
        return {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b",
            "url": r"https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?",
            "date": r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{2,4}[/-]\d{1,2}[/-]\d{1,2})\b",
            "time": r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?:\s?[AaPp][Mm])?\b",
            "currency": r"\$\d+(?:,\d{3})*(?:\.\d{2})?|\d+(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|EUR|GBP|JPY)",
            "percentage": r"\b\d+(?:\.\d+)?%\b",
            "number": r"\b\d+(?:,\d{3})*(?:\.\d+)?\b"
        }
    
    def _analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """Analyze sentiment of the input text."""
        words = re.findall(r'\b\w+\b', text.lower())
        
        sentiment_scores = []
        sentiment_words = []
        
        # Apply sentiment scoring
        for word in words:
            if word in self._sentiment_lexicon:
                score = self._sentiment_lexicon[word]
                sentiment_scores.append(score)
                sentiment_words.append((word, score))
        
        if not sentiment_scores:
            return {
                "overall_sentiment": "neutral",
                "sentiment_score": 0.0,
                "confidence": 0.0,
                "sentiment_words": []
            }
        
        # Calculate overall sentiment
        avg_sentiment = sum(sentiment_scores) / len(sentiment_scores)
        
        # Determine sentiment category
        if avg_sentiment > 0.2:
            sentiment_category = "positive"
        elif avg_sentiment < -0.2:
            sentiment_category = "negative"
        else:
            sentiment_category = "neutral"
        
        # Calculate confidence based on number of sentiment words
        confidence = min(1.0, len(sentiment_scores) / 10)
        
        return {
            "overall_sentiment": sentiment_category,
            "sentiment_score": round(avg_sentiment, 3),
            "confidence": round(confidence, 3),
            "sentiment_words": sentiment_words[:10]  # Top 10 sentiment words
        }
    
    def _classify_topics(self, text: str) -> Dict[str, Any]:
        """Classify topics in the input text."""
        text_lower = text.lower()
        topic_scores = {}
        
        for topic, keywords in self._topic_keywords.items():
            score = 0
            matched_keywords = []
            
            for keyword in keywords:
                if keyword in text_lower:
                    score += 1
                    matched_keywords.append(keyword)
            
            if score > 0:
                # Normalize score by text length
                normalized_score = score / len(text.split()) * 100
                topic_scores[topic] = {
                    "score": round(normalized_score, 3),
                    "matched_keywords": matched_keywords,
                    "keyword_count": score
                }
        
        # Sort topics by score
        sorted_topics = sorted(topic_scores.items(), key=lambda x: x[1]["score"], reverse=True)
        
        return {
            "primary_topic": sorted_topics[0][0] if sorted_topics else "general",
            "topic_scores": dict(sorted_topics[:3]),  # Top 3 topics
            "topic_confidence": sorted_topics[0][1]["score"] if sorted_topics else 0.0
        }
    
    def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract entities from the input text."""
        entities = {}
        
        for entity_type, pattern in self._entity_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                # Anonymize sensitive entities
                if entity_type in ["email", "phone"]:
                    entities[entity_type] = [f"[{entity_type.upper()}_{i+1}]" for i in range(len(matches))]
                else:
                    entities[entity_type] = matches[:5]  # Limit to 5 matches per type
        
        return entities
    
    def _analyze_text_statistics(self, text: str) -> Dict[str, Any]:
        """Analyze basic text statistics."""
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        paragraphs = text.split('\n\n')
        
        # Word frequency analysis
        word_freq = Counter(word.lower().strip('.,!?;:') for word in words if len(word) > 3)
        
        # Calculate readability metrics
        avg_words_per_sentence = len(words) / max(len(sentences), 1)
        avg_chars_per_word = sum(len(word) for word in words) / max(len(words), 1)
        
        return {
            "word_count": len(words),
            "sentence_count": len([s for s in sentences if s.strip()]),
            "paragraph_count": len([p for p in paragraphs if p.strip()]),
            "character_count": len(text),
            "avg_words_per_sentence": round(avg_words_per_sentence, 2),
            "avg_chars_per_word": round(avg_chars_per_word, 2),
            "most_common_words": word_freq.most_common(5),
            "unique_words": len(set(word.lower() for word in words))
        }
    
    def _detect_language(self, text: str) -> Dict[str, Any]:
        """Simple language detection based on character patterns."""
        # Basic language detection patterns
        language_patterns = {
            "english": r"[a-zA-Z\s.,!?;:'\"-]+",
            "italian": r"[a-zA-ZàáâäèéêëìíîïòóôöùúûüÀÁÂÄÈÉÊËÌÍÎÏÒÓÔÖÙÚÛÜ\s.,!?;:'\"-]+",
            "spanish": r"[a-zA-ZáéíóúüñÁÉÍÓÚÜÑ\s.,!?;:'\"-]+",
            "french": r"[a-zA-ZàâäéèêëïîôöùûüÿçÀÂÄÉÈÊËÏÎÔÖÙÛÜŸÇ\s.,!?;:'\"-]+"
        }
        
        language_scores = {}
        text_length = len(text)
        
        for lang, pattern in language_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                match_length = sum(len(match) for match in matches)
                score = match_length / text_length if text_length > 0 else 0
                language_scores[lang] = round(score, 3)
        
        # Determine primary language
        primary_lang = max(language_scores.items(), key=lambda x: x[1]) if language_scores else ("unknown", 0.0)
        
        return {
            "primary_language": primary_lang[0],
            "confidence": primary_lang[1],
            "language_scores": language_scores
        }
    
    def process(self, masked_input: Dict[str, Any]) -> Dict[str, Any]:
        """Process input for comprehensive content analysis."""
        if not self._validate_input(masked_input):
            return {
                "error": "Input validation failed",
                "analysis_status": "failed"
            }
        
        # Extract data payload
        data_payload = masked_input.get("data_payload", {})
        
        # Convert to text for analysis
        if isinstance(data_payload, dict):
            # Extract text from various fields
            text_content = ""
            for key, value in data_payload.items():
                if isinstance(value, str):
                    text_content += f"{value} "
                elif isinstance(value, (list, dict)):
                    text_content += f"{json.dumps(value)} "
        else:
            text_content = str(data_payload)
        
        if not text_content.strip():
            return {
                "error": "No analyzable content found",
                "analysis_status": "no_content"
            }
        
        # Perform various analyses
        sentiment_analysis = self._analyze_sentiment(text_content)
        topic_classification = self._classify_topics(text_content)
        entity_extraction = self._extract_entities(text_content)
        text_statistics = self._analyze_text_statistics(text_content)
        language_detection = self._detect_language(text_content)
        
        # Calculate overall analysis confidence
        confidence_factors = [
            sentiment_analysis["confidence"],
            topic_classification["topic_confidence"] / 100,  # Normalize to 0-1
            language_detection["confidence"],
            min(1.0, text_statistics["word_count"] / 100)  # More words = higher confidence
        ]
        
        overall_confidence = sum(confidence_factors) / len(confidence_factors)
        
        # Record processing in history
        self._input_history.append({
            "timestamp": masked_input.get("processing_context", {}).get("timestamp"),
            "content_length": len(text_content),
            "primary_topic": topic_classification["primary_topic"],
            "sentiment": sentiment_analysis["overall_sentiment"]
        })
        
        return {
            "status": "analysis_complete",
            "analysis_confidence": round(overall_confidence, 3),
            "content_analysis": {
                "sentiment": sentiment_analysis,
                "topics": topic_classification,
                "entities": entity_extraction,
                "statistics": text_statistics,
                "language": language_detection
            },
            "insights": {
                "content_type": self._determine_content_type(topic_classification, text_statistics),
                "complexity_level": self._assess_complexity(text_statistics),
                "engagement_potential": self._assess_engagement(sentiment_analysis, text_statistics)
            },
            "analysis_metadata": {
                "processed_length": len(text_content),
                "processing_timestamp": masked_input.get("processing_context", {}).get("timestamp"),
                "rnu_id": self.config.rnu_id
            }
        }
    
    def _determine_content_type(self, topics: Dict[str, Any], stats: Dict[str, Any]) -> str:
        """Determine the type of content based on analysis."""
        primary_topic = topics["primary_topic"]
        word_count = stats["word_count"]
        
        if word_count < 50:
            return "short_form"
        elif word_count < 200:
            return "medium_form"
        else:
            return "long_form"
    
    def _assess_complexity(self, stats: Dict[str, Any]) -> str:
        """Assess content complexity based on statistics."""
        avg_words_per_sentence = stats["avg_words_per_sentence"]
        avg_chars_per_word = stats["avg_chars_per_word"]
        unique_word_ratio = stats["unique_words"] / max(stats["word_count"], 1)
        
        complexity_score = (
            (avg_words_per_sentence / 20) +
            (avg_chars_per_word / 10) +
            unique_word_ratio
        ) / 3
        
        if complexity_score > 0.7:
            return "high"
        elif complexity_score > 0.4:
            return "medium"
        else:
            return "low"
    
    def _assess_engagement(self, sentiment: Dict[str, Any], stats: Dict[str, Any]) -> str:
        """Assess potential engagement based on sentiment and content."""
        sentiment_score = abs(sentiment["sentiment_score"])  # Absolute value for engagement
        word_count = stats["word_count"]
        
        # Higher sentiment (positive or negative) and optimal length increase engagement
        engagement_score = sentiment_score * 0.7 + min(1.0, word_count / 300) * 0.3
        
        if engagement_score > 0.6:
            return "high"
        elif engagement_score > 0.3:
            return "medium"
        else:
            return "low"