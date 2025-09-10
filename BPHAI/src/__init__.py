"""Bull Protector Hacker AI (BPHAI) - Prompt-less Intelligence System

A revolutionary AI security framework that eliminates prompt injection vulnerabilities
by implementing Rooted Neural Units (RNUs) with embedded behavioral patterns.

Author: Dr. Francesco Bulla
License: BullAI-Promptless License v1
"""

__version__ = "1.0.0"
__author__ = "Dr. Francesco Bulla"
__email__ = "150francescobulla@gmail.com"

from .core.rnu import RootedNeuralUnit
from .core.orchestrator import BPHAIOrchestrator
from .core.move_masking import MoveMasking
from .bphai import BPHAI

__all__ = [
    "RootedNeuralUnit",
    "BPHAIOrchestrator", 
    "MoveMasking",
    "BPHAI"
]