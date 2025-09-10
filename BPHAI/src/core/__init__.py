"""Core components of the BPHAI system.

This module contains the fundamental building blocks:
- RootedNeuralUnit: Base class for prompt-less neural units
- BPHAIOrchestrator: Aggregates and coordinates RNU responses
- MoveMasking: Generates deceptive responses for potential attacks
"""

from .rnu import RootedNeuralUnit
from .orchestrator import BPHAIOrchestrator
from .move_masking import MoveMasking

__all__ = ["RootedNeuralUnit", "BPHAIOrchestrator", "MoveMasking"]