"""
Prompt template system for AI code analysis.

This module provides a flexible, swappable prompt system that selects
the appropriate analysis prompt based on:
- Programming language
- Detected frameworks
- Threat model/security context
"""

from .template_engine import PromptEngine

__all__ = ['PromptEngine']
