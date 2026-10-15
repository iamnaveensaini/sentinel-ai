"""
Sentinel AI - LLM Provider Base Interface
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class BaseLLMProvider(ABC):
    @abstractmethod
    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Executes completion against the provider.
        """
        pass
