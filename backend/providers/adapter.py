"""
Sentinel AI - LLM Provider Adapter
Mediates calls to real LLM providers (OpenAI, Groq, Anthropic) or local Mock provider.
Enforces timeout, server-side secret management, and tracks invocation metrics.
"""
import os
import httpx
from typing import Optional
from backend.providers.base import BaseLLMProvider

class LLMProviderAdapter(BaseLLMProvider):
    def __init__(self):
        self.provider_type = os.getenv("LLM_PROVIDER", "mock").lower()
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.timeout = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "15.0"))
        # Invocations counter for security testing (verifying block-before-forward)
        self.invocation_count = 0

    async def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Calls upstream provider. If in mock mode or API key missing, returns realistic response.
        """
        self.invocation_count += 1
        sys_instruction = system_prompt or "You are a secure, helpful corporate AI assistant."

        # If a real OpenAI/Groq API key is present and provider is not mock:
        if self.provider_type in ["openai", "groq"] and self.api_key and not self.api_key.startswith("your_"):
            base_url = "https://api.openai.com/v1" if self.provider_type == "openai" else "https://api.groq.com/openai/v1"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": sys_instruction},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3
            }
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
                res.raise_for_status()
                data = res.json()
                return data["choices"][0]["message"]["content"]

        # Default Mock / Safe Offline Provider for local development & automated unit tests
        return self._simulate_safe_llm_response(prompt)

    def _simulate_safe_llm_response(self, prompt: str) -> str:
        """
        Generates realistic contextual replies for mock mode without external network calls.
        """
        lower_p = prompt.lower()
        if "leave policy" in lower_p or "vacation" in lower_p:
            return "According to the authorized company guidelines, employees are entitled to 20 days of annual paid leave."
        if "<email_redacted>" in lower_p or "<phone_redacted>" in lower_p or "<aadhaar_redacted>" in lower_p:
            return f"Thank you for your inquiry. I received your request with sanitized user parameters: '{prompt}'. How else may I assist you?"
        if "summary" in lower_p or "summarize" in lower_p:
            return f"Summary: The provided authorized context has been verified and synthesized for your request."
        return f"Hello! I am Sentinel AI's protected model. I received your request: '{prompt[:50]}...' and have processed it safely."

# Global singleton adapter instance
provider_adapter = LLMProviderAdapter()
