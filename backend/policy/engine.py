"""
Sentinel AI - Policy Enforcement Engine
Applies strict security precedence to all detector findings:
1. Secrets / Credentials -> BLOCK immediately (Provider is NEVER called)
2. Direct Prompt Injection -> BLOCK immediately
3. Personal Identifiable Information (PII) -> MASK before provider submission
4. Clean Request -> ALLOW
"""
from typing import List
from backend.detection.pii_detector import DetectedSpan
from backend.policy.models import PolicyAction, PolicyDecision

class PolicyEngine:
    def __init__(self, version: str = "v1.0"):
        self.version = version

    def evaluate(self, original_text: str, spans: List[DetectedSpan]) -> PolicyDecision:
        """
        Evaluates detected spans and returns a deterministic PolicyDecision.
        """
        if not spans:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                reason_codes=["NO_SENSITIVE_DATA_DETECTED"],
                sanitized_prompt=original_text,
                policy_version=self.version,
                categories_triggered=[]
            )

        categories = list({span.category for span in spans})
        has_secret = any(c.startswith("SECRET_") for c in categories)
        has_injection = any(c.startswith("PROMPT_INJECTION_") for c in categories)

        # Precedence Rule 1: Secrets or Injections must be strictly BLOCKED
        if has_secret or has_injection:
            reasons = []
            if has_secret:
                reasons.append("PROHIBITED_CREDENTIAL_DETECTED")
            if has_injection:
                reasons.append("INJECTION_ATTACK_DETECTED")
            
            return PolicyDecision(
                action=PolicyAction.BLOCK,
                reason_codes=reasons,
                sanitized_prompt=None, # Never forward blocked content
                policy_version=self.version,
                categories_triggered=categories
            )

        # Precedence Rule 2: PII is MASKED before forwarding
        masked_prompt = self.mask_text(original_text, spans)
        return PolicyDecision(
            action=PolicyAction.MASK,
            reason_codes=["PII_MASKED_BEFORE_FORWARDING"],
            sanitized_prompt=masked_prompt,
            policy_version=self.version,
            categories_triggered=categories
        )

    def mask_text(self, text: str, spans: List[DetectedSpan]) -> str:
        """
        Replaces detected spans from right to left to prevent index shifting.
        """
        # Sort in reverse order of appearance
        sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)
        result = text
        for span in sorted_spans:
            result = result[:span.start] + span.replacement + result[span.end:]
        return result

policy_engine = PolicyEngine()
