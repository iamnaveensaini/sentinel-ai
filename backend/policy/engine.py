"""
Sentinel AI - Policy Enforcement Engine
Applies strict security precedence to all detector findings:
1. Secrets / Credentials -> BLOCK immediately (sanitized_prompt = None, Provider is NEVER called)
2. Direct Prompt Injection -> BLOCK immediately (sanitized_prompt = None, Provider is NEVER called)
3. Personal Identifiable Information (PII) -> MASK before provider submission (reverse-offset replacement)
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
        Enforces strict security precedence: BLOCK > MASK > ALLOW.
        """
        if not spans:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                reason_codes=["NO_SENSITIVE_DATA_DETECTED"],
                sanitized_prompt=original_text,
                policy_version=self.version,
                categories_triggered=[]
            )

        categories = sorted(list({span.category for span in spans}))
        has_secret = any(c.startswith("SECRET_") for c in categories)
        has_injection = any(c.startswith("PROMPT_INJECTION_") for c in categories)

        # Precedence Rule 1: Any secret or injection must be strictly BLOCKED
        if has_secret or has_injection:
            reasons: List[str] = []
            if has_secret:
                reasons.append("PROHIBITED_CREDENTIAL_DETECTED")
            if has_injection:
                reasons.append("INJECTION_ATTACK_DETECTED")
            
            return PolicyDecision(
                action=PolicyAction.BLOCK,
                reason_codes=reasons,
                sanitized_prompt=None,  # Cardinal Guarantee: Never forward blocked prompts upstream
                policy_version=self.version,
                categories_triggered=categories
            )

        # Precedence Rule 2: PII detected -> MASK before forwarding
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
        Replaces detected spans in REVERSE order of appearance (right-to-left)
        so substring offsets do not shift.
        """
        if not spans:
            return text

        # Sort in reverse order of appearance (right-to-left)
        sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)

        # Ensure non-overlapping spans during replacement
        filtered_spans: List[DetectedSpan] = []
        last_start = len(text) + 1
        for span in sorted_spans:
            if span.end <= last_start:
                filtered_spans.append(span)
                last_start = span.start

        result = text
        for span in filtered_spans:
            result = result[:span.start] + span.replacement + result[span.end:]
        return result

policy_engine = PolicyEngine()
