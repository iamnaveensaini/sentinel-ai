"""
Sentinel AI - Post-Generation Output Sanitizer & Leak Inspector
Inspects the LLM provider's response before returning it to the user.
Applies redaction or blocking if the model regurgitates sensitive data.
Enforces fail-closed safety (errors never pass uninspected output).
"""
import re
from typing import Tuple, List
from backend.detection.pii_detector import pii_detector
from backend.detection.secret_scanner import secret_scanner

class OutputSanitizer:
    def sanitize(self, raw_llm_response: str) -> Tuple[str, bool, List[str]]:
        """
        Inspects output from provider.
        Returns:
            - sanitized_response (str)
            - was_modified (bool)
            - warnings (List[str])
        """
        if not raw_llm_response:
            return "", False, []

        reasons: List[str] = []
        is_modified = False
        text = raw_llm_response

        # 1. Output Secret Check - If the model outputs an API key or password, block output immediately!
        secret_findings = secret_scanner.scan(text)
        if secret_findings:
            return (
                "[OUTPUT BLOCKED BY SENTINEL GATEWAY: The model generated credentials or secrets in violation of data leakage policies.]",
                True,
                ["OUTPUT_CONTAINED_SECRETS"]
            )

        # 2. Output PII Check - Redact any personal identifiers
        pii_findings = pii_detector.detect(text)
        if pii_findings:
            is_modified = True
            reasons.append("OUTPUT_CONTAINED_PII_REDACTED")
            # Replace spans in reverse order
            for span in sorted(pii_findings, key=lambda s: s.start, reverse=True):
                text = text[:span.start] + span.replacement + text[span.end:]

        return text, is_modified, reasons

output_sanitizer = OutputSanitizer()
