"""
Sentinel AI - Prompt Injection & Jailbreak Detector
Identifies direct prompt injection attacks, jailbreaks, and system prompt override attempts.
"""
import re
from typing import List
from backend.detection.pii_detector import DetectedSpan

class InjectionDetector:
    def __init__(self):
        self.injection_signatures = [
            (
                re.compile(r'(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|existing)\s+(?:instructions|prompts|rules|constraints|directives)\b'),
                "PROMPT_INJECTION_OVERRIDE"
            ),
            (
                re.compile(r'(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|unrestricted|jailbroken|an\s+AI\s+without\s+rules|developer\s+mode)\b'),
                "PROMPT_INJECTION_JAILBREAK"
            ),
            (
                re.compile(r'(?i)\bDAN\s*\((?:Do\s+Anything\s+Now)\)\b'),
                "PROMPT_INJECTION_JAILBREAK"
            ),
            (
                re.compile(r'(?i)\b(?:reveal|print|show|dump|leak|extract)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|developer\s+(?:mode|instructions)|safety\s+guidelines|hidden\s+rules)\b'),
                "PROMPT_INJECTION_LEAK"
            ),
            (
                re.compile(r'(?i)\b(?:bypass|disable|circumvent|ignore)\s+(?:all\s+)?(?:safety|guardrails|content\s+filter|all\s+filters|safety\s+filters|filters)\b'),
                "PROMPT_INJECTION_BYPASS"
            ),
            (
                re.compile(r'(?i)\b(?:system:\s*role|assistant:\s*override|human:\s*ignore)\b'),
                "PROMPT_INJECTION_ROLEPLAY"
            ),
        ]

    def detect(self, text: str) -> List[DetectedSpan]:
        """
        Detects prompt injection patterns and jailbreak attempts.
        """
        raw_spans: List[DetectedSpan] = []
        for regex, category in self.injection_signatures:
            for match in regex.finditer(text):
                raw_spans.append(DetectedSpan(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(0),
                    confidence=0.95,
                    replacement="<INJECTION_ATTEMPT_BLOCKED>"
                ))

        # Sort spans by start index
        raw_spans.sort(key=lambda s: s.start)
        return raw_spans

injection_detector = InjectionDetector()
