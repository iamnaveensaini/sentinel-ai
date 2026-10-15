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
            (re.compile(r'(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)\b'), "PROMPT_INJECTION_OVERRIDE"),
            (re.compile(r'(?i)\b(?:you\s+are\s+now|act\s+as)\s+(?:DAN|unrestricted|jailbroken|an\s+AI\s+without\s+rules)\b'), "PROMPT_INJECTION_JAILBREAK"),
            (re.compile(r'(?i)\b(?:reveal|print|show|dump)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|developer\s+mode)\b'), "PROMPT_INJECTION_LEAK"),
            (re.compile(r'(?i)\b(?:bypass|disable)\s+(?:safety|guardrails|content\s+filter|all\s+filters)\b'), "PROMPT_INJECTION_BYPASS"),
            (re.compile(r'(?i)\b(?:system:\s*role|assistant:\s*override)\b'), "PROMPT_INJECTION_ROLEPLAY"),
        ]

    def detect(self, text: str) -> List[DetectedSpan]:
        """
        Detects prompt injection patterns.
        """
        spans: List[DetectedSpan] = []
        for regex, category in self.injection_signatures:
            for match in regex.finditer(text):
                spans.append(DetectedSpan(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(0),
                    confidence=0.91,
                    replacement="<INJECTION_ATTEMPT_BLOCKED>"
                ))
        return spans

injection_detector = InjectionDetector()
