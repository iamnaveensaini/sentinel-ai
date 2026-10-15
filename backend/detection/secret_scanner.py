"""
Sentinel AI - Secret Scanner
High-precision detector for credentials, API tokens, cryptographic private keys,
and cloud provider access secrets.
"""
import re
from typing import List
from backend.detection.pii_detector import DetectedSpan

class SecretScanner:
    def __init__(self):
        self.secret_patterns = {
            "SECRET_AWS_KEY": {
                "regex": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
                "confidence": 0.99
            },
            "SECRET_OPENAI_KEY": {
                "regex": re.compile(r'\b(sk-[a-zA-Z0-9_-]{20,})\b'),
                "confidence": 0.99
            },
            "SECRET_GITHUB_TOKEN": {
                "regex": re.compile(r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b'),
                "confidence": 0.99
            },
            "SECRET_PRIVATE_KEY": {
                "regex": re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY[^-]*-----'),
                "confidence": 1.00
            },
            "SECRET_PASSWORD": {
                "regex": re.compile(r'(?i)\b(password|passwd|db_pass|api_secret)\s*[:=]\s*["\']?([^\s"\']{8,})["\']?'),
                "confidence": 0.95
            }
        }

    def scan(self, text: str) -> List[DetectedSpan]:
        """
        Scans text for secrets, API credentials, and cryptographic keys.
        """
        raw_findings: List[DetectedSpan] = []
        for category, config in self.secret_patterns.items():
            for match in config["regex"].finditer(text):
                raw_findings.append(DetectedSpan(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(0),
                    confidence=config["confidence"],
                    replacement="<SECRET_BLOCKED>"
                ))

        # Sort and resolve any overlaps
        raw_findings.sort(key=lambda s: (s.start, -s.confidence))
        resolved: List[DetectedSpan] = []
        for current in raw_findings:
            if not resolved:
                resolved.append(current)
                continue
            last = resolved[-1]
            if current.start < last.end:
                if current.confidence > last.confidence:
                    resolved[-1] = current
            else:
                resolved.append(current)

        return resolved

secret_scanner = SecretScanner()
