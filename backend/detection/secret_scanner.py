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
                "regex": re.compile(r'\b(AKIA[0-9A-Z]{14,24})\b'),
                "confidence": 0.99
            },
            "SECRET_OPENAI_KEY": {
                "regex": re.compile(r'\b(sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{30,}|sk-[a-zA-Z0-9]{32,})\b'),
                "confidence": 0.99
            },
            "SECRET_GITHUB_TOKEN": {
                "regex": re.compile(r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b'),
                "confidence": 0.99
            },
            "SECRET_PRIVATE_KEY": {
                "regex": re.compile(r'-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE\s+KEY[^-]*-----'),
                "confidence": 1.00
            },
            "SECRET_GENERIC_PASSWORD": {
                "regex": re.compile(r'(?i)\b(?:password|passwd|db_pass|api_secret|auth_token)\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*()_+=-]{8,})["\']?'),
                "confidence": 0.92
            }
        }

    def scan(self, text: str) -> List[DetectedSpan]:
        """
        Scans text for secrets and credentials.
        """
        findings: List[DetectedSpan] = []
        for category, config in self.secret_patterns.items():
            for match in config["regex"].finditer(text):
                findings.append(DetectedSpan(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(0),
                    confidence=config["confidence"],
                    replacement="<SECRET_BLOCKED>"
                ))
        return findings

secret_scanner = SecretScanner()
