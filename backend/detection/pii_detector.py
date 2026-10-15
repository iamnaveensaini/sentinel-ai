"""
Sentinel AI - PII Detector
High-performance regex and contextual pattern engine for:
- Email addresses
- Phone numbers (Global & Indian 10-digit mobile)
- Credit / Debit Cards
- Indian Aadhaar Numbers (12 digits)
- Indian PAN Card Numbers (5 uppercase letters + 4 digits + 1 uppercase letter)
- Hinglish context cues
"""
import re
from typing import List, Dict, Any
from pydantic import BaseModel, Field

class DetectedSpan(BaseModel):
    category: str
    start: int
    end: int
    matched_text: str
    confidence: float
    replacement: str

class PIIDetector:
    def __init__(self):
        # Compiled deterministic regex patterns
        self.patterns = {
            "EMAIL": {
                "regex": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
                "replacement": "<EMAIL_REDACTED>",
                "confidence": 0.99
            },
            "PHONE_INDIAN": {
                "regex": re.compile(r'(?:\+91[-\s]?|91[-\s]?|0)?[6-9]\d{9}\b'),
                "replacement": "<PHONE_REDACTED>",
                "confidence": 0.95
            },
            "CREDIT_CARD": {
                "regex": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b'),
                "replacement": "<CARD_REDACTED>",
                "confidence": 0.92
            },
            "AADHAAR_ID": {
                # 12 digit format: XXXX XXXX XXXX or XXXXXXXXXXXX
                "regex": re.compile(r'\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b'),
                "replacement": "<AADHAAR_REDACTED>",
                "confidence": 0.90
            },
            "PAN_CARD": {
                # Standard Indian PAN: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F)
                "regex": re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
                "replacement": "<PAN_REDACTED>",
                "confidence": 0.98
            }
        }
        
        # Contextual Hinglish markers that elevate detection confidence
        self.hinglish_cues = re.compile(
            r'\b(?:mera|meri|humara|apna|ye|yeh|kripya|bhejo|check\s+karo|account\s+ka|card\s+ka|aadhaar|pan)\b', 
            re.IGNORECASE
        )

    def detect(self, text: str) -> List[DetectedSpan]:
        """
        Scans text for personal data patterns and returns detected spans.
        """
        results: List[DetectedSpan] = []
        has_hinglish_context = bool(self.hinglish_cues.search(text))

        for category, config in self.patterns.items():
            for match in config["regex"].finditer(text):
                matched_val = match.group()
                
                # Filter out obvious false positives for Aadhaar (e.g. 0000 0000 0000 or simple year ranges)
                if category == "AADHAAR_ID":
                    digits_only = re.sub(r'\D', '', matched_val)
                    if len(digits_only) != 12 or digits_only == digits_only[0] * 12:
                        continue

                # Filter out obvious false positives for Credit Card (must have 15 or 16 digits)
                if category == "CREDIT_CARD":
                    digits_only = re.sub(r'\D', '', matched_val)
                    if len(digits_only) not in (15, 16):
                        continue

                confidence = config["confidence"]
                if has_hinglish_context:
                    confidence = min(1.0, confidence + 0.05)

                results.append(DetectedSpan(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    matched_text=matched_val,
                    confidence=confidence,
                    replacement=config["replacement"]
                ))

        # Sort spans by start index
        results.sort(key=lambda s: s.start)
        return results

pii_detector = PIIDetector()
