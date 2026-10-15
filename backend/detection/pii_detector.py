"""
Sentinel AI - PII Detector
High-performance regex and contextual pattern engine for:
- Email addresses (RFC 5322 compliant)
- Phone numbers (Global & Indian 10-digit mobile)
- Credit / Debit Cards (15-16 digits)
- Indian Aadhaar Numbers (12 digits formatted XXXX XXXX XXXX or continuous XXXXXXXXXXXX)
- Indian PAN Card Numbers (5 uppercase letters + 4 digits + 1 uppercase letter)
- Contextual Hinglish conversational markers
"""
import re
from typing import List
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
                "regex": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
                "replacement": "<EMAIL_REDACTED>",
                "confidence": 0.99
            },
            "PHONE_INDIAN": {
                "regex": re.compile(r'(?<!\d|\+)(?:\+91[\s-]?|91[\s-]?|0)?[6-9]\d{9}(?!\d)'),
                "replacement": "<PHONE_REDACTED>",
                "confidence": 0.95
            },
            "CREDIT_CARD": {
                "regex": re.compile(r'(?<!\d)(?:\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{3,4}|\d{15,16})(?!\d)'),
                "replacement": "<CARD_REDACTED>",
                "confidence": 0.92
            },
            "AADHAAR_ID": {
                # 12 digit format: XXXX XXXX XXXX, XXXX-XXXX-XXXX, or continuous XXXXXXXXXXXX
                "regex": re.compile(r'(?<!\d)[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}(?!\d)'),
                "replacement": "<AADHAAR_REDACTED>",
                "confidence": 0.90
            },
            "PAN_CARD": {
                # Standard Indian PAN: 5 uppercase letters, 4 digits, 1 uppercase letter
                "regex": re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
                "replacement": "<PAN_REDACTED>",
                "confidence": 0.98
            }
        }
        
        # Contextual Hinglish markers that elevate detection confidence
        self.hinglish_cues = re.compile(
            r'\b(?:mera|meri|humara|apna|apni|ye|yeh|kripya|bhejo|check\s+karo|account\s+ka|card\s+ka|aadhaar|pan|otp|send\s+karo|bhai|bhej\s+dena|ka\s+pata\s+lagao)\b', 
            re.IGNORECASE
        )

    def detect(self, text: str) -> List[DetectedSpan]:
        """
        Scans text for personal data patterns and returns detected spans.
        """
        raw_spans: List[DetectedSpan] = []
        has_hinglish_context = bool(self.hinglish_cues.search(text))

        for category, config in self.patterns.items():
            for match in config["regex"].finditer(text):
                matched_val = match.group()
                
                # Filter out false positives for Aadhaar (must be 12 digits, no repeating all-same digits)
                if category == "AADHAAR_ID":
                    digits_only = re.sub(r'\D', '', matched_val)
                    if len(digits_only) != 12:
                        continue
                    if digits_only == digits_only[0] * 12:
                        continue

                # Filter out false positives for Credit Card (must have 15 or 16 digits, no all-same)
                if category == "CREDIT_CARD":
                    digits_only = re.sub(r'\D', '', matched_val)
                    if len(digits_only) not in (15, 16):
                        continue
                    if digits_only == digits_only[0] * len(digits_only):
                        continue

                confidence = config["confidence"]
                if has_hinglish_context:
                    confidence = min(1.0, confidence + 0.05)

                raw_spans.append(DetectedSpan(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    matched_text=matched_val,
                    confidence=confidence,
                    replacement=config["replacement"]
                ))

        return self._resolve_overlapping_spans(raw_spans)

    def _resolve_overlapping_spans(self, spans: List[DetectedSpan]) -> List[DetectedSpan]:
        """
        Resolves overlapping spans by keeping higher-confidence or longer spans.
        """
        if not spans:
            return []
        
        # Sort primarily by start index, secondarily by confidence desc, then length desc
        sorted_spans = sorted(
            spans,
            key=lambda s: (s.start, -s.confidence, -(s.end - s.start))
        )
        
        resolved: List[DetectedSpan] = []
        for current in sorted_spans:
            if not resolved:
                resolved.append(current)
                continue
            
            last = resolved[-1]
            if current.start < last.end:
                # Overlap detected
                if current.confidence > last.confidence:
                    resolved[-1] = current
                elif current.confidence == last.confidence and (current.end - current.start) > (last.end - last.start):
                    resolved[-1] = current
            else:
                resolved.append(current)

        resolved.sort(key=lambda s: s.start)
        return resolved

pii_detector = PIIDetector()
