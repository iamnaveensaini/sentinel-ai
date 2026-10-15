"""
Sentinel AI - PII & Sensitive Entity Detector
High-performance regex and contextual pattern engine for:
- Email addresses
- Phone numbers (Global & Indian 10-digit mobile)
- Credit / Debit Cards
- Indian Aadhaar Numbers (12 digits, handling 'adhar', 'aadhar', 'aadhaar', dots, dashes, spaces)
- Indian PAN Card Numbers (5 uppercase letters + 4 digits + 1 uppercase letter)
- Indian Postal Addresses, Localities, and 6-digit PIN Codes
- Company Confidential & Employee Personal Data (Salary, CTC, Employee IDs)
- Corporate Financial Data & Profit/Loss (P&L, EBITDA, Revenue, Margins)
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
                # Flexible 12-digit format with spaces, dots, hyphens, or continuous
                "regex": re.compile(r'(?i)(?:\b(?:aadhaar|aadhar|adhar|uidai|uid)\s*(?:no\.?|num\.?|number|id)?\s*[:=]?\s*)?([1-9]\d{3}[-\s.]?\d{4}[-\s.]?\d{4}|\b[1-9]\d{11}\b)'),
                "replacement": "<AADHAAR_REDACTED>",
                "confidence": 0.95
            },
            "PAN_CARD": {
                "regex": re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
                "replacement": "<PAN_REDACTED>",
                "confidence": 0.98
            },
            "ADDRESS_LOCATION": {
                # Indian PIN Codes, street indicators, and residential addresses
                "regex": re.compile(
                    r'(?i)(?:\b(?:house\s*no\.?|h\.no\.?|flat\s*no\.?|plot\s*no\.?|sector\s*\d+|street\s*\d+|road|nagar|vihar|colony|marg|lane|block\s*[a-z0-9]+|apartment|apartments|society)\b[^\n,;.]{2,40}(?:,\s*[^\n,;.]{2,40}){1,3}|\b(?:Noida|Delhi|New\s*Delhi|Gurgaon|Gurugram|Bangalore|Bengaluru|Mumbai|Pune|Hyderabad|Jaipur|Lucknow|Kolkata|Chennai)\b\s*(?:,\s*(?:UP|Uttar\s*Pradesh|Haryana|Maharashtra|Karnataka|Delhi|Rajasthan))?\s*(?:-\s*\d{6}|\b[1-9][0-9]{2}\s?[0-9]{3}\b)?|\bPIN\s*(?:code)?\s*[:=]?\s*[1-9][0-9]{2}\s?[0-9]{3}\b)'
                ),
                "replacement": "<ADDRESS_REDACTED>",
                "confidence": 0.91
            },
            "COMPANY_PERSONAL_DATA": {
                # Employee IDs, Salary, CTC, Compensation, Package
                "regex": re.compile(
                    r'(?i)(?:\b(?:EMP|EMP_ID|EMPLOYEE_ID)[-_#]?[0-9A-Z]{3,10}\b|\b(?:salary|ctc|in-hand|compensation|stipend|package)\s*(?:of|is|was|around|amounting\s*to)?\s*[:=]?\s*(?:rs\.?|inr|₹|\$)?\s*\d+(?:\.\d+)?\s*(?:lakhs?|lpa|cr|crores?|k|thousand|per\s*month|per\s*annum|pm|pa)\b)'
                ),
                "replacement": "<COMPANY_DATA_REDACTED>",
                "confidence": 0.93
            },
            "FINANCIAL_PROFIT_LOSS": {
                # P&L statements, profit/loss numbers, margins, EBITDA, revenue, turnover
                "regex": re.compile(
                    r'(?i)(?:\b(?:profit|loss|p&l|ebitda|net\s*income|gross\s*margin|net\s*profit\s*margin|revenue|turnover|operating\s*loss|net\s*profit)\s*(?:of|is|was|around|reached|amounted\s*to)?\s*[:=]?\s*(?:rs\.?|inr|₹|\$|usd|eur)?\s*\d+(?:\.\d+)?\s*(?:crores?|cr|lakhs?|million|billion|k|%|percent)?\b|\b(?:balance\s*sheet|profit\s*and\s*loss\s*statement|quarterly\s*earnings\s*report|unannounced\s*financials|ebitda\s*report)\b)'
                ),
                "replacement": "<FINANCIAL_DATA_REDACTED>",
                "confidence": 0.94
            }
        }
        
        self.hinglish_cues = re.compile(
            r'\b(?:mera|meri|humara|apna|ye|yeh|kripya|bhejo|check\s+karo|account\s+ka|card\s+ka|aadhaar|aadhar|adhar|pan|pate|address|kamayi|munafa|nuksan|ghata)\b', 
            re.IGNORECASE
        )

    def detect(self, text: str) -> List[DetectedSpan]:
        """
        Scans text for personal, corporate, and financial sensitive patterns.
        """
        results: List[DetectedSpan] = []
        has_hinglish_context = bool(self.hinglish_cues.search(text))

        for category, config in self.patterns.items():
            for match in config["regex"].finditer(text):
                matched_val = match.group(0).strip()
                
                # Filter false positives for Aadhaar (repeated digits or invalid length)
                if category == "AADHAAR_ID":
                    digits_only = re.sub(r'\D', '', matched_val)
                    if len(digits_only) != 12 or digits_only == digits_only[0] * 12:
                        continue

                # Filter false positives for Credit Card (must have 15 or 16 digits)
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
