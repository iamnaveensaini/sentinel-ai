"""
Sentinel AI - Authorized Document Store & Retrieval Service
Retrieves documents ONLY if verified by ACL service before retrieval.
Treats all retrieved documents as untrusted data to mitigate indirect prompt injection.
"""
from typing import List, Dict, Optional
from backend.auth.models import AuthenticatedUser
from backend.access_control.acl import acl_service

class DocumentStore:
    def __init__(self):
        # Sample document repository tagged with classification scopes
        self.documents: List[Dict[str, str]] = [
            {
                "id": "doc_pub_01",
                "scope": "public",
                "title": "Company Overview & Public Holidays 2026",
                "content": "All full-time staff observe standard gazetted national holidays and standard 20 days annual leave."
            },
            {
                "id": "doc_mkt_02",
                "scope": "marketing_general",
                "title": "Q3 Marketing Campaign Guidelines",
                "content": "Brand tone of voice must remain customer-centric, authentic, and compliant with privacy disclosures."
            },
            {
                "id": "doc_hr_03",
                "scope": "hr_confidential",
                "title": "Executive Compensation & Bonus Brackets",
                "content": "CONFIDENTIAL HR ONLY: Executive bonus allocations range from 30% to 75% tied to quarterly EBITDA targets."
            },
            {
                "id": "doc_fin_04",
                "scope": "financial_records",
                "title": "Unannounced M&A Acquisition Target Financials",
                "content": "RESTRICTED FINANCIAL: Valuation analysis for Project Titan target acquisition priced at $45M USD."
            }
        ]

    def retrieve(self, user: AuthenticatedUser, requested_scopes: List[str]) -> List[Dict[str, str]]:
        """
        Retrieves matching documents ONLY if user is authorized.
        Denies and omits unauthorized documents server-side BEFORE context injection.
        """
        authorized_scopes = acl_service.filter_authorized_scopes(user, requested_scopes)
        if not authorized_scopes:
            return []

        retrieved: List[Dict[str, str]] = []
        for doc in self.documents:
            if doc["scope"] in authorized_scopes:
                # Wrap document in untrusted context boundary to prevent indirect injection
                retrieved.append({
                    "id": doc["id"],
                    "scope": doc["scope"],
                    "title": doc["title"],
                    "untrusted_content": doc["content"]
                })
        return retrieved

doc_store = DocumentStore()
