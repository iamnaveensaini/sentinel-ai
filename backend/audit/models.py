"""
Sentinel AI - Audit Models
Defines schema for structured, privacy-preserving audit events.
Zero-Raw-Content Guarantee: Raw prompts, raw responses, and secrets are strictly excluded.
"""
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

class AuditEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    pseudonymous_user_id: str
    action_taken: str  # ALLOW | MASK | BLOCK
    rule_categories: List[str] = Field(default_factory=list)
    policy_version: str
    provider_called: bool
    gateway_latency_ms: float
    total_latency_ms: float
    provider_status_code: int = 200
    retrieval_scopes_used: List[str] = Field(default_factory=list)
