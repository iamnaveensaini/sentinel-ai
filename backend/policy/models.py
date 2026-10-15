"""
Sentinel AI - Policy Models
Defines Policy Decisions, Action Enums, and Rule Configuration Schemas.
"""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

class PolicyDecision(BaseModel):
    action: PolicyAction
    reason_codes: List[str] = Field(default_factory=list)
    sanitized_prompt: Optional[str] = None
    policy_version: str = "v1.0"
    categories_triggered: List[str] = Field(default_factory=list)
    fail_closed: bool = False
