"""
Sentinel AI - Authentication & Identity Models
Defines trusted user contexts, roles, and token schemas.
"""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class UserRole(str, Enum):
    END_USER = "end_user"
    POLICY_ADMIN = "policy_admin"
    SECURITY_REVIEWER = "security_reviewer"
    OPERATIONS_ADMIN = "operations_admin"

class AuthenticatedUser(BaseModel):
    user_id: str = Field(..., description="Unique pseudonymous user identifier")
    tenant_id: str = Field("default_tenant", description="Tenant isolation identifier")
    roles: List[UserRole] = Field(default_factory=lambda: [UserRole.END_USER])
    allowed_doc_scopes: List[str] = Field(default_factory=lambda: ["public"])

class TokenData(BaseModel):
    sub: str
    tenant_id: str = "default_tenant"
    roles: List[str] = ["end_user"]
    scopes: List[str] = ["public"]
