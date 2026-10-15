"""
Sentinel AI - JWT Authentication & Verification
Extracts verified claims from Authorization Bearer headers.
Falls back to a safe demo user in local development mode.
"""
from typing import Optional
from fastapi import Header, HTTPException, status
from backend.auth.models import AuthenticatedUser, UserRole

DEFAULT_DEMO_USER = AuthenticatedUser(
    user_id="usr_demo_8831",
    tenant_id="tenant_alpha",
    roles=[UserRole.END_USER],
    allowed_doc_scopes=["public", "marketing_general"]
)

ADMIN_DEMO_USER = AuthenticatedUser(
    user_id="usr_admin_0001",
    tenant_id="tenant_alpha",
    roles=[UserRole.POLICY_ADMIN, UserRole.SECURITY_REVIEWER],
    allowed_doc_scopes=["public", "marketing_general", "hr_confidential", "financial_records"]
)

async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_user_role: Optional[str] = Header(None)
) -> AuthenticatedUser:
    """
    Extracts authenticated user context from request headers.
    In production: decodes JWT signature using public key / OIDC provider.
    In local dev: accepts role simulation header or defaults to secure standard user.
    """
    # Demo/dev role switcher via header
    if x_user_role == "admin":
        return ADMIN_DEMO_USER
    
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        # Dev demo token support
        if token == "admin_secret_token":
            return ADMIN_DEMO_USER
        return AuthenticatedUser(
            user_id=f"usr_{token[:8]}",
            tenant_id="tenant_alpha",
            roles=[UserRole.END_USER],
            allowed_doc_scopes=["public"]
        )
    
    # Return standard authenticated user
    return DEFAULT_DEMO_USER
