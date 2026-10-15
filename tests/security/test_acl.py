"""
Sentinel AI - Security Test: Pre-Retrieval Document ACL Enforcement (FR-008)
Verifies that unauthorized documents are omitted server-side BEFORE reaching LLM context.
"""
import pytest
from backend.auth.models import AuthenticatedUser, UserRole
from backend.retrieval.doc_store import doc_store
from backend.access_control.acl import acl_service

def test_unauthorized_user_cannot_retrieve_hr_confidential():
    """Regular end user must not receive HR confidential or financial documents."""
    standard_user = AuthenticatedUser(
        user_id="user_john_doe",
        tenant_id="tenant_alpha",
        roles=[UserRole.END_USER],
        allowed_doc_scopes=["public"]
    )
    
    # Requesting both public and hr_confidential
    requested_scopes = ["public", "hr_confidential", "financial_records"]
    authorized_scopes = acl_service.filter_authorized_scopes(standard_user, requested_scopes)
    
    assert authorized_scopes == ["public"]
    assert "hr_confidential" not in authorized_scopes
    assert "financial_records" not in authorized_scopes
    
    # Verify retrieved docs only contains public
    docs = doc_store.retrieve(standard_user, requested_scopes)
    doc_scopes = [d["scope"] for d in docs]
    assert "hr_confidential" not in doc_scopes
    assert "financial_records" not in doc_scopes
    assert all(d["scope"] == "public" for d in docs)

def test_admin_user_can_retrieve_confidential():
    """Admin user with authorized scopes can retrieve HR confidential documents."""
    admin_user = AuthenticatedUser(
        user_id="admin_jane_doe",
        tenant_id="tenant_alpha",
        roles=[UserRole.POLICY_ADMIN],
        allowed_doc_scopes=["public", "hr_confidential"]
    )
    
    docs = doc_store.retrieve(admin_user, ["hr_confidential"])
    assert len(docs) > 0
    assert any(d["scope"] == "hr_confidential" for d in docs)
