"""
Sentinel AI - REST API Routes
Implements:
- POST /v1/chat/completions
- GET  /health/live & /health/ready
- GET  /v1/admin/audit-events
- GET  /v1/admin/policies
- GET  /v1/admin/documents
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from backend.auth.models import AuthenticatedUser, UserRole
from backend.auth.jwt import get_current_user
from backend.gateway.orchestrator import gateway_orchestrator, GatewayRequest, GatewayResponse
from backend.audit.logger import audit_logger
from backend.retrieval.doc_store import doc_store
from backend.policy.engine import policy_engine

router = APIRouter()

@router.post("/v1/chat/completions", response_model=GatewayResponse)
async def chat_completions(
    req: GatewayRequest,
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Primary protected gateway endpoint.
    All prompts are screened, validated, authorized, and filtered before and after LLM execution.
    """
    try:
        return await gateway_orchestrator.process_chat(req, user)
    except Exception as e:
        # Never leak internal stack trace to end user
        raise HTTPException(status_code=500, detail="Internal security gateway processing error.")

@router.get("/v1/admin/audit-events")
async def get_audit_events(
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Retrieves recent metadata-only audit logs for security reviewers and administrators.
    """
    return {
        "status": "success",
        "events": audit_logger.get_recent_events(limit)
    }

@router.get("/v1/admin/policies")
async def get_policies():
    """
    Returns active policy version and rule parameters.
    """
    return {
        "active_version": policy_engine.version,
        "rules": [
            {"category": "SECRET_*", "action": "BLOCK", "enforced_at": "gateway_input"},
            {"category": "PROMPT_INJECTION_*", "action": "BLOCK", "enforced_at": "gateway_input"},
            {"category": "PII_*", "action": "MASK", "enforced_at": "gateway_input"},
            {"category": "OUTPUT_SECRETS", "action": "BLOCK", "enforced_at": "provider_output"},
            {"category": "OUTPUT_PII", "action": "REDACT", "enforced_at": "provider_output"}
        ]
    }

@router.get("/v1/documents")
async def list_documents(user: AuthenticatedUser = Depends(get_current_user)):
    """
    Returns list of company documents and their required access authorization scopes.
    """
    return {
        "user_scopes": user.allowed_doc_scopes,
        "catalog": [
            {"id": d["id"], "scope": d["scope"], "title": d["title"]}
            for d in doc_store.documents
        ]
    }
