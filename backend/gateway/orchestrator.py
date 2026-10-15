"""
Sentinel AI - Central Security Gateway Orchestrator
The core mediation engine that enforces:
1. Authentication & Tenant scoping
2. Multi-tier Input Inspection (PII, Secrets, Injection)
3. Policy Enforcement (ALLOW / MASK / BLOCK)
4. BLOCK-BEFORE-FORWARD Guarantee (Provider adapter NEVER invoked if action == BLOCK)
5. Pre-retrieval Access Control (ACL)
6. Post-generation Output Leak Inspection
7. Zero-Raw-Content Audit Logging
"""
import time
import uuid
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from backend.auth.models import AuthenticatedUser
from backend.detection.pii_detector import pii_detector, DetectedSpan
from backend.detection.secret_scanner import secret_scanner
from backend.detection.injection_detector import injection_detector
from backend.policy.engine import policy_engine
from backend.policy.models import PolicyAction, PolicyDecision
from backend.retrieval.doc_store import doc_store
from backend.providers.adapter import provider_adapter
from backend.output_filter.sanitizer import output_sanitizer
from backend.audit.models import AuditEvent
from backend.audit.logger import audit_logger

class GatewayRequest(BaseModel):
    message: str = Field(..., max_length=32768)
    conversation_id: Optional[str] = "conv_default"
    retrieval_scope: Optional[List[str]] = Field(default_factory=list)
    client_request_id: Optional[str] = None

class GatewayResponse(BaseModel):
    request_id: str
    status: str  # allowed | masked | blocked
    policy_version: str
    response: Optional[str] = None
    sanitized_prompt_forwarded: Optional[str] = None
    reason_codes: List[str] = Field(default_factory=list)
    categories_detected: List[str] = Field(default_factory=list)
    gateway_latency_ms: float
    total_latency_ms: float
    provider_called: bool
    retrieved_doc_titles: List[str] = Field(default_factory=list)

class GatewayOrchestrator:
    async def process_chat(self, req: GatewayRequest, user: AuthenticatedUser) -> GatewayResponse:
        t0 = time.perf_counter()
        request_id = f"req_{uuid.uuid4().hex[:12]}"

        # Step 1: Input Inspection across PII, Secrets, and Injections
        all_spans: List[DetectedSpan] = []
        all_spans.extend(secret_scanner.scan(req.message))
        all_spans.extend(injection_detector.detect(req.message))
        all_spans.extend(pii_detector.detect(req.message))

        # Step 2: Policy Engine Evaluation
        decision: PolicyDecision = policy_engine.evaluate(req.message, all_spans)
        t_gateway_inspected = time.perf_counter()
        gateway_overhead_ms = round((t_gateway_inspected - t0) * 1000, 2)

        # Step 3: Enforce BLOCK-BEFORE-FORWARD Guarantee
        if decision.action == PolicyAction.BLOCK:
            total_time_ms = round((time.perf_counter() - t0) * 1000, 2)
            
            # Log audit event with zero raw content
            audit_logger.log(AuditEvent(
                event_id=request_id,
                tenant_id=user.tenant_id,
                pseudonymous_user_id=user.user_id,
                action_taken="BLOCK",
                rule_categories=decision.categories_triggered,
                policy_version=decision.policy_version,
                provider_called=False, # Verified: LLM never called!
                gateway_latency_ms=gateway_overhead_ms,
                total_latency_ms=total_time_ms,
                provider_status_code=403
            ))

            return GatewayResponse(
                request_id=request_id,
                status="blocked",
                policy_version=decision.policy_version,
                response="[REQUEST BLOCKED: Security policy prevented this prompt from reaching the AI provider due to detected credentials or policy violations.]",
                sanitized_prompt_forwarded=None,
                reason_codes=decision.reason_codes,
                categories_detected=decision.categories_triggered,
                gateway_latency_ms=gateway_overhead_ms,
                total_latency_ms=total_time_ms,
                provider_called=False
            )

        # Step 4: Handle Authorized Retrieval / RAG if requested
        prompt_to_send = decision.sanitized_prompt or req.message
        retrieved_titles: List[str] = []
        if req.retrieval_scope:
            authorized_docs = doc_store.retrieve(user, req.retrieval_scope)
            if authorized_docs:
                retrieved_titles = [d["title"] for d in authorized_docs]
                context_block = "\n".join([f"--- Context ({d['title']}) ---\n{d['untrusted_content']}" for d in authorized_docs])
                prompt_to_send = f"{context_block}\n\nUser Question: {prompt_to_send}"

        # Step 5: Forward Sanitized Prompt to Upstream LLM Provider
        raw_llm_response = await provider_adapter.generate_response(prompt_to_send)
        provider_called = True

        # Step 6: Post-Generation Output Inspection
        t_before_output = time.perf_counter()
        final_text, was_modified, output_warnings = output_sanitizer.sanitize(raw_llm_response)
        
        t_end = time.perf_counter()
        total_gateway_latency_ms = round((gateway_overhead_ms + ((t_end - t_before_output) * 1000)), 2)
        total_time_ms = round((t_end - t0) * 1000, 2)

        # Step 7: Record Privacy Audit Event
        combined_categories = list(set(decision.categories_triggered + output_warnings))
        final_action = "MASK" if decision.action == PolicyAction.MASK or was_modified else "ALLOW"
        
        audit_logger.log(AuditEvent(
            event_id=request_id,
            tenant_id=user.tenant_id,
            pseudonymous_user_id=user.user_id,
            action_taken=final_action,
            rule_categories=combined_categories,
            policy_version=decision.policy_version,
            provider_called=provider_called,
            gateway_latency_ms=total_gateway_latency_ms,
            total_latency_ms=total_time_ms,
            provider_status_code=200,
            retrieval_scopes_used=req.retrieval_scope or []
        ))

        return GatewayResponse(
            request_id=request_id,
            status=final_action.lower(),
            policy_version=decision.policy_version,
            response=final_text,
            sanitized_prompt_forwarded=prompt_to_send if decision.action == PolicyAction.MASK else "(identical to user prompt)",
            reason_codes=decision.reason_codes + output_warnings,
            categories_detected=combined_categories,
            gateway_latency_ms=total_gateway_latency_ms,
            total_latency_ms=total_time_ms,
            provider_called=provider_called,
            retrieved_doc_titles=retrieved_titles
        )

gateway_orchestrator = GatewayOrchestrator()
