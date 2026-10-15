# Sentinel AI — 3-Member Engineering Work Division & Responsibility Matrix
> **Project:** Sentinel AI (AI Data Leakage Prevention Gateway)  
> **Version:** 2.0 MVP Baseline | Date: 15 October 2026

---

## 1. Executive Summary & Separation of Concerns

To guarantee fast velocity and prevent merge conflicts across the 3 members while utilizing AI coding tools (Cursor, ChatGPT, Claude, Antigravity), the Sentinel AI architecture is decoupled into **three independent operational layers**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   MEMBER 1: SECURITY ARCHITECT                         │
│  - Input Interception (PII, Indian Aadhaar/PAN, AWS/API Keys)         │
│  - Policy Enforcement Engine (ALLOW / MASK / BLOCK)                   │
│  - Gateway Orchestration & Block-Before-Forward Guarantee             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Clean or Masked Request
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│             MEMBER 2: INTEGRATION & RETRIEVAL ENGINEER                 │
│  - Server-Side LLM Provider Adapter (OpenAI / Groq / Mock)            │
│  - Pre-Retrieval Document ACL & Tenant Scoping                        │
│  - Post-Generation Output Sanitizer & Leaked Data Redaction           │
│  - REST API Routes & Request/Response Schemas                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Gateway Metrics & Metadata
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 MEMBER 3: FULL-STACK & QA ENGINEER                     │
│  - Privacy-Preserving Metadata Audit Logger (Zero-Raw-Content in DB)  │
│  - 120+ Prompt Evaluation Benchmark Runner (Precision/Recall/Latency) │
│  - Interactive Chat UI & Security Inspector (Tailwind + Vanilla JS)   │
│  - Docker Containerization, Compose & CI/CD Packaging                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Detailed Member Work Breakdown

### 🛡️ Member 1: Core Gateway, Security Engine & Policy Layer (Security Architect)
**Focus:** Pre-forwarding interception, PII/Secret/Injection detection, Policy precedence, and the core Block-Before-Forward guarantee.

#### Assigned Repository Modules:
- `backend/auth/models.py` & `backend/auth/jwt.py`: User/tenant context extraction and role claims.
- `backend/detection/pii_detector.py`: Deterministic regex + Presidio engine for Email, Phone, Credit Cards, Indian Aadhaar (12-digit format), Indian PAN cards (`[A-Z]{5}[0-9]{4}[A-Z]`), and Hinglish conversational cues.
- `backend/detection/secret_scanner.py`: High-entropy secret scanner for AWS keys (`AKIA...`), OpenAI keys (`sk-...`), GitHub tokens (`ghp_...`), private keys, and passwords.
- `backend/detection/injection_detector.py`: Heuristics for direct prompt injection ("ignore previous instructions", "you are DAN", system prompt exfiltration).
- `backend/policy/models.py` & `backend/policy/engine.py`: Evaluates detected spans against active policy version; applies precedence (Secrets/Injections = BLOCK; PII = MASK; Clean = ALLOW); implements deterministic masking transformer.
- `backend/gateway/orchestrator.py`: Orchestrates request flow; **strictly enforces that if action == BLOCK, the upstream provider adapter is NEVER invoked.**
- `tests/unit/test_detection.py` & `tests/security/test_block_before_forward.py`: Unit and security tests.

#### Key Deliverables:
1. Complete detection suite with high precision on Indian identifiers (Aadhaar & PAN).
2. Masking logic that replaces PII spans from right-to-left without shifting index offsets.
3. Automated test proving that `provider_adapter.invocation_count` is 0 when a secret prompt is blocked.

---

### 🔌 Member 2: Provider Integration, RAG Access Control & Output Filter (Integration Engineer)
**Focus:** Server-side LLM mediation, document authorization before retrieval, and post-generation safety inspection.

#### Assigned Repository Modules:
- `backend/providers/base.py`: Abstract base class for LLM providers.
- `backend/providers/adapter.py`: Production adapter calling OpenAI / Groq / Anthropic using server-side keys; includes offline mock fallback for zero-cost development; enforces request timeouts.
- `backend/access_control/acl.py`: Strict RBAC/ABAC verification before document retrieval.
- `backend/retrieval/doc_store.py`: Document store with permission tags (`public`, `hr_confidential`, `financial_records`); wraps content in untrusted data boundaries.
- `backend/output_filter/sanitizer.py`: Scans generated LLM outputs before returning to user; redacts PII and blocks credentials if the model regurgitates sensitive internal data.
- `backend/api/routes.py`: REST endpoints: `POST /v1/chat/completions`, `GET /health/live`, `GET /health/ready`, `GET /v1/documents`.
- `tests/security/test_acl.py`: Tests proving unauthorized users cannot retrieve confidential HR/finance documents.

#### Key Deliverables:
1. Robust provider adapter with timeout and fallback support.
2. Pre-retrieval document ACL service ensuring the LLM never sees unauthorized context.
3. Output sanitizer that prevents model response leakage.

---

### 📊 Member 3: Audit, Evaluation Suite, Database & Interactive UI (Full-Stack & QA)
**Focus:** Zero-leakage audit logging, quantitative evaluation benchmarks, interactive frontend UI, and Docker deployment.

#### Assigned Repository Modules:
- `backend/audit/models.py` & `backend/audit/logger.py`: Structured metadata-only audit logger (SQLite / PostgreSQL); stores event_id, tenant_id, pseudonymous user_id, action, rule_categories, latency_ms; **guarantees zero raw text content in DB.**
- `tests/evaluation_corpus/dataset.json`: Curated 120+ test prompts across 9 categories (benign, PII, Indian Aadhaar, PAN, secrets, prompt injections, Hinglish).
- `backend/evaluation/benchmark.py`: Benchmark runner computing Precision, Recall, False-Positive Rate, Secret Prevention Rate, and Gateway Overhead Latency ($p_{50}$, $p_{95}$).
- `frontend/index.html`: Modern, responsive Single Page Application with interactive chat, real-time security decision badge (ALLOW / MASK / BLOCK), "What the LLM saw" diff viewer, document scope selector, and live audit log drawer.
- `deploy/Dockerfile` & `compose.yaml`: Multi-stage Docker build and one-command orchestration.

#### Key Deliverables:
1. Verifiable audit logger with automated test confirming zero raw sensitive content in database tables.
2. Repeatable benchmark script generating `eval_results_latest.json`.
3. Working interactive frontend UI enabling live team demos.
4. One-command startup via `docker compose up --build`.

---

## 3. Inter-Member Interface Contracts

To avoid merge conflicts, all 3 members agree on these fixed data schemas:

### A. Member 1 -> Member 2 Contract:
```python
class GatewayRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = "conv_default"
    retrieval_scope: Optional[List[str]] = []

class PolicyDecision(BaseModel):
    action: PolicyAction  # ALLOW | MASK | BLOCK
    sanitized_prompt: Optional[str]
    reason_codes: List[str]
    categories_triggered: List[str]
```

### B. Member 2 -> Member 3 Contract:
```python
class GatewayResponse(BaseModel):
    request_id: str
    status: str  # allowed | masked | blocked
    policy_version: str
    response: Optional[str]
    sanitized_prompt_forwarded: Optional[str]
    reason_codes: List[str]
    categories_detected: List[str]
    gateway_latency_ms: float
    total_latency_ms: float
    provider_called: bool
    retrieved_doc_titles: List[str]
```

### C. Member 1 & 2 -> Member 3 Audit Contract:
```python
class AuditEvent(BaseModel):
    event_id: str
    tenant_id: str
    pseudonymous_user_id: str
    action_taken: str  # ALLOW | MASK | BLOCK
    rule_categories: List[str]
    policy_version: str
    provider_called: bool
    gateway_latency_ms: float
    total_latency_ms: float
    provider_status_code: int
    retrieval_scopes_used: List[str]
```

---

## 4. 5-Week Implementation Roadmap

| Week | Milestone | Member 1 Focus | Member 2 Focus | Member 3 Focus |
| :---: | :--- | :--- | :--- | :--- |
| **Wk 1** | **Foundations & Core Slice** | Setup FastAPI, JWT models, request validation | Build LLM adapter with mock fallback and timeout | Setup SQLite DB, audit schema & initial repo scaffold |
| **Wk 2** | **Detection & ACL Engine** | Implement PII (Email/Phone/Aadhaar/PAN) & secret regexes | Implement pre-retrieval ACL & document store | Build initial 50-item evaluation dataset |
| **Wk 3** | **Enforcement & Filtering** | Build Policy Engine, MASK logic & Block-Before-Forward | Build post-generation output filter & redact engine | Implement evaluation metrics runner (Precision/Recall) |
| **Wk 4** | **Benchmark & Evaluation** | Add Hinglish detectors and injection heuristics | Finalize REST endpoints and error boundaries | Expand dataset to 120+ cases; run benchmark; verify zero leaks |
| **Wk 5** | **UI, Integration & Demo** | Security review & adversarial edge cases | Integration test with real OpenAI/Groq API | Polish Chat UI, Audit Log Drawer, Dockerize & Demo |
