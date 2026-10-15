# Sentinel AI — AI Coding Prompt Library for 3 Members
> **Usage:** Copy and paste these engineered prompts directly into your AI assistant of choice (**Cursor, ChatGPT-4o, Claude 3.5 Sonnet, or Antigravity**) to generate, refine, and test your assigned modules with zero prompt drift.

---

## 🛡️ MEMBER 1 PROMPTS (Security Architect)

### Prompt 1.1: PII & Indian Identifier Detector (Aadhaar, PAN, Phone, Email)
```text
You are an expert cybersecurity and Python engineer working on Sentinel AI, an enterprise AI Data Leakage Prevention Gateway.
Your task is to write a high-performance, deterministic PII detection module in Python located at `backend/detection/pii_detector.py`.

Requirements:
1. Detect standard PII:
   - Email addresses (RFC 5322 compliant regex)
   - Indian Mobile Phone Numbers (+91, 91, 0, or 10 digits starting with 6-9)
   - Global Credit/Debit Cards (15-16 digits with hyphen/space support)
2. Detect Indian National Identifiers:
   - Indian Aadhaar Card (12 digits in format XXXX XXXX XXXX or XXXXXXXXXXXX; exclude obvious false positives like all repeating digits or 0000...)
   - Indian PAN Card (5 uppercase letters + 4 digits + 1 uppercase letter, e.g., ABCDE1234F)
3. Support contextual Hinglish cues ("mera aadhaar", "apna phone number", "ye pan card hai") to boost confidence score.
4. Data Contract:
   Return a list of `DetectedSpan` objects with:
   - category (str)
   - start (int)
   - end (int)
   - matched_text (str)
   - confidence (float between 0.0 and 1.0)
   - replacement (str, e.g. "<AADHAAR_REDACTED>", "<EMAIL_REDACTED>")
5. Code Quality:
   - Type hinted with Pydantic models.
   - Compiled regex patterns for sub-millisecond execution.
   - Include standalone unit tests with pytest covering both positive and negative cases.
```

---

### Prompt 1.2: Secret Scanner & Prompt Injection Detector
```text
You are a senior security engineer implementing secret scanning and prompt injection detection for Sentinel AI.
Create two modules:
1. `backend/detection/secret_scanner.py`:
   - Detect AWS Access Keys (AKIA[0-9A-Z]{16})
   - Detect OpenAI API Keys (sk-[a-zA-Z0-9-]{20,})
   - Detect GitHub Personal Access Tokens (ghp_[a-zA-Z0-9]{36} and github_pat_...)
   - Detect Cryptographic Private Keys (-----BEGIN RSA/OPENSSH PRIVATE KEY-----)
   - Detect generic passwords and database tokens (password="...", db_pass="...")
2. `backend/detection/injection_detector.py`:
   - Detect direct prompt injection heuristics: "ignore previous instructions", "disregard prior rules", "you are now DAN", "dump system prompt", "bypass safety filters".
   - Return detected spans with confidence >= 0.90.
3. Ensure zero false positives on benign programming questions (e.g. asking how to write a Python regex or how to use git clone).
```

---

### Prompt 1.3: Policy Enforcement Engine & Masking Transformer
```text
You are developing the Policy Engine for Sentinel AI at `backend/policy/engine.py`.
The engine takes detected spans from the detectors and decides the operational action: ALLOW, MASK, or BLOCK.

Strict Security Precedence:
1. If ANY secret (AWS key, API key, private key, password) OR ANY prompt injection is detected -> Action MUST BE BLOCK.
   - For BLOCK, sanitized_prompt MUST be None (never forward blocked prompts upstream).
   - Return safe reason codes (e.g. "PROHIBITED_CREDENTIAL_DETECTED").
2. If PII is detected (Email, Phone, Aadhaar, PAN) -> Action is MASK.
   - Transform original text into sanitized_prompt by replacing spans with tokens (<EMAIL_REDACTED>, <AADHAAR_REDACTED>).
   - CRITICAL: Replace spans from right-to-left (reverse index order) to avoid index shift bugs!
3. If no sensitive data is detected -> Action is ALLOW.

Provide the complete `PolicyEngine` class, Pydantic schemas, and pytest unit tests.
```

---

### Prompt 1.4: Gateway Orchestrator & Block-Before-Forward Security Test
```text
You are writing the core orchestration engine at `backend/gateway/orchestrator.py` for Sentinel AI.
This module mediates between the client request and upstream providers.

Flow:
1. Receive GatewayRequest and AuthenticatedUser.
2. Run input inspection: secret_scanner, injection_detector, pii_detector.
3. Evaluate decision via policy_engine.
4. ENFORCE BLOCK-BEFORE-FORWARD (FR-005):
   - If decision.action == BLOCK:
     - DO NOT CALL provider_adapter!
     - Immediately record audit event (provider_called = False).
     - Return blocked response with safe reason codes.
5. If ALLOW or MASK:
   - Execute authorized document retrieval if scopes provided.
   - Forward sanitized prompt to provider_adapter.
   - Run output sanitizer on LLM response.
   - Log metadata-only audit event (provider_called = True).
   - Return final GatewayResponse.

Also write `tests/security/test_block_before_forward.py` using pytest and pytest-asyncio:
Assert that when a prompt containing "AKIAIOSFODNN7EXAMPLE" is sent, the provider adapter's invocation counter does not increase.
```

---

## 🔌 MEMBER 2 PROMPTS (Integration & Retrieval Engineer)

### Prompt 2.1: Production LLM Provider Adapter with Mock Fallback
```text
You are implementing the server-side LLM provider integration for Sentinel AI at `backend/providers/adapter.py`.

Requirements:
1. Class `LLMProviderAdapter` inheriting from `BaseLLMProvider`.
2. Support real LLM providers via HTTPX (OpenAI API or Groq API) using server-side environment variables `LLM_API_KEY`, `LLM_MODEL`, and `LLM_PROVIDER`.
3. Support an offline "mock" mode:
   - When `LLM_PROVIDER=mock` or API key is absent, generate realistic contextual responses locally without making network calls.
4. Implement strict timeout handling (`REQUEST_TIMEOUT_SECONDS`, default 15s) and safe error handling (never leak API keys or tracebacks in exceptions).
5. Maintain an internal `invocation_count` attribute to allow automated security tests to verify whether the provider was called.
```

---

### Prompt 2.2: Pre-Retrieval Document ACL & RAG Isolation
```text
You are designing the Access Control Layer and Document Store for Sentinel AI at:
- `backend/access_control/acl.py`
- `backend/retrieval/doc_store.py`

Requirements:
1. FR-008 Compliance:
   - Document permissions MUST be verified server-side BEFORE retrieval and before context is assembled.
   - The model must NEVER grant permissions or decide document access.
2. `AccessControlService`:
   - Checks if `user.allowed_doc_scopes` contains the requested document scope.
   - Filters requested scopes down to only permitted scopes.
3. `DocumentStore`:
   - Contains documents classified under scopes: `public`, `marketing_general`, `hr_confidential`, `financial_records`.
   - `retrieve(user, requested_scopes)` returns documents ONLY matching authorized scopes.
   - Treats retrieved content as untrusted data to guard against indirect injection.
4. Write pytest tests in `tests/security/test_acl.py` demonstrating that a standard user with `["public"]` scope receives 0 documents when asking for `hr_confidential`.
```

---

### Prompt 2.3: Post-Generation Output Sanitizer
```text
You are implementing the output safety filter at `backend/output_filter/sanitizer.py` for Sentinel AI.

Requirements:
1. FR-007 Compliance:
   - Inspect LLM provider response before returning it to the user.
2. Output Secret Check:
   - If the model's generated text contains credentials, API keys, or passwords, block the entire output with a safe security explanation.
3. Output PII Check:
   - If the model's output contains emails, phone numbers, or Aadhaar/PAN identifiers, redact them in place with `<REDACTED>` tokens.
4. Fail-Closed Error Handling:
   - If output scanning fails or encounters an unhandled exception, fail closed and never return uninspected output.
```

---

### Prompt 2.4: FastAPI REST API Routes & Health Endpoints
```text
You are building the REST API layer for Sentinel AI at `backend/api/routes.py` and `backend/app/main.py`.

Endpoints to implement:
1. `POST /v1/chat/completions`: Accepts `GatewayRequest` (message, conversation_id, retrieval_scope), calls `gateway_orchestrator.process_chat()`, and returns `GatewayResponse`.
2. `GET /health/live`: Liveness check returning `{"status": "alive"}`.
3. `GET /health/ready`: Readiness check verifying database and policy engine.
4. `GET /v1/admin/audit-events`: Authenticated endpoint returning recent metadata audit records.
5. `GET /v1/admin/policies`: Returns active policy rules and version.
6. `GET /v1/documents`: Returns catalog of document scopes and current user's permitted scopes.

Ensure CORS middleware is enabled and Pydantic models validate all inputs with size limits.
```

---

## 📊 MEMBER 3 PROMPTS (Full-Stack & QA Engineer)

### Prompt 3.1: Zero-Leakage Privacy Audit Logger & SQLite Models
```text
You are building the Privacy-Preserving Audit Logger for Sentinel AI at `backend/audit/logger.py` and `backend/audit/models.py`.

CRITICAL PRIVACY RULE:
Default logs must contain ZERO raw prompt text, ZERO raw LLM output text, and ZERO credentials.

Requirements:
1. Data Model `AuditEvent`:
   - event_id (str, unique)
   - timestamp (UTC ISO8601)
   - tenant_id (str)
   - pseudonymous_user_id (str)
   - action_taken (str: ALLOW | MASK | BLOCK)
   - rule_categories (list of str, e.g. ["AADHAAR_ID", "SECRET_AWS_KEY"])
   - policy_version (str)
   - provider_called (bool)
   - gateway_latency_ms (float)
   - total_latency_ms (float)
   - provider_status_code (int)
   - retrieval_scopes_used (list of str)
2. Storage Engine:
   - Persist to SQLite database table `audit_events`.
   - Maintain an in-memory cache of the last 50 events for quick admin queries.
3. Audit Verification Function:
   - Write a helper that scans all stored records in the audit table and verifies that no raw secrets (AKIA..., sk-...) or sensitive substrings appear in the values.
```

---

### Prompt 3.2: 120+ Case Evaluation Dataset & Benchmark Runner
```text
You are building the automated security evaluation suite for Sentinel AI at:
- `tests/evaluation_corpus/dataset.json`
- `backend/evaluation/benchmark.py`

Requirements:
1. Dataset:
   Create a JSON dataset containing 120+ test cases across 9 categories:
   - Benign prompts (Python code, SQL, business emails, recipes) -> Expected: ALLOW
   - PII Emails & Phone numbers -> Expected: MASK
   - PII Indian Aadhaar & PAN cards -> Expected: MASK
   - PII Credit cards -> Expected: MASK
   - Secrets: AWS keys, OpenAI keys, GitHub tokens, passwords -> Expected: BLOCK
   - Prompt Injections: DAN, system prompt extraction, rule overrides -> Expected: BLOCK
   - Hinglish sensitive prompts -> Expected: MASK / BLOCK
2. Benchmark Runner:
   - Iterate over all cases through `gateway_orchestrator.process_chat()`.
   - Compute and print:
     * Precision (TP / (TP + FP))
     * Recall (TP / (TP + FN))
     * False Positive Rate (FP / (FP + TN))
     * Secret Prevention Rate (Must be 100%)
     * Gateway Overhead Latency (p50 and p95 in ms)
     * Raw Leak Count in DB (Must be 0)
   - Export results to `eval_results_latest.json`.
```

---

### Prompt 3.3: Interactive Chat UI & Security Inspector Frontend
```text
You are building a responsive Single Page Application for Sentinel AI at `frontend/index.html`.

UI Architecture:
1. Framework: Tailwind CSS (via CDN) with clean, dark-mode cybersecurity palette (slate-950 background, cyan/emerald/rose accents).
2. Left Panel: Interactive Chat Stream:
   - Quick scenario buttons: "Benign Code", "Aadhaar + Phone (MASK)", "PAN + Card (MASK)", "AWS Key (BLOCK)", "Prompt Injection (BLOCK)", "Hinglish PII".
   - Message bubbles distinguishing user prompts and assistant replies.
   - Textarea and "Inspect & Send" button.
3. Right Panel: Real-time Gateway Inspector:
   - Decision Badge: Large badge displaying ALLOW (green), MASK (amber), or BLOCK (red).
   - "Provider Called?" Indicator: Green pulse if called, Red shield if blocked before forward.
   - Gateway Latency overhead display (e.g. "2.4 ms").
   - Triggered threat/PII categories chips.
   - "What the LLM Received" diff view showing masked text or block explanation.
   - Pre-retrieval ACL verification status.
4. Top Bar:
   - Role Switcher: "End User" vs "Security Reviewer / Admin".
   - Doc Scope Selector: "None", "Public", "HR Confidential", "Financial".
   - "Audit Logs" button opening a clean modal displaying metadata audit events.
5. Dual-Mode Connectivity:
   - Automatically connects to `http://localhost:8000/v1/chat/completions` if backend is live.
   - If backend is offline, falls back seamlessly to client-side emulation so the team can demo immediately!
```

---

### Prompt 3.4: Dockerfile, Docker Compose & Deployment Packaging
```text
You are packaging Sentinel AI for deployment in `deploy/Dockerfile` and `compose.yaml`.

Requirements:
1. Dockerfile:
   - Multi-stage or slim Python 3.11 base image.
   - Install dependencies from `backend/requirements.txt`.
   - Copy backend, frontend, and tests.
   - Expose port 8000.
   - Healthcheck curling `/health/live`.
2. Docker Compose (`compose.yaml`):
   - Service `sentinel-gateway` mapping `8000:8000`.
   - Mount volumes for live development reload.
   - Pass environment variables from `.env`.
   - Configure healthcheck and automatic restart.
```
