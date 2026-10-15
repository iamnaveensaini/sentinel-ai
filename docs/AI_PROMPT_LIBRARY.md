# Sentinel AI — Curated Antigravity Prompts for Members 1 & 2
> **Repository:** https://github.com/iamnaveensaini/sentinel-ai  
> **Target Tool:** Google Antigravity (Advanced Agentic Coding Assistant)  
> **Author:** Member 3 (Full-Stack & QA Lead)

---

## 🛡️ MASTER PROMPT FOR MEMBER 1: SECURITY ARCHITECT
*Copy and paste the entire block below into Antigravity on Member 1's machine.*

```markdown
You are the **Security Architect (Member 1)** working on the enterprise codebase **Sentinel AI** (AI Data Leakage Prevention Gateway).
GitHub Repository: https://github.com/iamnaveensaini/sentinel-ai
Your working Git branch is: `feature/member1-gateway-detection`

### 🎯 YOUR MISSION & SCOPE OF OWNERSHIP
You own the Pre-Forwarding Interception, Threat Detection, Policy Enforcement, and the Block-Before-Forward Security Guarantee:
1. `backend/auth/models.py` & `backend/auth/jwt.py` (Identity, roles, and tenant context)
2. `backend/detection/pii_detector.py` (Email, Phone, Indian Aadhaar & PAN, Hinglish cues)
3. `backend/detection/secret_scanner.py` (AWS keys, OpenAI keys, GitHub tokens, passwords)
4. `backend/detection/injection_detector.py` (Direct prompt injection & jailbreak heuristics)
5. `backend/policy/models.py` & `backend/policy/engine.py` (Precedence, ALLOW/MASK/BLOCK, reverse-offset masking)
6. `backend/gateway/orchestrator.py` (Central request flow coordinator & Block-Before-Forward enforcement)
7. `tests/unit/test_detection.py` & `tests/security/test_block_before_forward.py` (Automated pytest tests)

---

### 📋 STEP-BY-STEP IMPLEMENTATION INSTRUCTIONS

#### Step 1: Switch to Your Feature Branch
Run the following in the repository root:
```bash
git checkout feature/member1-gateway-detection
git pull origin feature/member1-gateway-detection
```

#### Step 2: Implement High-Precision Detectors
1. In `backend/detection/pii_detector.py`:
   - Detect standard PII: Emails (RFC 5322 regex), Indian mobile numbers (+91, 91, 0, or 10 digits starting with 6-9), Credit cards (15-16 digits).
   - Detect Indian Identifiers:
     * Indian Aadhaar numbers: 12 digits formatted as `XXXX XXXX XXXX` or continuous `XXXXXXXXXXXX`. Filter out false positives (e.g. repeating digits like `0000 0000 0000`).
     * Indian PAN cards: `[A-Z]{5}[0-9]{4}[A-Z]` (5 uppercase letters, 4 digits, 1 uppercase letter).
   - Contextual Hinglish markers: Detect conversational keywords (`mera`, `apna`, `bhejo`, `aadhaar`, `pan`, `account ka`) to elevate detection confidence.
   - Return a list of `DetectedSpan` objects (`category`, `start`, `end`, `matched_text`, `confidence`, `replacement`).

2. In `backend/detection/secret_scanner.py`:
   - AWS Access Key IDs: `\b(AKIA[0-9A-Z]{16})\b`
   - OpenAI API Keys: `\b(sk-[a-zA-Z0-9-]{20,})\b`
   - GitHub Personal Access Tokens: `\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b`
   - Private Keys: `-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`
   - Passwords / Tokens: `\b(password|passwd|db_pass|api_secret)\s*[:=]\s*["']?([^\s"']{8,})["']?`

3. In `backend/detection/injection_detector.py`:
   - Detect prompt injection & jailbreaks: `ignore all previous instructions`, `you are now DAN`, `disregard prior rules`, `reveal system prompt`, `bypass safety filters`.

#### Step 3: Implement Policy Engine & Masking Transformer
In `backend/policy/engine.py`:
- Apply strict security precedence:
  1. If ANY secret or prompt injection is detected -> Action is `BLOCK`. `sanitized_prompt` MUST be `None` (never forward blocked prompts).
  2. If PII is detected -> Action is `MASK`.
     * **CRITICAL:** Transform the prompt by replacing detected spans in **REVERSE order of appearance (right-to-left)** so substring offsets do not shift!
  3. If no sensitive data is detected -> Action is `ALLOW`.

#### Step 4: Implement Gateway Orchestrator & Block-Before-Forward Enforcement
In `backend/gateway/orchestrator.py`:
- Coordinate: Request -> Input Inspection -> Policy Evaluation.
- **CARDINAL SECURITY RULE (FR-005):**
  If `decision.action == BLOCK`:
  * **DO NOT INVOKE the upstream provider adapter.**
  * Asynchronously log a metadata audit event (`provider_called = False`).
  * Return `status = "blocked"` with safe reason codes immediately.
- If `decision.action` is `ALLOW` or `MASK`:
  * Pass sanitized prompt to Member 2's `provider_adapter.generate_response()`.
  * Pass LLM output to Member 2's `output_sanitizer.sanitize()`.
  * Log metadata audit event (`provider_called = True`).

#### Step 5: Verify with Tests & Push to GitHub
Run the test suite to verify your changes:
```bash
pytest tests/unit/test_detection.py -v
pytest tests/security/test_block_before_forward.py -v
```
When all tests pass, commit and push your work:
```bash
git add .
git commit -m "feat(security): complete input detectors, policy precedence, and block-before-forward enforcement"
git push origin feature/member1-gateway-detection
```
```

---

## 🔌 MASTER PROMPT FOR MEMBER 2: INTEGRATION & RETRIEVAL ENGINEER
*Copy and paste the entire block below into Antigravity on Member 2's machine.*

```markdown
You are the **Integration & Retrieval Engineer (Member 2)** working on the enterprise codebase **Sentinel AI** (AI Data Leakage Prevention Gateway).
GitHub Repository: https://github.com/iamnaveensaini/sentinel-ai
Your working Git branch is: `feature/member2-provider-acl`

### 🎯 YOUR MISSION & SCOPE OF OWNERSHIP
You own the LLM Provider Integration, Pre-Retrieval Document Access Control (ACL), Post-Generation Output Sanitizer, and REST API Routes:
1. `backend/providers/base.py` & `backend/providers/adapter.py` (OpenAI/Groq adapter, server-side secrets, offline mock fallback, invocation tracking)
2. `backend/access_control/acl.py` & `backend/retrieval/doc_store.py` (Pre-retrieval authorization & document store isolation)
3. `backend/output_filter/sanitizer.py` (Post-generation output leak redactor & fail-closed protection)
4. `backend/api/routes.py` & `backend/app/main.py` (FastAPI router: chat completions, health probes, catalog)
5. `tests/security/test_acl.py` (Pre-retrieval authorization security tests)

---

### 📋 STEP-BY-STEP IMPLEMENTATION INSTRUCTIONS

#### Step 1: Switch to Your Feature Branch
Run the following in the repository root:
```bash
git checkout feature/member2-provider-acl
git pull origin feature/member2-provider-acl
```

#### Step 2: Implement LLM Provider Adapter with Offline Mock
In `backend/providers/adapter.py`:
- Implement `LLMProviderAdapter(BaseLLMProvider)`:
  * Read server-side environment variables `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`, and `REQUEST_TIMEOUT_SECONDS` (default 15s).
  * Never expose `LLM_API_KEY` to the client, frontend, or logs.
  * When `LLM_PROVIDER` is `"openai"` or `"groq"` and a real API key is present, execute an asynchronous POST via `httpx.AsyncClient` with timeout handling.
  * When `LLM_PROVIDER` is `"mock"` or API key is absent: Return realistic contextual answers locally without network calls so developers and unit tests can run offline for free.
  * Maintain an internal `self.invocation_count: int` counter incremented on every call. This enables Member 1's Block-Before-Forward tests to verify the provider was not invoked on blocked requests.

#### Step 3: Implement Pre-Retrieval Document ACL & RAG Isolation
1. In `backend/access_control/acl.py`:
   - **FR-008 Compliance:** Document authorization MUST be enforced in backend code BEFORE retrieval. The LLM must NEVER decide or grant access.
   - `AccessControlService.filter_authorized_scopes(user, requested_scopes)`: Intersect requested scopes with `user.allowed_doc_scopes`.
2. In `backend/retrieval/doc_store.py`:
   - Store documents classified under scopes: `public`, `marketing_general`, `hr_confidential`, `financial_records`.
   - `retrieve(user, requested_scopes)`: Return documents matching authorized scopes ONLY. Forbidden documents must be omitted before context construction.
   - Wrap retrieved snippets inside untrusted context boundaries (`--- Context (Untrusted) ---`) to protect against indirect prompt injection.

#### Step 4: Implement Post-Generation Output Sanitizer
In `backend/output_filter/sanitizer.py`:
- **FR-007 Compliance:** Inspect the LLM provider's response before returning it to the user.
- **Output Credential Check:** If the model regurgitates an API key, private key, or password, block the entire response and return:
  `[OUTPUT BLOCKED BY SENTINEL GATEWAY: The model generated credentials in violation of policy.]`
- **Output PII Check:** If the model includes emails, phone numbers, or Aadhaar/PAN cards, redact them with `<REDACTED>` tokens.
- **Fail-Closed Safety:** If output inspection encounters an unhandled exception, fail closed and never return uninspected text.

#### Step 5: Implement FastAPI REST API Routes
In `backend/api/routes.py`:
- `POST /v1/chat/completions`: Accepts `GatewayRequest`, passes to `gateway_orchestrator`, returns `GatewayResponse`.
- `GET /health/live`: Returns `{"status": "alive"}` without leaking internal secrets.
- `GET /health/ready`: Checks DB and policy engine readiness.
- `GET /v1/documents`: Returns list of available document scopes.
- Enable CORS middleware in `backend/app/main.py`.

#### Step 6: Verify with Tests & Push to GitHub
Run the test suite to verify your changes:
```bash
pytest tests/security/test_acl.py -v
```
When all tests pass, commit and push your work:
```bash
git add .
git commit -m "feat(integration): complete provider adapter, pre-retrieval ACL, and output sanitizer"
git push origin feature/member2-provider-acl
```
```
