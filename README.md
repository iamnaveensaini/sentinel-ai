# Sentinel AI — AI Data Leakage Prevention Gateway
> **Version 2.0 MVP** | Production-Oriented PRD & Architecture Implementation

Sentinel AI is an application-layer security gateway that mediates requests between authenticated users/applications and LLM providers. It enforces data-handling policies, detects and masks personal data (including Indian Aadhaar and PAN), blocks credentials before they leave the enterprise perimeter, verifies pre-retrieval document access control (ACL), and records zero-raw-content audit trails.

---

## 🏛️ System Architecture & Request Flow

```
User Prompt (Client)
        │
        ▼
[1. Authentication & Tenant Scope Verification]
        │
        ▼
[2. Multi-tier Input Inspection] ──► PII, Secrets (AWS/API Keys), Prompt Injections
        │
        ▼
[3. Policy Engine Evaluation] ────► ALLOW / MASK / BLOCK
        │
        ├─────────────────────────► If BLOCK ──► [TERMINATE & AUDIT] (Provider is NEVER called)
        │
        ▼ (If ALLOW or MASK)
[4. Pre-Retrieval ACL Check] ─────► Verify document scope authorization server-side
        │
        ▼
[5. Upstream Provider Adapter] ───► Real LLM (OpenAI / Groq) or Offline Mock Fallback
        │
        ▼
[6. Post-Generation Output Filter] ► Scan & redact model outputs before return
        │
        ▼
[7. Privacy-Preserving Audit] ────► Store structured metadata (ZERO raw prompt/response)
        │
        ▼
Sanitized User Response
```

---

## 👥 3-Member Work Division Summary

| Member | Primary Role | Owned Modules | Core Responsibilities |
| :--- | :--- | :--- | :--- |
| **Member 1** | **Security Architect** | `backend/auth/`, `backend/detection/`, `backend/policy/`, `backend/gateway/` | Input inspection (PII, Indian Aadhaar/PAN, Secrets, Prompt Injection), Policy Engine, and the **Block-Before-Forward** guarantee. |
| **Member 2** | **Integration & Retrieval Engineer** | `backend/providers/`, `backend/access_control/`, `backend/retrieval/`, `backend/output_filter/`, `backend/api/` | LLM Provider Adapter (OpenAI/Groq/Mock), Pre-retrieval ACL enforcement, Document Store isolation, Post-generation output filter, and REST API routes. |
| **Member 3** | **Full-Stack & QA Engineer** | `backend/audit/`, `backend/evaluation/`, `frontend/`, `deploy/`, `compose.yaml` | Privacy-preserving metadata audit logging (zero-raw-leak), 120+ case evaluation benchmark runner, Interactive Web UI & Security Inspector, and Dockerization. |

👉 **For the complete team task breakdown, deliverables, and interface contracts, see [docs/TEAM_WORK_DIVISION.md](file:///c:/Amity%20project/docs/TEAM_WORK_DIVISION.md).**  
👉 **For copy-paste AI prompts for all members to build their parts, see [docs/AI_PROMPT_LIBRARY.md](file:///c:/Amity%20project/docs/AI_PROMPT_LIBRARY.md).**  
👉 **For the printable executive guide, see `SENTINEL_AI_Work_Division_and_Prompts.pdf`.**

---

## 🚀 Quickstart & Setup Guide

### Option 1: Instant Browser Demo (Zero Setup)
Simply open `frontend/index.html` directly in any web browser (Google Chrome, Microsoft Edge, Brave). It includes a full client-side emulation engine with sample buttons for testing Aadhaar masking, AWS key blocking, prompt injections, and audit logs.

### Option 2: Running the Python Backend
1. **Clone & Navigate:**
   ```bash
   cd "c:\Amity project"
   ```
2. **Create and Activate Virtual Environment:**
   ```bash
   python -m venv venv
   # Windows:
   .\venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```
3. **Install Dependencies:**
   ```bash
   pip install -r backend/requirements.txt
   ```
4. **Configure Environment:**
   ```bash
   copy .env.example .env
   ```
5. **Start Gateway Server:**
   ```bash
   uvicorn backend.app.main:app --reload --port 8000
   ```
6. Open `http://localhost:8000/ui/` in your browser.

### Option 3: Docker Compose
```bash
docker compose up --build
```

---

## 🧪 Running Security Tests & Evaluation Benchmark

### 1. Run Security Acceptance Tests
```bash
pytest tests/ -v
```
Tests verify:
- ✅ **Block-Before-Forward:** Asserts provider adapter is NOT called on blocked requests.
- ✅ **Pre-Retrieval ACL:** Asserts unauthorized users cannot retrieve HR or financial documents.
- ✅ **PII/Secret Detection:** Validates Indian Aadhaar, PAN, Emails, and AWS key triggers.

### 2. Run the 120+ Case Evaluation Benchmark
```bash
python backend/evaluation/benchmark.py
```
Outputs:
- **Recall & Precision** percentages
- **False-Positive Rate**
- **Secret Prevention Rate** (verified 100%)
- **Gateway Overhead Latency** ($p_{50}$ and $p_{95}$ in ms)
- **Zero-Raw-Content Audit Verification** (proves 0 raw prompts or secrets in DB)

---

## 📄 License & Team
Developed for Enterprise AI Governance & Data Leakage Prevention.
Part of the Sentinel AI Security Initiative.
