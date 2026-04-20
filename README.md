# IntelliDocs — Security Vulnerability Case Study

> **Purpose**: This document is a real, code-verified security analysis of the IntelliDocs RAG application. Every vulnerability listed here was found by scanning the actual source code. No vulnerabilities are fabricated or theoretical. Fixes are planned and will be implemented in future iterations.

---

## Project Overview

IntelliDocs is a RAG (Retrieval-Augmented Generation) PDF assistant built with:
- **FastAPI** — Python web framework handling all HTTP routes
- **ChromaDB** — Vector database storing document embeddings
- **Sentence Transformers** — `all-MiniLM-L6-v2` for generating embeddings
- **Groq API** — `llama-3.1-8b-instant` LLM for answering questions
- **Docker** — Containerized and deployed on Hugging Face Spaces

**Repository**: https://github.com/mzurain/IntelliDocs  
**Live Demo**: https://huggingface.co/spaces/mzurain/IntelliDocs

---

## Vulnerability Summary

| # | Vulnerability | File | Severity | OWASP Category | Status |
|---|--------------|------|----------|----------------|--------|
| 1 | Log Injection (CWE-117) | `main.py` lines 93, 98, 102, 112 | 🔴 High | A09 - Security Logging Failures | Open |
| 2 | Log Injection (CWE-117) | `services/vector_store.py` lines 61, 118 | 🔴 High | A09 - Security Logging Failures | Open |
| 3 | NoSQL Injection (CWE-943) | `main.py` lines 145–146 | 🔴 High | A03 - Injection | Open |
| 4 | No Authentication on any endpoint | `main.py` | 🔴 High | A01 - Broken Access Control | Open |
| 5 | Wildcard CORS Policy | `main.py` line 31 | 🟠 Medium | A05 - Security Misconfiguration | Open |
| 6 | No Rate Limiting | `main.py` | 🟠 Medium | A05 - Security Misconfiguration | Open |
| 7 | Full Exception Details Exposed to Client | `main.py` line 167 | 🟠 Medium | A05 - Security Misconfiguration | Open |
| 8 | Unrestricted File Upload | `main.py` lines 71–81 | 🟠 Medium | A04 - Insecure Design | Open |
| 9 | API Key Loaded Without Validation | `services/llm_service.py` line 15 | 🟠 Medium | A02 - Cryptographic Failures | Open |
| 10 | Naive Datetime (CWE-) | `services/vector_store.py` line 56 | 🟡 Low | A04 - Insecure Design | Open |
| 11 | High Function Coupling in upload route | `main.py` lines 58–59 | 🟡 Low | Code Quality | Open |

---

## Detailed Findings

---

### FINDING 1 — Log Injection (CWE-117, CWE-93)
**Severity**: 🔴 High  
**OWASP**: A09:2021 — Security Logging and Monitoring Failures  
**Files**: `main.py` (lines 93, 98, 102, 112), `services/vector_store.py` (lines 61, 118)

#### What is it?
Log injection occurs when unsanitized user-controlled input is written directly into application logs. An attacker can craft input containing newline characters (`\n`) or ANSI escape codes to forge fake log entries, hide malicious activity, or break log parsers.

#### Where exactly in the code?

In `main.py`:
```python
# Line 93 — filename comes directly from the uploaded file, user-controlled
logger.info("Saved '%s' (%d bytes)", upload.filename, len(content))

# Line 98
logger.info("'%s' → %d chunks", upload.filename, len(chunks))

# Line 102
logger.info("Stored '%s' as doc_id=%s in session=%s", upload.filename, doc_id, sid)
```

In `services/vector_store.py`:
```python
# Line 61 — filename is user-supplied
logger.info("Upserted %d vectors for '%s' in session '%s'", len(chunks), filename, session_id)

# Line 118 — session_id comes from the HTTP request
logger.info("Deleted session '%s'", session_id)
```

#### Attack Scenario
An attacker uploads a file named:
```
malicious.pdf\n[CRITICAL] Admin login successful from 192.168.1.1
```
This injects a fake critical log entry, potentially bypassing security monitors or framing legitimate users.

#### Planned Fix
- Strip or replace `\n`, `\r`, and control characters from all user-supplied values before logging
- Create a `sanitize_for_log(value: str) -> str` utility function
- Apply it to all filenames, session IDs, and question strings before they reach any logger call

---

### FINDING 2 — NoSQL Injection (CWE-943)
**Severity**: 🔴 High  
**OWASP**: A03:2021 — Injection  
**File**: `main.py` (lines 145–146)

#### What is it?
NoSQL injection occurs when user-controlled input is passed directly into a database query without sanitization. Even though ChromaDB is a vector database, it uses collection names and query parameters that can be manipulated if not validated.

#### Where exactly in the code?

```python
# main.py line 145 — req.session_id comes directly from the HTTP request body
context_chunks = vector_store.search(req.session_id, req.question, k=req.top_k)
```

The `req.session_id` is a raw string from the user's JSON body. It is passed directly into ChromaDB's `get_collection(session_id)` and `query()` calls with no validation of format or content.

#### Attack Scenario
A malicious user sends a crafted `session_id` like `../../etc` or a specially formed string targeting ChromaDB's internal SQLite layer (`chroma.sqlite3`), potentially accessing or corrupting another user's session data.

#### Planned Fix
- Validate `session_id` against a strict UUID format using regex before any DB operation
- Reject any session ID that doesn't match `^[a-f0-9-]{36}$`
- Apply the same validation to the `session_id` in the `/upload` endpoint

---

### FINDING 3 — No Authentication on Any Endpoint
**Severity**: 🔴 High  
**OWASP**: A01:2021 — Broken Access Control  
**File**: `main.py`

#### What is it?
Every single API endpoint in IntelliDocs is completely open — no API key, no token, no session validation. Anyone who knows the URL can upload documents, query any session, list all sessions, or delete any session.

#### Where exactly in the code?

```python
# All routes are fully public — no auth dependency anywhere
@app.post("/upload", response_model=UploadResponse)
async def upload_pdfs(...):

@app.post("/query", response_model=QueryResponse)
async def query(req: QueryRequest):

@app.get("/sessions")
async def list_sessions():

@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
```

#### Attack Scenario
- Anyone can call `GET /sessions` to enumerate all active session IDs
- Anyone can call `DELETE /session/{id}` to wipe another user's uploaded documents
- Anyone can spam `POST /upload` with large PDFs, exhausting memory and storage (DoS)
- Anyone can call `POST /query` against any session they enumerate

#### Planned Fix
- Add API key authentication via FastAPI's `HTTPBearer` or `APIKeyHeader` dependency
- Inject an `Authorization` header check on all sensitive routes
- Scope sessions to authenticated users so cross-session access is impossible

---

### FINDING 4 — Wildcard CORS Policy
**Severity**: 🟠 Medium  
**OWASP**: A05:2021 — Security Misconfiguration  
**File**: `main.py` (line 31)

#### What is it?
CORS (Cross-Origin Resource Sharing) controls which domains can make browser-based requests to your API. Setting `allow_origins=["*"]` means any website on the internet can make requests to IntelliDocs from a user's browser.

#### Where exactly in the code?

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # ← any origin allowed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Note: `allow_origins=["*"]` combined with `allow_credentials=True` is actually invalid per the CORS spec and will be rejected by browsers — but it still represents a misconfiguration.

#### Attack Scenario
A malicious website can embed JavaScript that silently calls IntelliDocs endpoints using a logged-in user's browser session, exfiltrating their uploaded document data (CSRF-style attack).

#### Planned Fix
- Replace `["*"]` with an explicit list of allowed origins (e.g., the HF Space URL)
- Remove `allow_credentials=True` unless cookies/sessions are actually being used

---

### FINDING 5 — No Rate Limiting
**Severity**: 🟠 Medium  
**OWASP**: A05:2021 — Security Misconfiguration  
**File**: `main.py`

#### What is it?
There is no rate limiting on any endpoint. The `/upload` and `/query` endpoints are the most dangerous — `/upload` triggers PDF processing, embedding generation, and ChromaDB writes; `/query` calls the Groq API which has its own rate limits and costs.

#### Attack Scenario
- An attacker floods `/query` with thousands of requests, exhausting the Groq API free tier quota instantly
- An attacker floods `/upload` with large PDFs, consuming all available memory in the Docker container and crashing the Space
- Groq API key gets rate-limited or banned due to abuse

#### Planned Fix
- Add `slowapi` (FastAPI rate limiting library) with limits like `5/minute` on `/upload` and `30/minute` on `/query`
- Add request size validation beyond just the 50MB file check

---

### FINDING 6 — Full Exception Details Exposed to Client
**Severity**: 🟠 Medium  
**OWASP**: A05:2021 — Security Misconfiguration  
**File**: `main.py` (line 167)

#### What is it?
When an unhandled exception occurs during a query, the full Python exception message — including internal stack details — is returned directly to the client in the HTTP response.

#### Where exactly in the code?

```python
# main.py line 167
except Exception as exc:
    logger.exception("Query failed")
    raise HTTPException(status_code=500, detail=f"Query error: {exc}")
    #                                                          ^^^^
    # Raw exception string sent to the user
```

#### Attack Scenario
If ChromaDB throws an error containing a file path like `/app/chroma_db/...` or the Groq client throws an error containing part of the API key or internal config, that information is sent directly to the attacker in the 500 response body.

#### Planned Fix
- Return a generic message to the client: `"An internal error occurred. Please try again."`
- Keep the full exception in server-side logs only (`logger.exception` already does this correctly)

---

### FINDING 7 — Unrestricted File Upload (Content Validation)
**Severity**: 🟠 Medium  
**OWASP**: A04:2021 — Insecure Design  
**File**: `main.py` (lines 71–81)

#### What is it?
The upload endpoint only checks the file extension (`.pdf`) and file size. It does not validate that the file is actually a PDF by inspecting its magic bytes (file signature). An attacker can rename any file to `.pdf` and upload it.

#### Where exactly in the code?

```python
# Only checks the extension string — trivially bypassed
if not f.filename.lower().endswith(".pdf"):
    raise HTTPException(...)
```

#### Attack Scenario
- An attacker uploads a malicious file renamed to `exploit.pdf`
- `pdfplumber` or `pypdf` attempts to parse it, potentially triggering a library vulnerability
- A zip bomb renamed to `.pdf` could exhaust memory during extraction

#### Planned Fix
- Read the first 4 bytes of the file and check for the PDF magic bytes: `%PDF` (`25 50 44 46`)
- Reject files that don't match regardless of extension
- Set a maximum chunk count limit to prevent zip-bomb-style DoS

---

### FINDING 8 — API Key Loaded Without Validation
**Severity**: 🟠 Medium  
**OWASP**: A02:2021 — Cryptographic Failures  
**File**: `services/llm_service.py` (line 15)

#### What is it?
The Groq API key is loaded from the environment at startup with no check that it actually exists. If `GROQ_API_KEY` is not set, `os.getenv()` returns `None`, and the Groq client is initialized with `api_key=None`. The app starts successfully but fails silently on the first query with a cryptic 401 error.

#### Where exactly in the code?

```python
def __init__(self):
    self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))  # None if not set
```

#### Attack Scenario
- App deploys with a missing secret — users get confusing 500 errors with no clear cause
- In a misconfigured environment, `None` could be passed to an API client that falls back to an insecure default

#### Planned Fix
- Add a startup check: if `GROQ_API_KEY` is `None` or empty, raise a `RuntimeError` immediately at boot with a clear message
- Use FastAPI's `lifespan` event to validate all required environment variables before accepting traffic

---

### FINDING 9 — Naive Datetime Usage
**Severity**: 🟡 Low  
**OWASP**: A04:2021 — Insecure Design  
**File**: `services/vector_store.py` (line 56)

#### What is it?
`datetime.utcnow()` returns a naive datetime object with no timezone info. This is deprecated in Python 3.12+ and can cause incorrect time comparisons, audit log inconsistencies, and subtle bugs in session expiry logic if added later.

#### Where exactly in the code?

```python
# line 56
"created_at": datetime.utcnow().isoformat()
```

#### Planned Fix
```python
from datetime import datetime, timezone
"created_at": datetime.now(timezone.utc).isoformat()
```

---

### FINDING 10 — High Function Coupling in Upload Route
**Severity**: 🟡 Low  
**OWASP**: Code Quality / Maintainability  
**File**: `main.py` (lines 58–130)

#### What is it?
The `upload_pdfs` route function calls 17 different functions internally. This makes it hard to test, hard to maintain, and means a change in any one of those functions can unexpectedly break the upload flow.

#### Planned Fix
- Extract file validation into a `validate_upload_file(file)` helper
- Extract the per-file processing pipeline into a `process_single_file(upload, sid)` helper
- The route handler should only orchestrate, not implement

---

## OWASP Top 10 — Coverage Map

| OWASP 2021 | Category | Affected in IntelliDocs? |
|------------|----------|--------------------------|
| A01 | Broken Access Control | ✅ Yes — No auth on any endpoint |
| A02 | Cryptographic Failures | ✅ Yes — API key not validated at startup |
| A03 | Injection | ✅ Yes — NoSQL injection via session_id |
| A04 | Insecure Design | ✅ Yes — Unrestricted file upload, naive datetime |
| A05 | Security Misconfiguration | ✅ Yes — Wildcard CORS, no rate limiting, exception leakage |
| A06 | Vulnerable & Outdated Components | ⚠️ Not scanned — dependency audit needed |
| A07 | Identification & Authentication Failures | ✅ Yes — No authentication exists |
| A08 | Software & Data Integrity Failures | ⚠️ Partial — No webhook/input signing |
| A09 | Security Logging & Monitoring Failures | ✅ Yes — Log injection in multiple files |
| A10 | Server-Side Request Forgery (SSRF) | ✅ Yes — Groq/HF API calls use user-influenced content |

---

## Planned Security Roadmap

### Phase 1 — Critical (Do First)
- [ ] Add API key authentication to all endpoints
- [ ] Sanitize all user inputs before logging
- [ ] Validate session_id format (UUID only) before DB operations
- [ ] Return generic error messages to clients, keep details server-side only

### Phase 2 — Important
- [ ] Add rate limiting with `slowapi`
- [ ] Validate PDF magic bytes on upload
- [ ] Restrict CORS to known origins
- [ ] Validate `GROQ_API_KEY` exists at startup

### Phase 3 — Hardening
- [ ] Replace `datetime.utcnow()` with timezone-aware equivalent
- [ ] Refactor upload route to reduce function coupling
- [ ] Run `pip-audit` to check for vulnerable dependencies
- [ ] Add security headers (X-Content-Type-Options, X-Frame-Options, CSP)

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Amazon Q Developer (Code Review) | SAST scanning — detected CWE-117, CWE-93, CWE-943 |
| Manual Code Analysis | Architecture review, auth gaps, CORS, rate limiting |
| OWASP Top 10 (2021) | Vulnerability classification framework |

---

## Document Info

- **Version**: 1.0 — Initial real findings
- **Scan Date**: 2025
- **Author**: mzurain
- **Status**: Vulnerabilities open — fixes planned in collaboration with Amazon Q Developer
- **Next Step**: Implement Phase 1 fixes and re-scan to verify remediation
