# 🔐 Pentest Agent System

An agentic AI penetration testing system built with LangGraph, OWASP ZAP, and RAG memory.

**⚠️ AUTHORIZED TESTING ONLY** — Designed for use against DVWA and OWASP Juice Shop running locally.

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │      LangGraph State Machine      │
                    │                                   │
                    │  START                            │
                    │    │                              │
                    │    ▼                              │
                    │  [recon_node]                     │
                    │    │ ReconAgent                   │
                    │    │ - HTTP probing               │
                    │    │ - Path discovery             │
                    │    │ - Tech fingerprinting        │
                    │    ▼                              │
                    │  [post_recon]  ← OrchestratorLLM │
                    │    │ Decides: auth or skip        │
                    │    ▼                              │
                    │  [auth_node]  (conditional)       │
                    │    │ AuthAgent                    │
                    │    │ - Login with test creds      │
                    │    │ - Access control tests       │
                    │    │ - Session analysis           │
                    │    ▼                              │
                    │  [scanner_node]                   │
                    │    │ ScannerAgent                 │
                    │    │ - ZAP spider                 │
                    │    │ - ZAP passive scan           │
                    │    │ - ZAP ACTIVE scan ⚡          │
                    │    ▼                              │
                    │  [post_scan]   ← OrchestratorLLM │
                    │    ▼                              │
                    │  [analyzer_node]                  │
                    │    │ AnalyzerAgent                │
                    │    │ - RAG knowledge retrieval    │
                    │    │ - LLM risk analysis          │
                    │    │ - OWASP mapping              │
                    │    │ - False positive removal     │
                    │    ▼                              │
                    │  [reporter_node]                  │
                    │    │ ReporterAgent                │
                    │    │ - Executive summary          │
                    │    │ - Technical findings         │
                    │    │ - Remediation steps          │
                    │    ▼                              │
                    │   END                             │
                    └─────────────────────────────────┘

Safety Layer (wraps every network call):
  ┌─ ScopeValidator  — deterministic allowlist check
  ├─ RateLimiter     — token bucket per host
  └─ AuditLogger     — immutable JSONL audit trail

AI Layer:
  ┌─ LangGraph       — orchestration graph
  ├─ GPT-4o          — reasoning and report generation
  ├─ RAG / ChromaDB  — security knowledge retrieval
  └─ text-embedding-3-small — vector embeddings
```

---

## Prerequisites

### 1. Python 3.11+
```bash
python --version  # must be 3.11+
```

### 2. OWASP ZAP
Download from https://www.zaproxy.org/download/

Start ZAP in daemon mode:
```bash
# macOS/Linux
./zap.sh -daemon -config api.key=changeme -port 8080 -host 127.0.0.1

# Windows
zap.bat -daemon -config api.key=changeme -port 8080 -host 127.0.0.1
```

### 3. DVWA (Damn Vulnerable Web Application)
```bash
# Easiest: Docker
docker run --rm -it -p 8888:80 vulnerables/web-dvwa

# After starting, go to http://localhost:8888/setup.php
# Click "Create / Reset Database"
# Login: admin / password
# Set Security Level to "Low" for maximum vulnerability exposure
```

### 4. OWASP Juice Shop (optional)
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
# Login: admin@juice-sh.op / admin123
```

---

## Setup

```bash
# Clone / create the project directory
cd pentest_agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — add your OpenAI API key and ZAP API key
```

### .env minimum required:
```env
OPENAI_API_KEY=sk-...
ZAP_API_KEY=changeme   # must match what you used when starting ZAP
```

---

## Usage

### Test DVWA
```bash
# Full active scan (recommended for learning)
python main.py --target http://localhost:8888 --app dvwa

# Passive only (safer, fewer findings)
python main.py --target http://localhost:8888 --app dvwa --mode passive

# No authentication (public surface only)
python main.py --target http://localhost:8888 --app dvwa --no-auth
```

### Test Juice Shop
```bash
python main.py --target http://localhost:3000 --app juiceshop
```

### Custom rate limit (slower = gentler on target)
```bash
python main.py --target http://localhost:8888 --app dvwa --rate-limit 2
```

---

## Output

```
output/
├── reports/
│   └── report_eng_20241201_143022.md    ← Full pentest report (Markdown)
├── logs/
│   └── audit_eng_20241201_143022.jsonl  ← Immutable audit trail
└── chroma_db/                           ← RAG vector store
    ├── knowledge/                        ← OWASP knowledge base
    └── findings/                         ← Engagement findings memory
```

---

## What the Active Scan Tests

ZAP active scan covers:

| Test Category | Examples |
|---|---|
| SQL Injection | `' OR '1'='1` in all input fields |
| XSS Reflected | `<script>alert(1)</script>` variants |
| XSS Stored | Persistent payload injection |
| Path Traversal | `../../../../etc/passwd` |
| Command Injection | `; ls -la ;` in inputs |
| CSRF | Missing/weak CSRF token detection |
| Auth Bypass | Direct object access without session |
| Security Headers | Missing HSTS, CSP, X-Frame-Options |
| Sensitive Disclosure | Stack traces, debug info, version headers |

Authentication testing covers:

| Test | What it checks |
|---|---|
| Unauthenticated access | Can you reach /admin without login? |
| Cross-user access | Can user A reach user B's resources? |
| Session cookie security | Secure flag, HttpOnly flag, SameSite |
| Token validity | JWT misconfiguration, weak secrets |

---

## OWASP Top 10 Coverage

| Category | Covered |
|---|---|
| A01: Broken Access Control | ✅ Auth agent + ZAP |
| A02: Cryptographic Failures | ✅ ZAP passive + headers |
| A03: Injection (SQL, XSS, Cmd) | ✅ ZAP active scan |
| A04: Insecure Design | ✅ LLM analysis |
| A05: Security Misconfiguration | ✅ ZAP passive + headers |
| A06: Vulnerable Components | ⚠️ Nuclei (add-on) |
| A07: Auth Failures | ✅ Auth agent |
| A08: Data Integrity | ⚠️ Partial — ZAP |
| A09: Logging Failures | ℹ️ Informational |
| A10: SSRF | ⚠️ Nuclei (add-on) |

---

## Adding Nuclei (Optional)

Install Nuclei binary: https://github.com/projectdiscovery/nuclei/releases

Then add to `agents/agents.py` ScannerAgent:
```python
# After ZAP scan:
nuclei_findings = self.run_nuclei(target)
state.raw_findings.extend(nuclei_findings)
```

---

## Extending the System

### Add a new agent
1. Create class in `agents/agents.py` extending `BaseAgent`
2. Add node function in `graphs/pentest_graph.py`
3. Connect with `graph.add_edge()`

### Add new RAG knowledge
Add entries to `OWASP_KNOWLEDGE` list in `memory/rag_memory.py`

### Add a new tool
1. Create wrapper in `tools/`
2. Always use `gate.check_and_acquire()` before any request
3. Return `list[RawFinding]`

---

## Safety Architecture

Every network request goes through this chain — no exceptions:

```
Agent wants to make request to URL
    │
    ▼
ScopeValidator.assert_allowed(url)
    ├─ URL in allowlist? → continue
    └─ URL NOT in allowlist? → ScopeViolationError (logged, request blocked)
    │
    ▼
RateLimiter.acquire(url)
    └─ Waits if rate exceeded (token bucket)
    │
    ▼
AuditLogger.log_tool_call(...)
    └─ Immutable JSONL entry written
    │
    ▼
Tool executes request
```

This is **deterministic** — no LLM involved in safety decisions.

---

## Legal Notice

This tool is for **authorized security testing only**.

- Only use against systems you own or have explicit written authorization to test
- Running this against unauthorized systems is illegal in most jurisdictions
- The default configuration only allows localhost targets for this reason
- Always review local laws before conducting security testing
