"""
memory/rag_memory.py
─────────────────────
RAG (Retrieval-Augmented Generation) memory system.

WHY RAG in a pentest agent?
  The LLM (GPT-4o) knows a lot about security — but its knowledge
  has a cutoff date and it can't know YOUR target's specific context.

  RAG lets us inject:
    1. CVE knowledge base — known vulnerabilities for detected tech
    2. OWASP remediation guides — exact fix recommendations per finding
    3. Previous engagement findings — learn from past tests
    4. Custom org knowledge — specific security policies

HOW IT WORKS:
  1. At startup, we load security documents into a vector database (ChromaDB)
  2. When AnalyzerAgent sees a finding, it queries: "what do I know about XSS?"
  3. ChromaDB returns the most relevant chunks
  4. We inject those chunks into the LLM prompt as context
  5. LLM now gives a much more accurate, specific, actionable response

ANALOGY:
  Without RAG: LLM is a smart analyst working from memory alone
  With RAG:    LLM is that same analyst with a full security library on their desk
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
# Import from .character to avoid pulling in .html (nltk/scipy) which can cause MemoryError
from langchain_text_splitters.character import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

from safety_layer import AuditLogger
from rich.console import Console

console = Console()


# ─── Built-in Security Knowledge ──────────────────────────────────────────────
# This is seeded at startup. In production, you'd load real CVE feeds,
# OWASP guides, NIST entries, etc.

OWASP_KNOWLEDGE = [
    {
        "id":    "A01_broken_access_control",
        "title": "A01:2025 - Broken Access Control",
        "content": """
Broken Access Control is the #1 OWASP risk. It occurs when users can act outside
their intended permissions — accessing other users' data, admin functions, or
resources they shouldn't reach.

Common vulnerabilities:
- IDOR (Insecure Direct Object Reference): Changing /api/users/123 to /api/users/124
  to access another user's data
- Forced browsing: Accessing /admin directly without being an admin
- Missing function-level access control: API endpoints that don't verify role
- CORS misconfiguration: Allowing untrusted origins to make authenticated requests
- JWT token manipulation: Changing role claim from 'user' to 'admin'

How to detect:
- Try accessing resources belonging to other users
- Modify object identifiers in API requests (user IDs, document IDs)
- Access authenticated endpoints without a valid session
- Try accessing /admin, /dashboard, /api/admin as a regular user

Remediation:
- Deny by default — every access should require explicit permission grant
- Implement proper server-side authorization checks (don't trust client-side)
- Use indirect object references (random UUIDs, not sequential IDs)
- Log access control failures and alert on repeated failures
- Apply rate limiting on failed access attempts

CVSS Base Score: Often High (7.0+) to Critical (9.0+) depending on data sensitivity.
""",
        "owasp_id": "A01",
        "severity": "High"
    },
    {
        "id":    "A02_crypto_failures",
        "title": "A04:2025 - Cryptographic Failures",
        "content": """
Cryptographic Failures (formerly 'Sensitive Data Exposure') covers weaknesses
in how applications protect data in transit and at rest.

Common vulnerabilities:
- HTTP instead of HTTPS for sensitive data transmission
- Weak TLS versions (TLS 1.0, TLS 1.1, SSL 3.0)
- Weak cipher suites (RC4, DES, 3DES)
- Hardcoded cryptographic keys or secrets in code
- Storing passwords in plaintext or with weak hashing (MD5, SHA-1 without salt)
- Unencrypted sensitive data in cookies, localStorage, or URL parameters
- Missing or incorrect HTTP security headers (HSTS, X-Content-Type-Options)

How to detect:
- Check if HTTP (not HTTPS) is used for login, payment, profile pages
- Inspect response headers for security headers
- Check if cookies have Secure and HttpOnly flags
- Look for sensitive data (passwords, tokens, PII) in URLs or logs
- Check TLS configuration with tools like testssl.sh

Remediation:
- Enforce HTTPS everywhere (HSTS with long max-age)
- Use TLS 1.2+ with strong cipher suites only
- Use bcrypt, scrypt, or Argon2 for password hashing (never MD5/SHA-1)
- Mark session cookies as Secure and HttpOnly
- Implement proper key management (rotate keys, never hardcode)
- Encrypt sensitive data at rest (AES-256-GCM)

CVSS Score: Medium (4.0) to High (7.0+) depending on data sensitivity.
""",
        "owasp_id": "A04",
        "severity": "High"
    },
    {
        "id":    "A05_injection",
        "title": "A05:2025 - Injection (SQL, XSS, Command)",
        "content": """
Injection flaws occur when untrusted data is sent to an interpreter as part of
a command or query. The attacker's hostile data can trick the interpreter into
executing unintended commands or accessing unauthorized data.

SQL Injection:
- Attacker inserts SQL code into input fields
- Example: username = ' OR '1'='1' -- 
- Impact: Authentication bypass, data extraction, data deletion, RCE in some cases
- Detection: ZAP active scan, sqlmap (in authorized tests), error messages revealing SQL

XSS (Cross-Site Scripting):
- Attacker injects malicious scripts into web pages viewed by other users
- Reflected XSS: payload in URL/request, reflected in response
- Stored XSS: payload saved to database, served to all users
- DOM XSS: payload executed via client-side JavaScript
- Impact: Session hijacking, credential theft, malware distribution
- Detection: ZAP active scan, manual testing with <script>alert(1)</script>

Command Injection:
- Attacker executes OS commands through vulnerable application
- Example: ping 8.8.8.8; cat /etc/passwd
- Impact: Full server compromise, data theft, lateral movement

Remediation:
- Use parameterized queries/prepared statements (NEVER string concatenation for SQL)
- Validate and sanitize ALL user input on the server side
- Use Content Security Policy (CSP) headers to mitigate XSS
- Apply principle of least privilege for database accounts
- Use ORM frameworks that handle escaping automatically
- Output encode all user-controlled data before rendering in HTML

CVSS Score: Critical (9.0+) for SQL injection, High (7.0+) for XSS.
""",
        "owasp_id": "A05",
        "severity": "Critical"
    },
    {
        "id":    "A06_insecure_design",
        "title": "A06:2025 - Insecure Design",
        "content": """
Insecure Design refers to missing or ineffective security controls in the
architecture and design phase — problems that can't be fixed by good implementation
because the design itself is fundamentally flawed.

Examples:
- No rate limiting on authentication = credential stuffing attacks possible
- Password reset via security questions = easily guessable/researchable answers
- Credential recovery via email only = account takeover if email is compromised
- Multi-tenant app stores all data in same database partition
- Missing server-side validation (relying on client-side only)
- Business logic flaws: negative quantity in shopping cart = negative charge
- Race conditions: two simultaneous requests both succeed when only one should

How to detect:
- Review authentication flows for missing rate limiting
- Test password reset/recovery flows
- Look for business logic that can be abused (negative values, skipped steps)
- Check if sensitive operations can be performed out of sequence
- Test concurrent requests for race conditions

Remediation:
- Apply threat modeling during design (not after implementation)
- Implement rate limiting and account lockout on all sensitive operations
- Use secure design patterns (defense in depth, fail secure, least privilege)
- Never rely solely on client-side validation
- Implement proper multi-tenancy data isolation

CVSS Score: Varies widely — can be Critical (10.0) for fundamental design flaws.
""",
        "owasp_id": "A06",
        "severity": "High"
    },
    {
        "id":    "A02_security_misconfig",
        "title": "A02:2025 - Security Misconfiguration",
        "content": """
Security Misconfiguration is one of the most common OWASP risks. It occurs when
security settings are not defined, implemented, or maintained properly.

Common vulnerabilities:
- Default credentials left unchanged on admin panels, databases, or services
- Unnecessary features enabled (directory listing, debug mode, sample apps)
- Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options)
- Overly permissive CORS configuration (Access-Control-Allow-Origin: *)
- Verbose error messages exposing stack traces, SQL queries, or server info
- Unnecessary HTTP methods enabled (PUT, DELETE, TRACE)
- Cloud storage buckets with public read/write access

How to detect:
- Check HTTP response headers for missing security headers
- Test for directory listing on common paths (/images/, /uploads/, /static/)
- Check CORS headers with cross-origin requests
- Look for verbose error messages by triggering errors intentionally
- Check for default admin accounts and pages

Remediation:
- Implement a repeatable hardening process for all environments
- Remove or disable unused features, frameworks, and services
- Review and update security configurations regularly
- Set restrictive CORS policies (never use wildcard in production)
- Implement proper error handling that doesn't expose internals
- Add all recommended security headers (HSTS, CSP, X-Frame-Options)

CVSS Score: Medium (4.0) to High (7.0) depending on misconfiguration impact.
""",
        "owasp_id": "A02",
        "severity": "Medium"
    },
    {
        "id":    "A03_supply_chain",
        "title": "A03:2025 - Software Supply Chain Failures",
        "content": """
Software Supply Chain Failures cover risks from third-party components, libraries,
and dependencies that are vulnerable, outdated, or compromised.

Common vulnerabilities:
- Using libraries with known CVEs (e.g., Log4Shell in Log4j, Spring4Shell)
- Not tracking dependency versions or failing to update regularly
- Pulling packages from untrusted registries without integrity verification
- Typosquatting attacks (installing malicious package with similar name)
- Compromised build pipelines injecting malicious code during CI/CD
- Including unnecessary dependencies that expand the attack surface

How to detect:
- Run dependency audit tools (npm audit, pip-audit, OWASP Dependency-Check)
- Check library versions against known CVE databases
- Scan for outdated packages in requirements.txt, package.json, pom.xml
- Review lock files for unexpected version changes

Remediation:
- Maintain a software bill of materials (SBOM) for all projects
- Use automated dependency scanning in CI/CD pipelines
- Pin dependency versions and verify package integrity (checksums, signatures)
- Subscribe to security advisories for all direct dependencies
- Remove unused dependencies to reduce attack surface
- Use only trusted package registries with reputation verification

CVSS Score: Varies — can be Critical (10.0) for vulnerabilities like Log4Shell.
""",
        "owasp_id": "A03",
        "severity": "High"
    },
    {
        "id":    "A07_auth_failures",
        "title": "A07:2025 - Authentication Failures",
        "content": """
Authentication Failures cover weaknesses in identity verification, session
management, and credential handling.

Common vulnerabilities:
- Weak password policies (no minimum length, no complexity, no common-password check)
- Missing brute-force protection (no rate limiting, no account lockout)
- Credential stuffing susceptibility (no multi-factor authentication)
- Session fixation (session ID not rotated after login)
- Session tokens in URLs (visible in logs, referer headers, browser history)
- Missing session expiration or overly long session lifetimes
- Insecure "Remember Me" functionality
- Password reset flaws (predictable tokens, no expiration, email-only verification)

How to detect:
- Test login with common passwords (admin/admin, test/test)
- Attempt brute force and check for rate limiting or lockout
- Check session cookie flags (Secure, HttpOnly, SameSite)
- Verify session rotation after authentication
- Test password reset flow for token predictability
- Check if MFA is available and enforced

Remediation:
- Implement multi-factor authentication (TOTP, WebAuthn, SMS as last resort)
- Enforce strong password policies with breach-database checks
- Implement account lockout after 5-10 failed attempts with exponential backoff
- Rotate session IDs after successful authentication
- Set session timeouts (idle: 15 min, absolute: 8 hours)
- Use Secure, HttpOnly, SameSite=Strict cookie attributes

CVSS Score: High (7.0+) to Critical (9.0+) depending on authentication bypass impact.
""",
        "owasp_id": "A07",
        "severity": "High"
    },
    {
        "id":    "A08_data_integrity",
        "title": "A08:2025 - Software or Data Integrity Failures",
        "content": """
Software or Data Integrity Failures cover assumptions about software updates,
critical data, and CI/CD pipelines without verifying integrity.

Common vulnerabilities:
- Insecure deserialization (accepting untrusted serialized objects)
- Auto-update mechanisms without signature verification
- CI/CD pipeline manipulation (injecting malicious build steps)
- Unsigned or unverified firmware/software updates
- Trusting data from CDNs or third-party sources without SRI (Subresource Integrity)
- Mass assignment vulnerabilities (accepting unexpected fields in API requests)

How to detect:
- Check if application uses serialization/deserialization of user-controlled data
- Review update mechanisms for signature verification
- Test API endpoints for mass assignment (send extra fields)
- Check JavaScript includes for SRI attributes
- Review CI/CD pipeline permissions and audit logs

Remediation:
- Never deserialize untrusted data; use safe serialization formats (JSON over Java serialization)
- Implement digital signatures for all software updates and packages
- Use Subresource Integrity (SRI) for all external JavaScript/CSS includes
- Protect CI/CD pipelines with code review, signed commits, and least-privilege access
- Validate all input against a whitelist of expected fields (prevent mass assignment)

CVSS Score: High (7.0+) for deserialization attacks, Critical (9.0+) for pipeline compromise.
""",
        "owasp_id": "A08",
        "severity": "High"
    },
    {
        "id":    "A09_logging_failures",
        "title": "A09:2025 - Security Logging and Alerting Failures",
        "content": """
Security Logging and Alerting Failures occur when breaches or attacks go undetected
due to insufficient logging, monitoring, or incident response capabilities.

Common vulnerabilities:
- Login failures, access control failures, or input validation failures not logged
- Logs not monitored for suspicious patterns or anomalies
- Logs stored only locally and easily deleted by attacker after compromise
- No alerting mechanism for critical security events
- Sensitive data (passwords, tokens, PII) logged in plaintext
- Log injection vulnerabilities (attacker can write false log entries)
- Insufficient log retention (logs deleted before forensic analysis can occur)

How to detect:
- Review logging configuration for security-critical events
- Check if failed login attempts are logged
- Verify log integrity protection (append-only, centralized storage)
- Test if security events trigger alerts
- Check for sensitive data in log files

Remediation:
- Log all authentication events (success, failure, lockout)
- Log all access control decisions (especially denials)
- Use structured logging (JSON) with consistent timestamps
- Send logs to centralized, tamper-resistant storage (SIEM)
- Implement real-time alerting for critical events (mass login failures, privilege escalation)
- Protect logs from injection by sanitizing logged data
- Never log passwords, tokens, or full credit card numbers

CVSS Score: Usually Info/Low as standalone issue, but enables Critical impact when attacks go undetected.
""",
        "owasp_id": "A09",
        "severity": "Medium"
    },
    {
        "id":    "A10_exceptional_conditions",
        "title": "A10:2025 - Mishandling of Exceptional Conditions",
        "content": """
Mishandling of Exceptional Conditions covers failures in how applications handle
errors, edge cases, and unexpected inputs.

Common vulnerabilities:
- Unhandled exceptions revealing stack traces with internal paths, database schemas, or code
- Generic error handling that masks the real issue from developers but confuses users
- Error messages that differ between "user not found" and "wrong password" (user enumeration)
- Application crashes on unexpected input (null bytes, oversized payloads, special characters)
- Race conditions in error-handling paths leading to inconsistent state
- Missing input validation leading to unhandled type errors or buffer overflows

How to detect:
- Submit malformed input (empty fields, null bytes, extremely long strings)
- Trigger errors and check if stack traces are visible in responses
- Compare error messages for existing vs non-existing users (enumeration)
- Send unexpected HTTP methods (PATCH, DELETE) to standard endpoints
- Test with special characters in all input fields

Remediation:
- Implement consistent error handling across the entire application
- Return generic error messages to users; log detailed errors server-side
- Use the same error message for "user not found" and "wrong password"
- Validate all input with strict type and length constraints
- Implement global exception handlers that prevent stack trace leakage
- Test error handling paths with fuzzing and edge-case inputs

CVSS Score: Low (2.0) to Medium (5.0) for information disclosure; higher if it enables further attacks.
""",
        "owasp_id": "A10",
        "severity": "Medium"
    },
    {
        "id":    "A05_xss_detection",
        "title": "A05:2025 - XSS Detection and Exploitation Patterns",
        "content": """
XSS (Cross-Site Scripting) Detection Patterns for Pentest Agents:

Reflected XSS Test Payloads (safe, non-destructive probes):
- <script>alert('XSS')</script>
- <img src=x onerror=alert('XSS')>
- <svg onload=alert('XSS')>
- javascript:alert('XSS')
- "><script>alert('XSS')</script>
- '><img src=x onerror=alert('XSS')>

How ZAP detects XSS:
1. Spider finds all forms and input fields
2. Active scan injects XSS payloads into each field
3. Checks if payload appears in response (reflected)
4. Checks if payload persists when page is revisited (stored)
5. Flags as finding if payload appears unescaped

Signs of XSS vulnerability in response:
- Injected script appears verbatim in HTML response body
- No output encoding applied (< not converted to &lt;)
- Response Content-Type is text/html (vs application/json)
- No Content-Security-Policy header present

False positive indicators:
- WAF (Web Application Firewall) strips payload
- Input is HTML-encoded in response
- Content-Type is JSON (XSS doesn't execute in JSON)
""",
        "owasp_id": "A05",
        "severity": "High"
    }
]


class RAGMemory:
    """
    Vector-based memory for the pentest agent system.

    Two collections:
      1. 'security_knowledge' — OWASP guides, CVE info, remediation steps
      2. 'engagement_findings' — findings from the current engagement

    Agents query this to get contextually relevant security knowledge
    before making analysis decisions.
    """

    def __init__(self, persist_dir: str = "./output/chroma_db"):
        self.persist_dir = persist_dir
        Path(persist_dir).mkdir(parents=True, exist_ok=True)

        self.embeddings = OpenAIEmbeddings(
            model="text-embedding-3-small",
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )

        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=100
        )

        self._knowledge_store: Optional[Chroma] = None
        self._findings_store: Optional[Chroma] = None

    def initialize(self) -> None:
        """
        Load security knowledge into vector store.
        Call once at agent system startup.
        """
        console.print("[cyan]🧠 Initializing RAG memory...[/cyan]")

        # Build documents from our built-in knowledge
        docs = []
        for item in OWASP_KNOWLEDGE:
            doc = Document(
                page_content=item["content"],
                metadata={
                    "id":       item["id"],
                    "title":    item["title"],
                    "owasp_id": item["owasp_id"],
                    "severity": item["severity"]
                }
            )
            docs.append(doc)

        splits = self.splitter.split_documents(docs)

        self._knowledge_store = Chroma.from_documents(
            documents=splits,
            embedding=self.embeddings,
            persist_directory=f"{self.persist_dir}/knowledge",
            collection_name="security_knowledge"
        )

        self._findings_store = Chroma(
            embedding_function=self.embeddings,
            persist_directory=f"{self.persist_dir}/findings",
            collection_name="engagement_findings"
        )

        console.print(f"[green]✓ RAG memory ready ({len(splits)} knowledge chunks)[/green]")
        AuditLogger.log("RAG_INITIALIZED", {"knowledge_chunks": len(splits)})

    def query_knowledge(self, query: str, k: int = 3) -> str:
        """
        Query the security knowledge base.

        Used by AnalyzerAgent:
          query = "SQL injection in login form"
          Returns: Relevant OWASP A03 content, detection patterns, remediation

        Returns formatted string ready to inject into LLM prompt.
        """
        if not self._knowledge_store:
            return ""

        docs = self._knowledge_store.similarity_search(query, k=k)

        context_parts = []
        for doc in docs:
            context_parts.append(
                f"[{doc.metadata.get('title', 'Security Reference')}]\n"
                f"{doc.page_content}"
            )

        return "\n\n---\n\n".join(context_parts)

    def store_finding(self, finding_text: str, metadata: dict) -> None:
        """
        Store a finding in the engagement memory.
        This lets the agent remember what it already found
        and avoid redundant analysis.
        """
        if not self._findings_store:
            return

        doc = Document(page_content=finding_text, metadata=metadata)
        self._findings_store.add_documents([doc])

    def query_similar_findings(self, finding_text: str, k: int = 3) -> list[str]:
        """Check if a similar finding was already reported (deduplication)."""
        if not self._findings_store:
            return []

        try:
            docs = self._findings_store.similarity_search(finding_text, k=k)
            return [doc.page_content for doc in docs]
        except Exception:
            return []
