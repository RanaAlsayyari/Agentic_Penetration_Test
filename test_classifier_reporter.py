"""
test_classifier_reporter.py
----------------------------
Standalone test: feed pre-built AnalyzedRisk objects into the Classifier
and Reporter agents to verify they complete without crashing.

Usage:
  python test_classifier_reporter.py

Requires:
  - OPENAI_API_KEY in .env
  - skills/classification/ files present
"""

import os
import sys
import json

# Fix Windows console encoding for Unicode/box-drawing characters
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dotenv import load_dotenv

load_dotenv()

from schemas import (
    AgentState, AgentPhase, EngagementConfig, ScanMode,
    TargetCredentials, AnalyzedRisk, Severity, RawFinding
)
from agents import ClassifierAgent, ReporterAgent
from rag_memory import RAGMemory
from safety_layer import ScopeValidator, RateLimiter, SafetyGate, AuditLogger
from rich.console import Console

console = Console()


def build_test_state() -> AgentState:
    """
    Reconstruct an AgentState with findings matching the real pipeline output.
    Includes both ZAP-sourced findings AND Auth Agent findings.
    """
    config = EngagementConfig(
        target_url="http://127.0.0.1:3000",
        allowed_targets=[
            "http://localhost:8888", "http://localhost:3000",
            "http://127.0.0.1:8888", "http://127.0.0.1:3000",
        ],
        mode=ScanMode.ACTIVE,
        rate_limit_rps=5,
        credentials=TargetCredentials(
            username="admin@juice-sh.op",
            password="admin123",
            login_url="http://127.0.0.1:3000/rest/user/login",
            auth_type="bearer",
        ),
        engagement_id="eng_test_classifier_reporter",
    )

    state = AgentState(config=config)
    state.current_phase = AgentPhase.ANALYSIS
    state.completed_phases = [
        AgentPhase.RECON, AgentPhase.AUTH_TEST,
        AgentPhase.ACTIVE_SCAN, AgentPhase.ANALYSIS,
    ]
    state.is_spa = True
    state.spa_framework = None
    state.spa_evidence = (
        "3/3 random paths returned identical 75054-byte response (HTTP 200). "
        "All routes serve the same shell."
    )

    # ── Findings from AnalyzerAgent (post-analysis, pre-classification) ──────
    # These simulate what the Analyzer would output.

    state.analyzed_risks = [
        # 1. SQL Injection — from ZAP active scan
        AnalyzedRisk(
            id="FINDING-001",
            title="SQL Injection on /rest/products/search?q=",
            affected_url="http://127.0.0.1:3000/rest/products/search?q=",
            affected_parameter="q",
            description=(
                "The product search endpoint is vulnerable to SQL injection. "
                "An attacker can inject SQL commands through the search parameter "
                "to extract database contents, modify data, or bypass access controls."
            ),
            technical_detail=(
                "ZAP active scan confirmed SQL injection on the 'q' parameter of "
                "/rest/products/search. The application appears to use a SQLite "
                "backend and the query parameter is concatenated directly into the "
                "SQL query without parameterization. Payload: q=test'))-- returned "
                "valid results instead of an error."
            ),
            evidence=(
                "ZAP injected payload: q=test'))-- and received HTTP 200 with valid "
                "product data. Error-based payloads also returned SQL error messages "
                "confirming SQLite backend."
            ),
            remediation_context=(
                "Use parameterized queries (prepared statements) in the Juice Shop "
                "search endpoint. Replace string concatenation with ORM query builders "
                "or parameterized SQL. Example: db.query('SELECT * FROM Products WHERE "
                "name LIKE ?', ['%' + searchTerm + '%'])"
            ),
            is_false_positive=False,
            severity_estimate=Severity.HIGH,
        ),

        # 2. Weak/Default Credentials — from Auth Agent
        AnalyzedRisk(
            id="FINDING-002",
            title="Weak/Default Credentials on Admin Login",
            affected_url="http://127.0.0.1:3000/rest/user/login",
            affected_parameter="email/password",
            description=(
                "The application's admin account uses weak, easily guessable "
                "credentials (admin@juice-sh.op / admin123). This allows an "
                "attacker to gain full administrative access."
            ),
            technical_detail=(
                "POST /rest/user/login with credentials admin@juice-sh.op:admin123 "
                "returned a valid JWT authentication token. The admin account has "
                "full administrative privileges including user management."
            ),
            evidence=(
                "POST http://127.0.0.1:3000/rest/user/login with credentials "
                "admin@juice-sh.op:admin123 returned valid session. User role: admin."
            ),
            remediation_context=(
                "1. Force password change on first login for all default accounts. "
                "2. Enforce strong password policy (min 12 chars, complexity). "
                "3. Implement account lockout after 5 failed attempts. "
                "4. Consider disabling default admin accounts entirely."
            ),
            is_false_positive=False,
            severity_estimate=Severity.HIGH,
        ),

        # 3. Cross-Domain Misconfiguration (CORS)
        AnalyzedRisk(
            id="FINDING-003",
            title="Cross-Domain Misconfiguration (CORS)",
            affected_url="http://127.0.0.1:3000/",
            affected_parameter=None,
            description=(
                "The application sets Access-Control-Allow-Origin to a wildcard or "
                "reflects the Origin header, allowing any domain to make "
                "authenticated cross-origin requests."
            ),
            technical_detail=(
                "The server responds with 'Access-Control-Allow-Origin: *' or "
                "reflects the requesting Origin header without validation. Combined "
                "with 'Access-Control-Allow-Credentials: true', this allows "
                "cross-site request forgery attacks from any domain."
            ),
            evidence=(
                "ZAP passive scan detected Access-Control-Allow-Origin header "
                "set to wildcard (*) on multiple endpoints."
            ),
            remediation_context=(
                "Configure CORS to only allow trusted origins. Replace wildcard "
                "with explicit domain whitelist. Never combine Allow-Credentials: "
                "true with Allow-Origin: *."
            ),
            is_false_positive=False,
            severity_estimate=Severity.MEDIUM,
        ),

        # 4. CSP Header Not Set
        AnalyzedRisk(
            id="FINDING-004",
            title="Content Security Policy (CSP) Header Not Set",
            affected_url="http://127.0.0.1:3000/",
            affected_parameter=None,
            description=(
                "The application does not set a Content-Security-Policy header, "
                "leaving it more vulnerable to cross-site scripting (XSS) attacks."
            ),
            technical_detail=(
                "No Content-Security-Policy or X-Content-Security-Policy header "
                "was found in any server response. CSP is a defense-in-depth "
                "mechanism that helps mitigate XSS by restricting script sources."
            ),
            evidence=(
                "ZAP passive scan: no CSP header detected on http://127.0.0.1:3000/"
            ),
            remediation_context=(
                "Add a Content-Security-Policy header. Start with a restrictive "
                "policy: default-src 'self'; script-src 'self'; style-src 'self' "
                "'unsafe-inline'; img-src 'self' data:; Then relax as needed."
            ),
            is_false_positive=False,
            severity_estimate=Severity.LOW,
        ),

        # 5. Application Error Disclosure
        AnalyzedRisk(
            id="FINDING-005",
            title="Application Error Disclosure",
            affected_url="http://127.0.0.1:3000/api",
            affected_parameter=None,
            description=(
                "The application reveals internal error details (stack traces, "
                "framework info) in HTTP responses, which helps attackers "
                "understand the server architecture."
            ),
            technical_detail=(
                "Requests to /api endpoints that cause errors return detailed "
                "Node.js/Express stack traces including file paths and line numbers."
            ),
            evidence=(
                "GET http://127.0.0.1:3000/api returned HTTP 500 with Express "
                "stack trace in response body."
            ),
            remediation_context=(
                "Configure Express error handler to return generic error messages "
                "in production. Set NODE_ENV=production and use a custom error "
                "middleware that logs details server-side but returns a safe message."
            ),
            is_false_positive=False,
            severity_estimate=Severity.LOW,
        ),

        # 6. Private IP Disclosure
        AnalyzedRisk(
            id="FINDING-006",
            title="Private IP Disclosure",
            affected_url="http://127.0.0.1:3000/profile",
            affected_parameter=None,
            description=(
                "The application leaks internal/private IP addresses in HTTP "
                "responses, which could help an attacker map the internal network."
            ),
            technical_detail=(
                "Private IP addresses (10.x.x.x, 172.16-31.x.x, or 192.168.x.x) "
                "were found in response headers or body content."
            ),
            evidence=(
                "ZAP passive scan found private IP addresses in response from "
                "/profile endpoint."
            ),
            remediation_context=(
                "Review response headers and body to remove private IP references. "
                "Configure reverse proxy to strip internal addressing from responses."
            ),
            is_false_positive=False,
            severity_estimate=Severity.LOW,
        ),
    ]

    return state


def main():
    print("\n===== TEST: CLASSIFIER + REPORTER AGENTS =====")

    # Initialize audit logging
    AuditLogger.initialize("eng_test_classifier_reporter")

    # Build safety layer (needed by agents but not used in this test)
    scope = ScopeValidator([
        "http://localhost:8888", "http://localhost:3000",
        "http://127.0.0.1:8888", "http://127.0.0.1:3000",
    ])
    limiter = RateLimiter(5)
    gate = SafetyGate(scope, limiter)

    # Initialize RAG memory
    rag = RAGMemory()
    rag.initialize()

    # Build test state with pre-analyzed findings
    state = build_test_state()
    console.print(f"[cyan]Test state built with {len(state.analyzed_risks)} analyzed risks:[/cyan]")
    for r in state.analyzed_risks:
        sev = r.severity_estimate.value if hasattr(r.severity_estimate, 'value') else str(r.severity_estimate)
        console.print(f"  {r.id}: {r.title} [{sev}]")

    # ── Run Classifier ────────────────────────────────────────────────────────
    console.print("\n[bold white on blue] PHASE: STANDARDS CLASSIFICATION [/bold white on blue]")
    classifier = ClassifierAgent(gate, rag)
    state = classifier.run(state)

    console.print(f"\n[green]Classifier done. Checking classification results:[/green]")
    for r in state.analyzed_risks:
        owasp = r.owasp_category.value if hasattr(r.owasp_category, 'value') else str(r.owasp_category) if r.owasp_category else "MISSING"
        console.print(
            f"  {r.id}: CVSS={r.cvss_score} | CWE={r.cwe_primary or 'MISSING'} | "
            f"OWASP={owasp}"
        )

    # ── Run Reporter ──────────────────────────────────────────────────────────
    console.print("\n[bold white on blue] PHASE: REPORT GENERATION [/bold white on blue]")
    reporter = ReporterAgent(gate, rag)
    state = reporter.run(state)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n===== TEST COMPLETE =====")
    console.print(f"\n[green]Report path:[/green] {state.report_path}")
    console.print(f"[green]Total findings in report:[/green] {len(state.analyzed_risks)}")

    if state.errors:
        console.print(f"\n[red]Errors: {state.errors}[/red]")
    else:
        console.print("\n[bold green]No errors — Classifier + Reporter completed successfully.[/bold green]")

    # Verify auth findings are in the report
    if state.report_path and os.path.exists(state.report_path):
        with open(state.report_path, "r") as f:
            report_text = f.read()

        auth_checks = [
            ("SQL Injection", "FINDING-001"),
            ("Weak/Default Credentials", "FINDING-002"),
            ("CORS", "FINDING-003"),
            ("CSP", "FINDING-004"),
            ("Error Disclosure", "FINDING-005"),
            ("Private IP", "FINDING-006"),
        ]
        console.print("\n[cyan]Verifying findings in report:[/cyan]")
        for label, finding_id in auth_checks:
            found = finding_id in report_text
            icon = "[green]✓[/green]" if found else "[red]✗[/red]"
            console.print(f"  {icon} {finding_id} ({label})")


if __name__ == "__main__":
    main()
