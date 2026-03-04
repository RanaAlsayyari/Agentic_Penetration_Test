"""
agents/agents.py
─────────────────
All specialist agents in the system.

Each agent:
  1. Has a clear, single responsibility
  2. Takes typed input from AgentState
  3. Returns results that update AgentState
  4. Logs everything through AuditLogger
  5. Uses SafetyGate before any network operation

AGENT HIERARCHY:
  OrchestratorAgent (in graphs/pentest_graph.py)
      │
      ├─ ReconAgent        — discover what exists
      ├─ ScannerAgent      — run ZAP against discovered hosts
      ├─ AuthAgent         — handle login + access control testing
      ├─ AnalyzerAgent     — LLM interprets raw findings (uses RAG)
      └─ ReporterAgent     — generates final report
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

from schemas import (
    AgentState, AgentPhase, RawFinding, AnalyzedRisk,
    Severity, OWASPCategory, Host, AuthSession
)
from zap_wrapper import ZAPWrapper
from http_tools import HTTPProber, AuthTool
from rag_memory import RAGMemory
from safety_layer import SafetyGate, AuditLogger
from agent_prompts import (
    RECON_SYSTEM, SCANNER_SYSTEM, ANALYZER_SYSTEM,
    ANALYZER_ANALYSIS_PROMPT, AUTH_AGENT_SYSTEM,
    CLASSIFIER_SYSTEM, CLASSIFIER_PROMPT,
    REPORTER_SYSTEM, REPORTER_EXECUTIVE_PROMPT,
    REPORTER_FINDING_PROMPT, REPORTER_METHODOLOGY_PROMPT
)
from rich.console import Console

console = Console()


# ─── BASE AGENT ───────────────────────────────────────────────────────────────

class BaseAgent:
    """Common functionality for all agents."""

    def __init__(self, gate: SafetyGate, rag: RAGMemory):
        self.gate = gate
        self.rag = rag
        self.llm = ChatOpenAI(
            model=os.getenv("LLM_MODEL", "gpt-4o"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )

    def _call_llm(self, system_prompt: str, human_prompt: str) -> str:
        """Call LLM with system + human prompt. Returns text response."""
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=human_prompt)
        ]
        response = self.llm.invoke(messages)
        return response.content

    def _parse_json_response(self, text: str) -> dict | list:
        """Parse LLM JSON response, handling markdown code blocks."""
        # Strip markdown fences if present
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1])
        return json.loads(text)


# ─── 1. RECON AGENT ───────────────────────────────────────────────────────────

class ReconAgent(BaseAgent):
    """
    Phase 1: Reconnaissance
    
    Discovers the attack surface:
      - Probes the primary target URL
      - Discovers common paths (/admin, /api, /login, etc.)
      - Fingerprints technology stack
      - Maps available entry points for the scanner

    ANALOGY: The agent walking around the building perimeter with a notebook,
              mapping every door, window, and entrance — before trying any of them.
    """

    # Common paths to probe on web apps — not brute-force, just smart guessing
    COMMON_PATHS = [
        "login", "admin", "administrator", "dashboard", "panel",
        "api", "api/v1", "api/v2", "graphql",
        "register", "signup", "forgot-password", "reset-password",
        "profile", "account", "settings",
        "user", "users", "admin/users",
        "upload", "file", "files",
        "config", "configuration", "setup",
        "debug", "test", "dev",
        "robots.txt", "sitemap.xml", ".well-known/security.txt",
        "swagger", "swagger-ui", "api-docs", "openapi.json",
        # DVWA-specific
        "dvwa", "vulnerabilities", "security",
        # Juice Shop specific
        "rest", "#/login", "#/score-board"
    ]

    def __init__(self, gate: SafetyGate, rag: RAGMemory):
        super().__init__(gate, rag)
        self.prober = HTTPProber(gate)

    def run(self, state: AgentState) -> AgentState:
        console.print("\n[bold cyan]═══ RECON AGENT STARTING ═══[/bold cyan]")
        AuditLogger.log_phase_transition("init", AgentPhase.RECON, "Starting reconnaissance")
        state.current_phase = AgentPhase.RECON

        target = state.config.target_url
        discovered = []

        # Step 1: Probe primary target
        console.print(f"\n[cyan]Step 1:[/cyan] Probing primary target: {target}")
        primary_host = self.prober.probe(target)
        if primary_host:
            discovered.append(primary_host)

        # Step 2: SPA detection — MUST happen before path discovery
        console.print(f"\n[cyan]Step 2:[/cyan] Detecting if target is a Single Page Application...")
        spa_result = self.prober.detect_spa(target)
        state.is_spa = spa_result["is_spa"]
        state.spa_framework = spa_result.get("framework")
        state.spa_evidence = spa_result.get("evidence")

        if state.is_spa:
            console.print(
                f"[bold yellow]⚠ SPA detected ({state.spa_framework or 'unknown framework'}).[/bold yellow] "
                f"Path discovery results will be filtered for SPA false positives."
            )

        # Step 3: Probe common paths
        console.print(f"\n[cyan]Step 3:[/cyan] Probing {len(self.COMMON_PATHS)} common paths...")
        path_results = self.prober.probe_paths(target, self.COMMON_PATHS)

        if state.is_spa:
            # Filter SPA false positives: if a path returns the same body as the
            # homepage, it's the SPA shell catching the route — not real content.
            baseline_size = spa_result.get("baseline_size", 0)
            filtered = []
            for host in path_results:
                # API endpoints and special files are real even on SPAs
                is_api_or_file = any(
                    kw in host.url.lower()
                    for kw in ["/api", "/rest", "/graphql", ".json", ".xml", ".txt",
                               ".php", "robots.txt", "sitemap", "swagger", "ftp"]
                )
                # Auth-related paths must survive SPA filter so should_run_auth() can find them
                is_auth_path = any(
                    kw in host.url.lower()
                    for kw in ["/login", "/signin", "/sign-in", "/register", "/signup",
                               "/sign-up", "/auth", "/forgot-password", "/reset-password",
                               "/sso", "/oauth", "/callback"]
                )
                if is_api_or_file or is_auth_path:
                    filtered.append(host)
                # Non-200 responses are meaningful (404 = server actually checked)
                elif host.status_code and host.status_code != 200:
                    filtered.append(host)
                # 200 responses on SPA need body-size verification
                # (can't do full body check here, but size difference is a signal)

            console.print(
                f"[yellow]  SPA filter: {len(path_results)} paths found, "
                f"{len(filtered)} kept after removing likely SPA shell responses[/yellow]"
            )
            path_results = filtered

        discovered.extend(path_results)

        # Step 4: LinkFinder — extract API endpoints from JavaScript files
        if state.is_spa:
            console.print(f"\n[cyan]Step 4:[/cyan] LinkFinder: extracting endpoints from JavaScript...")
            js_endpoints = self.prober.extract_js_endpoints(target)
            if js_endpoints:
                console.print(f"[green]  ✓ LinkFinder found {len(js_endpoints)} API endpoints[/green]")
                discovered.extend(js_endpoints)
            else:
                console.print("[yellow]  LinkFinder: No new endpoints extracted[/yellow]")

        # Step 5: LLM interprets what was found
        if discovered:
            hosts_summary = [
                {"url": h.url, "status": h.status_code, "tech": h.technologies}
                for h in discovered
            ]
            spa_note = ""
            if state.is_spa:
                spa_note = (
                    f"\n\nIMPORTANT: Target is a Single Page Application "
                    f"({state.spa_framework or 'unknown framework'}). "
                    f"{state.spa_evidence} "
                    f"HTTP 200 status codes should NOT be treated as evidence "
                    f"of real endpoint existence."
                )

            recon_prompt = f"""
            Reconnaissance complete. Here are the discovered hosts/paths:
            {json.dumps(hosts_summary, indent=2)}
            {spa_note}
            Analyze this attack surface and provide your assessment.
            """
            llm_analysis = self._call_llm(RECON_SYSTEM, recon_prompt)
            state.orchestrator_notes.append(f"[ReconAgent] {llm_analysis}")

        state.discovered_hosts = discovered
        state.completed_phases.append(AgentPhase.RECON)

        console.print(f"\n[green]✓ Recon complete. Discovered {len(discovered)} hosts/paths.[/green]")
        AuditLogger.log("RECON_COMPLETE", {
            "discovered_count": len(discovered),
            "is_spa": state.is_spa,
            "spa_framework": state.spa_framework
        })

        return state


# ─── 2. AUTH AGENT ────────────────────────────────────────────────────────────

class AuthAgent(BaseAgent):
    """
    Phase 2: Authentication + Access Control Testing

    Handles:
      - Logging in with test credentials
      - Testing unauthenticated access to protected pages (A01)
      - Testing cross-user access (IDOR, A01)
      - Assessing session security (cookie flags, token strength)

    WHY before scanning?
      We need authenticated sessions to pass to ZAP.
      Otherwise ZAP only scans the public surface.
      The most critical vulnerabilities are often behind login.
    """

    def __init__(self, gate: SafetyGate, rag: RAGMemory):
        super().__init__(gate, rag)
        self.auth_tool = AuthTool(gate)

    def run(self, state: AgentState) -> AgentState:
        console.print("\n[bold cyan]═══ AUTH AGENT STARTING ═══[/bold cyan]")
        AuditLogger.log_phase_transition(
            AgentPhase.MAPPING, AgentPhase.AUTH_TEST,
            "Starting authentication testing"
        )
        state.current_phase = AgentPhase.AUTH_TEST

        target = state.config.target_url
        creds = state.config.credentials

        if not creds:
            console.print("[yellow]⚠ No credentials configured — skipping auth testing[/yellow]")
            state.warnings.append("No credentials configured — authenticated testing skipped")
            state.completed_phases.append(AgentPhase.AUTH_TEST)
            return state

        # Detect which application we're testing
        auth_session = self._login(target, creds)

        if auth_session and auth_session.login_successful:
            state.auth_sessions.append(auth_session)
            console.print(f"[green]✓ Auth session established for {auth_session.username}[/green]")

            # ── Emit RawFinding for the login itself ─────────────────────────
            login_finding = self._classify_login_finding(target, creds, auth_session)
            if login_finding:
                state.raw_findings.append(login_finding)
                AuditLogger.log_finding(
                    "AuthAgent",
                    login_finding.finding_type,
                    login_finding.url,
                    login_finding.raw_severity or "High"
                )

            # Test access control on protected paths
            protected_paths = self._identify_protected_paths(state.discovered_hosts)
            access_findings = self._test_access_control(target, protected_paths, auth_session)

            # Convert access control findings to RawFindings
            for finding_data in access_findings:
                raw = RawFinding(
                    source_tool="auth_agent",
                    finding_type=finding_data["type"],
                    url=finding_data["url"],
                    raw_severity=finding_data["severity"],
                    raw_description=finding_data["description"],
                    confidence="High",
                    evidence=finding_data.get("evidence")
                )
                state.raw_findings.append(raw)
        else:
            if auth_session:
                console.print(f"[yellow]⚠ Login failed for {auth_session.username}[/yellow]")
                state.warnings.append(f"Auth login failed for {creds.username}")

        state.completed_phases.append(AgentPhase.AUTH_TEST)
        return state

    def _login(self, target: str, creds) -> Optional[AuthSession]:
        """Detect app type and login accordingly."""
        target_lower = target.lower()

        # DVWA detection
        if any(x in target_lower for x in ["8888", "dvwa"]):
            return self.auth_tool.login_dvwa(target, creds.username, creds.password)

        # Juice Shop detection (default port 3000)
        elif any(x in target_lower for x in ["3000", "juice"]):
            return self.auth_tool.login_juiceshop(target, creds.username, creds.password)

        else:
            # Try Juice Shop API format by default
            return self.auth_tool.login_juiceshop(target, creds.username, creds.password)

    def _identify_protected_paths(self, hosts: list[Host]) -> list[str]:
        """Find paths that should require authentication."""
        protected_keywords = [
            "admin", "dashboard", "profile", "account",
            "settings", "panel", "manage", "user", "api"
        ]
        protected = []
        for host in hosts:
            if any(kw in host.url.lower() for kw in protected_keywords):
                protected.append(host.url)
        return protected[:10]  # limit to 10 most interesting

    def _test_access_control(
        self,
        target: str,
        protected_paths: list[str],
        session: AuthSession
    ) -> list[dict]:
        """Test each protected path for access control issues."""
        findings = []

        for path in protected_paths:
            try:
                result = self.auth_tool.test_access_control(path, session)

                # Flag if unauthenticated access succeeds on a 'protected' path
                if result.get("unauthenticated", {}).get("issue"):
                    findings.append({
                        "type": "Broken Access Control - Unauthenticated Access",
                        "url": path,
                        "severity": "High",
                        "description": f"The path {path} is accessible without authentication. "
                                       f"It returned HTTP {result['unauthenticated']['status_code']}.",
                        "evidence": f"Unauthenticated GET to {path} returned status "
                                    f"{result['unauthenticated']['status_code']}"
                    })

            except Exception as e:
                console.print(f"[yellow]⚠ Access control test error for {path}: {e}[/yellow]")

        return findings

    def _classify_login_finding(
        self,
        target: str,
        creds,
        session: AuthSession
    ) -> Optional[RawFinding]:
        """
        Determine if the successful login constitutes a security finding.

        Cases:
          1. Login with SQL injection payload → Critical finding
          2. Login with default/weak credentials → High finding
          3. Login with strong unique creds → Not a finding (expected behavior)
        """
        login_url = creds.login_url or target
        password = creds.password
        username = creds.username

        # Check for SQL injection patterns in credentials
        sqli_patterns = ["'", "OR", "--", "1=1", "1='1", "UNION", "SELECT", ";"]
        is_sqli = any(p.lower() in password.lower() for p in sqli_patterns) or \
                  any(p.lower() in username.lower() for p in sqli_patterns)

        if is_sqli:
            return RawFinding(
                source_tool="auth_agent",
                finding_type="SQL Injection - Authentication Bypass",
                url=login_url,
                method="POST",
                parameter="email/password",
                raw_severity="Critical",
                raw_description=(
                    f"Authentication bypass via SQL injection. "
                    f"Login succeeded with SQLi payload in credentials for user '{username}'. "
                    f"This indicates the login endpoint does not use parameterized queries."
                ),
                confidence="High",
                evidence=(
                    f"POST {login_url} with SQL injection payload returned valid "
                    f"authentication token (JWT). User role: {session.role}."
                )
            )

        # Check for default/weak credentials
        weak_passwords = [
            "admin123", "password", "123456", "admin", "test", "guest",
            "password123", "letmein", "welcome", "monkey", "dragon"
        ]
        is_weak = password.lower() in weak_passwords

        # Check for default account patterns
        is_default_account = "admin" in username.lower() or "test" in username.lower()

        if is_weak or is_default_account:
            return RawFinding(
                source_tool="auth_agent",
                finding_type="Authentication Failure - Weak/Default Credentials",
                url=login_url,
                method="POST",
                parameter="email/password",
                raw_severity="High",
                raw_description=(
                    f"Login succeeded with {'default' if is_default_account else 'weak'} credentials "
                    f"for user '{username}'. "
                    f"{'Default admin account is active and accessible. ' if is_default_account else ''}"
                    f"Password '{password}' is a commonly-used weak password."
                ),
                confidence="High",
                evidence=(
                    f"POST {login_url} with credentials {username}:{password} "
                    f"returned valid session. User role: {session.role}."
                )
            )

        # Normal login with strong creds — not a finding
        return None


# ─── 3. SCANNER AGENT ─────────────────────────────────────────────────────────

class ScannerAgent(BaseAgent):
    """
    Phase 3: Active Scanning with OWASP ZAP

    What this agent does:
      1. Opens target in ZAP
      2. Runs ZAP spider to discover all pages + forms
      3. Runs passive scan on discovered traffic
      4. Runs active scan to test for vulnerabilities
      5. If auth session available: passes cookies to ZAP for authenticated scan
      6. Collects all alerts and structures them as RawFindings

    The active scan tests for:
      - SQL Injection (every input field)
      - XSS Reflected + Stored
      - Path Traversal
      - Command Injection
      - CSRF
      - Security header issues
      - And 100+ more ZAP rules
    """

    def __init__(self, gate: SafetyGate, rag: RAGMemory):
        super().__init__(gate, rag)
        self.zap = ZAPWrapper(gate)

    def run(self, state: AgentState) -> AgentState:
        console.print("\n[bold cyan]═══ SCANNER AGENT STARTING ═══[/bold cyan]")
        AuditLogger.log_phase_transition(
            AgentPhase.AUTH_TEST, AgentPhase.ACTIVE_SCAN,
            "Starting ZAP active scan"
        )
        state.current_phase = AgentPhase.ACTIVE_SCAN

        target = state.config.target_url

        # ── Pass auth context to ZAP (cookies + headers/tokens) ──────────────
        if state.auth_sessions:
            session = state.auth_sessions[0]
            if session.login_successful:
                if session.cookies:
                    self.zap.set_authentication_cookie(session.cookies)
                # Also pass auth headers (e.g., Authorization: Bearer <JWT>)
                if session.headers:
                    for header_name, header_value in session.headers.items():
                        self.zap.set_authentication_header(header_name, header_value)
                console.print("[green]✓ ZAP configured with auth context (cookies + headers)[/green]")
                AuditLogger.log("SCANNER_AUTH_CONTEXT", {
                    "has_cookies": bool(session.cookies),
                    "has_headers": bool(session.headers),
                    "header_names": list(session.headers.keys()) if session.headers else [],
                    "token_present": session.token is not None,
                    "username": session.username,
                    "role": session.role
                })

        # ── Step 1: Open target in ZAP ───────────────────────────────────────
        console.print("\n[cyan]Step 1:[/cyan] Opening target in ZAP...")
        self.zap.open_url(target)

        # Seed ZAP with all discovered URLs from recon
        if state.discovered_hosts:
            console.print(f"[cyan]  Seeding ZAP with {len(state.discovered_hosts)} discovered paths...[/cyan]")
            api_endpoints = [h for h in state.discovered_hosts
                            if any(kw in h.url.lower() for kw in ["/api", "/rest", "/graphql"])]
            if api_endpoints:
                console.print(f"[cyan]  Including {len(api_endpoints)} API endpoints for targeted scanning[/cyan]")
                AuditLogger.log("SCANNER_API_SEEDS", {
                    "api_endpoint_count": len(api_endpoints),
                    "endpoints": [h.url for h in api_endpoints[:10]]
                })
            for host in state.discovered_hosts:
                try:
                    self.zap.open_url(host.url)
                except Exception:
                    pass  # Non-critical — ZAP will find these during spider anyway

        # ── Step 2: AJAX Spider for SPAs ─────────────────────────────────────
        if state.is_spa:
            console.print("\n[cyan]Step 2:[/cyan] Running AJAX Spider (SPA detected)...")
            console.print(f"[yellow]  Framework: {state.spa_framework or 'unknown'} — "
                          f"standard spider can't follow client-side routes[/yellow]")
            try:
                ajax_urls = self.zap.ajax_spider(target, max_duration_minutes=5)
                console.print(f"[green]✓ AJAX Spider found {len(ajax_urls)} URLs[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠ AJAX Spider error: {e} — continuing with standard spider[/yellow]")
                state.warnings.append(f"AJAX Spider failed: {e}")

        # ── Step 3: Standard spider ──────────────────────────────────────────
        console.print("\n[cyan]Step 3:[/cyan] Running ZAP standard spider...")
        try:
            discovered_urls = self.zap.spider(target, max_depth=3)
            console.print(f"[green]✓ Spidered {len(discovered_urls)} URLs[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Spider error: {e} — continuing with target URL only[/yellow]")
            state.warnings.append(f"ZAP spider failed: {e}")
            discovered_urls = [target]

        # ── Step 3.5: Proxy-seed endpoints with parameters ─────────────────
        console.print("\n[cyan]Step 3.5:[/cyan] Proxy-seeding endpoints with dummy parameters...")
        console.print("[yellow]  Populates ZAP's site tree with testable input vectors[/yellow]")
        seed_urls = list(set(
            [h.url for h in state.discovered_hosts] + discovered_urls
        ))
        auth_hdrs = None
        if state.auth_sessions and state.auth_sessions[0].login_successful:
            auth_hdrs = state.auth_sessions[0].headers
        try:
            seeded_count = self.zap.proxy_seed(seed_urls, auth_headers=auth_hdrs)
            console.print(f"[green]✓ Proxy-seeded {seeded_count} request/param combinations[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Proxy seeding error: {e} — continuing without[/yellow]")
            state.warnings.append(f"Proxy seeding failed: {e}")

        # ── Step 4: Passive scan ─────────────────────────────────────────────
        console.print("\n[cyan]Step 4:[/cyan] Running ZAP passive scan...")
        try:
            passive_findings = self.zap.passive_scan(target)
            state.raw_findings.extend(passive_findings)
            console.print(f"[green]✓ Passive scan: {len(passive_findings)} alerts[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Passive scan error: {e}[/yellow]")
            state.warnings.append(f"ZAP passive scan failed: {e}")

        # ── Step 5: Active scan (only if mode=active) ────────────────────────
        if state.config.mode.value == "active":
            console.print("\n[cyan]Step 5:[/cyan] Running ZAP ACTIVE scan...")
            console.print("[yellow]  ⚡ Active scan sends real attack payloads — this is authorized[/yellow]")
            try:
                active_findings = self.zap.active_scan(target)
                state.raw_findings.extend(active_findings)
                console.print(f"[green]✓ Active scan: {len(active_findings)} alerts[/green]")
            except Exception as e:
                console.print(f"[red]✗ Active scan error: {e}[/red]")
                state.errors.append(f"ZAP active scan failed: {e}")
        else:
            console.print("[yellow]⚠ Mode is passive — skipping active scan[/yellow]")

        state.completed_phases.append(AgentPhase.ACTIVE_SCAN)
        console.print(f"\n[green]✓ Scanning complete. Total raw findings: {len(state.raw_findings)}[/green]")

        return state


# ─── 4. ANALYZER AGENT ────────────────────────────────────────────────────────

class AnalyzerAgent(BaseAgent):
    """
    Phase 4: LLM-Powered Security Analysis

    This is where AI adds the most value:
      - Raw scanner output is noisy and verbose
      - ZAP produces 100s of alerts, many duplicates or false positives
      - LLM reads all findings + RAG knowledge + context = accurate analysis

    The RAG query is KEY:
      For each finding type, we query our knowledge base:
      "SQL Injection in login form" → retrieves OWASP A03 knowledge
      This knowledge is injected into the LLM prompt as context.
      Result: LLM gives expert-level analysis, not just a summary.

    ANALOGY:
      Without RAG: A smart analyst who's heard of SQL injection
      With RAG:    That same analyst with the OWASP Testing Guide open on their desk
    """

    # ── Noise alert types that never need AI judgment ──────────────────────────
    NOISE_ALERT_TYPES = {
        "Timestamp Disclosure - Unix",
        "Modern Web Application",
        "User Agent Fuzzer",
        "Session Management Response Identified",
        "Re-examine Cache-control Directives",
        "Information Disclosure - Suspicious Comments",
    }

    BATCH_SIZE = 40  # findings per LLM call
    BATCH_DELAY_SECONDS = 2  # delay between batches to respect rate limits

    def run(self, state: AgentState) -> AgentState:
        console.print("\n[bold cyan]═══ ANALYZER AGENT STARTING ═══[/bold cyan]")
        AuditLogger.log_phase_transition(
            AgentPhase.ACTIVE_SCAN, AgentPhase.ANALYSIS,
            "Starting LLM analysis of findings"
        )
        state.current_phase = AgentPhase.ANALYSIS

        if not state.raw_findings:
            console.print("[yellow]⚠ No raw findings to analyze[/yellow]")
            state.warnings.append("No findings were generated — target may be hardened or ZAP failed")
            state.completed_phases.append(AgentPhase.ANALYSIS)
            return state

        console.print(f"[cyan]Analyzing {len(state.raw_findings)} raw findings...[/cyan]")

        # ── Fix 2: Pre-filter noise before LLM call ──────────────────────────────
        filtered_findings = [
            f for f in state.raw_findings
            if f.finding_type not in self.NOISE_ALERT_TYPES
        ]
        noise_count = len(state.raw_findings) - len(filtered_findings)
        if noise_count:
            console.print(
                f"[yellow]  Pre-filter: removed {noise_count} noise alerts "
                f"({len(filtered_findings)} remain)[/yellow]"
            )
            AuditLogger.log("NOISE_FILTERED", {
                "original_count": len(state.raw_findings),
                "noise_removed": noise_count,
                "remaining": len(filtered_findings),
            })

        # Build RAG context from all finding types
        finding_types = list(set(f.finding_type for f in filtered_findings))
        rag_query = f"Security vulnerabilities: {', '.join(finding_types)}"
        rag_context = self.rag.query_knowledge(rag_query, k=4)

        console.print(f"[cyan]📚 RAG retrieved {len(rag_context.split())} words of context[/cyan]")

        # Smart Deduplication: group by (finding_type, url, parameter)
        unique_findings = {}
        for f in filtered_findings:
            key = (f.finding_type, f.url, f.parameter)
            if key not in unique_findings:
                unique_findings[key] = f

        deduped_list = list(unique_findings.values())
        console.print(f"[cyan]Deduplicated {len(filtered_findings)} findings down to {len(deduped_list)} unique issues.[/cyan]")

        # Access control results
        access_findings = [f for f in state.raw_findings if "Access Control" in f.finding_type]
        access_json = json.dumps([
            {"type": f.finding_type, "url": f.url, "evidence": f.evidence}
            for f in access_findings
        ], indent=2)

        # Technologies
        techs = []
        for host in state.discovered_hosts:
            techs.extend(host.technologies)
        tech_str = ", ".join(set(techs)) if techs else "Unknown"

        # SPA context — critical for FP filtering
        spa_warning = ""
        if state.is_spa:
            spa_warning = (
                "\n⚠ IMPORTANT: This target IS a Single Page Application. "
                "Apply SPA false positive rules strictly. Any finding based "
                "solely on HTTP 200 status code is almost certainly a false positive."
            )

        # Auth sessions summary — so Analyzer knows what was confirmed
        auth_summary_parts = []
        for sess in state.auth_sessions:
            if sess.login_successful:
                auth_summary_parts.append(
                    f"- Successful login as '{sess.username}' (role: {sess.role}) "
                    f"via {'JWT token' if sess.token else 'session cookie'}"
                )
        auth_sessions_summary = "\n".join(auth_summary_parts) if auth_summary_parts else "No authenticated sessions."

        # Build the system prompt once (shared across batches)
        system_prompt = ANALYZER_SYSTEM.format(rag_context=rag_context)

        # ── Fix 1: Batch LLM calls ──────────────────────────────────────────────
        batches = [
            deduped_list[i:i + self.BATCH_SIZE]
            for i in range(0, len(deduped_list), self.BATCH_SIZE)
        ]
        total_batches = len(batches)
        console.print(f"[cyan]Split into {total_batches} batch(es) of up to {self.BATCH_SIZE} findings each.[/cyan]")

        all_findings_data = []

        for batch_idx, batch in enumerate(batches):
            batch_num = batch_idx + 1
            console.print(f"[cyan]🤖 LLM analyzing batch {batch_num}/{total_batches} ({len(batch)} findings)...[/cyan]")

            findings_json = json.dumps(
                [
                    {
                        "tool": f.source_tool,
                        "type": f.finding_type,
                        "url": f.url,
                        "method": f.method,
                        "parameter": f.parameter,
                        "evidence": f.evidence,
                        "severity": f.raw_severity,
                        "confidence": f.confidence,
                        "description": f.raw_description
                    }
                    for f in batch
                ],
                indent=2
            )

            human_prompt = ANALYZER_ANALYSIS_PROMPT.format(
                target_url=state.config.target_url,
                raw_findings_json=findings_json,
                access_control_results=access_json,
                technologies=tech_str,
                is_spa=state.is_spa,
                spa_framework=state.spa_framework or "Not detected",
                spa_evidence=state.spa_evidence or "N/A",
                spa_warning=spa_warning,
                auth_sessions_summary=auth_sessions_summary
            )

            try:
                llm_response = self._call_llm(system_prompt, human_prompt)
                batch_data = self._parse_json_response(llm_response)
                if not isinstance(batch_data, list):
                    batch_data = [batch_data]
                all_findings_data.extend(batch_data)
            except json.JSONDecodeError as e:
                console.print(f"[red]✗ Failed to parse LLM analysis for batch {batch_num}: {e}[/red]")
                console.print(f"[red]Raw response (first 500 chars): {llm_response[:500]}[/red]")
                state.errors.append(f"Analysis parsing failed (batch {batch_num}): {e}")
            except Exception as e:
                console.print(f"[red]✗ LLM call failed for batch {batch_num}: {e}[/red]")
                state.errors.append(f"LLM call failed (batch {batch_num}): {e}")

            # Rate limit delay between batches
            if batch_num < total_batches:
                console.print(f"[dim]  Waiting {self.BATCH_DELAY_SECONDS}s before next batch...[/dim]")
                time.sleep(self.BATCH_DELAY_SECONDS)

        # Parse merged results into AnalyzedRisk objects
        for finding_data in all_findings_data:
            if finding_data.get("is_false_positive"):
                AuditLogger.log("FALSE_POSITIVE_SKIPPED", {
                    "title": finding_data.get("title"),
                    "reason": finding_data.get("false_positive_reason")
                })
                continue

            risk = AnalyzedRisk(
                id=finding_data.get("id", f"FINDING-{len(state.analyzed_risks)+1:03d}"),
                title=finding_data.get("title", "Unknown Finding"),
                affected_url=finding_data.get("affected_url", state.config.target_url),
                affected_parameter=finding_data.get("affected_parameter"),
                description=finding_data.get("description", ""),
                technical_detail=finding_data.get("technical_detail", ""),
                evidence=finding_data.get("evidence"),
                remediation_context=finding_data.get("remediation_context", ""),
                is_false_positive=False,
                severity_estimate=self._parse_severity(
                    finding_data.get("severity_estimate", "Info")
                ),
            )
            state.analyzed_risks.append(risk)

            AuditLogger.log_finding(
                "AnalyzerAgent", risk.title, risk.affected_url, risk.severity_estimate
            )

        state.completed_phases.append(AgentPhase.ANALYSIS)
        console.print(
            f"\n[green]✓ Analysis complete. "
            f"Found {len(state.analyzed_risks)} genuine risks.[/green]"
        )
        return state

    def _parse_severity(self, raw: str) -> Severity:
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "informational": Severity.INFO
        }
        return mapping.get(raw.lower(), Severity.INFO)

    def _parse_owasp(self, raw: str) -> OWASPCategory:
        for category in OWASPCategory:
            if category.value.lower() in raw.lower() or \
               raw.upper() in category.value:
                return category
        return OWASPCategory.UNKNOWN


# ─── 5. CLASSIFIER AGENT ──────────────────────────────────────────────────────

class ClassifierAgent(BaseAgent):
    """
    Phase 5: Standards Classification

    Takes confirmed findings from AnalyzerAgent and enriches each one with:
      - OWASP Top 10 2025 category + reference URL
      - CWE ID(s) + reference URL(s)
      - CVSS 3.1 vector string + numeric score + severity label
      - Classification reasoning (chain-of-thought)
      - Discrepancy note if CVSS severity differs from analyst estimate
      - Standard remediation from OWASP/CWE guidance

    READS skill files at runtime — does not rely on LLM memory for CWE IDs or CVSS rules.

    WHY skill files over RAG here:
      Classification is a lookup task, not a search task. The Classifier knows
      exactly what it's looking for — it needs to apply a known mapping table,
      not find the most semantically similar chunk. The full mapping fits in
      context and the LLM can reason through it systematically.
    """

    SKILL_DIR = "./skills/classification"

    def __init__(self, gate: SafetyGate, rag: RAGMemory):
        super().__init__(gate, rag)
        self._skill_owasp_cwe = self._load_skill("owasp_cwe_map.md")
        self._skill_cvss = self._load_skill("cvss_scoring.md")

    def _load_skill(self, filename: str) -> str:
        """Load a skill file from the classification skill directory."""
        path = os.path.join(self.SKILL_DIR, filename)
        try:
            with open(path, "r") as f:
                return f.read()
        except FileNotFoundError:
            console.print(f"[red]✗ Skill file not found: {path}[/red]")
            return f"[Skill file {filename} not found — classification may be incomplete]"

    def run(self, state: AgentState) -> AgentState:
        console.print("\n[bold cyan]═══ CLASSIFIER AGENT STARTING ═══[/bold cyan]")
        AuditLogger.log_phase_transition(
            AgentPhase.ANALYSIS, AgentPhase.CLASSIFICATION,
            "Starting standards classification"
        )
        state.current_phase = AgentPhase.CLASSIFICATION

        if not state.analyzed_risks:
            console.print("[yellow]⚠ No confirmed findings to classify[/yellow]")
            state.completed_phases.append(AgentPhase.CLASSIFICATION)
            return state

        console.print(f"[cyan]Classifying {len(state.analyzed_risks)} confirmed findings...[/cyan]")

        # Prepare findings for the LLM — only Analyzer fields needed
        findings_json = json.dumps([
            {
                "id": r.id,
                "title": r.title,
                "affected_url": r.affected_url,
                "affected_parameter": r.affected_parameter,
                "evidence": r.evidence,
                "severity_estimate": r.severity_estimate.value if hasattr(r.severity_estimate, 'value') else str(r.severity_estimate),
                "description": r.description,
                "technical_detail": r.technical_detail,
            }
            for r in state.analyzed_risks
        ], indent=2)

        system_prompt = CLASSIFIER_SYSTEM.format(
            skill_owasp_cwe=self._skill_owasp_cwe,
            skill_cvss=self._skill_cvss
        )

        human_prompt = CLASSIFIER_PROMPT.format(
            findings_json=findings_json
        )

        console.print("[cyan]🤖 LLM classifying findings against OWASP 2025 / CWE / CVSS 3.1...[/cyan]")
        llm_response = self._call_llm(system_prompt, human_prompt)

        try:
            classifications = self._parse_json_response(llm_response)
            if not isinstance(classifications, list):
                classifications = [classifications]

            # Build lookup by finding ID
            classification_map = {c["id"]: c for c in classifications}

            # Enrich each AnalyzedRisk with classification fields
            for risk in state.analyzed_risks:
                c = classification_map.get(risk.id)
                if not c:
                    console.print(f"[yellow]⚠ No classification returned for {risk.id}[/yellow]")
                    continue

                risk.owasp_category = self._parse_owasp(c.get("owasp_category", ""))
                risk.owasp_reference_url = c.get("owasp_reference_url")
                risk.cwe_ids = c.get("cwe_ids", [])
                risk.cwe_primary = c.get("cwe_primary")
                risk.cwe_reference_urls = c.get("cwe_reference_urls", [])
                risk.cvss_vector = c.get("cvss_vector")
                risk.cvss_score = c.get("cvss_score")
                risk.cvss_severity = self._parse_severity(c.get("cvss_severity", "Info"))
                risk.classification_reasoning = c.get("classification_reasoning")
                risk.severity_discrepancy_note = c.get("severity_discrepancy_note")
                risk.remediation_standard = c.get("remediation_standard")
                risk.classification_confidence = c.get("classification_confidence", "High")

                AuditLogger.log("FINDING_CLASSIFIED", {
                    "id": risk.id,
                    "owasp": risk.owasp_category,
                    "cwe_primary": risk.cwe_primary,
                    "cvss_score": risk.cvss_score,
                    "cvss_severity": risk.cvss_severity,
                    "analyst_estimate": risk.severity_estimate,
                    "discrepancy": risk.severity_discrepancy_note is not None
                })

                console.print(
                    f"[green]  ✓ {risk.id}:[/green] {risk.cwe_primary} | "
                    f"CVSS {risk.cvss_score} ({risk.cvss_severity}) | "
                    f"Analyst: {risk.severity_estimate}"
                )

        except json.JSONDecodeError as e:
            console.print(f"[red]✗ Failed to parse Classifier response: {e}[/red]")
            state.errors.append(f"Classification parsing failed: {e}")

        state.completed_phases.append(AgentPhase.CLASSIFICATION)
        console.print(f"\n[green]✓ Classification complete.[/green]")
        return state

    def _parse_severity(self, raw: str) -> Severity:
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "informational": Severity.INFO,
            "none": Severity.INFO
        }
        return mapping.get(raw.lower(), Severity.INFO)

    def _parse_owasp(self, raw: str) -> OWASPCategory:
        for category in OWASPCategory:
            if category.value.lower() in raw.lower():
                return category
        return OWASPCategory.UNKNOWN


# ─── 6. REPORTER AGENT ────────────────────────────────────────────────────────

class ReporterAgent(BaseAgent):
    """
    Phase 6: Professional Report Generation (PTES format)

    Generates the report in focused passes — one LLM call per section —
    rather than dumping everything into a single call.

    Pass order:
      1. Executive summary
      2. Risk table
      3. Finding detail (one call per finding)
      4. Methodology section

    Each pass produces a focused, high-quality section.
    The Reporter also merges the Analyzer's context-specific remediation
    with the Classifier's standard remediation into a unified remediation block.
    """

    SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4
    }

    def run(self, state: AgentState) -> AgentState:
        console.print("\n[bold cyan]═══ REPORTER AGENT STARTING ═══[/bold cyan]")
        AuditLogger.log_phase_transition(
            AgentPhase.CLASSIFICATION, AgentPhase.REPORTING,
            "Generating final report (PTES format)"
        )
        state.current_phase = AgentPhase.REPORTING

        sorted_risks = sorted(
            state.analyzed_risks,
            key=lambda r: self.SEVERITY_ORDER.get(r.cvss_severity or r.severity_estimate, 99)
        )

        risk_counts = {}
        for risk in sorted_risks:
            sev = risk.cvss_severity or risk.severity_estimate
            risk_counts[sev] = risk_counts.get(sev, 0) + 1

        sections = []

        # ── Pass 1: Executive Summary ──────────────────────────────────────────
        console.print("[cyan]📝 Pass 1: Executive summary...[/cyan]")
        top_findings = [
            {"id": r.id, "title": r.title,
             "cvss_score": r.cvss_score,
             "cvss_severity": r.cvss_severity.value if hasattr(r.cvss_severity, 'value') else str(r.cvss_severity) if r.cvss_severity else None,
             "description": r.description}
            for r in sorted_risks[:3]
        ]
        exec_summary = self._call_llm(
            REPORTER_SYSTEM,
            REPORTER_EXECUTIVE_PROMPT.format(
                target_url=state.config.target_url,
                engagement_id=state.config.engagement_id,
                date=datetime.now().strftime("%Y-%m-%d"),
                mode=state.config.mode.value,
                critical_count=risk_counts.get(Severity.CRITICAL, 0),
                high_count=risk_counts.get(Severity.HIGH, 0),
                medium_count=risk_counts.get(Severity.MEDIUM, 0),
                low_count=risk_counts.get(Severity.LOW, 0),
                info_count=risk_counts.get(Severity.INFO, 0),
                total_count=len(sorted_risks),
                top_findings_json=json.dumps(top_findings, indent=2)
            )
        )
        sections.append("## Executive Summary\n\n" + exec_summary)

        # ── Pass 2: Risk Table ─────────────────────────────────────────────────
        console.print("[cyan]📝 Pass 2: Risk summary table...[/cyan]")
        table_rows = ["| ID | Title | Severity | CVSS Score | OWASP Category | CWE | Affected URL |",
                      "|---|---|---|---|---|---|---|"]
        for r in sorted_risks:
            sev_raw = r.cvss_severity or r.severity_estimate
            sev = sev_raw.value if hasattr(sev_raw, 'value') else str(sev_raw)
            owasp_raw = r.owasp_category or "Pending"
            owasp = owasp_raw.value if hasattr(owasp_raw, 'value') else str(owasp_raw)
            cwe = r.cwe_primary or "Pending"
            cvss = str(r.cvss_score) if r.cvss_score else "Pending"
            table_rows.append(
                f"| {r.id} | {r.title} | {sev} | {cvss} | {owasp} | {cwe} | {r.affected_url} |"
            )
        sections.append("## Risk Summary\n\n" + "\n".join(table_rows))

        # ── Pass 3: Finding Details (one call per finding) ─────────────────────
        console.print(f"[cyan]📝 Pass 3: Detailed findings ({len(sorted_risks)} findings)...[/cyan]")
        finding_sections = []
        for i, risk in enumerate(sorted_risks):
            console.print(f"  Writing finding {i+1}/{len(sorted_risks)}: {risk.id}", end="\r")

            # Merge remediation fields for the prompt
            # Use .value for enums to avoid repr() leaking into report
            finding_dict = {
                "id": risk.id,
                "title": risk.title,
                "severity_estimate": risk.severity_estimate.value if hasattr(risk.severity_estimate, 'value') else str(risk.severity_estimate),
                "cvss_severity": risk.cvss_severity.value if hasattr(risk.cvss_severity, 'value') else str(risk.cvss_severity) if risk.cvss_severity else None,
                "cvss_score": risk.cvss_score,
                "cvss_vector": risk.cvss_vector,
                "severity_discrepancy_note": risk.severity_discrepancy_note,
                "owasp_category": risk.owasp_category.value if hasattr(risk.owasp_category, 'value') else str(risk.owasp_category) if risk.owasp_category else None,
                "owasp_reference_url": risk.owasp_reference_url,
                "cwe_ids": risk.cwe_ids,
                "cwe_primary": risk.cwe_primary,
                "cwe_reference_urls": risk.cwe_reference_urls,
                "affected_url": risk.affected_url,
                "affected_parameter": risk.affected_parameter,
                "description": risk.description,
                "technical_detail": risk.technical_detail,
                "evidence": risk.evidence,
                "remediation_context": risk.remediation_context,
                "remediation_standard": risk.remediation_standard,
            }

            finding_detail = self._call_llm(
                REPORTER_SYSTEM,
                REPORTER_FINDING_PROMPT.format(
                    finding_json=json.dumps(finding_dict, indent=2)
                )
            )

            # Store merged remediation back on the risk object
            risk.remediation_final = finding_detail
            finding_sections.append(finding_detail)

            AuditLogger.log("FINDING_WRITTEN", {"id": risk.id})

        console.print()
        sections.append("## Detailed Findings\n\n" + "\n\n---\n\n".join(finding_sections))

        # ── Pass 4: Methodology ────────────────────────────────────────────────
        console.print("[cyan]📝 Pass 4: Methodology section...[/cyan]")
        methodology = self._call_llm(
            REPORTER_SYSTEM,
            REPORTER_METHODOLOGY_PROMPT.format(
                target_url=state.config.target_url,
                allowed_targets=state.config.allowed_targets,
                mode=state.config.mode.value,
                engagement_id=state.config.engagement_id
            )
        )
        sections.append("## Testing Scope and Methodology\n\n" + methodology)

        # ── Assemble full report ───────────────────────────────────────────────
        header = f"""---
Engagement ID: {state.config.engagement_id}
Target: {state.config.target_url}
Date: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}
Mode: {state.config.mode.value}
Template: PTES (Penetration Testing Execution Standard)
Classification: OWASP Top 10 2025 | CWE (MITRE) | CVSS 3.1 (FIRST)
Total Findings: {len(state.analyzed_risks)}
Critical: {risk_counts.get(Severity.CRITICAL, 0)}
High: {risk_counts.get(Severity.HIGH, 0)}
Medium: {risk_counts.get(Severity.MEDIUM, 0)}
Low: {risk_counts.get(Severity.LOW, 0)}
Info: {risk_counts.get(Severity.INFO, 0)}
---

# Penetration Test Report
**Target:** {state.config.target_url}
**Engagement:** {state.config.engagement_id}
**Date:** {datetime.now().strftime("%Y-%m-%d")}

"""
        full_report = header + "\n\n".join(sections)

        import os
        os.makedirs("./output/reports", exist_ok=True)
        report_path = f"./output/reports/report_{state.config.engagement_id}.md"
        with open(report_path, "w") as f:
            f.write(full_report)

        state.report_path = report_path
        state.report_summary = (
            f"Report saved to {report_path}. "
            f"Found {len(state.analyzed_risks)} confirmed findings."
        )
        state.completed_phases.append(AgentPhase.REPORTING)
        state.current_phase = AgentPhase.COMPLETE

        console.print(f"\n[bold green]✓ Report generated: {report_path}[/bold green]")
        AuditLogger.log("REPORT_GENERATED", {
            "path": report_path,
            "findings": len(state.analyzed_risks),
            "passes": 4
        })
        return state