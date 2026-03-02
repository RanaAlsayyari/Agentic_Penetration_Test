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
    REPORTER_SYSTEM, REPORTER_GENERATION_PROMPT
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

        # Step 2: Probe common paths
        console.print(f"\n[cyan]Step 2:[/cyan] Probing {len(self.COMMON_PATHS)} common paths...")
        path_results = self.prober.probe_paths(target, self.COMMON_PATHS)
        discovered.extend(path_results)

        # Step 3: LLM interprets what was found
        if discovered:
            hosts_summary = [
                {"url": h.url, "status": h.status_code, "tech": h.technologies}
                for h in discovered
            ]
            recon_prompt = f"""
            Reconnaissance complete. Here are the discovered hosts/paths:
            {json.dumps(hosts_summary, indent=2)}
            
            Analyze this attack surface and provide your assessment.
            """
            llm_analysis = self._call_llm(RECON_SYSTEM, recon_prompt)
            state.orchestrator_notes.append(f"[ReconAgent] {llm_analysis}")

        state.discovered_hosts = discovered
        state.completed_phases.append(AgentPhase.RECON)

        console.print(f"\n[green]✓ Recon complete. Discovered {len(discovered)} hosts/paths.[/green]")
        AuditLogger.log("RECON_COMPLETE", {"discovered_count": len(discovered)})

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

        # Set auth cookies if we have them
        if state.auth_sessions:
            session = state.auth_sessions[0]
            if session.login_successful and session.cookies:
                self.zap.set_authentication_cookie(session.cookies)
                console.print("[green]✓ ZAP will scan authenticated areas[/green]")

        # Step 1: Open target and spider
        console.print("\n[cyan]Step 1:[/cyan] Opening target in ZAP...")
        self.zap.open_url(target)

        console.print("\n[cyan]Step 2:[/cyan] Running ZAP spider...")
        try:
            discovered_urls = self.zap.spider(target, max_depth=3)
            console.print(f"[green]✓ Spidered {len(discovered_urls)} URLs[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Spider error: {e} — continuing with target URL only[/yellow]")
            state.warnings.append(f"ZAP spider failed: {e}")
            discovered_urls = [target]

        # Step 2: Passive scan
        console.print("\n[cyan]Step 3:[/cyan] Running ZAP passive scan...")
        try:
            passive_findings = self.zap.passive_scan(target)
            state.raw_findings.extend(passive_findings)
            console.print(f"[green]✓ Passive scan: {len(passive_findings)} alerts[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Passive scan error: {e}[/yellow]")
            state.warnings.append(f"ZAP passive scan failed: {e}")

        # Step 3: Active scan (only if mode=active)
        if state.config.mode.value == "active":
            console.print("\n[cyan]Step 4:[/cyan] Running ZAP ACTIVE scan...")
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

        # Build RAG context from all finding types
        finding_types = list(set(f.finding_type for f in state.raw_findings))
        rag_query = f"Security vulnerabilities: {', '.join(finding_types)}"
        rag_context = self.rag.query_knowledge(rag_query, k=4)

        console.print(f"[cyan]📚 RAG retrieved {len(rag_context.split())} words of context[/cyan]")

        # Prepare findings for LLM
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
                for f in state.raw_findings
            ],
            indent=2
        )

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

        # Call LLM
        system_prompt = ANALYZER_SYSTEM.format(rag_context=rag_context)
        human_prompt = ANALYZER_ANALYSIS_PROMPT.format(
            target_url=state.config.target_url,
            raw_findings_json=findings_json,
            access_control_results=access_json,
            technologies=tech_str
        )

        console.print("[cyan]🤖 LLM analyzing findings...[/cyan]")
        llm_response = self._call_llm(system_prompt, human_prompt)

        # Parse LLM response into AnalyzedRisk objects
        try:
            risks_data = self._parse_json_response(llm_response)
            if not isinstance(risks_data, list):
                risks_data = [risks_data]

            for risk_data in risks_data:
                if risk_data.get("is_false_positive"):
                    continue  # skip false positives

                risk = AnalyzedRisk(
                    id=risk_data.get("id", f"RISK-{len(state.analyzed_risks)+1:03d}"),
                    title=risk_data.get("title", "Unknown Risk"),
                    severity=self._parse_severity(risk_data.get("severity", "Info")),
                    owasp_category=self._parse_owasp(risk_data.get("owasp_category", "")),
                    affected_url=risk_data.get("affected_url", state.config.target_url),
                    affected_parameter=risk_data.get("affected_parameter"),
                    description=risk_data.get("description", ""),
                    technical_detail=risk_data.get("technical_detail", ""),
                    evidence=risk_data.get("evidence"),
                    remediation=risk_data.get("remediation", ""),
                    is_false_positive=False,
                    cvss_score=risk_data.get("cvss_score"),
                    references=risk_data.get("references", [])
                )
                state.analyzed_risks.append(risk)

                # Store in RAG memory (for future deduplication)
                self.rag.store_finding(
                    f"{risk.title}: {risk.description}",
                    {"severity": risk.severity, "owasp": risk.owasp_category}
                )

                AuditLogger.log_finding(
                    "AnalyzerAgent", risk.title, risk.affected_url, risk.severity
                )

        except json.JSONDecodeError as e:
            console.print(f"[red]✗ Failed to parse LLM analysis: {e}[/red]")
            console.print(f"[red]Raw response: {llm_response[:500]}[/red]")
            state.errors.append(f"Analysis parsing failed: {e}")

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


# ─── 5. REPORTER AGENT ────────────────────────────────────────────────────────

class ReporterAgent(BaseAgent):
    """
    Phase 5: Professional Report Generation

    Produces:
      - Executive summary (business language)
      - Risk table sorted by severity
      - Detailed finding writeups
      - Remediation guidance
      - Testing methodology notes

    Output: Markdown report saved to output/reports/
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
            AgentPhase.ANALYSIS, AgentPhase.REPORTING,
            "Generating final report"
        )
        state.current_phase = AgentPhase.REPORTING

        # Sort risks by severity
        sorted_risks = sorted(
            state.analyzed_risks,
            key=lambda r: self.SEVERITY_ORDER.get(r.severity, 99)
        )

        # Prepare data for LLM
        risks_json = json.dumps(
            [
                {
                    "id": r.id, "title": r.title,
                    "severity": r.severity, "owasp": r.owasp_category,
                    "url": r.affected_url, "parameter": r.affected_parameter,
                    "description": r.description, "technical": r.technical_detail,
                    "evidence": r.evidence, "remediation": r.remediation,
                    "cvss": r.cvss_score, "references": r.references
                }
                for r in sorted_risks
            ],
            indent=2
        )

        hosts_json = json.dumps(
            [{"url": h.url, "status": h.status_code, "tech": h.technologies}
             for h in state.discovered_hosts],
            indent=2
        )

        human_prompt = REPORTER_GENERATION_PROMPT.format(
            target_url=state.config.target_url,
            engagement_id=state.config.engagement_id,
            date=datetime.now().strftime("%Y-%m-%d"),
            mode=state.config.mode.value,
            risks_json=risks_json,
            hosts_json=hosts_json,
            audit_log_path=f"./output/logs/audit_{state.config.engagement_id}.jsonl"
        )

        console.print("[cyan]🤖 LLM generating report...[/cyan]")
        report_content = self._call_llm(REPORTER_SYSTEM, human_prompt)

        # Add metadata header
        risk_counts = {}
        for risk in state.analyzed_risks:
            risk_counts[risk.severity] = risk_counts.get(risk.severity, 0) + 1

        header = f"""---
Engagement ID: {state.config.engagement_id}
Target: {state.config.target_url}
Date: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}
Mode: {state.config.mode.value}
Total Risks: {len(state.analyzed_risks)}
Critical: {risk_counts.get(Severity.CRITICAL, 0)}
High: {risk_counts.get(Severity.HIGH, 0)}
Medium: {risk_counts.get(Severity.MEDIUM, 0)}
Low: {risk_counts.get(Severity.LOW, 0)}
Info: {risk_counts.get(Severity.INFO, 0)}
---

"""
        full_report = header + report_content

        # Save report
        import os
        os.makedirs("./output/reports", exist_ok=True)
        report_path = f"./output/reports/report_{state.config.engagement_id}.md"
        with open(report_path, "w") as f:
            f.write(full_report)

        state.report_path = report_path
        state.report_summary = f"Report saved to {report_path}. " \
                               f"Found {len(state.analyzed_risks)} risks."
        state.completed_phases.append(AgentPhase.REPORTING)
        state.current_phase = AgentPhase.COMPLETE

        console.print(f"\n[bold green]✓ Report generated: {report_path}[/bold green]")
        AuditLogger.log("REPORT_GENERATED", {"path": report_path, "risks": len(state.analyzed_risks)})

        return state
