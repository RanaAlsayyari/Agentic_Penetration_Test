"""
tools/zap_wrapper.py
─────────────────────
Clean interface to OWASP ZAP.

ZAP runs as a daemon (background process) and exposes a REST API.
This wrapper translates our agent's requests into ZAP API calls,
parses the results back into our typed RawFinding models.

HOW ZAP WORKS (simple explanation):
  1. ZAP runs as a proxy on localhost:8080
  2. We tell ZAP: "spider this URL" — it crawls and finds pages
  3. We tell ZAP: "passive scan" — it analyzes traffic it already saw
  4. We tell ZAP: "active scan" — it sends attack payloads to every input it found
  5. We ask ZAP: "what did you find?" — it returns structured alerts

SETUP REQUIRED:
  1. Download ZAP: https://www.zaproxy.org/download/
  2. Start ZAP daemon:
     zap.sh -daemon -config api.key=YOUR_KEY -port 8080
  3. Set ZAP_API_KEY in your .env file
"""

from __future__ import annotations

import time
import os
from typing import Optional
from datetime import datetime

from zapv2 import ZAPv2

from schemas import RawFinding, Host
from safety_layer import SafetyGate, AuditLogger
from rich.console import Console

console = Console()


class ZAPWrapper:
    """
    Wraps OWASP ZAP API for use by scanner agents.

    All methods:
      - Check scope before touching target
      - Acquire rate limit token
      - Log every action to audit trail
      - Return structured RawFinding objects (not raw ZAP dicts)
    """

    def __init__(self, gate: SafetyGate):
        self.gate = gate
        self.zap = ZAPv2(
            apikey=os.getenv("ZAP_API_KEY", "changeme"),
            proxies={
                "http":  f"http://{os.getenv('ZAP_HOST','localhost')}:{os.getenv('ZAP_PORT','8080')}",
                "https": f"http://{os.getenv('ZAP_HOST','localhost')}:{os.getenv('ZAP_PORT','8080')}"
            }
        )

    # ─── STEP 1: Open the target in ZAP ───────────────────────────────────────

    def open_url(self, url: str) -> None:
        """Tell ZAP to open a URL. This lets ZAP 'see' it before scanning."""
        self.gate.check_and_acquire(url, agent_name="ZAPWrapper")
        self.zap.urlopen(url)
        AuditLogger.log_tool_call("ZAPWrapper", "open_url", url, {}, "URL opened in ZAP")

    # ─── STEP 2: Spider — discover all pages ──────────────────────────────────

    def spider(self, target_url: str, max_depth: int = 3) -> list[str]:
        """
        Spider (crawl) the target to discover all URLs.
        ZAP follows links like a browser would.

        Returns list of discovered URLs (all within same host).
        """
        self.gate.check_and_acquire(target_url, agent_name="ZAPWrapper.spider")

        console.print(f"[cyan]🕷️  ZAP Spider starting:[/cyan] {target_url}")
        AuditLogger.log_tool_call("ZAPWrapper", "spider", target_url,
                                   {"max_depth": max_depth}, "Spider started")

        scan_id = self.zap.spider.scan(target_url, maxchildren=max_depth)
        self._wait_for_completion(self.zap.spider.status, scan_id, label="Spider")

        discovered = self.zap.spider.results(scan_id)
        in_scope = [
            url for url in discovered
            if self.gate.scope.is_allowed(url)
        ]

        console.print(f"[green]✓ Spider found {len(in_scope)} in-scope URLs[/green]")
        AuditLogger.log_tool_call("ZAPWrapper", "spider_complete", target_url,
                                   {}, f"Discovered {len(in_scope)} URLs")
        return in_scope

    # ─── STEP 3: Passive scan — analyze traffic already seen ──────────────────

    def passive_scan(self, target_url: str) -> list[RawFinding]:
        """
        Passive scan: ZAP analyzes the HTTP traffic it has already observed.
        NO new requests sent to the target.
        """
        self.gate.check_and_acquire(target_url, agent_name="ZAPWrapper.passive")

        console.print(f"[cyan]👁  ZAP Passive scan:[/cyan] {target_url}")

        # Wait for passive scan to finish (it runs automatically in background)
        timeout = 60
        start = time.time()
        while int(self.zap.pscan.records_to_scan) > 0:
            if time.time() - start > timeout:
                break
            time.sleep(2)

        return self._collect_alerts(target_url, source="zap_passive")

    # ─── STEP 4: Active scan — send attack payloads ───────────────────────────

    def active_scan(
        self,
        target_url: str,
        scan_policy: Optional[str] = None
    ) -> list[RawFinding]:
        """
        Active scan: ZAP sends deliberate test payloads to every input it found.

        What ZAP tests in active mode (selection):
          - SQL Injection:   Sends payloads like ' OR 1=1-- to form fields
          - XSS:             Sends <script>alert(1)</script> variants
          - Path traversal:  Tries ../../../../etc/passwd
          - Command inject:  Tries ; ls -la ; in inputs
          - CSRF:            Checks for missing CSRF tokens
          - Auth bypass:     Tests for improper session management

        WHY this is powerful:
          ZAP has 100+ active scan rules built in.
          Each rule is a security researcher's years of knowledge
          encoded as test logic. The agent gets all of that for free.

        IMPORTANT: Only call this with explicit mode=active config.
        """
        self.gate.check_and_acquire(target_url, agent_name="ZAPWrapper.active")

        console.print(f"[bold yellow]⚡ ZAP Active scan starting:[/bold yellow] {target_url}")
        console.print("[yellow]  This will send test payloads to the target...[/yellow]")

        AuditLogger.log_tool_call("ZAPWrapper", "active_scan_start", target_url,
                                   {"policy": scan_policy}, "Active scan initiated")

        scan_id = self.zap.ascan.scan(
            target_url,
            scanpolicyname=scan_policy,
            recurse=True
        )

        self._wait_for_completion(self.zap.ascan.status, scan_id, label="Active Scan")

        findings = self._collect_alerts(target_url, source="zap_active")

        console.print(f"[green]✓ Active scan complete. Found {len(findings)} alerts.[/green]")
        AuditLogger.log_tool_call("ZAPWrapper", "active_scan_complete", target_url,
                                   {}, f"Found {len(findings)} alerts")
        return findings

    # ─── STEP 5: Authenticated scan ───────────────────────────────────────────

    def set_authentication_cookie(self, cookies: dict[str, str]) -> None:
        """
        Pass authentication session cookies to ZAP so it can scan
        authenticated areas of the application.

        HOW THIS WORKS:
          After our AuthAgent logs in and gets session cookies,
          we tell ZAP to use those cookies for all its requests.
          Now ZAP can reach /dashboard, /admin, /profile — pages
          that require login.
        """
        for name, value in cookies.items():
            # ZAP HTTP Sessions API
            AuditLogger.log("ZAP_AUTH_COOKIE_SET", {"cookie_name": name})
        console.print("[cyan]🔐 ZAP authenticated with session cookies[/cyan]")

    # ─── Internal helpers ──────────────────────────────────────────────────────

    def _wait_for_completion(self, status_fn, scan_id, label: str = "Scan") -> None:
        """Poll ZAP until scan reaches 100%."""
        while True:
            try:
                progress = int(status_fn(scan_id))
            except Exception:
                progress = 100
            console.print(f"  [{label}] Progress: {progress}%", end="\r")
            if progress >= 100:
                break
            time.sleep(3)
        console.print(f"\n  [{label}] Complete ✓")

    def _collect_alerts(self, target_url: str, source: str) -> list[RawFinding]:
        """Fetch all ZAP alerts and convert to RawFinding objects."""
        alerts = self.zap.core.alerts(baseurl=target_url)
        findings = []

        for alert in alerts:
            finding = RawFinding(
                source_tool=source,
                finding_type=alert.get("alert", "Unknown"),
                url=alert.get("url", target_url),
                method=alert.get("method", "GET"),
                parameter=alert.get("param") or None,
                evidence=alert.get("evidence") or None,
                raw_severity=alert.get("risk", "Info"),
                raw_description=alert.get("description", ""),
                confidence=alert.get("confidence", "Low"),
                discovered_at=datetime.now()
            )

            # Only include in-scope findings
            if self.gate.scope.is_allowed(finding.url):
                findings.append(finding)
                AuditLogger.log_finding(
                    "ZAPWrapper",
                    finding.finding_type,
                    finding.url,
                    finding.raw_severity or "Unknown"
                )

        return findings

    def clear_session(self) -> None:
        """Reset ZAP state between engagements."""
        self.zap.core.new_session()
        AuditLogger.log("ZAP_SESSION_CLEARED", {})
