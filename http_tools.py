"""
tools/http_tools.py
────────────────────
Two tools:
  1. HTTPProber      — discovers hosts, fingerprints tech stack
  2. AuthTool        — handles login and session management for authenticated testing

WHY a separate auth tool?
  Authentication testing is the most sensitive part of pentesting.
  A separate, audited tool keeps login logic isolated, traceable,
  and easy to review or disable.
"""

from __future__ import annotations

import re
import httpx
from typing import Optional
from datetime import datetime

from schemas import Host, AuthSession, TargetCredentials
from safety_layer import SafetyGate, AuditLogger
from rich.console import Console

console = Console()


# ─── 1. HTTP PROBER ───────────────────────────────────────────────────────────

class HTTPProber:
    """
    Probes URLs to determine:
      - Is the host alive?
      - What server/tech is it running?
      - What HTTP headers does it return?
      - Are there redirects?

    This is always the FIRST tool called in any engagement.
    No point scanning a host that's offline.
    """

    def __init__(self, gate: SafetyGate):
        self.gate = gate
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            verify=False  # DVWA/JuiceShop may use self-signed certs
        )

    def probe(self, url: str) -> Optional[Host]:
        """
        Probe a single URL. Returns a Host object or None if unreachable.
        """
        self.gate.check_and_acquire(url, agent_name="HTTPProber")

        try:
            console.print(f"[cyan]🔍 Probing:[/cyan] {url}")
            response = self.client.get(url)

            host = Host(
                url=str(response.url),
                status_code=response.status_code,
                server_header=response.headers.get("server"),
                technologies=self._detect_technologies(response),
                discovered_at=datetime.now()
            )

            AuditLogger.log_tool_call(
                "HTTPProber", "probe", url,
                {},
                f"Status {host.status_code}, Server: {host.server_header}, "
                f"Tech: {host.technologies}"
            )

            console.print(
                f"[green]  ✓ {url}[/green] — "
                f"[yellow]{host.status_code}[/yellow] | "
                f"{host.server_header} | {host.technologies}"
            )
            return host

        except (httpx.ConnectError, httpx.TimeoutException) as e:
            console.print(f"[red]  ✗ {url} — unreachable: {e}[/red]")
            AuditLogger.log("PROBE_FAILED", {"url": url, "error": str(e)})
            return None

    def probe_paths(self, base_url: str, paths: list[str]) -> list[Host]:
        """
        Probe a list of specific paths on a base URL.
        Used for common path discovery: /admin, /api, /login, etc.
        """
        found = []
        for path in paths:
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            if not self.gate.scope.is_allowed(url):
                continue
            result = self.probe(url)
            if result and result.status_code not in [404, 410]:
                found.append(result)
        return found

    def _detect_technologies(self, response: httpx.Response) -> list[str]:
        """
        Infer technologies from HTTP response headers and body.
        This is 'passive fingerprinting' — no extra requests needed.
        """
        techs = []
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text[:5000]  # first 5KB is enough for fingerprinting

        # Server header
        if "server" in headers:
            techs.append(headers["server"])

        # Common tech fingerprints
        fingerprints = {
            "X-Powered-By":        headers.get("x-powered-by", ""),
            "X-Generator":         headers.get("x-generator", ""),
            "X-Drupal-Cache":      headers.get("x-drupal-cache", ""),
            "Django":              "csrftoken" in headers.get("set-cookie", ""),
            "Laravel":             "laravel_session" in headers.get("set-cookie", ""),
            "WordPress":           "wp-content" in body or "wp-json" in body,
            "React":               "react" in body.lower() or "__reactFiber" in body,
            "jQuery":              "jquery" in body.lower(),
            "Bootstrap":           "bootstrap" in body.lower(),
            "PHP":                 ".php" in str(response.url) or "php" in headers.get("x-powered-by","").lower(),
            "nginx":               "nginx" in headers.get("server","").lower(),
            "Apache":              "apache" in headers.get("server","").lower(),
        }

        for name, detected in fingerprints.items():
            if detected:
                if isinstance(detected, str) and detected:
                    techs.append(f"{name}: {detected}")
                elif detected is True:
                    techs.append(name)

        return list(set(techs))


# ─── 2. AUTH TOOL ─────────────────────────────────────────────────────────────

class AuthTool:
    """
    Handles authentication for pentest targets.

    Supports:
      - Form-based login (DVWA, Juice Shop, most web apps)
      - Token-based (JWT Bearer)
      - Basic auth

    WHY this matters for security testing:
      Many vulnerabilities only appear AFTER login:
        - Broken Access Control (A01): Can user A see user B's data?
        - IDOR: Can you access /api/users/123 when you're user 456?
        - Privilege escalation: Can a regular user reach /admin?

      Without authenticated sessions, you miss the most critical bugs.

    SAFETY: Credentials are ONLY for test accounts on authorized targets.
            Never use production credentials.
    """

    def __init__(self, gate: SafetyGate):
        self.gate = gate
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=15.0,
            verify=False
        )

    # ─── DVWA Login ───────────────────────────────────────────────────────────

    def login_dvwa(self, base_url: str, username: str, password: str) -> AuthSession:
        """
        Login to DVWA (Damn Vulnerable Web Application).

        DVWA login flow:
          1. GET /login.php  → extract CSRF token (user_token)
          2. POST /login.php with username, password, user_token
          3. Check redirect to /index.php → success
          4. Extract PHPSESSID cookie
        """
        login_url = base_url.rstrip("/") + "/login.php"
        self.gate.check_and_acquire(login_url, agent_name="AuthTool.dvwa")

        console.print(f"[cyan]🔐 Logging into DVWA as '{username}'...[/cyan]")
        AuditLogger.log("AUTH_ATTEMPT", {"target": "dvwa", "url": login_url, "user": username})

        try:
            # Step 1: GET login page — extract CSRF token
            get_resp = self.client.get(login_url)
            user_token = self._extract_csrf_token(get_resp.text, field_name="user_token")

            # Step 2: POST credentials
            post_resp = self.client.post(login_url, data={
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": user_token
            })

            # Step 3: Verify success
            if "index.php" in str(post_resp.url) or "Welcome" in post_resp.text:
                session = AuthSession(
                    username=username,
                    role="admin" if username == "admin" else "user",
                    cookies=dict(self.client.cookies),
                    login_successful=True
                )
                console.print(f"[green]  ✓ DVWA login successful as '{username}'[/green]")
                AuditLogger.log("AUTH_SUCCESS", {"target": "dvwa", "user": username})
                return session
            else:
                console.print(f"[red]  ✗ DVWA login failed[/red]")
                AuditLogger.log("AUTH_FAILED", {"target": "dvwa", "user": username})
                return AuthSession(username=username, role="unknown", login_successful=False)

        except Exception as e:
            AuditLogger.log("AUTH_ERROR", {"error": str(e)})
            return AuthSession(username=username, role="unknown", login_successful=False)

    # ─── Juice Shop Login ─────────────────────────────────────────────────────

    def login_juiceshop(self, base_url: str, email: str, password: str) -> AuthSession:
        """
        Login to OWASP Juice Shop.

        Juice Shop is a modern SPA (React app).
        Login is via REST API — returns a JWT Bearer token.

        Flow:
          POST /rest/user/login  →  { authentication: { token: "eyJ..." } }
        """
        login_url = base_url.rstrip("/") + "/rest/user/login"
        self.gate.check_and_acquire(login_url, agent_name="AuthTool.juiceshop")

        console.print(f"[cyan]🔐 Logging into Juice Shop as '{email}'...[/cyan]")
        AuditLogger.log("AUTH_ATTEMPT", {"target": "juiceshop", "url": login_url, "user": email})

        try:
            resp = self.client.post(login_url, json={
                "email": email,
                "password": password
            })

            data = resp.json()
            token = data.get("authentication", {}).get("token")

            if token:
                session = AuthSession(
                    username=email,
                    role="admin" if "admin" in email else "user",
                    token=token,
                    headers={"Authorization": f"Bearer {token}"},
                    cookies=dict(self.client.cookies),
                    login_successful=True
                )
                console.print(f"[green]  ✓ Juice Shop login successful[/green]")
                AuditLogger.log("AUTH_SUCCESS", {"target": "juiceshop", "user": email})
                return session
            else:
                AuditLogger.log("AUTH_FAILED", {"target": "juiceshop", "user": email})
                return AuthSession(username=email, role="unknown", login_successful=False)

        except Exception as e:
            AuditLogger.log("AUTH_ERROR", {"error": str(e)})
            return AuthSession(username=email, role="unknown", login_successful=False)

    # ─── Access Control Tests ─────────────────────────────────────────────────

    def test_access_control(
        self,
        url: str,
        session_a: AuthSession,
        session_b: Optional[AuthSession] = None
    ) -> dict:
        """
        Test for Broken Access Control (OWASP A01).

        Tests:
          1. Can unauthenticated user access this URL? (should return 401/403)
          2. Can session_b access a resource that belongs to session_a?
          3. Does removing auth token still allow access? (auth bypass)

        Returns a dict of test results for the AnalyzerAgent to interpret.
        """
        self.gate.check_and_acquire(url, agent_name="AuthTool.access_control")

        results = {}

        # Test 1: Unauthenticated access
        unauth_client = httpx.Client(follow_redirects=False, verify=False)
        unauth_resp = unauth_client.get(url)
        results["unauthenticated"] = {
            "status_code": unauth_resp.status_code,
            "accessible": unauth_resp.status_code < 400,
            "issue": unauth_resp.status_code < 400  # True = potential issue
        }

        # Test 2: Session A access (should work)
        auth_headers = {**session_a.headers}
        auth_resp = self.client.get(url, cookies=session_a.cookies, headers=auth_headers)
        results["session_a"] = {
            "username": session_a.username,
            "status_code": auth_resp.status_code,
            "accessible": auth_resp.status_code < 400
        }

        # Test 3: Session B access (if provided) — cross-user access
        if session_b:
            b_headers = {**session_b.headers}
            b_resp = self.client.get(url, cookies=session_b.cookies, headers=b_headers)
            results["session_b_cross_access"] = {
                "username": session_b.username,
                "status_code": b_resp.status_code,
                "accessible": b_resp.status_code < 400,
                "issue": b_resp.status_code < 400  # B shouldn't access A's data
            }

        AuditLogger.log("ACCESS_CONTROL_TEST", {"url": url, "results": results})
        return results

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _extract_csrf_token(self, html: str, field_name: str = "csrf_token") -> str:
        """Extract hidden CSRF token from HTML form."""
        pattern = rf'name=["\']?{field_name}["\']?\s+value=["\']([^"\']+)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
        # Try alternate format
        pattern2 = rf'value=["\']([^"\']+)["\']\s+name=["\']?{field_name}'
        match2 = re.search(pattern2, html, re.IGNORECASE)
        return match2.group(1) if match2 else ""
