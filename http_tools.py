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

    def detect_spa(self, base_url: str) -> dict:
        """
        Detect if target is a Single Page Application.

        SPAs (Angular, React, Vue) use client-side routing — the server returns
        the SAME index.html shell for every path. This means HTTP 200 is NOT a
        reliable indicator that an endpoint exists or has real content.

        Detection: request 3 random nonsense paths. If responses are identical
        to the homepage, the target is an SPA.
        """
        self.gate.check_and_acquire(base_url, agent_name="HTTPProber.spa_detect")

        # Get baseline (homepage)
        try:
            baseline_resp = self.client.get(base_url)
            baseline_body = baseline_resp.text.strip()
            baseline_status = baseline_resp.status_code
        except Exception:
            return {"is_spa": False, "framework": None, "evidence": "Could not reach target"}

        # Request 3 random nonsense paths that definitely don't exist
        fake_paths = ["/xyzzy-test-void-1", "/qwerty-fake-void-2", "/asdf-none-void-3"]
        identical_count = 0

        for path in fake_paths:
            url = base_url.rstrip("/") + path
            if not self.gate.scope.is_allowed(url):
                continue
            try:
                self.gate.check_and_acquire(url, agent_name="HTTPProber.spa_detect")
                resp = self.client.get(url)
                if resp.status_code == 200 and resp.text.strip() == baseline_body:
                    identical_count += 1
            except Exception:
                pass

        is_spa = identical_count >= 2  # 2+ out of 3 fake paths return same body = SPA

        # Detect framework from baseline
        framework = None
        body = baseline_body[:5000]
        if "ng-version" in body or "ng-app" in body or "<app-root" in body:
            framework = "Angular"
        elif "__reactFiber" in body or "_reactRoot" in body or "react-root" in body:
            framework = "React"
        elif "__vue__" in body or "data-v-" in body:
            framework = "Vue.js"
        elif "__next" in body or "_next/static" in body:
            framework = "Next.js"

        evidence = (
            f"{identical_count}/3 random paths returned identical "
            f"{len(baseline_body)}-byte response (HTTP {baseline_status}). "
            f"All routes serve the same shell — HTTP status codes are NOT reliable."
        ) if is_spa else (
            "Server returns different responses for nonexistent paths — server-rendered."
        )

        result = {
            "is_spa": is_spa,
            "framework": framework,
            "evidence": evidence,
            "baseline_size": len(baseline_body)
        }

        if is_spa:
            console.print(
                f"[bold yellow]⚠ SPA DETECTED:[/bold yellow] "
                f"{framework or 'Unknown framework'} — "
                f"HTTP status codes are NOT reliable indicators of endpoint existence"
            )
        else:
            console.print(
                f"[green]✓ Not an SPA — server returns different responses for different paths[/green]"
            )

        AuditLogger.log("SPA_DETECTION", result)
        return result

    def extract_js_endpoints(self, base_url: str) -> list[Host]:
        """
        LinkFinder-style extraction: fetch JavaScript files from the target
        and extract API endpoints using regex patterns.

        Modern SPAs embed API routes as string literals in their compiled
        JavaScript bundles. Extracting these reveals the real API surface
        that the SPA shell hides from traditional crawling.
        """
        import re
        from urllib.parse import urljoin

        self.gate.check_and_acquire(base_url, agent_name="HTTPProber.linkfinder")

        console.print(f"[cyan]  LinkFinder: Scanning JavaScript files for API endpoints...[/cyan]")

        # Step 1: Get main page and find all script src references
        try:
            resp = self.client.get(base_url)
            body = resp.text
        except Exception as e:
            console.print(f"[yellow]  LinkFinder: Could not fetch base page: {e}[/yellow]")
            return []

        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        script_urls = [urljoin(base_url, s) for s in script_pattern.findall(body)]

        # Filter to in-scope scripts only
        script_urls = [s for s in script_urls if self.gate.scope.is_allowed(s)]

        console.print(f"[cyan]  LinkFinder: Found {len(script_urls)} in-scope JavaScript files[/cyan]")

        # Step 2: Fetch each JS file and extract endpoint patterns
        endpoint_patterns = [
            # REST-style paths: /api/..., /rest/..., /v1/...
            re.compile(r'["\'](/(?:api|rest|v[0-9]+)/[a-zA-Z0-9/_\-]+)["\']'),
            # Relative paths with at least one slash segment
            re.compile(r'["\'](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9/_\-]+)["\']'),
            # Full URLs pointing to same host with api/rest path
            re.compile(r'["\'](https?://[^"\']+/(?:api|rest)/[^"\']*)["\']'),
        ]

        skip_extensions = [
            '.js', '.css', '.png', '.jpg', '.svg', '.gif',
            '.woff', '.woff2', '.ttf', '.ico', '.map', '.eot',
            'node_modules', 'webpack', 'polyfill', 'vendor', 'chunk',
            '__webpack', 'sourcemap', '.scss', '.less'
        ]

        found_paths: set[str] = set()
        scripts_scanned = 0
        for script_url in script_urls[:10]:  # Limit to 10 scripts
            try:
                self.gate.check_and_acquire(script_url, agent_name="HTTPProber.linkfinder")
                js_resp = self.client.get(script_url)
                js_text = js_resp.text
                scripts_scanned += 1

                for pattern in endpoint_patterns:
                    for match in pattern.findall(js_text):
                        path = match.strip()
                        if any(skip in path.lower() for skip in skip_extensions):
                            continue
                        if len(path) < 4 or len(path) > 100:
                            continue
                        found_paths.add(path)
            except Exception:
                continue

        console.print(f"[cyan]  LinkFinder: Extracted {len(found_paths)} unique endpoint paths[/cyan]")
        AuditLogger.log("LINKFINDER_EXTRACTION", {
            "scripts_scanned": scripts_scanned,
            "endpoints_found": len(found_paths),
            "sample_endpoints": sorted(found_paths)[:10]
        })

        # Step 3: Probe each discovered endpoint
        discovered = []
        for path in sorted(found_paths)[:30]:  # Limit to 30 endpoints
            if path.startswith('http'):
                url = path
            else:
                url = base_url.rstrip("/") + "/" + path.lstrip("/")

            if not self.gate.scope.is_allowed(url):
                continue

            result = self.probe(url)
            if result and result.status_code not in [404, 410]:
                discovered.append(result)

        console.print(f"[green]  LinkFinder: {len(discovered)} endpoints confirmed alive[/green]")
        return discovered

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
        x_powered = headers.get("x-powered-by", "").lower()
        fingerprints = {
            "X-Powered-By":        headers.get("x-powered-by", ""),
            "X-Generator":         headers.get("x-generator", ""),
            "X-Drupal-Cache":      headers.get("x-drupal-cache", ""),
            "Django":              "csrftoken" in headers.get("set-cookie", ""),
            "Laravel":             "laravel_session" in headers.get("set-cookie", ""),
            "WordPress":           "wp-content" in body or "wp-json" in body,
            "React":               "__reactFiber" in body or "_reactRoot" in body or "react-root" in body,
            "Angular":             "ng-version" in body or "ng-app" in body or "<app-root" in body,
            "Vue.js":              "__vue__" in body or "data-v-" in body or "vue-router" in body.lower(),
            "Next.js":             "__next" in body or "_next/static" in body,
            "Express":             "express" in x_powered,
            "jQuery":              "jquery" in body.lower(),
            "Bootstrap":           "bootstrap" in body.lower(),
            "PHP":                 ".php" in str(response.url) or "php" in x_powered,
            "Node.js":             "express" in x_powered or "koa" in x_powered,
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

    def _is_real_content(self, response_a: httpx.Response, response_b: httpx.Response) -> bool:
        """
        Detect SPA false positives: if the unauthenticated response body is
        nearly identical to the authenticated response body, the server is
        likely returning the same SPA shell for both — not real content.

        Returns True only if the responses have meaningfully different bodies.
        """
        body_a = response_a.text.strip()
        body_b = response_b.text.strip()

        # If bodies are identical, the server is returning the same SPA shell
        if body_a == body_b:
            return False

        # Short bodies with very similar length are likely the same template
        if len(body_a) > 0 and len(body_b) > 0:
            length_ratio = min(len(body_a), len(body_b)) / max(len(body_a), len(body_b))
            if length_ratio > 0.95 and len(body_a) < 5000:
                return False

        return True

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

        Handles:
          - 3xx redirects (e.g. to login) are NOT treated as "accessible"
          - SPA false positives: if unauth response body matches auth response,
            the server is returning the same SPA shell, not real content

        Returns a dict of test results for the AnalyzerAgent to interpret.
        """
        self.gate.check_and_acquire(url, agent_name="AuthTool.access_control")

        results = {}

        # Test 1: Unauthenticated access
        unauth_client = httpx.Client(follow_redirects=False, verify=False, timeout=10.0)
        unauth_resp = unauth_client.get(url)

        # 3xx redirects (e.g. to /login) mean access IS properly restricted
        is_redirect = 300 <= unauth_resp.status_code < 400
        is_ok = unauth_resp.status_code < 300

        results["unauthenticated"] = {
            "status_code": unauth_resp.status_code,
            "accessible": is_ok,
            "redirected": is_redirect,
            "issue": False  # will be determined after SPA check below
        }

        # Test 2: Session A access (should work — this is the baseline)
        auth_headers = {**session_a.headers}
        auth_resp = self.client.get(url, cookies=session_a.cookies, headers=auth_headers)
        results["session_a"] = {
            "username": session_a.username,
            "status_code": auth_resp.status_code,
            "accessible": auth_resp.status_code < 300
        }

        # Determine if unauthenticated 200 is a real issue or SPA false positive
        if is_ok:
            # Compare unauth vs auth response bodies to detect SPA shell
            is_real = self._is_real_content(unauth_resp, auth_resp)
            results["unauthenticated"]["issue"] = is_real
            results["unauthenticated"]["spa_check"] = "different_content" if is_real else "same_spa_shell"
        else:
            results["unauthenticated"]["issue"] = False

        # Test 3: Session B access (if provided) — cross-user access
        if session_b:
            b_headers = {**session_b.headers}
            b_resp = self.client.get(url, cookies=session_b.cookies, headers=b_headers)
            b_is_ok = b_resp.status_code < 300
            results["session_b_cross_access"] = {
                "username": session_b.username,
                "status_code": b_resp.status_code,
                "accessible": b_is_ok,
                "issue": b_is_ok and self._is_real_content(b_resp, auth_resp)
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
