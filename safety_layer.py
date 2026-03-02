"""
safety/safety_layer.py
───────────────────────
The FIRST thing built. The LAST thing you'd ever remove.

Three components:
  1. ScopeValidator  — deterministic, no LLM, blocks out-of-scope requests
  2. RateLimiter     — token bucket per host, prevents accidental DoS
  3. AuditLogger     — immutable append-only log of every action

RULE: Every tool wrapper MUST call ScopeValidator.assert_allowed()
      before making ANY network request. No exceptions.
"""

from __future__ import annotations

import json
import time
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from fnmatch import fnmatch
from typing import Optional
from rich.console import Console

console = Console()


# ─── 1. SCOPE VALIDATOR ───────────────────────────────────────────────────────

class ScopeViolationError(Exception):
    """Raised when an agent tries to touch something outside approved scope."""
    pass


class ScopeValidator:
    """
    Deterministic allowlist-based scope checker.

    WHY deterministic (not LLM)?
    An LLM could be prompted or reasoned into thinking an out-of-scope
    target is "close enough." This must be hard logic. No exceptions.

    Supports:
      - Exact URL match:      http://localhost:8888
      - Wildcard host match:  *.example.com
      - IP ranges are NOT supported — keep scope explicit
    """

    def __init__(self, allowed_targets: list[str]):
        self.allowed_targets = allowed_targets
        self._parsed_allowed = [urlparse(t) for t in allowed_targets]
        AuditLogger.log("SCOPE_INIT", {
            "allowed_targets": allowed_targets,
            "count": len(allowed_targets)
        })

    def is_allowed(self, url: str) -> bool:
        """Returns True only if url matches an approved target."""
        try:
            parsed = urlparse(url)
            request_host = parsed.hostname or ""
            request_port = parsed.port

            for allowed in self._parsed_allowed:
                allowed_host = allowed.hostname or ""
                allowed_port = allowed.port

                # Check host match (supports wildcard like *.example.com)
                host_match = (
                    request_host == allowed_host or
                    fnmatch(request_host, allowed_host)
                )

                # Port must match if specified in allowed target
                port_match = (
                    allowed_port is None or
                    request_port == allowed_port
                )

                if host_match and port_match:
                    return True

            return False

        except Exception:
            return False  # if we can't parse it, it's not allowed

    def assert_allowed(self, url: str, agent_name: str = "unknown") -> None:
        """
        Call this before EVERY network request.
        Raises ScopeViolationError if url is out of scope.
        Also logs the check for audit trail.
        """
        allowed = self.is_allowed(url)

        AuditLogger.log("SCOPE_CHECK", {
            "url": url,
            "agent": agent_name,
            "result": "ALLOWED" if allowed else "BLOCKED"
        })

        if not allowed:
            msg = (
                f"SCOPE VIOLATION: Agent '{agent_name}' attempted to access "
                f"'{url}' which is outside the approved scope. "
                f"Allowed: {self.allowed_targets}"
            )
            console.print(f"[bold red]🚫 {msg}[/bold red]")
            raise ScopeViolationError(msg)

        console.print(f"[green]✓ Scope check passed:[/green] {url}")


# ─── 2. RATE LIMITER ──────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter, per host.

    WHY per host?
    Different hosts could legitimately have different rate limits.
    Also prevents one busy host from consuming all your request budget.

    WHY rate limit at all?
    Even "authorized" testing can accidentally DoS a server if you
    blast thousands of requests per second. Active ZAP scans will
    send many requests — this keeps them humane.
    """

    def __init__(self, requests_per_second: float = 5.0):
        self.rps = requests_per_second
        self._buckets: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _get_host(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.hostname}:{parsed.port or 80}"

    def acquire(self, url: str) -> None:
        """Block until this host's rate limit allows a request."""
        host = self._get_host(url)

        with self._lock:
            now = time.monotonic()

            if host not in self._buckets:
                self._buckets[host] = {
                    "tokens": self.rps,
                    "last_check": now
                }

            bucket = self._buckets[host]
            elapsed = now - bucket["last_check"]
            bucket["tokens"] = min(
                self.rps,
                bucket["tokens"] + elapsed * self.rps
            )
            bucket["last_check"] = now

            if bucket["tokens"] < 1:
                sleep_time = (1 - bucket["tokens"]) / self.rps
                time.sleep(sleep_time)
                bucket["tokens"] = 0
            else:
                bucket["tokens"] -= 1

        AuditLogger.log("RATE_LIMIT_ACQUIRE", {"host": host, "url": url})


# ─── 3. AUDIT LOGGER ──────────────────────────────────────────────────────────

class AuditLogger:
    """
    Immutable append-only audit log.

    WHY immutable?
    The audit log proves what the system did (and didn't do).
    If a client asks "did your agent touch /admin/secret?" — the log answers.
    Making it append-only means no entry can be retroactively deleted.

    Format: JSONL (one JSON object per line) — easy to parse, easy to stream.
    """

    _log_path: Optional[Path] = None
    _lock = threading.Lock()
    _engagement_id: str = "unset"

    @classmethod
    def initialize(cls, engagement_id: str, log_dir: str = "./output/logs") -> None:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        cls._log_path = Path(log_dir) / f"audit_{engagement_id}.jsonl"
        cls._engagement_id = engagement_id
        cls.log("AUDIT_START", {
            "engagement_id": engagement_id,
            "log_path": str(cls._log_path)
        })
        console.print(f"[cyan]📋 Audit log:[/cyan] {cls._log_path}")

    @classmethod
    def log(cls, event_type: str, data: dict) -> None:
        """Write one audit entry. Thread-safe. Never raises — log failures silently."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engagement_id": cls._engagement_id,
            "event": event_type,
            **data
        }

        if cls._log_path is None:
            return  # not yet initialized — skip

        try:
            with cls._lock:
                with open(cls._log_path, "a") as f:
                    f.write(json.dumps(entry) + "\n")
        except Exception:
            pass  # audit logging must never crash the agent

    @classmethod
    def log_tool_call(
        cls,
        agent: str,
        tool: str,
        target: str,
        params: dict,
        result_summary: str
    ) -> None:
        """Convenience method specifically for tool invocations."""
        cls.log("TOOL_CALL", {
            "agent": agent,
            "tool": tool,
            "target": target,
            "params": params,
            "result_summary": result_summary
        })

    @classmethod
    def log_finding(cls, agent: str, finding_type: str, url: str, severity: str) -> None:
        cls.log("FINDING_DISCOVERED", {
            "agent": agent,
            "finding_type": finding_type,
            "url": url,
            "severity": severity
        })

    @classmethod
    def log_phase_transition(cls, from_phase: str, to_phase: str, reason: str) -> None:
        cls.log("PHASE_TRANSITION", {
            "from": from_phase,
            "to": to_phase,
            "reason": reason
        })


# ─── 4. SAFETY GATE — wraps all tool calls ────────────────────────────────────

class SafetyGate:
    """
    Convenience class that bundles scope + rate limit checks.
    Every tool wrapper uses this. One call = all safety checks.

    Usage:
        gate = SafetyGate(scope_validator, rate_limiter)
        gate.check_and_acquire("http://localhost:8888/login", agent_name="ScannerAgent")
    """

    def __init__(self, scope: ScopeValidator, rate_limiter: RateLimiter):
        self.scope = scope
        self.rate = rate_limiter

    def check_and_acquire(self, url: str, agent_name: str = "unknown") -> None:
        """Scope check first, then acquire rate limit token. Order matters."""
        self.scope.assert_allowed(url, agent_name=agent_name)
        self.rate.acquire(url)
