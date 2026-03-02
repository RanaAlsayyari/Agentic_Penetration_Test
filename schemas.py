"""
models/schemas.py
─────────────────
Typed data contracts between all agents.
Every agent input and output is validated through these Pydantic models.
Think of these as the API spec for inter-agent communication.
"""

from __future__ import annotations
from enum import Enum
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, HttpUrl, field_validator


# ─── Enumerations ─────────────────────────────────────────────────────────────

class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE  = "active"

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"

class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL     = "A01:2021 - Broken Access Control"
    A02_CRYPTO_FAILURES           = "A02:2021 - Cryptographic Failures"
    A03_INJECTION                 = "A03:2021 - Injection"
    A04_INSECURE_DESIGN           = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIG        = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS     = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES             = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY            = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES          = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF                      = "A10:2021 - Server-Side Request Forgery"
    UNKNOWN                       = "Unknown"

class AgentPhase(str, Enum):
    RECON          = "reconnaissance"
    MAPPING        = "surface_mapping"
    AUTH_TEST      = "authentication_testing"
    ACTIVE_SCAN    = "active_scanning"
    ACCESS_CONTROL = "access_control_testing"
    ANALYSIS       = "analysis"
    REPORTING      = "reporting"
    COMPLETE       = "complete"
    ERROR          = "error"


# ─── Core Data Models ─────────────────────────────────────────────────────────

class EngagementConfig(BaseModel):
    """
    The 'contract' document for this pentest engagement.
    Loaded once at startup. Immutable during the run.
    """
    target_url: str
    allowed_targets: list[str]           # whitelist — scope validator uses this
    mode: ScanMode = ScanMode.ACTIVE
    rate_limit_rps: int = 5
    max_scan_depth: int = 3
    credentials: Optional[TargetCredentials] = None
    engagement_id: str = ""

    def model_post_init(self, __context: Any) -> None:
        from datetime import datetime
        if not self.engagement_id:
            self.engagement_id = f"eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


class TargetCredentials(BaseModel):
    username: str
    password: str
    login_url: Optional[str] = None
    auth_type: str = "form"              # form | bearer | basic


class Host(BaseModel):
    """A discovered host/endpoint."""
    url: str
    status_code: Optional[int]    = None
    server_header: Optional[str]  = None
    technologies: list[str]       = []
    open_ports: list[int]         = []
    is_authenticated_area: bool   = False
    discovered_at: datetime       = datetime.now()


class RawFinding(BaseModel):
    """
    Raw output from a scanner tool — NOT yet analyzed.
    Think of this as the tool's stdout, structured.
    """
    source_tool: str                          # "zap" | "nuclei" | "manual"
    finding_type: str                         # e.g. "XSS" | "SQL Injection"
    url: str
    method: str = "GET"
    parameter: Optional[str]     = None       # which input field/param triggered it
    evidence: Optional[str]      = None       # raw response snippet
    raw_severity: Optional[str]  = None       # tool's own severity label
    raw_description: str         = ""
    confidence: Optional[str]    = None       # "High" | "Medium" | "Low"
    discovered_at: datetime      = datetime.now()


class AnalyzedRisk(BaseModel):
    """
    A fully analyzed, LLM-interpreted security risk.
    This is what the reporter uses to write the report.
    """
    id: str
    title: str
    severity: Severity
    owasp_category: OWASPCategory
    affected_url: str
    affected_parameter: Optional[str]  = None
    description: str                          # plain English, for non-technical reader
    technical_detail: str                     # for developer audience
    evidence: Optional[str]            = None # proof of finding
    remediation: str                          # concrete fix steps
    is_false_positive: bool            = False
    cvss_score: Optional[float]        = None
    references: list[str]              = []
    raw_finding: Optional[RawFinding]  = None


class AuthSession(BaseModel):
    """Holds authenticated session state for access control testing."""
    username: str
    role: str                                 # "admin" | "user" | "guest"
    cookies: dict[str, str]     = {}
    headers: dict[str, str]     = {}
    token: Optional[str]        = None
    login_successful: bool      = False


class AgentState(BaseModel):
    """
    The shared state object passed between LangGraph nodes.
    This is THE central nervous system of the agent system.
    Every agent reads from and writes to this.
    """
    # ── Engagement setup ──────────────────────────────────────────────────────
    config: EngagementConfig
    current_phase: AgentPhase = AgentPhase.RECON

    # ── Discovered data ───────────────────────────────────────────────────────
    discovered_hosts: list[Host]            = []
    raw_findings: list[RawFinding]          = []
    analyzed_risks: list[AnalyzedRisk]      = []
    auth_sessions: list[AuthSession]        = []

    # ── Orchestrator reasoning ────────────────────────────────────────────────
    orchestrator_plan: list[str]            = []   # current plan steps
    orchestrator_notes: list[str]           = []   # running commentary
    completed_phases: list[AgentPhase]      = []

    # ── Report ────────────────────────────────────────────────────────────────
    report_path: Optional[str]              = None
    report_summary: Optional[str]           = None

    # ── Error handling ────────────────────────────────────────────────────────
    errors: list[str]                       = []
    warnings: list[str]                     = []

    class Config:
        arbitrary_types_allowed = True
