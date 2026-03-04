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
    A01_BROKEN_ACCESS_CONTROL         = "A01:2025 - Broken Access Control"
    A02_SECURITY_MISCONFIG            = "A02:2025 - Security Misconfiguration"
    A03_SUPPLY_CHAIN_FAILURES         = "A03:2025 - Software Supply Chain Failures"
    A04_CRYPTO_FAILURES               = "A04:2025 - Cryptographic Failures"
    A05_INJECTION                     = "A05:2025 - Injection"
    A06_INSECURE_DESIGN               = "A06:2025 - Insecure Design"
    A07_AUTH_FAILURES                 = "A07:2025 - Authentication Failures"
    A08_DATA_INTEGRITY                = "A08:2025 - Software or Data Integrity Failures"
    A09_LOGGING_FAILURES              = "A09:2025 - Security Logging and Alerting Failures"
    A10_EXCEPTIONAL_CONDITIONS        = "A10:2025 - Mishandling of Exceptional Conditions"
    UNKNOWN                           = "Unknown"

class AgentPhase(str, Enum):
    RECON          = "reconnaissance"
    MAPPING        = "surface_mapping"
    AUTH_TEST      = "authentication_testing"
    ACTIVE_SCAN    = "active_scanning"
    ACCESS_CONTROL = "access_control_testing"
    ANALYSIS       = "analysis"
    CLASSIFICATION = "classification"
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

    FIELDS ARE SPLIT BY AGENT RESPONSIBILITY:

    ── AnalyzerAgent fills these ──────────────────────────────────────────────
    id, title, affected_url, affected_parameter, description, technical_detail,
    evidence, remediation_context, is_false_positive, severity_estimate,
    raw_finding

    ── ClassifierAgent fills these (appended after Analyzer) ──────────────────
    owasp_category, owasp_reference_url, cwe_ids, cwe_primary, cwe_reference_urls,
    cvss_vector, cvss_score, cvss_severity, classification_reasoning,
    severity_discrepancy_note, remediation_standard, classification_confidence

    ── ReporterAgent merges these ─────────────────────────────────────────────
    remediation_final (merged from remediation_context + remediation_standard)
    """

    # ── AnalyzerAgent fields ──────────────────────────────────────────────────
    id: str
    title: str
    affected_url: str
    affected_parameter: Optional[str]       = None
    description: str                                # plain English for business reader
    technical_detail: str                           # for developer audience
    evidence: Optional[str]                 = None  # proof from scanner output
    remediation_context: str                = ""    # context-specific fix for this app
    is_false_positive: bool                 = False
    severity_estimate: Severity             = Severity.INFO  # analyst's human judgment
    raw_finding: Optional[RawFinding]       = None

    # ── ClassifierAgent fields (None until Classifier runs) ───────────────────
    owasp_category: Optional[OWASPCategory] = None
    owasp_reference_url: Optional[str]      = None
    cwe_ids: list[str]                      = []    # e.g. ["CWE-89", "CWE-20"]
    cwe_primary: Optional[str]              = None  # e.g. "CWE-89"
    cwe_reference_urls: list[str]           = []
    cvss_vector: Optional[str]              = None  # e.g. "CVSS:3.1/AV:N/AC:L/..."
    cvss_score: Optional[float]             = None  # e.g. 9.8
    cvss_severity: Optional[Severity]       = None  # derived from cvss_score
    classification_reasoning: Optional[str] = None  # chain-of-thought explanation
    severity_discrepancy_note: Optional[str]= None  # if estimate != cvss_severity
    remediation_standard: Optional[str]    = None  # standard fix from OWASP/CWE
    classification_confidence: Optional[str]= None  # High / Medium / Low

    # ── ReporterAgent merges into this ────────────────────────────────────────
    remediation_final: Optional[str]        = None  # merged remediation for report


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

    # ── SPA detection (set by ReconAgent) ──────────────────────────────────
    is_spa: bool                            = False
    spa_framework: Optional[str]            = None
    spa_evidence: Optional[str]             = None

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