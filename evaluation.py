#!/usr/bin/env python3
"""
evaluation.py
─────────────
Comprehensive three-layer evaluation system for the Agentic Penetration Testing pipeline.

LAYER 1 — Agent-Level:  Did each agent execute, produce valid output, make correct
                         decisions, and hand off correctly to the next agent?
LAYER 2 — Tool-Level:   Are tools configured and used correctly? What is the
                         capability ceiling vs. what the agent actually extracted?
LAYER 3 — System-Level: End-to-end metrics — scoreboard solves, precision, recall,
                         exploit depth, pipeline reliability, time efficiency.

Usage:
  # Evaluate the latest completed engagement
  python evaluation.py

  # Evaluate a specific audit log
  python evaluation.py output/logs/audit_eng_20260304_201254.jsonl

  # Evaluate with a specific report
  python evaluation.py output/logs/audit_eng_20260304_201254.jsonl output/reports/report_eng_20260304_201254.md
"""

from __future__ import annotations

import json
import os
import re
import sys
import glob
import time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# Fix Windows console encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
except ImportError:
    requests = None

# ─── Configuration ───────────────────────────────────────────────────────────

TARGET_URL = os.getenv("TARGET_URL", "http://127.0.0.1:3000")
ZAP_API = os.getenv("ZAP_API", f"http://{os.getenv('ZAP_HOST', 'localhost')}:{os.getenv('ZAP_PORT', '8080')}")
ZAP_KEY = os.getenv("ZAP_API_KEY", "changeme")

# Known Juice Shop API routes (ground truth for endpoint coverage)
KNOWN_JUICESHOP_ENDPOINTS = [
    "/rest/user/login",
    "/rest/user/whoami",
    "/rest/user/change-password",
    "/rest/products/search",
    "/rest/basket",
    "/rest/saveLoginIp",
    "/rest/deluxe-membership",
    "/rest/memories",
    "/rest/chatbot",
    "/rest/track-order",
    "/rest/country-mapping",
    "/rest/2fa/status",
    "/api/Users",
    "/api/Products",
    "/api/Feedbacks",
    "/api/Challenges",
    "/api/Complaints",
    "/api/Recycles",
    "/api/SecurityQuestions",
    "/api/SecurityAnswers",
    "/api/Quantitys",
    "/api/Cards",
    "/api/Deliverys",
    "/api/Addresss",
    "/api/BasketItems",
    "/api/Wallets",
    "/b2b/v2/orders",
    "/file-upload",
    "/profile",
    "/ftp",
    "/snippets",
    "/metrics",
    "/promotion",
    "/video",
    "/dataerasure",
    "/redirect",
    "/login",
    "/register",
    "/search",
    "/contact",
    "/about",
    "/photo-wall",
    "/complain",
    "/chatbot",
    "/score-board",
    "/administration",
    "/accounting",
    "/privacy-security",
    "/wallet",
    "/order-history",
    "/address",
    "/payment",
    "/delivery-method",
    "/order-summary",
    "/order-completion",
    "/track-result",
    "/recycle",
    "/saved-payment-methods",
]

# Known Juice Shop tech stack components
KNOWN_TECH_STACK = [
    "Angular",       # or React (depends on version; recent = Angular)
    "Node.js",
    "Express",
    "SQLite",
    "JWT",
]

# OWASP category mappings (ground truth for classifier validation)
CORRECT_OWASP_MAPPINGS = {
    "SQL Injection":               "A05",
    "Cross-Site Scripting":        "A05",
    "XSS":                         "A05",
    "Weak Credentials":            "A07",
    "Default Credentials":         "A07",
    "Weak/Default Credentials":    "A07",
    "Broken Access Control":       "A01",
    "IDOR":                        "A01",
    "CORS":                        "A02",
    "Cross-Domain Misconfiguration": "A02",
    "CSP":                         "A02",
    "Content Security Policy":     "A02",
    "Error Disclosure":            "A02",
    "Application Error Disclosure":"A02",
    "Private IP Disclosure":       "A02",
    "Information Disclosure":      "A02",
    "Path Traversal":              "A01",
    "Command Injection":           "A05",
    "CSRF":                        "A01",
    "Cryptographic Failures":      "A04",
    "Insecure Design":             "A06",
}

# Alert types that the Analyzer should always filter out
KNOWN_NOISE_ALERTS = {
    "Timestamp Disclosure - Unix",
    "Modern Web Application",
    "User Agent Fuzzer",
    "Session Management Response Identified",
    "Re-examine Cache-control Directives",
    "Information Disclosure - Suspicious Comments",
}

# CWE mappings for common finding types
CORRECT_CWE_MAPPINGS = {
    "SQL Injection":            "CWE-89",
    "Cross-Site Scripting":     "CWE-79",
    "XSS":                      "CWE-79",
    "Path Traversal":           "CWE-22",
    "Command Injection":        "CWE-78",
    "CORS":                     "CWE-942",
    "Cross-Domain Misconfiguration": "CWE-942",
    "CSRF":                     "CWE-352",
    "Weak Credentials":         "CWE-521",
    "Default Credentials":      "CWE-798",
    "Weak/Default Credentials": "CWE-521",
    "Private IP Disclosure":    "CWE-200",
    "Error Disclosure":         "CWE-209",
    "Application Error Disclosure": "CWE-209",
}


# ─── Data Structures ────────────────────────────────────────────────────────

@dataclass
class TestResult:
    """A single evaluation test result."""
    name: str
    layer: str       # "agent", "tool", "system"
    agent: str       # which agent/tool/system component
    passed: bool
    score: float     # 0.0 to 1.0
    detail: str = ""
    metric_value: Optional[float] = None
    metric_unit: str = ""

@dataclass
class LayerScore:
    """Aggregated score for one evaluation layer."""
    layer: str
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    avg_score: float = 0.0
    results: list = field(default_factory=list)

@dataclass
class EvaluationReport:
    """Complete evaluation report across all layers."""
    timestamp: str = ""
    engagement_id: str = ""
    audit_log_path: str = ""
    report_path: str = ""
    agent_layer: LayerScore = field(default_factory=lambda: LayerScore("agent"))
    tool_layer: LayerScore = field(default_factory=lambda: LayerScore("tool"))
    system_layer: LayerScore = field(default_factory=lambda: LayerScore("system"))
    composite_score: float = 0.0
    composite_breakdown: dict = field(default_factory=dict)


# ─── Audit Log Helpers ───────────────────────────────────────────────────────

def load_audit_log(path: str) -> list[dict]:
    """Load and parse JSONL audit log."""
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def find_event(log: list[dict], event_name: str, **filters) -> Optional[dict]:
    """Find first event matching name and optional filters."""
    for entry in log:
        if entry.get("event") == event_name:
            if all(entry.get(k) == v for k, v in filters.items()):
                return entry
    return None


def find_all_events(log: list[dict], event_name: str) -> list[dict]:
    """Find all events matching name."""
    return [e for e in log if e.get("event") == event_name]


def find_events_by_prefix(log: list[dict], prefix: str) -> list[dict]:
    """Find all events whose type starts with prefix."""
    return [e for e in log if e.get("event", "").startswith(prefix)]


def load_report(path: str) -> str:
    """Load report markdown file."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def parse_report_findings(report_text: str) -> list[dict]:
    """Extract FINDING-XXX entries from report markdown."""
    findings = []
    finding_pattern = re.compile(r"(FINDING-\d+)")
    finding_ids = set(finding_pattern.findall(report_text))
    for fid in sorted(finding_ids):
        findings.append({"id": fid})
    return findings


def get_engagement_timestamps(log: list[dict]) -> tuple[Optional[str], Optional[str]]:
    """Extract start and end timestamps from audit log."""
    start_event = find_event(log, "ENGAGEMENT_START")
    end_event = find_event(log, "ENGAGEMENT_COMPLETE")
    start_ts = start_event.get("timestamp") if start_event else None
    end_ts = end_event.get("timestamp") if end_event else None
    return start_ts, end_ts


def compute_duration_seconds(start_ts: str, end_ts: str) -> float:
    """Compute duration between two ISO timestamps."""
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    try:
        start = datetime.strptime(start_ts, fmt)
        end = datetime.strptime(end_ts, fmt)
        return (end - start).total_seconds()
    except Exception:
        # Try without microseconds
        fmt2 = "%Y-%m-%dT%H:%M:%SZ"
        try:
            start = datetime.strptime(start_ts, fmt2)
            end = datetime.strptime(end_ts, fmt2)
            return (end - start).total_seconds()
        except Exception:
            return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1: AGENT-LEVEL EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_recon_agent(log: list[dict], report_text: str) -> list[TestResult]:
    """Evaluate Recon Agent: execution, output validity, decision quality, handoff."""
    results = []

    # 1. Did it execute?
    recon_event = find_event(log, "RECON_COMPLETE")
    results.append(TestResult(
        name="recon_executed",
        layer="agent", agent="ReconAgent",
        passed=recon_event is not None,
        score=1.0 if recon_event else 0.0,
        detail=f"Discovered {recon_event.get('discovered_count', 'N/A')} hosts" if recon_event else "RECON_COMPLETE event not found",
    ))

    # 2. Did it discover sufficient endpoints?
    discovered_count = recon_event.get("discovered_count", 0) if recon_event else 0
    # Juice Shop has many paths; 20+ unique endpoints is decent
    endpoint_score = min(1.0, discovered_count / 30.0)
    results.append(TestResult(
        name="recon_endpoint_coverage",
        layer="agent", agent="ReconAgent",
        passed=discovered_count >= 20,
        score=endpoint_score,
        detail=f"Discovered {discovered_count} endpoints (target: >= 20)",
        metric_value=discovered_count,
        metric_unit="endpoints",
    ))

    # 3. SPA Detection — critical decision
    spa_event = find_event(log, "SPA_DETECTION")
    spa_detected = spa_event.get("is_spa", False) if spa_event else False
    results.append(TestResult(
        name="recon_spa_detection",
        layer="agent", agent="ReconAgent",
        passed=spa_detected,  # Juice Shop IS an SPA
        score=1.0 if spa_detected else 0.0,
        detail=f"SPA={spa_detected}, framework={spa_event.get('framework')}" if spa_event else "SPA_DETECTION event not found",
    ))

    # 4. Technology fingerprinting
    tool_calls = find_all_events(log, "TOOL_CALL")
    tech_mentions = set()
    for tc in tool_calls:
        summary = tc.get("result_summary", "")
        for tech in KNOWN_TECH_STACK:
            if tech.lower() in summary.lower():
                tech_mentions.add(tech)
    tech_score = len(tech_mentions) / max(len(KNOWN_TECH_STACK), 1)
    results.append(TestResult(
        name="recon_tech_fingerprinting",
        layer="agent", agent="ReconAgent",
        passed=len(tech_mentions) >= 2,
        score=tech_score,
        detail=f"Identified: {tech_mentions or 'none'} out of {KNOWN_TECH_STACK}",
        metric_value=len(tech_mentions),
        metric_unit="tech components",
    ))

    # 5. Endpoint coverage vs known Juice Shop routes
    probe_calls = [tc for tc in tool_calls if tc.get("tool") == "probe"]
    probed_urls = {tc.get("target", "") for tc in probe_calls}
    known_found = 0
    for known in KNOWN_JUICESHOP_ENDPOINTS:
        for probed in probed_urls:
            if known.lower() in probed.lower():
                known_found += 1
                break
    coverage = known_found / max(len(KNOWN_JUICESHOP_ENDPOINTS), 1)
    results.append(TestResult(
        name="recon_known_endpoint_coverage",
        layer="agent", agent="ReconAgent",
        passed=known_found >= 10,
        score=coverage,
        detail=f"Found {known_found}/{len(KNOWN_JUICESHOP_ENDPOINTS)} known Juice Shop endpoints",
        metric_value=coverage * 100,
        metric_unit="%",
    ))

    # 6. LinkFinder execution
    linkfinder_event = find_event(log, "LINKFINDER_EXTRACTION")
    lf_endpoints = linkfinder_event.get("endpoints_found", 0) if linkfinder_event else 0
    results.append(TestResult(
        name="recon_linkfinder_executed",
        layer="agent", agent="ReconAgent",
        passed=linkfinder_event is not None and lf_endpoints >= 5,
        score=min(1.0, lf_endpoints / 15.0) if linkfinder_event else 0.0,
        detail=f"LinkFinder extracted {lf_endpoints} endpoints from JS files" if linkfinder_event else "LINKFINDER_EXTRACTION not found",
        metric_value=lf_endpoints,
        metric_unit="JS endpoints",
    ))

    # 7. Handoff quality — auth paths preserved for AuthAgent
    auth_related_probed = any(
        "login" in url.lower() or "auth" in url.lower() or "signin" in url.lower()
        for url in probed_urls
    )
    results.append(TestResult(
        name="recon_handoff_auth_paths",
        layer="agent", agent="ReconAgent",
        passed=auth_related_probed,
        score=1.0 if auth_related_probed else 0.0,
        detail="Auth-related paths (login/auth/signin) included in discovery" if auth_related_probed else "No auth paths discovered",
    ))

    return results


def evaluate_auth_agent(log: list[dict]) -> list[TestResult]:
    """Evaluate Auth Agent: authentication method, token validity, finding emission, handoff."""
    results = []

    # 1. Did it execute?
    auth_attempt = find_event(log, "AUTH_ATTEMPT")
    results.append(TestResult(
        name="auth_executed",
        layer="agent", agent="AuthAgent",
        passed=auth_attempt is not None,
        score=1.0 if auth_attempt else 0.0,
        detail=f"Auth attempted on {auth_attempt.get('target', 'unknown')}" if auth_attempt else "No AUTH_ATTEMPT event",
    ))

    # 2. Did it choose the correct auth method?
    correct_method = False
    if auth_attempt:
        target = auth_attempt.get("target", "")
        url = auth_attempt.get("url", "")
        # Juice Shop should use REST API login (JSON POST), not form-based
        if "juiceshop" in target or "3000" in url:
            correct_method = "/rest/user/login" in url
        elif "dvwa" in target or "8888" in url:
            correct_method = "/login.php" in url
        else:
            correct_method = True  # Unknown target, any method is ok
    results.append(TestResult(
        name="auth_correct_method",
        layer="agent", agent="AuthAgent",
        passed=correct_method,
        score=1.0 if correct_method else 0.0,
        detail=f"Used endpoint: {auth_attempt.get('url', 'N/A')}" if auth_attempt else "No auth attempt",
    ))

    # 3. Did authentication succeed?
    auth_success = find_event(log, "AUTH_SUCCESS")
    results.append(TestResult(
        name="auth_succeeded",
        layer="agent", agent="AuthAgent",
        passed=auth_success is not None,
        score=1.0 if auth_success else 0.0,
        detail=f"Logged in as {auth_success.get('user', 'unknown')}" if auth_success else "No AUTH_SUCCESS event",
    ))

    # 4. Did it emit a finding?
    auth_findings = [e for e in find_all_events(log, "FINDING_DISCOVERED") if e.get("agent") == "AuthAgent"]
    results.append(TestResult(
        name="auth_finding_emitted",
        layer="agent", agent="AuthAgent",
        passed=len(auth_findings) > 0,
        score=1.0 if auth_findings else 0.0,
        detail=f"Emitted {len(auth_findings)} finding(s): {[f.get('finding_type','') for f in auth_findings]}" if auth_findings else "No auth findings emitted",
    ))

    # 5. Finding classification quality — weak/default creds or SQLi should be High+
    correct_severity = False
    for af in auth_findings:
        sev = af.get("severity", "").lower()
        ftype = af.get("finding_type", "").lower()
        if ("weak" in ftype or "default" in ftype or "sql" in ftype) and sev in ("high", "critical"):
            correct_severity = True
    results.append(TestResult(
        name="auth_finding_severity_correct",
        layer="agent", agent="AuthAgent",
        passed=correct_severity or len(auth_findings) == 0,
        score=1.0 if correct_severity else (0.5 if len(auth_findings) == 0 else 0.0),
        detail="Auth finding severity matches expected range" if correct_severity else "Severity may not match",
    ))

    # 6. Handoff — token stored in shared state
    scanner_auth = find_event(log, "SCANNER_AUTH_CONTEXT")
    has_auth_context = False
    if scanner_auth:
        has_auth_context = scanner_auth.get("has_headers", False) or scanner_auth.get("has_cookies", False)
    results.append(TestResult(
        name="auth_handoff_to_scanner",
        layer="agent", agent="AuthAgent",
        passed=has_auth_context,
        score=1.0 if has_auth_context else 0.0,
        detail="Auth context passed to Scanner" if has_auth_context else "Scanner did not receive auth context",
    ))

    return results


def evaluate_scanner_agent(log: list[dict]) -> list[TestResult]:
    """Evaluate Scanner Agent: ZAP configuration, AJAX spider, proxy seeding, active scan."""
    results = []

    # 1. Auth context injection
    scanner_auth = find_event(log, "SCANNER_AUTH_CONTEXT")
    auth_injected = scanner_auth is not None and (
        scanner_auth.get("has_headers", False) or scanner_auth.get("has_cookies", False)
    )
    results.append(TestResult(
        name="scanner_auth_injected",
        layer="agent", agent="ScannerAgent",
        passed=auth_injected,
        score=1.0 if auth_injected else 0.0,
        detail="Auth context injected into ZAP" if auth_injected else "No auth context for ZAP",
    ))

    # 2. AJAX Spider execution (critical for SPAs)
    ajax_events = [e for e in find_all_events(log, "TOOL_CALL") if e.get("tool") == "ajax_spider"]
    ajax_complete = [e for e in find_all_events(log, "TOOL_CALL") if e.get("tool") == "ajax_spider_complete"]
    ajax_ran = len(ajax_events) > 0
    ajax_urls = 0
    if ajax_complete:
        match = re.search(r"(\d+)\s*URLs", ajax_complete[0].get("result_summary", ""))
        if match:
            ajax_urls = int(match.group(1))
    results.append(TestResult(
        name="scanner_ajax_spider",
        layer="agent", agent="ScannerAgent",
        passed=ajax_ran,
        score=1.0 if ajax_ran else 0.0,
        detail=f"AJAX Spider discovered {ajax_urls} URLs" if ajax_ran else "AJAX Spider did not run",
        metric_value=ajax_urls,
        metric_unit="URLs",
    ))

    # 3. API endpoint seeding
    seed_event = find_event(log, "SCANNER_API_SEEDS")
    api_seeds = seed_event.get("api_endpoint_count", 0) if seed_event else 0
    results.append(TestResult(
        name="scanner_api_seeded",
        layer="agent", agent="ScannerAgent",
        passed=api_seeds >= 10,
        score=min(1.0, api_seeds / 15.0),
        detail=f"Seeded {api_seeds} API endpoints",
        metric_value=api_seeds,
        metric_unit="endpoints",
    ))

    # 4. Proxy seeding
    proxy_event = find_event(log, "PROXY_SEED_COMPLETE")
    proxy_seeded = proxy_event.get("requests_seeded", 0) if proxy_event else 0
    results.append(TestResult(
        name="scanner_proxy_seeded",
        layer="agent", agent="ScannerAgent",
        passed=proxy_seeded >= 30,
        score=min(1.0, proxy_seeded / 50.0),
        detail=f"Proxy-seeded {proxy_seeded} request/param combinations",
        metric_value=proxy_seeded,
        metric_unit="requests",
    ))

    # 5. Active scan execution
    active_start = [e for e in find_all_events(log, "TOOL_CALL") if e.get("tool") == "active_scan_start"]
    active_complete = [e for e in find_all_events(log, "TOOL_CALL") if e.get("tool") == "active_scan_complete"]
    active_ran = len(active_start) > 0
    active_alerts = 0
    if active_complete:
        match = re.search(r"(\d+)\s*alerts", active_complete[0].get("result_summary", ""))
        if match:
            active_alerts = int(match.group(1))
    results.append(TestResult(
        name="scanner_active_scan",
        layer="agent", agent="ScannerAgent",
        passed=active_ran,
        score=1.0 if active_ran else 0.0,
        detail=f"Active scan found {active_alerts} alerts" if active_ran else "Active scan did not run",
        metric_value=active_alerts,
        metric_unit="alerts",
    ))

    # 6. ZAP High alerts found
    findings = find_all_events(log, "FINDING_DISCOVERED")
    zap_findings = [f for f in findings if f.get("agent") == "ZAPWrapper"]
    high_findings = [f for f in zap_findings if f.get("severity", "").lower() in ("high", "critical")]
    results.append(TestResult(
        name="scanner_high_alerts",
        layer="agent", agent="ScannerAgent",
        passed=len(high_findings) >= 1,
        score=min(1.0, len(high_findings) / 3.0),
        detail=f"ZAP found {len(high_findings)} High/Critical alerts out of {len(zap_findings)} total",
        metric_value=len(high_findings),
        metric_unit="high alerts",
    ))

    # 7. Output validity — findings have required fields
    valid_findings = 0
    for f in zap_findings:
        has_url = bool(f.get("url"))
        has_type = bool(f.get("finding_type"))
        if has_url and has_type:
            valid_findings += 1
    validity_score = valid_findings / max(len(zap_findings), 1)
    results.append(TestResult(
        name="scanner_output_validity",
        layer="agent", agent="ScannerAgent",
        passed=validity_score >= 0.9,
        score=validity_score,
        detail=f"{valid_findings}/{len(zap_findings)} findings have valid schema",
    ))

    return results


def evaluate_analyzer_agent(log: list[dict]) -> list[TestResult]:
    """Evaluate Analyzer Agent: noise filtering, FP detection, severity calibration, deduplication."""
    results = []

    # 1. Noise filtering
    noise_event = find_event(log, "NOISE_FILTERED")
    noise_removed = noise_event.get("noise_removed", 0) if noise_event else 0
    noise_ran = noise_event is not None
    results.append(TestResult(
        name="analyzer_noise_filtered",
        layer="agent", agent="AnalyzerAgent",
        passed=noise_ran,
        score=1.0 if noise_ran else 0.0,
        detail=f"Pre-filtered {noise_removed} noise alerts" if noise_ran else "NOISE_FILTERED event not found",
        metric_value=noise_removed,
        metric_unit="noise alerts",
    ))

    # 2. False positive rejection
    fp_events = find_all_events(log, "FALSE_POSITIVE_SKIPPED")
    results.append(TestResult(
        name="analyzer_fp_filtering",
        layer="agent", agent="AnalyzerAgent",
        passed=True,  # Any number of FPs is valid as long as the filter ran
        score=1.0,
        detail=f"Rejected {len(fp_events)} false positives: {[e.get('title','')[:40] for e in fp_events[:5]]}",
        metric_value=len(fp_events),
        metric_unit="false positives",
    ))

    # 3. True positive retention — High-confidence ZAP findings should survive
    all_findings = find_all_events(log, "FINDING_DISCOVERED")
    zap_high = [f for f in all_findings if f.get("agent") == "ZAPWrapper" and f.get("severity", "").lower() in ("high", "critical")]
    analyzer_findings = [f for f in all_findings if f.get("agent") == "AnalyzerAgent"]
    # Check that analyzer produced findings from ZAP high alerts
    retained_high = 0
    for zh in zap_high:
        zap_type = zh.get("finding_type", "").lower()
        for af in analyzer_findings:
            if zap_type in af.get("finding_type", "").lower() or zap_type[:10] in af.get("url", "").lower():
                retained_high += 1
                break
    retention_rate = retained_high / max(len(zap_high), 1) if zap_high else 1.0
    results.append(TestResult(
        name="analyzer_true_positive_retention",
        layer="agent", agent="AnalyzerAgent",
        passed=retention_rate >= 0.8,
        score=retention_rate,
        detail=f"Retained {retained_high}/{len(zap_high)} ZAP High/Critical findings",
        metric_value=retention_rate * 100,
        metric_unit="%",
    ))

    # 4. Analyzer produced output
    results.append(TestResult(
        name="analyzer_output_produced",
        layer="agent", agent="AnalyzerAgent",
        passed=len(analyzer_findings) > 0,
        score=min(1.0, len(analyzer_findings) / 3.0),
        detail=f"Analyzer produced {len(analyzer_findings)} confirmed findings",
        metric_value=len(analyzer_findings),
        metric_unit="findings",
    ))

    # 5. No rate limit / 429 errors
    all_errors = [e for e in log if e.get("event") in ("ERROR", "EXCEPTION")
                  or "rate_limit" in str(e.get("error", "")).lower()
                  or "429" in str(e.get("error", ""))]
    results.append(TestResult(
        name="analyzer_no_rate_errors",
        layer="agent", agent="AnalyzerAgent",
        passed=len(all_errors) == 0,
        score=1.0 if len(all_errors) == 0 else 0.0,
        detail=f"{len(all_errors)} rate limit / API errors found" if all_errors else "No rate limit errors",
    ))

    return results


def evaluate_classifier_agent(log: list[dict], report_text: str) -> list[TestResult]:
    """Evaluate Classifier Agent: OWASP mapping, CWE accuracy, CVSS accuracy."""
    results = []

    # 1. Did it execute?
    classified = find_all_events(log, "FINDING_CLASSIFIED")
    results.append(TestResult(
        name="classifier_executed",
        layer="agent", agent="ClassifierAgent",
        passed=len(classified) > 0,
        score=1.0 if classified else 0.0,
        detail=f"Classified {len(classified)} findings",
    ))

    # 2. OWASP category accuracy — validate from report
    owasp_correct = 0
    owasp_total = 0
    owasp_details = []
    for ce in classified:
        owasp_cat = ce.get("owasp_category", "")
        finding_title = ce.get("title", "")
        owasp_total += 1
        # Check against known mappings
        matched = False
        for pattern, expected_code in CORRECT_OWASP_MAPPINGS.items():
            if pattern.lower() in finding_title.lower():
                if expected_code.lower() in owasp_cat.lower():
                    owasp_correct += 1
                    matched = True
                    owasp_details.append(f"OK: {finding_title[:30]} -> {owasp_cat}")
                else:
                    owasp_details.append(f"WRONG: {finding_title[:30]} -> {owasp_cat} (expected {expected_code})")
                    matched = True
                break
        if not matched:
            owasp_correct += 1  # Unknown mapping, assume correct
            owasp_details.append(f"UNVERIFIED: {finding_title[:30]} -> {owasp_cat}")

    owasp_accuracy = owasp_correct / max(owasp_total, 1)
    results.append(TestResult(
        name="classifier_owasp_accuracy",
        layer="agent", agent="ClassifierAgent",
        passed=owasp_accuracy >= 0.8,
        score=owasp_accuracy,
        detail=f"{owasp_correct}/{owasp_total} correct. {'; '.join(owasp_details[:5])}",
        metric_value=owasp_accuracy * 100,
        metric_unit="%",
    ))

    # 3. CWE accuracy
    cwe_correct = 0
    cwe_total = 0
    for ce in classified:
        cwe_primary = ce.get("cwe_primary", "")
        finding_title = ce.get("title", "")
        if cwe_primary:
            cwe_total += 1
            for pattern, expected_cwe in CORRECT_CWE_MAPPINGS.items():
                if pattern.lower() in finding_title.lower():
                    if expected_cwe.lower() in cwe_primary.lower():
                        cwe_correct += 1
                    break
            else:
                cwe_correct += 1  # Unknown, assume correct

    cwe_accuracy = cwe_correct / max(cwe_total, 1)
    results.append(TestResult(
        name="classifier_cwe_accuracy",
        layer="agent", agent="ClassifierAgent",
        passed=cwe_accuracy >= 0.7,
        score=cwe_accuracy,
        detail=f"{cwe_correct}/{cwe_total} CWE mappings validated",
        metric_value=cwe_accuracy * 100,
        metric_unit="%",
    ))

    # 4. CVSS vector present and valid format
    cvss_valid = 0
    cvss_total = 0
    for ce in classified:
        cvss_vec = ce.get("cvss_vector", "")
        if cvss_vec:
            cvss_total += 1
            if cvss_vec.startswith("CVSS:3.1/") and "AV:" in cvss_vec:
                cvss_valid += 1
    cvss_validity = cvss_valid / max(cvss_total, 1)
    results.append(TestResult(
        name="classifier_cvss_valid",
        layer="agent", agent="ClassifierAgent",
        passed=cvss_validity >= 0.9,
        score=cvss_validity,
        detail=f"{cvss_valid}/{cvss_total} CVSS vectors are valid CVSS:3.1 format",
    ))

    # 5. All findings have classification fields
    all_classified = all(
        ce.get("owasp_category") and ce.get("cwe_primary") and ce.get("cvss_vector")
        for ce in classified
    ) if classified else False
    results.append(TestResult(
        name="classifier_completeness",
        layer="agent", agent="ClassifierAgent",
        passed=all_classified,
        score=1.0 if all_classified else 0.5,
        detail="All findings have OWASP + CWE + CVSS" if all_classified else "Some findings missing classification fields",
    ))

    return results


def evaluate_reporter_agent(log: list[dict], report_text: str) -> list[TestResult]:
    """Evaluate Reporter Agent: completeness, evidence quality, remediation specificity."""
    results = []

    # 1. Report generated
    report_event = find_event(log, "REPORT_GENERATED")
    results.append(TestResult(
        name="reporter_executed",
        layer="agent", agent="ReporterAgent",
        passed=report_event is not None,
        score=1.0 if report_event else 0.0,
        detail=f"Report at {report_event.get('path', 'N/A')}" if report_event else "REPORT_GENERATED not found",
    ))

    if not report_text:
        results.append(TestResult(
            name="reporter_file_exists",
            layer="agent", agent="ReporterAgent",
            passed=False, score=0.0,
            detail="Report file not found or empty",
        ))
        return results

    # 2. All findings included in report
    classified = find_all_events(log, "FINDING_CLASSIFIED")
    finding_written = find_all_events(log, "FINDING_WRITTEN")
    expected_ids = {ce.get("id", "") for ce in classified if ce.get("id")}
    found_in_report = set()
    for fid in expected_ids:
        if fid in report_text:
            found_in_report.add(fid)
    missing = expected_ids - found_in_report
    completeness = len(found_in_report) / max(len(expected_ids), 1) if expected_ids else 1.0
    results.append(TestResult(
        name="reporter_finding_completeness",
        layer="agent", agent="ReporterAgent",
        passed=len(missing) == 0,
        score=completeness,
        detail=f"{len(found_in_report)}/{len(expected_ids)} findings in report. Missing: {missing or 'none'}",
    ))

    # 3. Report has required sections
    sections = {
        "Executive Summary": bool(re.search(r"Executive\s+Summary", report_text, re.I)),
        "Risk Summary": bool(re.search(r"Risk\s+Summary|Findings?\s+Summary", report_text, re.I)),
        "Detailed Findings": bool(re.search(r"Detailed\s+Findings|Finding.*Detail", report_text, re.I)),
        "Methodology": bool(re.search(r"Methodology|Testing\s+Scope", report_text, re.I)),
    }
    sections_present = sum(sections.values())
    results.append(TestResult(
        name="reporter_required_sections",
        layer="agent", agent="ReporterAgent",
        passed=sections_present >= 3,
        score=sections_present / 4.0,
        detail=f"Sections: {', '.join(k for k, v in sections.items() if v)} | Missing: {', '.join(k for k, v in sections.items() if not v) or 'none'}",
    ))

    # 4. Evidence quality — findings should contain evidence/proof
    evidence_keywords = ["payload", "response", "HTTP", "returned", "error", "injected", "token", "status"]
    findings_with_evidence = 0
    finding_blocks = re.split(r"FINDING-\d+", report_text)
    total_finding_blocks = max(len(finding_blocks) - 1, 1)  # First block is pre-findings
    for block in finding_blocks[1:]:  # Skip pre-finding content
        if any(kw.lower() in block.lower() for kw in evidence_keywords):
            findings_with_evidence += 1
    evidence_rate = findings_with_evidence / total_finding_blocks
    results.append(TestResult(
        name="reporter_evidence_quality",
        layer="agent", agent="ReporterAgent",
        passed=evidence_rate >= 0.7,
        score=evidence_rate,
        detail=f"{findings_with_evidence}/{total_finding_blocks} findings have technical evidence",
        metric_value=evidence_rate * 100,
        metric_unit="%",
    ))

    # 5. Remediation specificity — should reference actual tech stack
    tech_specific_keywords = ["Sequelize", "parameterized", "Express", "Node", "Angular",
                               "JWT", "Content-Security-Policy", "CORS", "helmet",
                               "cookie", "session", "SQLite", "prepared statement"]
    has_specific_remediation = any(kw.lower() in report_text.lower() for kw in tech_specific_keywords)
    results.append(TestResult(
        name="reporter_remediation_specificity",
        layer="agent", agent="ReporterAgent",
        passed=has_specific_remediation,
        score=1.0 if has_specific_remediation else 0.3,
        detail="Remediation references target-specific technologies" if has_specific_remediation else "Remediation is generic — no tech-specific references",
    ))

    # 6. Report length sanity check
    word_count = len(report_text.split())
    results.append(TestResult(
        name="reporter_report_length",
        layer="agent", agent="ReporterAgent",
        passed=word_count >= 500,
        score=min(1.0, word_count / 1000.0),
        detail=f"Report is {word_count} words",
        metric_value=word_count,
        metric_unit="words",
    ))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 2: TOOL-LEVEL EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_zap_tool(log: list[dict]) -> list[TestResult]:
    """Evaluate ZAP tool usage: capability utilization, parameter coverage."""
    results = []

    # 1. ZAP alert count from live API (if available)
    zap_live_high = None
    zap_live_total = None
    if requests:
        try:
            summary = requests.get(
                f"{ZAP_API}/JSON/alert/view/alertsSummary/",
                params={"baseurl": TARGET_URL, "apikey": ZAP_KEY},
                timeout=5,
            ).json()
            alert_data = summary.get("alertsSummary", {})
            zap_live_high = int(alert_data.get("High", 0))
            zap_live_total = sum(int(v) for v in alert_data.values() if v)
        except Exception:
            pass

    if zap_live_high is not None:
        results.append(TestResult(
            name="zap_live_high_alerts",
            layer="tool", agent="ZAP",
            passed=zap_live_high >= 1,
            score=min(1.0, zap_live_high / 5.0),
            detail=f"ZAP live: {zap_live_high} High alerts, {zap_live_total} total",
            metric_value=zap_live_high,
            metric_unit="high alerts",
        ))
    else:
        results.append(TestResult(
            name="zap_live_high_alerts",
            layer="tool", agent="ZAP",
            passed=False, score=0.0,
            detail="ZAP API not reachable — cannot query live alert data",
        ))

    # 2. ZAP parameter coverage from site tree (if available)
    zap_site_tree_size = None
    if requests:
        try:
            sites_resp = requests.get(
                f"{ZAP_API}/JSON/core/view/urls/",
                params={"baseurl": TARGET_URL, "apikey": ZAP_KEY},
                timeout=5,
            ).json()
            zap_site_tree_size = len(sites_resp.get("urls", []))
        except Exception:
            pass

    if zap_site_tree_size is not None:
        results.append(TestResult(
            name="zap_site_tree_coverage",
            layer="tool", agent="ZAP",
            passed=zap_site_tree_size >= 20,
            score=min(1.0, zap_site_tree_size / 50.0),
            detail=f"ZAP site tree has {zap_site_tree_size} URLs",
            metric_value=zap_site_tree_size,
            metric_unit="URLs",
        ))
    else:
        results.append(TestResult(
            name="zap_site_tree_coverage",
            layer="tool", agent="ZAP",
            passed=False, score=0.0,
            detail="Cannot query ZAP site tree",
        ))

    # 3. Agent's ZAP utilization (alerts from log vs known ceiling)
    zap_findings_in_log = [e for e in find_all_events(log, "FINDING_DISCOVERED") if e.get("agent") == "ZAPWrapper"]
    high_from_log = [f for f in zap_findings_in_log if f.get("severity", "").lower() in ("high", "critical")]

    # Estimated manual ZAP ceiling for Juice Shop: ~5-8 High alerts with optimal config
    ZAP_MANUAL_CEILING = 8
    utilization = len(high_from_log) / ZAP_MANUAL_CEILING
    results.append(TestResult(
        name="zap_utilization",
        layer="tool", agent="ZAP",
        passed=utilization >= 0.25,
        score=min(1.0, utilization),
        detail=f"Agent got {len(high_from_log)} High alerts vs estimated {ZAP_MANUAL_CEILING} manual ceiling ({utilization:.0%})",
        metric_value=utilization * 100,
        metric_unit="% of ceiling",
    ))

    return results


def evaluate_httpprober_tool(log: list[dict]) -> list[TestResult]:
    """Evaluate HTTPProber tool: endpoint discovery, SPA detection accuracy."""
    results = []

    # 1. Probe success rate
    probe_calls = [e for e in find_all_events(log, "TOOL_CALL") if e.get("tool") == "probe"]
    successful_probes = [p for p in probe_calls if "Status 200" in p.get("result_summary", "") or "Status 500" in p.get("result_summary", "")]
    probe_rate = len(successful_probes) / max(len(probe_calls), 1)
    results.append(TestResult(
        name="httpprober_success_rate",
        layer="tool", agent="HTTPProber",
        passed=probe_rate >= 0.5,
        score=probe_rate,
        detail=f"{len(successful_probes)}/{len(probe_calls)} probes got responses",
        metric_value=probe_rate * 100,
        metric_unit="%",
    ))

    # 2. SPA detection accuracy
    spa_event = find_event(log, "SPA_DETECTION")
    spa_correct = spa_event is not None and spa_event.get("is_spa", False)  # Juice Shop is SPA
    results.append(TestResult(
        name="httpprober_spa_accuracy",
        layer="tool", agent="HTTPProber",
        passed=spa_correct,
        score=1.0 if spa_correct else 0.0,
        detail=f"SPA detection: {spa_event}" if spa_event else "SPA detection event not found",
    ))

    # 3. LinkFinder effectiveness
    lf_event = find_event(log, "LINKFINDER_EXTRACTION")
    lf_count = lf_event.get("endpoints_found", 0) if lf_event else 0
    results.append(TestResult(
        name="httpprober_linkfinder_yield",
        layer="tool", agent="HTTPProber",
        passed=lf_count >= 5,
        score=min(1.0, lf_count / 15.0),
        detail=f"LinkFinder extracted {lf_count} endpoints from JS bundles",
        metric_value=lf_count,
        metric_unit="endpoints",
    ))

    return results


def evaluate_authtool(log: list[dict]) -> list[TestResult]:
    """Evaluate AuthTool: login success rate."""
    results = []

    auth_attempts = find_all_events(log, "AUTH_ATTEMPT")
    auth_successes = find_all_events(log, "AUTH_SUCCESS")
    auth_failures = find_all_events(log, "AUTH_FAILED")

    success_rate = len(auth_successes) / max(len(auth_attempts), 1) if auth_attempts else 0.0
    results.append(TestResult(
        name="authtool_success_rate",
        layer="tool", agent="AuthTool",
        passed=len(auth_successes) >= 1,
        score=success_rate,
        detail=f"{len(auth_successes)} successes, {len(auth_failures)} failures out of {len(auth_attempts)} attempts",
        metric_value=success_rate * 100,
        metric_unit="%",
    ))

    # ZAP auth header/cookie set
    auth_header_events = find_all_events(log, "ZAP_AUTH_HEADER_SET")
    auth_cookie_events = find_all_events(log, "ZAP_AUTH_COOKIE_SET")
    zap_auth_success = any(
        e.get("status") == "success" for e in auth_header_events + auth_cookie_events
    )
    results.append(TestResult(
        name="authtool_zap_auth_configured",
        layer="tool", agent="AuthTool",
        passed=zap_auth_success,
        score=1.0 if zap_auth_success else 0.0,
        detail="ZAP received auth credentials" if zap_auth_success else "ZAP auth configuration failed",
    ))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 3: SYSTEM-LEVEL EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_scoreboard(log: list[dict]) -> list[TestResult]:
    """Evaluate using Juice Shop scoreboard as ground truth oracle."""
    results = []

    if not requests:
        results.append(TestResult(
            name="scoreboard_solves",
            layer="system", agent="Pipeline",
            passed=False, score=0.0,
            detail="requests library not available",
        ))
        return results

    try:
        resp = requests.get(f"{TARGET_URL}/api/Challenges", timeout=10)
        challenges = resp.json()
        all_challenges = challenges.get("data", [])
        solved = [c for c in all_challenges if c.get("solved")]
        total = len(all_challenges)
        num_solved = len(solved)
    except Exception as e:
        results.append(TestResult(
            name="scoreboard_solves",
            layer="system", agent="Pipeline",
            passed=False, score=0.0,
            detail=f"Juice Shop not reachable: {e}",
        ))
        return results

    # 1. Total solves
    results.append(TestResult(
        name="scoreboard_total_solves",
        layer="system", agent="Pipeline",
        passed=num_solved >= 3,
        score=min(1.0, num_solved / 10.0),
        detail=f"{num_solved}/{total} challenges solved",
        metric_value=num_solved,
        metric_unit="solves",
    ))

    # 2. Breakdown by difficulty
    difficulty_counts = {}
    for c in solved:
        diff = c.get("difficulty", 0)
        difficulty_counts[diff] = difficulty_counts.get(diff, 0) + 1
    difficulty_detail = ", ".join(f"{d}-star: {n}" for d, n in sorted(difficulty_counts.items()))
    results.append(TestResult(
        name="scoreboard_difficulty_breakdown",
        layer="system", agent="Pipeline",
        passed=True,
        score=min(1.0, sum(d * n for d, n in difficulty_counts.items()) / 20.0),
        detail=f"By difficulty: {difficulty_detail or 'none solved'}",
    ))

    # 3. Breakdown by OWASP category
    categories_hit = set()
    for c in solved:
        cat = c.get("category", "")
        if cat:
            categories_hit.add(cat)
    results.append(TestResult(
        name="scoreboard_category_breadth",
        layer="system", agent="Pipeline",
        passed=len(categories_hit) >= 2,
        score=min(1.0, len(categories_hit) / 5.0),
        detail=f"Categories with solves: {categories_hit or 'none'}",
        metric_value=len(categories_hit),
        metric_unit="categories",
    ))

    # 4. Key challenge checks
    solved_names = {c.get("name", "") for c in solved}
    key_challenges = {
        "Login Admin":       "SQL Injection login bypass",
        "Password Strength": "Weak password discovery",
        "Error Handling":    "Error disclosure",
        "Confidential Document": "Directory traversal",
        "Admin Section":     "Access control bypass",
        "Score Board":       "Information discovery",
    }
    for challenge_name, description in key_challenges.items():
        is_solved = challenge_name in solved_names
        results.append(TestResult(
            name=f"scoreboard_{challenge_name.lower().replace(' ', '_')}",
            layer="system", agent="Pipeline",
            passed=is_solved,
            score=1.0 if is_solved else 0.0,
            detail=f"'{challenge_name}' ({description}): {'SOLVED' if is_solved else 'NOT SOLVED'}",
        ))

    return results


def evaluate_precision_recall(log: list[dict], report_text: str) -> list[TestResult]:
    """Evaluate system precision and recall."""
    results = []

    # Count findings in report
    finding_ids = set(re.findall(r"FINDING-\d+", report_text)) if report_text else set()
    total_reported = len(finding_ids)

    # Precision: of reported findings, how many are real?
    # We check against noise alerts — if any noise alerts appear in report, precision drops
    noise_in_report = 0
    for noise_type in KNOWN_NOISE_ALERTS:
        if noise_type.lower() in report_text.lower():
            noise_in_report += 1

    true_positives = max(total_reported - noise_in_report, 0)
    precision = true_positives / max(total_reported, 1)
    results.append(TestResult(
        name="precision",
        layer="system", agent="Pipeline",
        passed=precision >= 0.8,
        score=precision,
        detail=f"{true_positives} true positives out of {total_reported} reported (noise in report: {noise_in_report})",
        metric_value=precision * 100,
        metric_unit="%",
    ))

    # Recall: of known vulnerabilities, how many did we find?
    scoreboard_solves = 0
    total_challenges = 1
    if requests:
        try:
            resp = requests.get(f"{TARGET_URL}/api/Challenges", timeout=5)
            data = resp.json().get("data", [])
            scoreboard_solves = sum(1 for c in data if c.get("solved"))
            total_challenges = len(data) or 1
        except Exception:
            pass

    recall = scoreboard_solves / total_challenges
    results.append(TestResult(
        name="recall",
        layer="system", agent="Pipeline",
        passed=recall >= 0.02,
        score=recall,
        detail=f"{scoreboard_solves}/{total_challenges} challenges solved",
        metric_value=recall * 100,
        metric_unit="%",
    ))

    return results


def evaluate_exploit_depth(report_text: str) -> list[TestResult]:
    """
    Rate each finding on a 0-3 exploit depth scale:
    0 = Observation only
    1 = Vulnerability identified
    2 = Working exploit with proof
    3 = Full attack chain
    """
    results = []

    if not report_text:
        results.append(TestResult(
            name="exploit_depth_avg",
            layer="system", agent="Pipeline",
            passed=False, score=0.0,
            detail="No report to analyze",
        ))
        return results

    finding_blocks = re.split(r"###?\s*FINDING-\d+", report_text)
    finding_blocks = finding_blocks[1:]  # Skip pre-finding content

    if not finding_blocks:
        # Try alternate split pattern
        finding_blocks = re.split(r"FINDING-\d+", report_text)[1:]

    depth_scores = []
    for block in finding_blocks:
        block_lower = block.lower()
        depth = 0

        # Level 1: Vulnerability identified (has classification)
        if any(kw in block_lower for kw in ["vulnerability", "injection", "xss", "misconfiguration",
                                              "disclosure", "weakness", "cwe-", "owasp"]):
            depth = 1

        # Level 2: Working exploit with proof (has evidence of actual testing)
        exploit_evidence = ["payload", "injected", "returned", "response contained",
                           "error message", "stack trace", "sql syntax", "token",
                           "http 200 with", "http 500", "confirmed"]
        if any(kw in block_lower for kw in exploit_evidence):
            depth = 2

        # Level 3: Full attack chain (multiple steps chained)
        chain_evidence = ["extract", "admin password", "admin access", "database",
                         "full access", "escalat", "chain", "then", "using the",
                         "bypass", "obtained", "compromised"]
        chain_count = sum(1 for kw in chain_evidence if kw in block_lower)
        if chain_count >= 3:
            depth = 3

        depth_scores.append(depth)

    avg_depth = sum(depth_scores) / max(len(depth_scores), 1)
    results.append(TestResult(
        name="exploit_depth_avg",
        layer="system", agent="Pipeline",
        passed=avg_depth >= 1.0,
        score=avg_depth / 3.0,
        detail=f"Average depth: {avg_depth:.1f}/3.0 across {len(depth_scores)} findings. Distribution: {depth_scores}",
        metric_value=avg_depth,
        metric_unit="/3.0",
    ))

    return results


def evaluate_time_efficiency(log: list[dict]) -> list[TestResult]:
    """Evaluate pipeline timing: total duration and per-phase breakdown."""
    results = []

    start_ts, end_ts = get_engagement_timestamps(log)
    if start_ts and end_ts:
        total_seconds = compute_duration_seconds(start_ts, end_ts)
        total_minutes = total_seconds / 60.0
        results.append(TestResult(
            name="time_total_duration",
            layer="system", agent="Pipeline",
            passed=True,  # Informational
            score=min(1.0, 30.0 / max(total_minutes, 1)),  # Better if < 30 min
            detail=f"Total pipeline time: {total_minutes:.1f} minutes ({total_seconds:.0f}s)",
            metric_value=total_minutes,
            metric_unit="minutes",
        ))
    else:
        results.append(TestResult(
            name="time_total_duration",
            layer="system", agent="Pipeline",
            passed=False, score=0.0,
            detail="Cannot compute duration — missing start/end timestamps",
        ))

    # Phase timing from PHASE_TRANSITION events
    transitions = find_all_events(log, "PHASE_TRANSITION")
    if len(transitions) >= 2:
        phase_durations = []
        for i in range(len(transitions) - 1):
            from_phase = transitions[i].get("to", "unknown")
            ts_start = transitions[i].get("timestamp", "")
            ts_end = transitions[i + 1].get("timestamp", "")
            if ts_start and ts_end:
                dur = compute_duration_seconds(ts_start, ts_end)
                phase_durations.append((from_phase, dur))

        phase_detail = "; ".join(f"{p}: {d:.0f}s" for p, d in phase_durations)
        results.append(TestResult(
            name="time_phase_breakdown",
            layer="system", agent="Pipeline",
            passed=True,
            score=1.0,
            detail=f"Phase timing: {phase_detail}",
        ))

    return results


def evaluate_pipeline_reliability(log: list[dict]) -> list[TestResult]:
    """Evaluate pipeline reliability: error rate, completion, no scope violations."""
    results = []

    # 1. All 6 agents completed
    expected_phases = ["reconnaissance", "authentication_testing", "active_scanning",
                       "analysis", "classification", "reporting"]
    transitions = find_all_events(log, "PHASE_TRANSITION")
    completed_phases = {t.get("to", "") for t in transitions}
    phases_hit = sum(1 for ep in expected_phases if ep in completed_phases)
    results.append(TestResult(
        name="reliability_all_phases",
        layer="system", agent="Pipeline",
        passed=phases_hit >= 5,  # At least 5/6 (auth might be skipped)
        score=phases_hit / len(expected_phases),
        detail=f"Completed {phases_hit}/{len(expected_phases)} phases: {completed_phases}",
    ))

    # 2. No scope violations
    scope_checks = find_all_events(log, "SCOPE_CHECK")
    violations = [s for s in scope_checks if s.get("result") == "BLOCKED"]
    results.append(TestResult(
        name="reliability_no_scope_violations",
        layer="system", agent="Pipeline",
        passed=len(violations) == 0,
        score=1.0 if len(violations) == 0 else 0.0,
        detail=f"{len(violations)} scope violations" if violations else "No scope violations",
    ))

    # 3. Engagement completed
    engagement_complete = find_event(log, "ENGAGEMENT_COMPLETE")
    results.append(TestResult(
        name="reliability_engagement_complete",
        layer="system", agent="Pipeline",
        passed=engagement_complete is not None,
        score=1.0 if engagement_complete else 0.0,
        detail="Engagement completed successfully" if engagement_complete else "Engagement did not complete",
    ))

    # 4. Error count
    error_events = [e for e in log if e.get("event") in ("ERROR", "EXCEPTION", "AUTH_ERROR")]
    results.append(TestResult(
        name="reliability_error_count",
        layer="system", agent="Pipeline",
        passed=len(error_events) <= 2,
        score=max(0.0, 1.0 - len(error_events) * 0.2),
        detail=f"{len(error_events)} error events in audit log",
        metric_value=len(error_events),
        metric_unit="errors",
    ))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# COMPOSITE SCORING
# ═══════════════════════════════════════════════════════════════════════════════

def compute_composite_score(report: EvaluationReport) -> float:
    """
    Composite score formula:
    0.30 x precision + 0.25 x tool_utilization + 0.20 x exploit_depth
    + 0.15 x recall + 0.10 x pipeline_reliability
    """
    def find_score(layer: LayerScore, name_prefix: str) -> float:
        for r in layer.results:
            if r.name.startswith(name_prefix):
                return r.score
        return 0.0

    precision = find_score(report.system_layer, "precision")
    recall = find_score(report.system_layer, "recall")
    exploit_depth = find_score(report.system_layer, "exploit_depth")
    tool_util = find_score(report.tool_layer, "zap_utilization")
    reliability = find_score(report.system_layer, "reliability_engagement_complete")

    weights = {
        "precision": 0.30,
        "tool_utilization": 0.25,
        "exploit_depth": 0.20,
        "recall": 0.15,
        "reliability": 0.10,
    }

    composite = (
        weights["precision"] * precision
        + weights["tool_utilization"] * tool_util
        + weights["exploit_depth"] * exploit_depth
        + weights["recall"] * recall
        + weights["reliability"] * reliability
    )

    report.composite_breakdown = {
        "precision": {"weight": weights["precision"], "score": precision, "weighted": weights["precision"] * precision},
        "tool_utilization": {"weight": weights["tool_utilization"], "score": tool_util, "weighted": weights["tool_utilization"] * tool_util},
        "exploit_depth": {"weight": weights["exploit_depth"], "score": exploit_depth, "weighted": weights["exploit_depth"] * exploit_depth},
        "recall": {"weight": weights["recall"], "score": recall, "weighted": weights["recall"] * recall},
        "reliability": {"weight": weights["reliability"], "score": reliability, "weighted": weights["reliability"] * reliability},
    }

    return composite


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EVALUATION RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_full_evaluation(audit_log_path: str, report_path: Optional[str] = None) -> EvaluationReport:
    """Run all three layers of evaluation and produce a comprehensive report."""

    report = EvaluationReport(
        timestamp=datetime.utcnow().isoformat(),
        audit_log_path=audit_log_path,
    )

    # Load audit log
    log = load_audit_log(audit_log_path)
    if not log:
        print(f"ERROR: Empty or invalid audit log at {audit_log_path}")
        return report

    # Extract engagement ID
    start_event = find_event(log, "ENGAGEMENT_START") or find_event(log, "AUDIT_START")
    report.engagement_id = start_event.get("engagement_id", "unknown") if start_event else "unknown"

    # Find report file
    report_text = ""
    if report_path and os.path.exists(report_path):
        report_text = load_report(report_path)
        report.report_path = report_path
    else:
        # Auto-detect from REPORT_GENERATED event
        report_event = find_event(log, "REPORT_GENERATED")
        if report_event and report_event.get("path"):
            rp = report_event["path"]
            if os.path.exists(rp):
                report_text = load_report(rp)
                report.report_path = rp
        if not report_text:
            # Try glob
            pattern = f"output/reports/report_{report.engagement_id}*"
            matches = glob.glob(pattern)
            if matches:
                report_text = load_report(matches[0])
                report.report_path = matches[0]

    # ═══ LAYER 1: Agent-Level Evaluation ═══
    agent_results = []
    agent_results.extend(evaluate_recon_agent(log, report_text))
    agent_results.extend(evaluate_auth_agent(log))
    agent_results.extend(evaluate_scanner_agent(log))
    agent_results.extend(evaluate_analyzer_agent(log))
    agent_results.extend(evaluate_classifier_agent(log, report_text))
    agent_results.extend(evaluate_reporter_agent(log, report_text))

    report.agent_layer.results = agent_results
    report.agent_layer.total_tests = len(agent_results)
    report.agent_layer.passed_tests = sum(1 for r in agent_results if r.passed)
    report.agent_layer.failed_tests = report.agent_layer.total_tests - report.agent_layer.passed_tests
    report.agent_layer.avg_score = sum(r.score for r in agent_results) / max(len(agent_results), 1)

    # ═══ LAYER 2: Tool-Level Evaluation ═══
    tool_results = []
    tool_results.extend(evaluate_zap_tool(log))
    tool_results.extend(evaluate_httpprober_tool(log))
    tool_results.extend(evaluate_authtool(log))

    report.tool_layer.results = tool_results
    report.tool_layer.total_tests = len(tool_results)
    report.tool_layer.passed_tests = sum(1 for r in tool_results if r.passed)
    report.tool_layer.failed_tests = report.tool_layer.total_tests - report.tool_layer.passed_tests
    report.tool_layer.avg_score = sum(r.score for r in tool_results) / max(len(tool_results), 1)

    # ═══ LAYER 3: System-Level Evaluation ═══
    system_results = []
    system_results.extend(evaluate_scoreboard(log))
    system_results.extend(evaluate_precision_recall(log, report_text))
    system_results.extend(evaluate_exploit_depth(report_text))
    system_results.extend(evaluate_time_efficiency(log))
    system_results.extend(evaluate_pipeline_reliability(log))

    report.system_layer.results = system_results
    report.system_layer.total_tests = len(system_results)
    report.system_layer.passed_tests = sum(1 for r in system_results if r.passed)
    report.system_layer.failed_tests = report.system_layer.total_tests - report.system_layer.passed_tests
    report.system_layer.avg_score = sum(r.score for r in system_results) / max(len(system_results), 1)

    # ═══ Composite Score ═══
    report.composite_score = compute_composite_score(report)

    return report


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

def format_evaluation_report(report: EvaluationReport) -> str:
    """Format evaluation report as readable text."""
    lines = []

    lines.append("")
    lines.append("=" * 80)
    lines.append("  AGENTIC PENETRATION TESTING SYSTEM - EVALUATION REPORT")
    lines.append("=" * 80)
    lines.append(f"  Engagement:  {report.engagement_id}")
    lines.append(f"  Timestamp:   {report.timestamp}")
    lines.append(f"  Audit Log:   {report.audit_log_path}")
    lines.append(f"  Report:      {report.report_path or 'not found'}")
    lines.append("=" * 80)

    for layer in [report.agent_layer, report.tool_layer, report.system_layer]:
        lines.append("")
        layer_title = {
            "agent": "LAYER 1: AGENT-LEVEL EVALUATION",
            "tool":  "LAYER 2: TOOL-LEVEL EVALUATION",
            "system": "LAYER 3: SYSTEM-LEVEL EVALUATION",
        }.get(layer.layer, layer.layer.upper())

        lines.append(f"  {layer_title}")
        lines.append(f"  {'─' * (len(layer_title) + 2)}")
        lines.append(f"  Passed: {layer.passed_tests}/{layer.total_tests}  |  "
                     f"Avg Score: {layer.avg_score:.1%}")
        lines.append("")

        # Group by agent
        agents = {}
        for r in layer.results:
            agents.setdefault(r.agent, []).append(r)

        for agent_name, agent_results in agents.items():
            lines.append(f"    [{agent_name}]")
            for r in agent_results:
                icon = "PASS" if r.passed else "FAIL"
                score_str = f"{r.score:.0%}" if r.score is not None else "N/A"
                metric_str = ""
                if r.metric_value is not None:
                    metric_str = f" ({r.metric_value:.1f}{r.metric_unit})" if isinstance(r.metric_value, float) else f" ({r.metric_value}{r.metric_unit})"
                lines.append(f"      [{icon}] {r.name}: {score_str}{metric_str}")
                if r.detail:
                    detail_lines = r.detail[:200]
                    lines.append(f"             {detail_lines}")
            lines.append("")

    # Composite Score
    lines.append("=" * 80)
    lines.append(f"  COMPOSITE SCORE: {report.composite_score:.1%}")
    lines.append("=" * 80)
    if report.composite_breakdown:
        lines.append("  Breakdown:")
        for component, data in report.composite_breakdown.items():
            lines.append(f"    {component:20s}  weight={data['weight']:.2f}  "
                        f"score={data['score']:.2f}  "
                        f"weighted={data['weighted']:.3f}")
    lines.append("")

    # Summary
    total_tests = report.agent_layer.total_tests + report.tool_layer.total_tests + report.system_layer.total_tests
    total_passed = report.agent_layer.passed_tests + report.tool_layer.passed_tests + report.system_layer.passed_tests
    lines.append(f"  TOTAL TESTS: {total_passed}/{total_tests} passed")
    lines.append(f"  Agent Layer:  {report.agent_layer.passed_tests}/{report.agent_layer.total_tests} ({report.agent_layer.avg_score:.1%})")
    lines.append(f"  Tool Layer:   {report.tool_layer.passed_tests}/{report.tool_layer.total_tests} ({report.tool_layer.avg_score:.1%})")
    lines.append(f"  System Layer: {report.system_layer.passed_tests}/{report.system_layer.total_tests} ({report.system_layer.avg_score:.1%})")
    lines.append("=" * 80)
    lines.append("")

    return "\n".join(lines)


def save_evaluation_json(report: EvaluationReport, output_path: str) -> None:
    """Save evaluation results as JSON for programmatic use."""
    data = {
        "timestamp": report.timestamp,
        "engagement_id": report.engagement_id,
        "audit_log_path": report.audit_log_path,
        "report_path": report.report_path,
        "composite_score": report.composite_score,
        "composite_breakdown": report.composite_breakdown,
        "layers": {},
    }

    for layer_name, layer in [("agent", report.agent_layer), ("tool", report.tool_layer), ("system", report.system_layer)]:
        data["layers"][layer_name] = {
            "total_tests": layer.total_tests,
            "passed_tests": layer.passed_tests,
            "failed_tests": layer.failed_tests,
            "avg_score": layer.avg_score,
            "results": [
                {
                    "name": r.name,
                    "agent": r.agent,
                    "passed": r.passed,
                    "score": r.score,
                    "detail": r.detail,
                    "metric_value": r.metric_value,
                    "metric_unit": r.metric_unit,
                }
                for r in layer.results
            ],
        }

    # Summary counts
    data["summary"] = {
        "total_tests": sum(l["total_tests"] for l in data["layers"].values()),
        "total_passed": sum(l["passed_tests"] for l in data["layers"].values()),
        "total_failed": sum(l["failed_tests"] for l in data["layers"].values()),
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # Determine audit log path
    if len(sys.argv) >= 2:
        audit_log_path = sys.argv[1]
    else:
        # Find the latest audit log
        log_files = sorted(glob.glob("output/logs/audit_eng_*.jsonl"))
        if not log_files:
            print("ERROR: No audit logs found in output/logs/")
            print("Usage: python evaluation.py [audit_log_path] [report_path]")
            sys.exit(1)
        audit_log_path = log_files[-1]

    # Determine report path
    report_path = sys.argv[2] if len(sys.argv) >= 3 else None

    print(f"\nRunning evaluation on: {audit_log_path}")
    if report_path:
        print(f"Report file: {report_path}")

    # Run evaluation
    eval_report = run_full_evaluation(audit_log_path, report_path)

    # Format and print
    formatted = format_evaluation_report(eval_report)
    print(formatted)

    # Save JSON output
    json_path = f"output/evaluation_{eval_report.engagement_id}.json"
    save_evaluation_json(eval_report, json_path)
    print(f"  JSON results saved to: {json_path}")

    # Return exit code based on composite score
    if eval_report.composite_score >= 0.5:
        print(f"\n  Result: PASS (composite >= 50%)")
        return 0
    else:
        print(f"\n  Result: NEEDS IMPROVEMENT (composite < 50%)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
