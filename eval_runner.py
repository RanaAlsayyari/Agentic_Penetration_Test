#!/usr/bin/env python3
"""Automated evaluation runner for Agentic Penetration Test system."""

import json, sys, requests, glob, os
from pathlib import Path
from datetime import datetime

# ── Config ──
TARGET_URL = os.getenv('TARGET_URL', 'http://127.0.0.1:3000')
ZAP_API = os.getenv('ZAP_API', 'http://localhost:8080')
ZAP_KEY = os.getenv('ZAP_API_KEY', 'changeme')

# ── Helpers ──
def load_audit_log(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]

def find_event(log, event_name, **filters):
    for entry in log:
        if entry.get('event') == event_name:
            if all(entry.get(k) == v for k, v in filters.items()):
                return entry
    return None

def find_all_events(log, event_name):
    return [e for e in log if e.get('event') == event_name]

# ── Tests ──
def run_evaluation(audit_log_path):
    log = load_audit_log(audit_log_path)
    results = {'timestamp': datetime.utcnow().isoformat(), 'tests': {}, 'pass': 0, 'fail': 0}

    def check(name, condition, detail=''):
        passed = bool(condition)
        results['tests'][name] = {'passed': passed, 'detail': detail}
        results['pass' if passed else 'fail'] += 1

    # 1. Recon
    recon = find_event(log, 'RECON_COMPLETE')
    check('recon_completed', recon, str(recon.get('discovered_count','N/A')) if recon else 'missing')
    check('recon_spa_detected', recon and recon.get('is_spa'), '')
    check('recon_endpoints_sufficient', recon and recon.get('discovered_count',0) >= 30, '')

    # 2. Auth
    auth = find_event(log, 'AUTH_SUCCESS')
    check('auth_succeeded', auth, auth.get('user','') if auth else 'not found')
    auth_finding = find_event(log, 'FINDING_DISCOVERED', agent='AuthAgent')
    check('auth_finding_emitted', auth_finding, auth_finding.get('finding_type','') if auth_finding else '')

    # 3. Scanner
    auth_ctx = find_event(log, 'SCANNER_AUTH_CONTEXT')
    check('scanner_has_auth', auth_ctx and auth_ctx.get('has_headers'), '')
    seeds = find_event(log, 'SCANNER_API_SEEDS')
    check('scanner_api_seeded', seeds and seeds.get('api_endpoint_count',0) >= 10, '')
    proxy = find_event(log, 'PROXY_SEED_COMPLETE')
    check('scanner_proxy_seeded', proxy and proxy.get('requests_seeded',0) >= 50, '')

    # 4. ZAP alerts
    try:
        summary = requests.get(f'{ZAP_API}/JSON/alert/view/alertsSummary/',
            params={'baseurl': TARGET_URL, 'apikey': ZAP_KEY}, timeout=5).json()
        high = int(summary.get('alertsSummary',{}).get('High', 0))
        check('zap_high_alerts', high >= 1, f'High={high}')
    except: check('zap_high_alerts', False, 'ZAP not reachable')

    # 5. Scoreboard
    try:
        challenges = requests.get(f'{TARGET_URL}/api/Challenges', timeout=5).json()
        solved = [c for c in challenges['data'] if c.get('solved')]
        check('scoreboard_min_solves', len(solved) >= 5, f'{len(solved)} solved')
        names = [c['name'] for c in solved]
        check('scoreboard_sqli', 'Login Admin' in names, '')
        check('scoreboard_auth', 'Password Strength' in names, '')
    except: check('scoreboard_min_solves', False, 'Juice Shop not reachable')

    # 6. No errors
    errors = [e for e in log if e.get('event') in ['ERROR', 'EXCEPTION'] 
            or 'rate_limit' in str(e.get('error','')).lower() 
            or '429' in str(e.get('error',''))]
    check('no_rate_limit_errors', len(errors) == 0, f'{len(errors)} errors')

    # Summary
    total = results['pass'] + results['fail']
    results['score'] = f"{results['pass']}/{total}"
    print(json.dumps(results, indent=2))
    return results

if __name__ == '__main__':
    # log_path = sys.argv[1] if len(sys.argv) > 1 else glob.glob('output/logs/audit_*.jsonl')[-1]
    log_path = 'output/logs/audit_eng_20260304_201254.jsonl'
    run_evaluation(log_path)
