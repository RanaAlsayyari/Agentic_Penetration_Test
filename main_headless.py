"""
main_headless.py
─────────────────
Non-interactive entry point for the Pentest Agent System.
Identical to main.py but skips the interactive confirmation prompt,
making it suitable for subprocess invocation from server.py.
"""

import os
import sys
import argparse
from dotenv import load_dotenv

from schemas import TargetCredentials
from pentest_graph import run_pentest_engagement


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Pentest Agent System — Headless Mode")

    parser.add_argument("--target", required=True, help="Primary target URL")
    parser.add_argument("--app", choices=["dvwa", "juiceshop", "custom"], default="dvwa")
    parser.add_argument("--mode", choices=["passive", "active"], default="active")
    parser.add_argument("--username", help="Test account username")
    parser.add_argument("--password", help="Test account password")
    parser.add_argument("--rate-limit", type=int, default=5)
    parser.add_argument("--no-auth", action="store_true")

    args = parser.parse_args()

    # Flush stdout after every print so the WebSocket relay gets lines immediately
    sys.stdout.reconfigure(line_buffering=True)

    # ── Build credentials ─────────────────────────────────────────────────────
    credentials = None

    if not args.no_auth:
        if args.app == "dvwa":
            username = args.username or os.getenv("DVWA_USERNAME", "admin")
            password = args.password or os.getenv("DVWA_PASSWORD", "password")
            credentials = TargetCredentials(
                username=username,
                password=password,
                login_url=f"{args.target}/login.php",
                auth_type="form",
            )
        elif args.app == "juiceshop":
            username = args.username or os.getenv("JUICESHOP_USERNAME", "admin@juice-sh.op")
            password = args.password or os.getenv("JUICESHOP_PASSWORD", "admin123")
            credentials = TargetCredentials(
                username=username,
                password=password,
                login_url=f"{args.target}/rest/user/login",
                auth_type="bearer",
            )
        elif args.app == "custom" and args.username and args.password:
            credentials = TargetCredentials(
                username=args.username,
                password=args.password,
                auth_type="form",
            )

    # ── Build scope 
    env_targets = os.getenv("ALLOWED_TARGETS", "")
    if env_targets:
        allowed = [t.strip() for t in env_targets.split(",") if t.strip()]
    else:
        allowed = [
            "http://localhost:8888",
            "http://localhost:3000",
            "http://127.0.0.1:8888",
            "http://127.0.0.1:3000",
        ]

    if args.target not in allowed:
        allowed.append(args.target)

    # ── Run ───────────────────────────────────────────────────────────────────
    print(f"[VOID] Target  : {args.target}")
    print(f"[VOID] App     : {args.app}")
    print(f"[VOID] Mode    : {args.mode.upper()}")
    print(f"[VOID] Auth    : {'Disabled' if args.no_auth else 'Enabled'}")
    print(f"[VOID] Rate    : {args.rate_limit} req/s")
    print("[VOID] Starting engagement...")

    final_state = run_pentest_engagement(
        target_url=args.target,
        allowed_targets=allowed,
        mode=args.mode,
        credentials=credentials,
        rate_limit_rps=args.rate_limit,
    )

    if final_state.report_path:
        print(f"[VOID] Report saved to: {final_state.report_path}")
    print("[VOID] Engagement complete.")


if __name__ == "__main__":
    main()
