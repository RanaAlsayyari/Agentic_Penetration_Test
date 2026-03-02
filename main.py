"""
main.py
────────
Entry point for the Pentest Agent System.

Run against DVWA:
  python main.py --target http://localhost:8888 --app dvwa

Run against Juice Shop:
  python main.py --target http://localhost:3000 --app juiceshop

Run passive only (no attack payloads):
  python main.py --target http://localhost:3000 --app juiceshop --mode passive
"""

import os
import argparse
from dotenv import load_dotenv

from schemas import TargetCredentials
from pentest_graph import run_pentest_engagement


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Pentest Agent System — Authorized Security Testing Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test DVWA (default port 8888)
  python main.py --target http://localhost:8888 --app dvwa

  # Test Juice Shop (default port 3000)
  python main.py --target http://localhost:3000 --app juiceshop

  # Passive scan only
  python main.py --target http://localhost:3000 --app juiceshop --mode passive

  # Custom credentials
  python main.py --target http://localhost:8888 --app dvwa \\
                 --username admin --password password

WARNING: Only run against systems you own or have explicit written authorization to test.
        """
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Primary target URL (e.g. http://localhost:8888)"
    )
    parser.add_argument(
        "--app",
        choices=["dvwa", "juiceshop", "custom"],
        default="dvwa",
        help="Target application type (determines default credentials and ports)"
    )
    parser.add_argument(
        "--mode",
        choices=["passive", "active"],
        default="active",
        help="Scan mode. 'active' sends test payloads. 'passive' only observes."
    )
    parser.add_argument(
        "--username",
        help="Test account username (overrides .env)"
    )
    parser.add_argument(
        "--password",
        help="Test account password (overrides .env)"
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=5,
        help="Max requests per second per host (default: 5)"
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Skip authenticated testing"
    )

    args = parser.parse_args()

    # ── Build credentials ──────────────────────────────────────────────────────
    credentials = None

    if not args.no_auth:
        if args.app == "dvwa":
            username = args.username or os.getenv("DVWA_USERNAME", "admin")
            password = args.password or os.getenv("DVWA_PASSWORD", "password")
            credentials = TargetCredentials(
                username=username,
                password=password,
                login_url=f"{args.target}/login.php",
                auth_type="form"
            )

        elif args.app == "juiceshop":
            username = args.username or os.getenv("JUICESHOP_USERNAME", "admin@juice-sh.op")
            password = args.password or os.getenv("JUICESHOP_PASSWORD", "admin123")
            credentials = TargetCredentials(
                username=username,
                password=password,
                login_url=f"{args.target}/rest/user/login",
                auth_type="bearer"
            )

        elif args.app == "custom" and args.username and args.password:
            credentials = TargetCredentials(
                username=args.username,
                password=args.password,
                auth_type="form"
            )

    # ── Build scope — always include both possible targets ─────────────────────
    # Read from env first, then use target
    env_targets = os.getenv("ALLOWED_TARGETS", "")
    if env_targets:
        allowed = [t.strip() for t in env_targets.split(",") if t.strip()]
    else:
        # Default: allow both DVWA and Juice Shop local instances
        allowed = [
            "http://localhost:8888",
            "http://localhost:3000",
            "http://127.0.0.1:8888",
            "http://127.0.0.1:3000",
        ]

    # Always include the explicitly specified target
    if args.target not in allowed:
        allowed.append(args.target)

    # ── Run engagement ─────────────────────────────────────────────────────────
    print("\n⚠️  IMPORTANT: Only run against systems you own or have explicit authorization to test.")
    print(f"   Target: {args.target}")
    print(f"   App: {args.app}")
    print(f"   Mode: {args.mode.upper()}")

    if args.mode == "active":
        print("\n   Active mode will send test payloads to the target.")
        confirm = input("   Continue? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("   Aborted.")
            return

    final_state = run_pentest_engagement(
        target_url=args.target,
        allowed_targets=allowed,
        mode=args.mode,
        credentials=credentials,
        rate_limit_rps=args.rate_limit
    )

    if final_state.report_path:
        print(f"\n✅ Report saved to: {final_state.report_path}")


if __name__ == "__main__":
    main()
