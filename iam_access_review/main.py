#!/usr/bin/env python3
"""
IAM Access Review Simulator — CLI
===================================
Simulates the quarterly user access certification process used in GRC/IAM roles.
Detects violations in Active Directory user accounts and generates audit reports.

Usage:
    python main.py demo          → run full review on sample AD data + show dashboard
    python main.py dashboard     → show dashboard for last review
    python main.py report        → generate all reports (CSV + JSON)
    python main.py user <id>     → show all violations for a specific user
    python main.py critical      → show only CRITICAL and HIGH risk violations
    python main.py stats         → show violation statistics only
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "data"))

from iam_engine import IAMReviewEngine
from reporter import (
    print_dashboard,
    generate_violation_csv,
    generate_user_csv,
    generate_audit_summary_json,
)
from sample_users import get_sample_users


def cmd_demo():
    print("\n[*] Loading sample Active Directory users...")
    users = get_sample_users()
    print(f"[*] {len(users)} users loaded. Running access review checks...")

    engine = IAMReviewEngine(inactive_days=90)
    engine.load_users(users)
    engine.run_review()

    print_dashboard(engine)
    generate_violation_csv(engine)
    generate_user_csv(engine)
    generate_audit_summary_json(engine)
    print("\n[+] All reports saved to /reports/")


def cmd_critical():
    users = get_sample_users()
    engine = IAMReviewEngine()
    engine.load_users(users)
    engine.run_review()

    critical = [v for v in engine.violations if v.risk_level() in ("CRITICAL", "HIGH")]
    if not critical:
        print("\n✅ No CRITICAL or HIGH risk violations found.")
        return

    print(f"\n🔴 CRITICAL & HIGH RISK VIOLATIONS ({len(critical)} found)\n")
    print(f"  {'User':<22} {'Violation':<30} {'Score':<8} Detail")
    print(f"  {'─'*21} {'─'*29} {'─'*7} {'─'*30}")
    for v in sorted(critical, key=lambda x: x.risk_score, reverse=True):
        icon  = "🔴" if v.risk_level() == "CRITICAL" else "🟠"
        vtype = v.violation_type.replace("_", " ").title()
        print(f"  {v.user.full_name:<22} {vtype:<30} {icon} {v.risk_score:<5}  {v.detail[:60]}...")
        print(f"  {'':22} 👉 {v.recommendation[:80]}")
        print()


def cmd_user(user_id: str):
    users = get_sample_users()
    engine = IAMReviewEngine()
    engine.load_users(users)
    engine.run_review()

    user_violations = [v for v in engine.violations
                       if v.user.user_id.upper() == user_id.upper()
                       or v.user.username.lower() == user_id.lower()]

    if not user_violations:
        user = next((u for u in users if u.user_id.upper() == user_id.upper()
                     or u.username.lower() == user_id.lower()), None)
        if user:
            print(f"\n✅ {user.full_name} ({user.username}) — No violations found. Account is clean.")
        else:
            print(f"\n[!] User '{user_id}' not found.")
        return

    u = user_violations[0].user
    print(f"\n── User Report: {u.full_name} ({u.username}) ──────────────────────────")
    print(f"  Department : {u.department}")
    print(f"  Job Title  : {u.job_title}")
    print(f"  Status     : {u.account_status.upper()} / {u.employment_status.upper()}")
    print(f"  Last Login : {u.last_login or 'Never'}")
    print(f"  MFA        : {'✅ Enabled' if u.mfa_enabled else '❌ Disabled'}")
    print(f"  Access     : {', '.join(u.access_groups)}")
    print(f"\n  Violations ({len(user_violations)}):")
    for i, v in enumerate(user_violations, 1):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v.risk_level(), "⚪")
        print(f"\n  [{i}] {icon} {v.violation_type.replace('_',' ').title()} — {v.risk_level()} (score: {v.risk_score})")
        print(f"       Detail : {v.detail}")
        print(f"       Action : {v.recommendation}")


def cmd_stats():
    users = get_sample_users()
    engine = IAMReviewEngine()
    engine.load_users(users)
    engine.run_review()
    s = engine.get_summary()

    print("\n── IAM Review Statistics ──────────────────────────────────────────")
    print(f"  Total Users     : {s['total_users']}")
    print(f"  Flagged Users   : {s['flagged_users']}")
    print(f"  Compliance Rate : {s['compliance_rate']}%")
    print(f"\n  Violations by Type:")
    for vtype, count in sorted(s["by_violation_type"].items(), key=lambda x: x[1], reverse=True):
        bar = "█" * count
        print(f"    {vtype.replace('_',' ').title():<35} {bar} {count}")
    print(f"\n  Violations by Risk Level:")
    for level, count in s["by_risk_level"].items():
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        print(f"    {icons[level]} {level:<10} : {count}")
    print()


def cmd_report():
    users = get_sample_users()
    engine = IAMReviewEngine()
    engine.load_users(users)
    engine.run_review()
    print("\n── Generating Reports ──────────────────────────────────────────────")
    generate_violation_csv(engine)
    generate_user_csv(engine)
    generate_audit_summary_json(engine)
    print("\n[+] All reports saved to /reports/")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1].lower()

    if cmd == "demo":
        cmd_demo()
    elif cmd == "dashboard":
        users = get_sample_users()
        engine = IAMReviewEngine()
        engine.load_users(users)
        engine.run_review()
        print_dashboard(engine)
    elif cmd == "critical":
        cmd_critical()
    elif cmd == "stats":
        cmd_stats()
    elif cmd == "report":
        cmd_report()
    elif cmd == "user":
        if len(sys.argv) < 3:
            print("Usage: python main.py user <user_id or username>")
        else:
            cmd_user(sys.argv[2])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
