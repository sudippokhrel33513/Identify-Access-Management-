"""
Report generator for IAM Access Review Simulator.
Produces terminal dashboard, CSV violation report, and JSON audit summary.
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from iam_engine import IAMReviewEngine, RISK_WEIGHTS


def print_dashboard(engine: IAMReviewEngine):
    """Print a colour-coded terminal dashboard."""
    s = engine.get_summary()
    v = engine.violations

    print("\n" + "=" * 70)
    print("   IAM QUARTERLY ACCESS REVIEW — RESULTS DASHBOARD")
    print("   " + s["review_date"])
    print("=" * 70)
    print(f"  Total Users Reviewed : {s['total_users']}")
    print(f"  Clean (No Issues)    : {s['clean_users']}  ✅")
    print(f"  Flagged              : {s['flagged_users']}  ⚠️")
    print(f"  Total Violations     : {s['total_violations']}")
    print(f"  Compliance Rate      : {s['compliance_rate']}%")
    print("─" * 70)

    # By risk level
    lvl = s["by_risk_level"]
    print(f"\n  Risk Breakdown:")
    print(f"    🔴 CRITICAL : {lvl['CRITICAL']}")
    print(f"    🟠 HIGH     : {lvl['HIGH']}")
    print(f"    🟡 MEDIUM   : {lvl['MEDIUM']}")
    print(f"    🟢 LOW      : {lvl['LOW']}")

    # By violation type
    print(f"\n  Violations by Type:")
    type_labels = {
        "orphaned_account":       "Orphaned Accounts (terminated user still active)",
        "inactive_account":       "Inactive Accounts (90+ days no login)",
        "excessive_privileges":   "Excessive Privileges (beyond role policy)",
        "missing_mfa":            "Missing MFA",
        "shared_account":         "Shared Accounts",
        "password_never_expires": "Password Never Expires",
        "role_mismatch":          "Role / Department Mismatch",
    }
    for vtype, count in s["by_violation_type"].items():
        label = type_labels.get(vtype, vtype)
        print(f"    • {label}: {count}")

    # Top violations table
    print(f"\n{'─'*70}")
    print(f"  {'User':<22} {'Department':<16} {'Violation':<28} {'Risk'}")
    print(f"  {'─'*21} {'─'*15} {'─'*27} {'─'*8}")
    for viol in sorted(v, key=lambda x: x.risk_score, reverse=True):
        risk_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(viol.risk_level(), "⚪")
        name  = viol.user.full_name[:21]
        dept  = viol.user.department[:15]
        vtype = viol.violation_type.replace("_", " ").title()[:27]
        print(f"  {name:<22} {dept:<16} {vtype:<28} {risk_icon} {viol.risk_level()}")

    print("=" * 70 + "\n")


def generate_violation_csv(engine: IAMReviewEngine, output_dir: str = "reports") -> str:
    """Export all violations to CSV — ready for auditor or manager review."""
    Path(output_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = f"{output_dir}/violations_{ts}.csv"

    fieldnames = [
        "user_id", "username", "full_name", "department", "job_title",
        "violation_type", "risk_score", "risk_level", "detail",
        "recommendation", "detected_at"
    ]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for v in sorted(engine.violations, key=lambda x: x.risk_score, reverse=True):
            writer.writerow(v.to_dict())

    print(f"[+] Violation report exported → {filepath}")
    return filepath


def generate_user_csv(engine: IAMReviewEngine, output_dir: str = "reports") -> str:
    """Export full user list with all attributes — simulates AD export."""
    Path(output_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = f"{output_dir}/user_access_list_{ts}.csv"

    if not engine.users:
        return filepath

    fieldnames = list(engine.users[0].to_dict().keys())
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for user in engine.users:
            writer.writerow(user.to_dict())

    print(f"[+] User access list exported → {filepath}")
    return filepath


def generate_audit_summary_json(engine: IAMReviewEngine, output_dir: str = "reports") -> str:
    """Generate full audit summary JSON for handoff."""
    Path(output_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = f"{output_dir}/audit_summary_{ts}.json"

    s = engine.get_summary()
    summary = {
        **s,
        "framework_alignment": [
            "SOC 2 CC6.1 — Logical access security measures",
            "SOC 2 CC6.2 — New user access provisioning",
            "SOC 2 CC6.3 — Timely access removal on termination",
            "NIST CSF PR.AC-1 — Identities and credentials managed",
            "NIST CSF PR.AC-4 — Access permissions managed",
            "ISO 27001 A.9 — Access control",
        ],
        "violations": [v.to_dict() for v in
                       sorted(engine.violations, key=lambda x: x.risk_score, reverse=True)],
        "remediation_priority": {
            "immediate_action": [
                v.to_dict() for v in engine.violations
                if v.risk_level() == "CRITICAL"
            ],
            "within_5_days": [
                v.to_dict() for v in engine.violations
                if v.risk_level() == "HIGH"
            ],
            "within_30_days": [
                v.to_dict() for v in engine.violations
                if v.risk_level() in ("MEDIUM", "LOW")
            ],
        }
    }

    with open(filepath, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[+] Audit summary JSON exported → {filepath}")
    return filepath
