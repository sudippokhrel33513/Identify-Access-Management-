# IAM Access Review Simulator

A Python tool that simulates the **quarterly user access certification process** used in real GRC and IAM roles. Detects security violations in Active Directory user accounts and generates audit-ready reports — directly mirroring SOC 2 CC6.x control requirements.

---

## 🎯 What This Simulates

In real GRC roles, every quarter an analyst must review ALL user accounts and answer:

- Do any **terminated employees** still have active accounts? *(orphaned accounts)*
- Are there accounts with **no login activity** for 90+ days? *(inactive accounts)*
- Do users have **more access than their role requires?** *(excessive privileges)*
- Is **MFA enabled** for all active users? *(missing MFA)*
- Are there **shared accounts** that violate individual accountability? *(shared accounts)*
- Is **password expiry** enforced? *(password never expires)*
- Does a user's access **match their department?** *(role/department mismatch)*

This tool automates all 7 checks, scores each violation by risk level, and generates reports ready for auditor handoff.

---

## 🗂️ Project Structure

```
iam_access_review/
│
├── main.py                    # CLI entry point
├── requirements.txt
├── README.md
│
├── src/
│   ├── iam_engine.py          # Core engine: user model, violation detection, risk scoring
│   └── reporter.py            # Dashboard + CSV/JSON report generation
│
├── data/
│   └── sample_users.py        # 20 realistic AD users with intentional violations
│
├── reports/                   # Auto-generated audit reports (gitignored)
│   ├── violations_*.csv
│   ├── user_access_list_*.csv
│   └── audit_summary_*.json
```

---

## ⚙️ Setup

```bash
git clone https://github.com/YOUR_USERNAME/iam-access-review-simulator.git
cd iam-access-review-simulator

# No external dependencies required — pure Python standard library
python main.py demo
```

---

## 🚀 Usage

### Run full demo (20 sample users + dashboard + reports)
```bash
python main.py demo
```

**Sample output:**
```
======================================================================
   IAM QUARTERLY ACCESS REVIEW — RESULTS DASHBOARD
   2024-11-15 09:32:11
======================================================================
  Total Users Reviewed : 20
  Clean (No Issues)    : 5  ✅
  Flagged              : 15  ⚠️
  Total Violations     : 28
  Compliance Rate      : 25.0%
──────────────────────────────────────────────────────────────────────
  Risk Breakdown:
    🔴 CRITICAL : 2
    🟠 HIGH     : 8
    🟡 MEDIUM   : 14
    🟢 LOW      : 4

  Violations by Type:
    • Orphaned Accounts (terminated user still active): 2
    • Inactive Accounts (90+ days no login): 7
    • Excessive Privileges (beyond role policy): 5
    • Missing MFA: 6
    • Role / Department Mismatch: 4
    • Password Never Expires: 2
    • Shared Accounts: 2
```

### Show only CRITICAL and HIGH risk violations
```bash
python main.py critical
```

### Investigate a specific user
```bash
python main.py user U006
python main.py user mbrown
```

### View violation statistics only
```bash
python main.py stats
```

### Generate all reports
```bash
python main.py report
# → reports/violations_*.csv
# → reports/user_access_list_*.csv
# → reports/audit_summary_*.json
```

---

## 🔍 Violation Types & Risk Scores

| Violation | Risk Score | Description |
|-----------|-----------|-------------|
| Excessive Privileges | 40 | User has access groups beyond their role policy |
| Orphaned Account | 35 | Terminated employee account still active |
| Role Mismatch | 30 | Access doesn't align with department |
| Inactive Account | 30 | No login in 90+ days |
| Missing MFA | 25 | No multi-factor authentication enabled |
| Shared Account | 20 | Account used by multiple individuals |
| Password Never Expires | 15 | Password rotation not enforced |

**Risk Levels:**

| Score | Level |
|-------|-------|
| 81–100 | 🔴 CRITICAL |
| 51–80 | 🟠 HIGH |
| 21–50 | 🟡 MEDIUM |
| 0–20 | 🟢 LOW |

---

## 📊 Report Outputs

### Violation Report CSV (`violations_*.csv`)
Every violation with user details, risk score, risk level, description, and recommended remediation action. Ready for import into ServiceNow or Jira as remediation tickets.

### User Access List CSV (`user_access_list_*.csv`)
Full AD user export showing all attributes — simulates what you would pull from Active Directory for auditor evidence (SOC 2 CC6.1).

### Audit Summary JSON (`audit_summary_*.json`)
Complete machine-readable summary including:
- Overall compliance rate
- Violations mapped to SOC 2 and NIST controls
- Remediation priority buckets (immediate / within 5 days / within 30 days)

---

## 🔗 SOC 2 & NIST Framework Alignment

| Check | SOC 2 Control | NIST CSF |
|-------|--------------|----------|
| Orphaned accounts | CC6.3 — Timely access removal | PR.AC-1 |
| Excessive privileges | CC6.1 — Logical access security | PR.AC-4 |
| New user provisioning | CC6.2 — Access provisioning | PR.AC-1 |
| MFA enforcement | CC6.1 — Logical access security | PR.AC-7 |
| Inactive accounts | CC6.1 — Logical access security | PR.AC-4 |
| Role mismatch | CC6.1 — Separation of duties | PR.AC-4 |

---

## 💡 Real-World Relevance

This project directly mirrors work performed in IAM and GRC analyst roles:

| Tool Feature | Real GRC Equivalent |
|---|---|
| User access list loading | AD export via PowerShell or SIEM |
| Orphaned account detection | Termination report cross-check |
| Excessive privilege check | Role-based access control (RBAC) review |
| Violation CSV export | Evidence for SOC 2 CC6.x controls |
| Audit summary JSON | Auditor handoff package |
| Remediation recommendations | ServiceNow / Jira ticket creation |

---

## 👤 Author

**Sudip Pokhrel**
Information Security Analyst — GRC & Compliance
[LinkedIn](https://linkedin.com/in/YOUR_PROFILE) | sudippokhrel33513@gmail.com

*Built to demonstrate practical IAM and GRC skills: quarterly access certification,
RBAC enforcement, SOC 2 CC6.x compliance, and audit-ready evidence generation.*
