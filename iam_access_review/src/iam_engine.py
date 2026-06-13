"""
IAM Access Review Simulator
============================
Simulates quarterly user access certification process used in real GRC/IAM roles.
Detects over-privileged accounts, inactive users, role misalignments,
orphaned accounts, and missing MFA — exactly as done in Active Directory environments.
"""

import json
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ── Risk scoring weights ───────────────────────────────────────────────────────

RISK_WEIGHTS = {
    "excessive_privileges":   40,   # User has more access than their role requires
    "inactive_account":       30,   # No login in 90+ days
    "orphaned_account":       35,   # Employee terminated but account still active
    "missing_mfa":            25,   # No multi-factor authentication enabled
    "shared_account":         20,   # Account shared between multiple people
    "password_never_expires": 15,   # Password expiry disabled
    "role_mismatch":          30,   # Access doesn't match job title/department
}

RISK_LEVELS = {
    (0,  20):  "LOW",
    (21, 50):  "MEDIUM",
    (51, 80):  "HIGH",
    (81, 999): "CRITICAL",
}

# Role → allowed access groups mapping (simulates AD group policy)
ROLE_ACCESS_POLICY = {
    "IT Support":         ["IT_Basic", "Helpdesk", "Asset_Management"],
    "IT Manager":         ["IT_Basic", "Helpdesk", "Asset_Management", "IT_Admin", "Network_Admin"],
    "HR Specialist":      ["HR_Basic", "Payroll_Read"],
    "HR Manager":         ["HR_Basic", "Payroll_Read", "Payroll_Write", "HR_Admin"],
    "Finance Analyst":    ["Finance_Read", "Reporting"],
    "Finance Manager":    ["Finance_Read", "Finance_Write", "Reporting", "Finance_Admin"],
    "Developer":          ["Dev_Basic", "Source_Control", "Dev_Environment"],
    "Senior Developer":   ["Dev_Basic", "Source_Control", "Dev_Environment", "Prod_ReadOnly"],
    "Executive":          ["Executive_Dashboard", "Finance_Read", "HR_Read", "Reporting"],
    "Contractor":         ["Contractor_Limited"],
}


# ── User model ─────────────────────────────────────────────────────────────────

class ADUser:
    def __init__(
        self,
        user_id: str,
        username: str,
        full_name: str,
        department: str,
        job_title: str,
        email: str,
        account_status: str,           # active / disabled / locked
        employment_status: str,        # employed / terminated / contractor
        last_login: Optional[str],     # YYYY-MM-DD or None
        access_groups: list[str],
        mfa_enabled: bool,
        password_never_expires: bool,
        is_shared_account: bool,
        manager: str,
        created_date: str,
        termination_date: Optional[str] = None,
    ):
        self.user_id             = user_id
        self.username            = username
        self.full_name           = full_name
        self.department          = department
        self.job_title           = job_title
        self.email               = email
        self.account_status      = account_status
        self.employment_status   = employment_status
        self.last_login          = last_login
        self.access_groups       = access_groups
        self.mfa_enabled         = mfa_enabled
        self.password_never_expires = password_never_expires
        self.is_shared_account   = is_shared_account
        self.manager             = manager
        self.created_date        = created_date
        self.termination_date    = termination_date

    def to_dict(self) -> dict:
        return {
            "user_id":               self.user_id,
            "username":              self.username,
            "full_name":             self.full_name,
            "department":            self.department,
            "job_title":             self.job_title,
            "email":                 self.email,
            "account_status":        self.account_status,
            "employment_status":     self.employment_status,
            "last_login":            self.last_login or "Never",
            "access_groups":         "; ".join(self.access_groups),
            "mfa_enabled":           self.mfa_enabled,
            "password_never_expires": self.password_never_expires,
            "is_shared_account":     self.is_shared_account,
            "manager":               self.manager,
            "created_date":          self.created_date,
            "termination_date":      self.termination_date or "N/A",
        }


# ── Violation model ────────────────────────────────────────────────────────────

class Violation:
    def __init__(self, user: ADUser, violation_type: str, detail: str, recommendation: str):
        self.user          = user
        self.violation_type = violation_type
        self.detail        = detail
        self.recommendation = recommendation
        self.risk_score    = RISK_WEIGHTS.get(violation_type, 10)
        self.detected_at   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def risk_level(self) -> str:
        for (low, high), level in RISK_LEVELS.items():
            if low <= self.risk_score <= high:
                return level
        return "UNKNOWN"

    def to_dict(self) -> dict:
        return {
            "user_id":        self.user.user_id,
            "username":       self.user.username,
            "full_name":      self.user.full_name,
            "department":     self.user.department,
            "job_title":      self.user.job_title,
            "violation_type": self.violation_type,
            "risk_score":     self.risk_score,
            "risk_level":     self.risk_level(),
            "detail":         self.detail,
            "recommendation": self.recommendation,
            "detected_at":    self.detected_at,
        }


# ── Core review engine ─────────────────────────────────────────────────────────

class IAMReviewEngine:
    def __init__(self, inactive_days: int = 90):
        self.inactive_days = inactive_days
        self.users: list[ADUser] = []
        self.violations: list[Violation] = []

    def load_users(self, users: list[ADUser]):
        self.users = users
        self.violations = []

    def run_review(self) -> list[Violation]:
        """Run all access review checks against loaded users."""
        self.violations = []
        for user in self.users:
            self._check_orphaned_account(user)
            self._check_inactive_account(user)
            self._check_excessive_privileges(user)
            self._check_missing_mfa(user)
            self._check_shared_account(user)
            self._check_password_never_expires(user)
            self._check_role_mismatch(user)
        return self.violations

    # ── Individual checks ──────────────────────────────────────────────────────

    def _check_orphaned_account(self, user: ADUser):
        """Terminated employee with account still active."""
        if user.employment_status == "terminated" and user.account_status == "active":
            term_date = user.termination_date or "unknown date"
            self.violations.append(Violation(
                user=user,
                violation_type="orphaned_account",
                detail=f"Account is ACTIVE but employee was terminated on {term_date}. "
                       f"Access groups still assigned: {', '.join(user.access_groups)}.",
                recommendation="Immediately disable account and remove all access group memberships. "
                               "Escalate to IT Manager for same-day remediation.",
            ))

    def _check_inactive_account(self, user: ADUser):
        """Account with no login activity for 90+ days."""
        if user.account_status != "active":
            return
        if not user.last_login:
            self.violations.append(Violation(
                user=user,
                violation_type="inactive_account",
                detail="Account has NEVER been logged into since creation. "
                       f"Account created: {user.created_date}.",
                recommendation="Verify with manager if account is still needed. "
                               "Disable if no business justification provided within 5 business days.",
            ))
            return
        last = datetime.strptime(user.last_login, "%Y-%m-%d")
        days_inactive = (datetime.now() - last).days
        if days_inactive >= self.inactive_days:
            self.violations.append(Violation(
                user=user,
                violation_type="inactive_account",
                detail=f"No login activity for {days_inactive} days "
                       f"(last login: {user.last_login}). Threshold: {self.inactive_days} days.",
                recommendation="Notify manager to confirm if user still requires access. "
                               "Disable account if no response within 5 business days.",
            ))

    def _check_excessive_privileges(self, user: ADUser):
        """User has access groups beyond what their role allows."""
        allowed = set(ROLE_ACCESS_POLICY.get(user.job_title, []))
        actual  = set(user.access_groups)
        excess  = actual - allowed
        if excess:
            self.violations.append(Violation(
                user=user,
                violation_type="excessive_privileges",
                detail=f"User has {len(excess)} access group(s) beyond their role policy: "
                       f"{', '.join(sorted(excess))}. "
                       f"Allowed for '{user.job_title}': {', '.join(sorted(allowed)) or 'None defined'}.",
                recommendation=f"Remove excessive groups: {', '.join(sorted(excess))}. "
                               f"Obtain manager approval if business justification exists.",
            ))

    def _check_missing_mfa(self, user: ADUser):
        """Active user without MFA enabled."""
        if user.account_status == "active" and not user.mfa_enabled:
            self.violations.append(Violation(
                user=user,
                violation_type="missing_mfa",
                detail="Multi-Factor Authentication (MFA) is NOT enabled for this active account. "
                       "Account is vulnerable to credential-based attacks.",
                recommendation="Enroll user in MFA immediately. Flag as high priority "
                               "if user has access to sensitive systems or privileged groups.",
            ))

    def _check_shared_account(self, user: ADUser):
        """Shared accounts violate accountability principles."""
        if user.is_shared_account:
            self.violations.append(Violation(
                user=user,
                violation_type="shared_account",
                detail="This is a shared account used by multiple individuals. "
                       "Shared accounts violate the principle of individual accountability "
                       "and make audit trails unreliable.",
                recommendation="Create individual accounts for each user. "
                               "Disable shared account after individual accounts are provisioned.",
            ))

    def _check_password_never_expires(self, user: ADUser):
        """Password expiry disabled — security risk."""
        if user.account_status == "active" and user.password_never_expires:
            self.violations.append(Violation(
                user=user,
                violation_type="password_never_expires",
                detail="Account has 'Password Never Expires' flag set. "
                       "This means the password has never been forced to rotate, "
                       "increasing risk of credential compromise.",
                recommendation="Enable password expiry policy (90-day rotation recommended). "
                               "Force immediate password reset if account has privileged access.",
            ))

    def _check_role_mismatch(self, user: ADUser):
        """Access groups don't match the user's department."""
        dept_keywords = {
            "IT":        ["IT_", "Helpdesk", "Network", "Asset"],
            "HR":        ["HR_", "Payroll"],
            "Finance":   ["Finance_", "Reporting"],
            "Executive": ["Executive_", "Dashboard"],
        }
        for dept, keywords in dept_keywords.items():
            if dept.lower() in user.department.lower():
                cross_access = [
                    g for g in user.access_groups
                    if any(k in g for k in keywords)
                    and dept.lower() not in user.department.lower()
                ]
                # Check if user has OTHER department's sensitive access
                other_dept_access = []
                for other_dept, other_keywords in dept_keywords.items():
                    if other_dept != dept and other_dept.lower() not in user.department.lower():
                        found = [g for g in user.access_groups
                                 if any(k in g for k in other_keywords)]
                        other_dept_access.extend(found)
                if other_dept_access:
                    self.violations.append(Violation(
                        user=user,
                        violation_type="role_mismatch",
                        detail=f"User in '{user.department}' department has access to "
                               f"groups from other departments: {', '.join(other_dept_access)}. "
                               f"This violates least-privilege and separation of duties.",
                        recommendation=f"Review with manager. Remove cross-department access "
                                       f"unless formal business justification is documented and approved.",
                    ))
                break

    # ── Summary stats ──────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        total_users    = len(self.users)
        total_violations = len(self.violations)
        flagged_users  = len({v.user.user_id for v in self.violations})
        clean_users    = total_users - flagged_users

        by_type = {}
        by_level = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in self.violations:
            by_type[v.violation_type] = by_type.get(v.violation_type, 0) + 1
            by_level[v.risk_level()] += 1

        return {
            "review_date":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_users":       total_users,
            "flagged_users":     flagged_users,
            "clean_users":       clean_users,
            "total_violations":  total_violations,
            "by_violation_type": by_type,
            "by_risk_level":     by_level,
            "compliance_rate":   round((clean_users / total_users) * 100, 1) if total_users else 0,
        }
