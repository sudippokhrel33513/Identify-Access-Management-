"""
Sample Active Directory user data loader.
20 realistic users with intentional violations for demo purposes.
Mirrors what a real AD export looks like in a GRC access review.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from iam_engine import ADUser


def get_sample_users() -> list[ADUser]:
    return [
        # ── CLEAN users ───────────────────────────────────────────────────────
        ADUser("U001","jsmith","John Smith","IT","IT Support","jsmith@company.com",
               "active","employed","2024-10-15",
               ["IT_Basic","Helpdesk","Asset_Management"],
               True, False, False, "Mike Thompson","2022-03-01"),

        ADUser("U002","alee","Amanda Lee","HR","HR Specialist","alee@company.com",
               "active","employed","2024-11-01",
               ["HR_Basic","Payroll_Read"],
               True, False, False, "Sandra Kim","2021-06-15"),

        ADUser("U003","rchang","Robert Chang","Finance","Finance Manager","rchang@company.com",
               "active","employed","2024-10-28",
               ["Finance_Read","Finance_Write","Reporting","Finance_Admin"],
               True, False, False, "CEO Office","2019-01-10"),

        ADUser("U004","kpatel","Kavya Patel","IT","IT Manager","kpatel@company.com",
               "active","employed","2024-11-10",
               ["IT_Basic","Helpdesk","Asset_Management","IT_Admin","Network_Admin"],
               True, False, False, "CTO","2020-04-22"),

        ADUser("U005","lwilson","Liam Wilson","Development","Senior Developer","lwilson@company.com",
               "active","employed","2024-10-30",
               ["Dev_Basic","Source_Control","Dev_Environment","Prod_ReadOnly"],
               True, False, False, "Dev Lead","2021-09-01"),

        # ── ORPHANED accounts (terminated but still active) ───────────────────
        ADUser("U006","mbrown","Marcus Brown","Finance","Finance Analyst","mbrown@company.com",
               "active","terminated","2024-06-01",   # ← TERMINATED, account still ACTIVE
               ["Finance_Read","Finance_Write","Reporting","Finance_Admin"],
               True, False, False, "Robert Chang","2020-11-01",
               termination_date="2024-06-01"),

        ADUser("U007","tnguyen","Tina Nguyen","HR","HR Manager","tnguyen@company.com",
               "active","terminated","2024-03-15",   # ← TERMINATED 8 months ago
               ["HR_Basic","Payroll_Read","Payroll_Write","HR_Admin"],
               False, False, False, "Sandra Kim","2018-07-20",
               termination_date="2024-03-15"),

        # ── INACTIVE accounts (90+ days no login) ─────────────────────────────
        ADUser("U008","dgarcia","David Garcia","IT","IT Support","dgarcia@company.com",
               "active","employed","2024-01-15",     # ← Last login Jan 2024 (300+ days ago)
               ["IT_Basic","Helpdesk"],
               True, False, False, "Kavya Patel","2023-02-01"),

        ADUser("U009","fsaeed","Fatima Saeed","Finance","Finance Analyst","fsaeed@company.com",
               "active","employed","2023-12-01",     # ← Last login Dec 2023 (340+ days ago)
               ["Finance_Read","Reporting"],
               True, False, False, "Robert Chang","2023-08-14"),

        ADUser("U010","jkowalski","Jan Kowalski","HR","HR Specialist","jkowalski@company.com",
               "active","employed", None,            # ← NEVER logged in
               ["HR_Basic","Payroll_Read"],
               False, False, False, "Sandra Kim","2024-09-01"),

        # ── EXCESSIVE PRIVILEGES ───────────────────────────────────────────────
        ADUser("U011","pmurphy","Patrick Murphy","Finance","Finance Analyst","pmurphy@company.com",
               "active","employed","2024-11-05",
               ["Finance_Read","Reporting","Finance_Admin","IT_Admin","HR_Admin"],  # ← WAY too much
               True, False, False, "Robert Chang","2022-05-17"),

        ADUser("U012","ychen","Ying Chen","Development","Developer","ychen@company.com",
               "active","employed","2024-10-20",
               ["Dev_Basic","Source_Control","Dev_Environment","Prod_ReadOnly","Finance_Write"],  # ← Finance access?
               True, False, False, "Dev Lead","2023-03-01"),

        # ── MISSING MFA ────────────────────────────────────────────────────────
        ADUser("U013","bthomas","Brian Thomas","IT","IT Support","bthomas@company.com",
               "active","employed","2024-11-08",
               ["IT_Basic","Helpdesk","Asset_Management"],
               False, False, False, "Kavya Patel","2024-01-15"),   # ← MFA disabled

        ADUser("U014","nrobinson","Nina Robinson","Executive","Executive","nrobinson@company.com",
               "active","employed","2024-10-25",
               ["Executive_Dashboard","Finance_Read","HR_Read","Reporting"],
               False, False, False, "Board","2015-03-01"),          # ← Executive with NO MFA!

        # ── PASSWORD NEVER EXPIRES ─────────────────────────────────────────────
        ADUser("U015","gjackson","George Jackson","Finance","Finance Manager","gjackson@company.com",
               "active","employed","2024-11-01",
               ["Finance_Read","Finance_Write","Reporting","Finance_Admin"],
               True, True, False, "CFO","2016-08-22"),              # ← Password never expires

        ADUser("U016","smarcos","Sofia Marcos","IT","IT Manager","smarcos@company.com",
               "active","employed","2024-10-15",
               ["IT_Basic","Helpdesk","Asset_Management","IT_Admin","Network_Admin"],
               True, True, False, "CTO","2017-02-14"),              # ← IT Manager, pwd never expires

        # ── SHARED ACCOUNTS ────────────────────────────────────────────────────
        ADUser("U017","reception","Reception Shared","Operations","Contractor","reception@company.com",
               "active","employed","2024-11-09",
               ["Contractor_Limited"],
               False, False, True, "Office Manager","2020-01-01"),  # ← Shared account

        # ── ROLE / DEPARTMENT MISMATCH ─────────────────────────────────────────
        ADUser("U018","hpark","Hannah Park","HR","HR Specialist","hpark@company.com",
               "active","employed","2024-10-18",
               ["HR_Basic","Payroll_Read","Finance_Write","Finance_Admin"],  # ← HR with Finance_Write
               True, False, False, "Sandra Kim","2022-11-30"),

        ADUser("U019","odiallo","Omar Diallo","Development","Developer","odiallo@company.com",
               "active","employed","2024-11-02",
               ["Dev_Basic","Source_Control","Dev_Environment","HR_Admin","Payroll_Write"],  # ← Dev with HR access
               True, False, False, "Dev Lead","2023-07-10"),

        # ── CONTRACTOR with excessive access ───────────────────────────────────
        ADUser("U020","ext_vendor","External Vendor (TechCorp)","IT","Contractor",
               "vendor@techcorp.com",
               "active","contractor","2024-08-01",
               ["IT_Basic","IT_Admin","Network_Admin","Finance_Read","HR_Basic"],  # ← Contractor with too much
               False, True, True, "Kavya Patel","2024-06-01"),
    ]


if __name__ == "__main__":
    users = get_sample_users()
    print(f"[+] Sample data: {len(users)} users loaded")
    employed   = sum(1 for u in users if u.employment_status == "employed")
    terminated = sum(1 for u in users if u.employment_status == "terminated")
    contractor = sum(1 for u in users if u.employment_status == "contractor")
    print(f"    Employed:   {employed}")
    print(f"    Terminated: {terminated}")
    print(f"    Contractor: {contractor}")
