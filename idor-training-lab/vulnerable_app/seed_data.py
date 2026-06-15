"""
Seed Data — Vulnerable App
Populates the database with realistic test users, orders, invoices,
documents, and support tickets for IDOR training demonstrations.

Test Accounts
─────────────────────────────────────────────────────────────────
  Role       Username   Password     Notes
  ─────────  ─────────  ───────────  ────────────────────────────
  admin      alice      alice123     Full access, salary visible
  manager    diana      diana123     HR manager
  user       bob        bob123       Sales department
  user       charlie    charlie123   Engineering department
  user       eve        eve123       Finance department
─────────────────────────────────────────────────────────────────
"""

import os
import sys
import sqlite3
import hashlib

# Allow running from any directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'vulnerable.db')

# Import init_db from app
sys.path.insert(0, BASE_DIR)
from app import init_db


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def seed():
    init_db()
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")

    # Clear existing data
    db.executescript("""
        DELETE FROM tickets;
        DELETE FROM documents;
        DELETE FROM invoices;
        DELETE FROM orders;
        DELETE FROM users;
        DELETE FROM sqlite_sequence WHERE name IN
            ('tickets','documents','invoices','orders','users');
    """)

    # ── Users ──────────────────────────────────────────────────────────────
    users = [
        # id=1
        (1, 'alice',   'alice@corpportal.local',   hash_password('alice123'),
         'Alice Johnson',  '+1-555-0101', '14 Oak Street, Springfield, IL 62701',
         'admin',   'Executive',    120000.00, 'SSN: 123-45-6789'),
        # id=2
        (2, 'bob',     'bob@corpportal.local',     hash_password('bob123'),
         'Bob Martinez',   '+1-555-0102', '27 Maple Ave, Springfield, IL 62702',
         'user',    'Sales',         65000.00, 'SSN: 987-65-4321'),
        # id=3
        (3, 'charlie', 'charlie@corpportal.local', hash_password('charlie123'),
         'Charlie Kim',    '+1-555-0103', '8 Pine Road, Springfield, IL 62703',
         'user',    'Engineering',   85000.00, 'SSN: 456-78-9012'),
        # id=4
        (4, 'diana',   'diana@corpportal.local',   hash_password('diana123'),
         'Diana Patel',    '+1-555-0104', '33 Elm Drive, Springfield, IL 62704',
         'manager', 'Human Resources',95000.00, 'SSN: 321-54-9876'),
        # id=5
        (5, 'eve',     'eve@corpportal.local',     hash_password('eve123'),
         'Eve Thompson',   '+1-555-0105', '19 Birch Lane, Springfield, IL 62705',
         'user',    'Finance',       70000.00, 'SSN: 654-32-1098'),
    ]
    db.executemany("""
        INSERT INTO users (id, username, email, password, full_name, phone, address,
                           role, department, salary, ssn)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, users)

    # ── Orders ─────────────────────────────────────────────────────────────
    orders = [
        # Alice's orders (id=1,2,3)
        (1, 1, 'Enterprise Software License – Suite Pro',  1,   4500.00,  4500.00,
         'completed', '14 Oak Street, Springfield, IL 62701', 'Annual renewal'),
        (2, 1, 'MacBook Pro 16" M3 Max',                   2,   3999.00,  7998.00,
         'shipped',   '14 Oak Street, Springfield, IL 62701', 'For new hires'),
        (3, 1, 'Standing Desk (Adjustable)',               3,    599.00,  1797.00,
         'pending',   '14 Oak Street, Springfield, IL 62701', 'Home office setup'),

        # Bob's orders (id=4,5,6)
        (4, 2, 'Salesforce CRM – Professional Plan',       1,   1200.00,  1200.00,
         'completed', '27 Maple Ave, Springfield, IL 62702', 'Monthly subscription'),
        (5, 2, 'Business Travel Kit',                      1,    249.99,   249.99,
         'shipped',   '27 Maple Ave, Springfield, IL 62702', 'Q1 client visits'),
        (6, 2, 'Marketing Collateral Print Run',           500,    1.20,   600.00,
         'pending',   'Print & Ship Direct to Customer', 'Campaign materials'),

        # Charlie's orders (id=7,8,9)
        (7, 3, 'AWS Reserved Instances (1yr)',             1,   8640.00,  8640.00,
         'completed', '8 Pine Road, Springfield, IL 62703', 'Dev environment'),
        (8, 3, 'GitHub Enterprise License',               10,    231.00,  2310.00,
         'completed', 'Digital delivery', 'Engineering team'),
        (9, 3, 'Mechanical Keyboard – Keychron Q5',        1,    179.00,   179.00,
         'pending',   '8 Pine Road, Springfield, IL 62703', 'Personal preference approved'),

        # Diana's orders (id=10,11)
        (10, 4, 'HR Software – BambooHR Annual',           1,   3600.00,  3600.00,
         'completed', 'Digital delivery', 'Company-wide HR system'),
        (11, 4, 'Training Room Supplies',                 30,     22.00,   660.00,
         'shipped',   '33 Elm Drive, Springfield, IL 62704', 'Onboarding kits'),

        # Eve's orders (id=12,13)
        (12, 5, 'QuickBooks Enterprise 2024',              1,   1720.00,  1720.00,
         'completed', 'Digital delivery', 'Finance department license'),
        (13, 5, 'Ergonomic Chair – Herman Miller',         1,   1495.00,  1495.00,
         'pending',   '19 Birch Lane, Springfield, IL 62705', 'Approved by manager'),
    ]
    db.executemany("""
        INSERT INTO orders
            (id, user_id, product_name, quantity, unit_price, total_price,
             status, shipping_address, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, orders)

    # ── Invoices ───────────────────────────────────────────────────────────
    invoices = [
        # Alice's invoices (id=1,2,3)
        (1, 1, 1, 'INV-2024-0001',  4500.00, 405.00, 'paid',
         '2024-02-15', 'AMEX Corporate Card ending 4821 | Auth: TXN-8834521'),
        (2, 1, 2, 'INV-2024-0002',  7998.00, 719.82, 'paid',
         '2024-03-01', 'ACH Bank Transfer | Account: ****7723 | Ref: PAY-2209'),
        (3, 1, 3, 'INV-2024-0003',  1797.00, 161.73, 'unpaid',
         '2024-04-30', 'Pending — NET30 terms'),

        # Bob's invoices (id=4,5,6)
        (4, 2, 4, 'INV-2024-0004',  1200.00, 108.00, 'paid',
         '2024-02-28', 'VISA Corporate Card ending 3390 | Auth: TXN-1123009'),
        (5, 2, 5, 'INV-2024-0005',   249.99,  22.50, 'paid',
         '2024-03-15', 'Mastercard ending 6612 | Auth: TXN-5542011'),
        (6, 2, 6, 'INV-2024-0006',   600.00,  54.00, 'unpaid',
         '2024-05-01', 'Pending approval'),

        # Charlie's invoices (id=7,8,9)
        (7, 3, 7, 'INV-2024-0007',  8640.00, 777.60, 'paid',
         '2024-02-01', 'ACH Transfer | Account: ****9901 | Ref: AWS-CORP-2024'),
        (8, 3, 8, 'INV-2024-0008',  2310.00, 207.90, 'paid',
         '2024-03-10', 'AMEX Corporate Card ending 1177 | Auth: TXN-7788432'),
        (9, 3, 9, 'INV-2024-0009',   179.00,  16.11, 'unpaid',
         '2024-05-15', 'NET30 — awaiting PO approval'),

        # Diana's invoices (id=10,11)
        (10, 4, 10, 'INV-2024-0010', 3600.00, 324.00, 'paid',
         '2024-02-20', 'VISA Business ending 9988 | Auth: TXN-3300887'),
        (11, 4, 11, 'INV-2024-0011',  660.00,  59.40, 'unpaid',
         '2024-04-25', 'Pending'),

        # Eve's invoices (id=12,13)
        (12, 5, 12, 'INV-2024-0012', 1720.00, 154.80, 'paid',
         '2024-03-05', 'ACH Transfer | Account: ****4455 | Ref: QB-2024-ANNUAL'),
        (13, 5, 13, 'INV-2024-0013', 1495.00, 134.55, 'unpaid',
         '2024-05-30', 'Approved — awaiting vendor invoice'),
    ]
    db.executemany("""
        INSERT INTO invoices
            (id, user_id, order_id, invoice_number, amount, tax, status,
             due_date, payment_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, invoices)

    # ── Documents ──────────────────────────────────────────────────────────
    documents = [
        # Alice's documents (id=1,2,3)
        (1, 1, 'q1_executive_report.pdf', 'application/pdf',
         'Q1 2024 Executive Performance Report', 1,
         """CONFIDENTIAL — EXECUTIVE SUMMARY Q1 2024
Board Distribution Only

Revenue: $4.2M (+18% YoY)
Gross Margin: 67.3%
EBITDA: $1.1M

Headcount: 47 (+6 from Q4 2023)
Open requisitions: 8

Strategic Initiatives:
1. APAC expansion — Target Q3 launch, $800K budget allocated
2. Product v3.0 — On track for August GA
3. ISO 27001 certification — Gap assessment complete

Compensation Adjustments (Confidential):
- Engineering band raised by 8%
- Sales OTE increase approved for top performers
- Executive bonus pool: $240,000 for FY24

Contact alice@corpportal.local with questions."""),

        (2, 1, 'password_policy.txt', 'text/plain',
         'IT Password Policy — Admin Reference', 0,
         """IT SECURITY — PASSWORD POLICY v2.3

Admin Service Accounts (DO NOT SHARE):
  db-backup-svc  : Backup$2024!Secure
  monitoring-svc : Mon!tor_Prod_99
  deploy-bot     : D3pl0y#AutoB0t

Policy Requirements:
- Minimum 14 characters
- Complexity: upper, lower, digit, symbol
- Rotation: 90 days
- No reuse of last 12 passwords

Emergency break-glass credentials stored in 1Password vault 'IT-Emergency'.
Contact alice@corpportal.local for access."""),

        (3, 1, 'org_chart_2024.txt', 'text/plain',
         'Organization Chart with Salaries', 1,
         """CONFIDENTIAL — ORG CHART WITH COMPENSATION DATA

Role             Name             Salary      SSN
─────────────────────────────────────────────────────
CEO / Admin      Alice Johnson    $120,000    123-45-6789
HR Manager       Diana Patel      $95,000     321-54-9876
Sr. Engineer     Charlie Kim      $85,000     456-78-9012
Finance Analyst  Eve Thompson     $70,000     654-32-1098
Sales Rep        Bob Martinez     $65,000     987-65-4321

This document is for HR use only. Unauthorized access is a
violation of company policy and applicable law."""),

        # Bob's documents (id=4,5)
        (4, 2, 'q1_sales_pipeline.txt', 'text/plain',
         'Q1 2024 Sales Pipeline Report', 0,
         """SALES PIPELINE — Q1 2024

Active Deals:
  Acme Corp        $45,000   Stage: Proposal    Close: Mar 15
  TechStart Inc    $12,000   Stage: Demo        Close: Mar 30
  GlobalMed        $78,000   Stage: Negotiation Close: Apr 5

Won Deals (Q1):
  NovaTech         $31,500
  City Council     $8,200

Target: $180,000  |  Current: $174,700  |  Gap: $5,300

Owner: bob@corpportal.local"""),

        (5, 2, 'client_contacts.txt', 'text/plain',
         'Client Contact List — Sales', 1,
         """CONFIDENTIAL — CLIENT CONTACTS

Acme Corp:
  Contact: John Davis, VP Procurement
  Direct: +1-555-2201
  Email: jdavis@acme.example.com
  Note: Decision maker, golf Saturdays

TechStart Inc:
  Contact: Lisa Wong, CTO
  Direct: +1-555-4409
  Email: lwong@techstart.example.com

GlobalMed:
  Contact: Dr. Raj Patel, Director IT
  Direct: +1-555-8876
  Note: Competing with SalesForce incumbent"""),

        # Charlie's documents (id=6,7)
        (6, 3, 'system_architecture.txt', 'text/plain',
         'Production System Architecture Notes', 1,
         """INTERNAL — PRODUCTION ARCHITECTURE

Database Servers:
  Primary:  db-prod-01.internal  (PostgreSQL 15)
  Replica:  db-prod-02.internal  (read-only)
  Backups:  S3 bucket: corp-db-backups-prod (encrypted)

API Servers:
  api-prod-01 through api-prod-04
  Load balanced via nginx — config at /etc/nginx/conf.d/api.conf

Admin Endpoints (Internal only):
  GET /internal/admin/users    — List all users
  POST /internal/admin/reset   — Force password reset
  GET /internal/metrics        — Prometheus metrics

VPN Required: vpn.corpportal.local
  Credentials in 1Password vault 'Engineering'

SSH Key fingerprint: SHA256:xKj9mN2pQ7rL4sH1vB6wC3yF8zA5dE0gI"""),

        (7, 3, 'bug_report_2024_003.txt', 'text/plain',
         'Security Bug Report #2024-003', 0,
         """BUG REPORT #2024-003
Severity: HIGH
Status: In Progress

Title: SQL injection in legacy reporting endpoint

Reporter: charlie@corpportal.local
Affected: /reports/generate endpoint (legacy v1 API)

Description:
The `date_range` parameter is not sanitized and is concatenated
directly into the SQL query. Confirmed blind SQL injection.

PoC: date_range=2024-01-01' OR '1'='1

Impact: Full database read access, potential data exfiltration.

Mitigation: Parameterized queries. Patch ETA: 2 weeks.
DO NOT DISCLOSE until patched."""),

        # Diana's documents (id=8,9)
        (8, 4, 'performance_reviews_2024.txt', 'text/plain',
         'Annual Performance Reviews — Confidential', 1,
         """CONFIDENTIAL — PERFORMANCE REVIEW SUMMARY 2024

Employee Reviews:
─────────────────────────────────────────────────────────────────
Bob Martinez (Sales):
  Rating: 3/5 — Meets Expectations
  Notes: Missed Q3 quota by 12%. Attitude issues in team meetings.
  PIP recommended if Q4 targets missed.
  Salary increase: 0% (held)

Charlie Kim (Engineering):
  Rating: 5/5 — Exceeds Expectations
  Notes: Led successful migration. Excellent technical leadership.
  Salary increase: 10% approved
  Promotion to Senior Engineer effective Jan 1.

Eve Thompson (Finance):
  Rating: 4/5 — Above Expectations
  Notes: Clean audit, strong process improvements.
  Salary increase: 5% approved

Prepared by: Diana Patel, HR Manager
Distribution: CEO, CFO only"""),

        (9, 4, 'disciplinary_record_bob.txt', 'text/plain',
         'Disciplinary Record — B. Martinez', 1,
         """CONFIDENTIAL — DISCIPLINARY RECORD

Employee: Bob Martinez (ID: 2)
Date: 2024-01-15
Type: Written Warning

Incident: Inappropriate comments made to Eve Thompson during
the January all-hands meeting. Two other employees witnessed.

Actions Taken:
  - Verbal counseling: 2024-01-12
  - Written warning issued: 2024-01-15
  - Mandatory HR training scheduled: 2024-02-01

Employee Acknowledgment: Signed (copy on file)
Issued by: Diana Patel, HR Manager
Witness: Alice Johnson, CEO"""),

        # Eve's documents (id=10,11)
        (10, 5, 'budget_forecast_2024.txt', 'text/plain',
         'Budget Forecast FY2024 — Finance', 1,
         """CONFIDENTIAL — BUDGET FORECAST FY2024

Approved Headcount Budget:   $2,850,000
  Current spend (Q1):          $712,000 (25%)

Operational Budget:          $1,200,000
  IT/Software:                  $340,000
  Travel & Entertainment:       $180,000
  Marketing:                    $420,000
  Facilities:                   $260,000

Capital Expenditure:           $450,000
  Hardware refresh:             $200,000
  Office renovation (Phase 2):  $250,000

Projected Year-End:
  Revenue:     $16,800,000
  Net Income:   $2,940,000 (17.5% margin)

Prepared by: Eve Thompson, Finance Analyst
Reviewed by: Alice Johnson, CEO"""),

        (11, 5, 'vendor_contracts.txt', 'text/plain',
         'Vendor Contract Summary', 0,
         """VENDOR CONTRACTS — ACTIVE

AWS Inc.:
  Contract value: $103,680/year
  Renewal: 2025-01-15
  Discount: 12% enterprise
  Account Manager: Sarah Chen, +1-555-3300

Salesforce:
  Contract value: $14,400/year
  Renewal: 2024-12-01
  Notes: Evaluate alternatives before renewal

GitHub (Microsoft):
  Contract value: $27,720/year
  Renewal: 2025-03-01

BambooHR:
  Contract value: $3,600/year
  Month-to-month — cancel with 30 days notice

Total Annual Vendor Spend: $149,400"""),
    ]
    db.executemany("""
        INSERT INTO documents
            (id, user_id, filename, content_type, description, is_confidential, content)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, documents)

    # ── Support Tickets ────────────────────────────────────────────────────
    tickets = [
        # Alice's tickets (id=1,2)
        (1, 1, 'MFA not working after phone replacement', 'open', 'high', 'IT Support',
         """My authenticator app is not generating valid codes since I got a new iPhone.
I need access restored urgently — I have a board call in 2 hours.
Please use my recovery codes: ALICE-2024-RC: 8472-1938-5623-7401
This is blocking me from accessing the admin panel.""",
         None),

        (2, 1, 'Request: Increase cloud spend limit to $15,000/month', 'resolved',
         'medium', 'Finance Request',
         """We need to increase our AWS monthly spend limit from $10K to $15K
for the APAC expansion project. Budget has been approved by the board.""",
         'Approved. Limit updated by Finance. New limit effective immediately.'),

        # Bob's tickets (id=3,4)
        (3, 2, 'Cannot access CRM — password reset loop', 'open', 'high', 'IT Support',
         """Salesforce keeps prompting me to reset my password even after
I've done it 3 times. My current password is: B0b$ales2024!
Please fix this — I have client demos today.""",
         None),

        (4, 2, 'Expense report: Feb travel to Chicago', 'resolved', 'low', 'Finance',
         """Submitting expense report for Chicago client visit Feb 12-14:
  Hotel: $342 (Marriott — receipt attached)
  Flights: $287 (United — receipt attached)
  Meals: $124
  Total: $753""",
         'Approved and processed. Reimbursement in next payroll cycle.'),

        # Charlie's tickets (id=5,6)
        (5, 3, 'Production deployment access request', 'open', 'medium', 'DevOps',
         """Need elevated access to push hotfix for the SQL injection bug
(Bug Report #2024-003). This is time-sensitive — patch is ready.
Requesting: SSH access to api-prod-01, api-prod-02 for 4 hours.""",
         None),

        (6, 3, 'Laptop battery replacement — MacBook Pro', 'resolved', 'low', 'IT Support',
         """Battery health shows 71%. Requesting replacement under AppleCare+.
Serial number: C02XL0ZHJGH5""",
         'Approved. Scheduled with Apple Store for next Tuesday 2pm. Charlie confirmed.'),

        # Diana's tickets (id=7,8)
        (7, 4, 'Employee termination — immediate action required', 'open', 'critical',
         'HR - Confidential',
         """CONFIDENTIAL — DO NOT FORWARD
Employee termination effective immediately (details in separate email).
Action required from IT:
1. Disable all system access NOW
2. Preserve email archive for legal hold
3. Collect company devices by EOD

Legal has been notified. Do not inform the employee's team until notified.""",
         None),

        (8, 4, 'HR system upgrade — BambooHR migration', 'resolved', 'medium',
         'IT Support',
         """Need assistance migrating employee records from old HR system
to BambooHR. Estimated 47 employee records including salary, performance,
and disciplinary data. Please ensure data is encrypted in transit.""",
         'Migration completed successfully. All 47 records verified. Encryption confirmed.'),

        # Eve's tickets (id=9,10)
        (9, 5, 'Access to accounts payable module — urgent', 'open', 'high',
         'IT Support',
         """I need access to the AP module to process $340K in vendor payments
before the end of Q1. Current permissions only allow read access.
CFO approval: approved verbally in standup — Alice can confirm.""",
         None),

        (10, 5, 'Payroll data export — Q1 audit', 'resolved', 'medium', 'Finance',
         """Requesting payroll data export for Q1 2024 for external audit.
Auditor firm: KPMG — Contact: audit@kpmg.example.com
Data required: All employee compensation, bonuses, and deductions.
Please send via encrypted channel only.""",
         'Export completed. Sent via SecureShare to KPMG contact. Ref: AUDIT-Q1-2024-07'),
    ]
    db.executemany("""
        INSERT INTO tickets
            (id, user_id, subject, status, priority, category, description, resolution)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, tickets)

    db.commit()
    db.close()

    print("✓ Seed data inserted successfully into vulnerable.db")
    print()
    print("Test Accounts:")
    print("  alice   / alice123  (admin)")
    print("  diana   / diana123  (manager)")
    print("  bob     / bob123    (user)")
    print("  charlie / charlie123 (user)")
    print("  eve     / eve123    (user)")


if __name__ == '__main__':
    seed()
