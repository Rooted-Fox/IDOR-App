"""
Seed Data — Secure App (identical data model as vulnerable app)
Same test accounts, same data — different app with proper access controls.
"""
import os, sys, sqlite3, hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'secure.db')
sys.path.insert(0, BASE_DIR)
from app import init_db

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

def seed():
    init_db()
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        DELETE FROM audit_logs;
        DELETE FROM tickets; DELETE FROM documents; DELETE FROM invoices;
        DELETE FROM orders;  DELETE FROM users;
        DELETE FROM sqlite_sequence WHERE name IN
            ('audit_logs','tickets','documents','invoices','orders','users');
    """)

    # ── Import shared seed data ─────────────────────────────────────────
    # (identical to vulnerable app — same data, different protections)
    vuln_seed = os.path.join(os.path.dirname(BASE_DIR),
                             'vulnerable_app', 'seed_data.py')
    if os.path.exists(vuln_seed):
        # Re-run the seed logic against secure.db
        pass

    users = [
        (1,'alice','alice@corpportal.local',hash_password('alice123'),
         'Alice Johnson','+1-555-0101','14 Oak Street, Springfield, IL 62701',
         'admin','Executive',120000.00,'SSN: 123-45-6789'),
        (2,'bob','bob@corpportal.local',hash_password('bob123'),
         'Bob Martinez','+1-555-0102','27 Maple Ave, Springfield, IL 62702',
         'user','Sales',65000.00,'SSN: 987-65-4321'),
        (3,'charlie','charlie@corpportal.local',hash_password('charlie123'),
         'Charlie Kim','+1-555-0103','8 Pine Road, Springfield, IL 62703',
         'user','Engineering',85000.00,'SSN: 456-78-9012'),
        (4,'diana','diana@corpportal.local',hash_password('diana123'),
         'Diana Patel','+1-555-0104','33 Elm Drive, Springfield, IL 62704',
         'manager','Human Resources',95000.00,'SSN: 321-54-9876'),
        (5,'eve','eve@corpportal.local',hash_password('eve123'),
         'Eve Thompson','+1-555-0105','19 Birch Lane, Springfield, IL 62705',
         'user','Finance',70000.00,'SSN: 654-32-1098'),
    ]
    db.executemany("""INSERT INTO users
        (id,username,email,password,full_name,phone,address,role,department,salary,ssn)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)""", users)

    orders = [
        (1,1,'Enterprise Software License – Suite Pro',1,4500.00,4500.00,'completed','14 Oak Street, Springfield, IL 62701','Annual renewal'),
        (2,1,'MacBook Pro 16" M3 Max',2,3999.00,7998.00,'shipped','14 Oak Street, Springfield, IL 62701','For new hires'),
        (3,1,'Standing Desk (Adjustable)',3,599.00,1797.00,'pending','14 Oak Street, Springfield, IL 62701','Home office setup'),
        (4,2,'Salesforce CRM – Professional Plan',1,1200.00,1200.00,'completed','27 Maple Ave, Springfield, IL 62702','Monthly subscription'),
        (5,2,'Business Travel Kit',1,249.99,249.99,'shipped','27 Maple Ave, Springfield, IL 62702','Q1 client visits'),
        (6,2,'Marketing Collateral Print Run',500,1.20,600.00,'pending','Print & Ship Direct to Customer','Campaign materials'),
        (7,3,'AWS Reserved Instances (1yr)',1,8640.00,8640.00,'completed','8 Pine Road, Springfield, IL 62703','Dev environment'),
        (8,3,'GitHub Enterprise License',10,231.00,2310.00,'completed','Digital delivery','Engineering team'),
        (9,3,'Mechanical Keyboard – Keychron Q5',1,179.00,179.00,'pending','8 Pine Road, Springfield, IL 62703','Personal preference approved'),
        (10,4,'HR Software – BambooHR Annual',1,3600.00,3600.00,'completed','Digital delivery','Company-wide HR system'),
        (11,4,'Training Room Supplies',30,22.00,660.00,'shipped','33 Elm Drive, Springfield, IL 62704','Onboarding kits'),
        (12,5,'QuickBooks Enterprise 2024',1,1720.00,1720.00,'completed','Digital delivery','Finance department license'),
        (13,5,'Ergonomic Chair – Herman Miller',1,1495.00,1495.00,'pending','19 Birch Lane, Springfield, IL 62705','Approved by manager'),
    ]
    db.executemany("INSERT INTO orders(id,user_id,product_name,quantity,unit_price,total_price,status,shipping_address,notes) VALUES(?,?,?,?,?,?,?,?,?)",orders)

    invoices = [
        (1,1,1,'INV-2024-0001',4500.00,405.00,'paid','2024-02-15','AMEX Corporate Card ending 4821 | Auth: TXN-8834521'),
        (2,1,2,'INV-2024-0002',7998.00,719.82,'paid','2024-03-01','ACH Bank Transfer | Account: ****7723 | Ref: PAY-2209'),
        (3,1,3,'INV-2024-0003',1797.00,161.73,'unpaid','2024-04-30','Pending — NET30 terms'),
        (4,2,4,'INV-2024-0004',1200.00,108.00,'paid','2024-02-28','VISA Corporate Card ending 3390 | Auth: TXN-1123009'),
        (5,2,5,'INV-2024-0005',249.99,22.50,'paid','2024-03-15','Mastercard ending 6612 | Auth: TXN-5542011'),
        (6,2,6,'INV-2024-0006',600.00,54.00,'unpaid','2024-05-01','Pending approval'),
        (7,3,7,'INV-2024-0007',8640.00,777.60,'paid','2024-02-01','ACH Transfer | Account: ****9901 | Ref: AWS-CORP-2024'),
        (8,3,8,'INV-2024-0008',2310.00,207.90,'paid','2024-03-10','AMEX Corporate Card ending 1177 | Auth: TXN-7788432'),
        (9,3,9,'INV-2024-0009',179.00,16.11,'unpaid','2024-05-15','NET30 — awaiting PO approval'),
        (10,4,10,'INV-2024-0010',3600.00,324.00,'paid','2024-02-20','VISA Business ending 9988 | Auth: TXN-3300887'),
        (11,4,11,'INV-2024-0011',660.00,59.40,'unpaid','2024-04-25','Pending'),
        (12,5,12,'INV-2024-0012',1720.00,154.80,'paid','2024-03-05','ACH Transfer | Account: ****4455 | Ref: QB-2024-ANNUAL'),
        (13,5,13,'INV-2024-0013',1495.00,134.55,'unpaid','2024-05-30','Approved — awaiting vendor invoice'),
    ]
    db.executemany("INSERT INTO invoices(id,user_id,order_id,invoice_number,amount,tax,status,due_date,payment_details) VALUES(?,?,?,?,?,?,?,?,?)",invoices)

    documents=[
        (1,1,'q1_executive_report.pdf','application/pdf','Q1 2024 Executive Performance Report',1,
         'CONFIDENTIAL — EXECUTIVE SUMMARY Q1 2024\nBoard Distribution Only\n\nRevenue: $4.2M (+18% YoY)\nGross Margin: 67.3%\nEBITDA: $1.1M\n\nCompensation Adjustments (Confidential):\n- Engineering band raised by 8%\n- Executive bonus pool: $240,000 for FY24'),
        (2,1,'password_policy.txt','text/plain','IT Password Policy — Admin Reference',0,
         'IT SECURITY — PASSWORD POLICY v2.3\n\nAdmin Service Accounts:\n  db-backup-svc : Backup$2024!Secure\n  monitoring-svc: Mon!tor_Prod_99\n\nPolicy Requirements: Minimum 14 characters, complexity required, rotation: 90 days'),
        (3,1,'org_chart_2024.txt','text/plain','Organization Chart with Salaries',1,
         'CONFIDENTIAL — ORG CHART WITH COMPENSATION DATA\n\nAlice Johnson (Admin): $120,000 | SSN: 123-45-6789\nDiana Patel (Manager): $95,000  | SSN: 321-54-9876\nCharlie Kim (Engineer): $85,000 | SSN: 456-78-9012\nEve Thompson (Finance): $70,000 | SSN: 654-32-1098\nBob Martinez (Sales): $65,000   | SSN: 987-65-4321'),
        (4,2,'q1_sales_pipeline.txt','text/plain','Q1 2024 Sales Pipeline Report',0,
         'SALES PIPELINE Q1 2024\n\nAcme Corp: $45,000 (Proposal)\nTechStart Inc: $12,000 (Demo)\nGlobalMed: $78,000 (Negotiation)\n\nTarget: $180,000 | Current: $174,700'),
        (5,2,'client_contacts.txt','text/plain','Client Contact List — Sales',1,
         'CONFIDENTIAL — CLIENT CONTACTS\n\nAcme Corp: John Davis +1-555-2201\nTechStart Inc: Lisa Wong +1-555-4409\nGlobalMed: Dr. Raj Patel +1-555-8876'),
        (6,3,'system_architecture.txt','text/plain','Production System Architecture Notes',1,
         'INTERNAL — PRODUCTION ARCHITECTURE\n\nDB Primary: db-prod-01.internal (PostgreSQL 15)\nAdmin Endpoints: /internal/admin/users, /internal/admin/reset\nVPN: vpn.corpportal.local'),
        (7,3,'bug_report_2024_003.txt','text/plain','Security Bug Report #2024-003',0,
         'BUG REPORT #2024-003 — Severity: HIGH\n\nSQL injection in legacy reporting endpoint.\nPoC: date_range=2024-01-01\' OR \'1\'=\'1\nDO NOT DISCLOSE until patched.'),
        (8,4,'performance_reviews_2024.txt','text/plain','Annual Performance Reviews — Confidential',1,
         'CONFIDENTIAL — PERFORMANCE REVIEW SUMMARY 2024\n\nBob Martinez: 3/5 — PIP recommended\nCharlie Kim: 5/5 — Promotion approved\nEve Thompson: 4/5 — 5% increase'),
        (9,4,'disciplinary_record_bob.txt','text/plain','Disciplinary Record — B. Martinez',1,
         'CONFIDENTIAL — DISCIPLINARY RECORD\nEmployee: Bob Martinez\nDate: 2024-01-15\nType: Written Warning\nIncident: Inappropriate comments to Eve Thompson'),
        (10,5,'budget_forecast_2024.txt','text/plain','Budget Forecast FY2024 — Finance',1,
         'CONFIDENTIAL — BUDGET FORECAST FY2024\n\nHeadcount Budget: $2,850,000\nProjected Revenue: $16,800,000\nNet Income: $2,940,000 (17.5% margin)'),
        (11,5,'vendor_contracts.txt','text/plain','Vendor Contract Summary',0,
         'VENDOR CONTRACTS\n\nAWS: $103,680/year (renewal 2025-01-15)\nSalesforce: $14,400/year\nGitHub: $27,720/year\nTotal: $149,400'),
    ]
    db.executemany("INSERT INTO documents(id,user_id,filename,content_type,description,is_confidential,content) VALUES(?,?,?,?,?,?,?)",documents)

    tickets=[
        (1,1,'MFA not working after phone replacement','open','high','IT Support',
         'My authenticator app is not generating valid codes. Recovery codes: ALICE-2024-RC: 8472-1938-5623-7401',None),
        (2,1,'Request: Increase cloud spend limit to $15,000/month','resolved','medium','Finance Request',
         'Need AWS monthly limit increased from $10K to $15K for APAC expansion.',
         'Approved. Limit updated by Finance.'),
        (3,2,'Cannot access CRM — password reset loop','open','high','IT Support',
         'Salesforce keeps prompting password reset. Current password: B0b$ales2024!',None),
        (4,2,'Expense report: Feb travel to Chicago','resolved','low','Finance',
         'Hotel: $342, Flights: $287, Meals: $124. Total: $753',
         'Approved and processed. Reimbursement in next payroll cycle.'),
        (5,3,'Production deployment access request','open','medium','DevOps',
         'Need SSH access to api-prod-01, api-prod-02 for hotfix deployment.',None),
        (6,3,'Laptop battery replacement — MacBook Pro','resolved','low','IT Support',
         'Battery health shows 71%. Serial: C02XL0ZHJGH5',
         'Scheduled with Apple Store. Charlie confirmed.'),
        (7,4,'Employee termination — immediate action required','open','critical','HR - Confidential',
         'CONFIDENTIAL — Disable all system access immediately. Preserve email for legal hold.',None),
        (8,4,'HR system upgrade — BambooHR migration','resolved','medium','IT Support',
         'Need assistance migrating 47 employee records including salary and disciplinary data.',
         'Migration completed. All 47 records verified. Encryption confirmed.'),
        (9,5,'Access to accounts payable module — urgent','open','high','IT Support',
         'Need AP module access to process $340K in vendor payments. CFO approval: verbal.',None),
        (10,5,'Payroll data export — Q1 audit','resolved','medium','Finance',
         'Requesting payroll export for KPMG external audit. Auditor: audit@kpmg.example.com',
         'Export sent via SecureShare to KPMG. Ref: AUDIT-Q1-2024-07'),
    ]
    db.executemany("INSERT INTO tickets(id,user_id,subject,status,priority,category,description,resolution) VALUES(?,?,?,?,?,?,?,?)",tickets)

    db.commit()
    db.close()
    print("✓ Seed data inserted successfully into secure.db")
    print()
    print("Test Accounts:")
    print("  alice   / alice123  (admin)")
    print("  diana   / diana123  (manager)")
    print("  bob     / bob123    (user)")
    print("  charlie / charlie123 (user)")
    print("  eve     / eve123    (user)")

if __name__ == '__main__':
    seed()
