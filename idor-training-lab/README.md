# IDOR Training Lab

A realistic two-application security training environment for demonstrating, validating, and remediating **Insecure Direct Object Reference (IDOR)** vulnerabilities. Both applications share an identical UI and dataset — one is intentionally vulnerable, the other is fully patched.

> **⚠️ For authorized security training and education use only.**  
> Deploy in isolated, local lab environments. Do not expose to the internet.

---

## Applications at a Glance

| | Vulnerable App | Secure App |
|---|---|---|
| **Port** | 5001 | 5002 |
| **Purpose** | Demonstrate IDOR findings | Validate fixes / negative test |
| **IDOR Count** | 12 vulnerabilities | 0 vulnerabilities |
| **Visual Indicator** | 🔴 Red sidebar badge | 🟢 Green sidebar badge |
| **Extra Features** | — | Audit log viewer |

---

## Quick Start (No Docker)

### Prerequisites

- Python 3.8+
- pip3

### Option A — Automated Setup

```bash
git clone <repo-url> idor-training-lab
cd idor-training-lab
bash setup.sh          # installs deps + seeds DBs + starts both apps
```

Both apps will start in the background:
- Vulnerable → http://localhost:5001
- Secure → http://localhost:5002

### Option B — Manual Setup

```bash
cd idor-training-lab

# --- Vulnerable App ---
cd vulnerable_app
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 seed_data.py
python3 app.py &          # runs on :5001
deactivate && cd ..

# --- Secure App ---
cd secure_app
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 seed_data.py
python3 app.py &          # runs on :5002
deactivate && cd ..
```

### Setup Script Commands

```bash
bash setup.sh install   # create venvs + install dependencies
bash setup.sh seed      # populate SQLite databases
bash setup.sh run       # start both apps in background
bash setup.sh stop      # kill both apps
bash setup.sh reset     # wipe DBs + re-seed (fresh state)
bash setup.sh status    # check which apps are running
```

---

## Quick Start (Docker)

```bash
docker-compose up --build
```

- Vulnerable → http://localhost:5001
- Secure → http://localhost:5002

To reset data:
```bash
docker-compose down -v && docker-compose up --build
```

---

## Test Accounts

Both applications share the same credentials and dataset.

| Username  | Password     | Role    | Department      | Salary    |
|-----------|--------------|---------|-----------------|-----------|
| alice     | alice123     | admin   | Executive       | $120,000  |
| diana     | diana123     | manager | Human Resources | $95,000   |
| bob       | bob123       | user    | Sales           | $65,000   |
| charlie   | charlie123   | user    | Engineering     | $85,000   |
| eve       | eve123       | user    | Finance         | $70,000   |

---

## Project Structure

```
idor-training-lab/
├── vulnerable_app/
│   ├── app.py                  # Flask app — intentional IDOR vulnerabilities
│   ├── seed_data.py            # Inserts test users, orders, invoices, docs, tickets
│   ├── requirements.txt
│   └── templates/              # Jinja2 HTML (Bootstrap 5)
│       ├── base.html
│       ├── login.html
│       ├── dashboard.html
│       ├── profile.html
│       ├── orders.html / order_detail.html
│       ├── invoices.html / invoice_detail.html
│       ├── documents.html / document_detail.html
│       └── tickets.html / ticket_detail.html
│
├── secure_app/
│   ├── app.py                  # Flask app — ownership checks + audit logging
│   ├── seed_data.py
│   ├── requirements.txt
│   └── templates/              # Same templates + audit_log.html
│       └── audit_log.html      # Admin-only audit log viewer
│
├── Dockerfile
├── docker-compose.yml
├── setup.sh                    # Local management script
├── README.md                   # This file
├── TRAINING_GUIDE.md           # Full vulnerability walkthrough + remediation guide
└── test_scenarios.md           # curl-based test cases + expected scanner results
```

---

## Vulnerability Coverage

The vulnerable application contains **12 IDOR vulnerabilities** across web UI and REST API endpoints.

| ID | Endpoint | Method | Impact |
|----|----------|--------|--------|
| VULN-IDOR-001 | `/profile/<user_id>` | GET | Salary, SSN, home address |
| VULN-IDOR-002 | `/orders/<order_id>` | GET | Any user's order history |
| VULN-IDOR-003 | `/invoices/<invoice_id>` | GET | Payment details |
| VULN-IDOR-004 | `/documents/<doc_id>` | GET | Confidential HR/legal documents |
| VULN-IDOR-005 | `/tickets/<ticket_id>` | GET | Private support/HR tickets |
| VULN-IDOR-006 | `/api/users/<user_id>` | GET | Full user record via API |
| VULN-IDOR-007 | `/api/users/<user_id>` | PUT | Modify any profile + privilege escalation |
| VULN-IDOR-008 | `/api/orders/<order_id>` | GET | API order access |
| VULN-IDOR-009 | `/api/invoices/<invoice_id>` | GET | API invoice access |
| VULN-IDOR-010 | `/api/documents/<doc_id>` | GET | API document access |
| VULN-IDOR-011 | `/api/tickets/<ticket_id>` | GET | API ticket access |
| VULN-IDOR-012 | `/api/users?role=<role>` | GET | Mass user enumeration |

### Security Controls in the Secure App

- **Object-level ownership check** (`check_ownership()`) on every protected resource
- **Role-based bypass**: admin users can access all resources; regular users can only access their own
- **Audit logging**: every access attempt (success and failure) is written to `audit_logs` table
- **Sensitive field stripping**: `salary` and `ssn` are API-only for admins; `password` is never returned
- **Privilege escalation prevention**: non-admins cannot update `role` or `department` via API
- **Consistent error responses**: 403/404 to avoid resource existence leakage

---

## Modules

### User Profiles
Users can view their own profile with name, department, role, salary, and contact information.

### Orders
Purchase order history per user with item, quantity, total, and status.

### Invoices
Financial invoices including payment method and bank/card details.

### Documents
File repository with documents tagged by sensitivity (`INTERNAL`, `CONFIDENTIAL`, `PUBLIC`). Confidential documents include HR contracts with salary/SSN data.

### Support Tickets
IT and HR support tickets, some containing sensitive internal information (policy changes, PIP records, salary review requests).

---

## Intended Use

1. **Security Tool Validation** — Run your IDOR scanner against both apps and compare findings
2. **Developer Training** — Walk developers through the attack, then show the fix side-by-side
3. **Security Awareness** — Demonstrate real-world business impact of broken access control
4. **Red Team Practice** — Manual IDOR testing with realistic data

See [TRAINING_GUIDE.md](TRAINING_GUIDE.md) for full walkthrough and remediation explanations.  
See [test_scenarios.md](test_scenarios.md) for curl-based test cases and expected scanner output.

---

## Resetting the Lab

```bash
bash setup.sh reset     # wipes both DBs and re-seeds from scratch
```

Or manually:
```bash
rm vulnerable_app/vulnerable.db secure_app/secure.db
cd vulnerable_app && python3 seed_data.py && cd ..
cd secure_app && python3 seed_data.py && cd ..
```

---

## License

For internal security education use only. Not for production deployment.
