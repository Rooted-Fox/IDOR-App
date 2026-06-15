"""
=============================================================================
IDOR TRAINING LAB — VULNERABLE APPLICATION  (Port 5001)
=============================================================================
⚠️  WARNING: This application is INTENTIONALLY VULNERABLE.
    It contains Broken Access Control / IDOR vulnerabilities BY DESIGN.
    For security training, education, and authorized tool validation ONLY.
    DO NOT deploy in any environment connected to the internet or production.
=============================================================================

IDOR Vulnerability Index
─────────────────────────────────────────────────────────────────────────────
  VULN-IDOR-001  GET  /profile/<user_id>           — View any user's profile (UI)
  VULN-IDOR-002  GET  /orders/<order_id>            — View any order (UI)
  VULN-IDOR-003  GET  /invoices/<invoice_id>        — View any invoice (UI)
  VULN-IDOR-004  GET  /documents/<doc_id>           — View any document (UI)
  VULN-IDOR-005  GET  /tickets/<ticket_id>          — View any support ticket (UI)
  VULN-IDOR-006  GET  /api/users/<user_id>          — Read any user's full profile (API)
  VULN-IDOR-007  PUT  /api/users/<user_id>          — Modify any user's profile (API)
  VULN-IDOR-008  GET  /api/orders/<order_id>        — Read any order (API)
  VULN-IDOR-009  GET  /api/invoices/<invoice_id>    — Read any invoice (API)
  VULN-IDOR-010  GET  /api/documents/<doc_id>       — Read any document content (API)
  VULN-IDOR-011  GET  /api/tickets/<ticket_id>      — Read any ticket (API)
  VULN-IDOR-012  GET  /api/users?role=<role>        — List users filtered by role (API)
=============================================================================
"""

import os
import sqlite3
import hashlib
from datetime import datetime
from functools import wraps
from flask import (Flask, request, jsonify, session, render_template,
                   redirect, url_for, flash, g)

app = Flask(__name__)
# [INSECURE]: Hard-coded secret key — makes session tokens predictable
app.secret_key = 'corpportal-vulnerable-secret-2024-do-not-use'

DB_PATH = os.path.join(os.path.dirname(__file__), 'vulnerable.db')
APP_MODE = 'vulnerable'


# ─── Database helpers ────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Create database tables."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            email       TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            full_name   TEXT    NOT NULL,
            phone       TEXT,
            address     TEXT,
            role        TEXT    NOT NULL DEFAULT 'user',
            department  TEXT,
            salary      REAL,
            ssn         TEXT,
            created_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS orders (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id          INTEGER NOT NULL,
            product_name     TEXT    NOT NULL,
            quantity         INTEGER NOT NULL,
            unit_price       REAL    NOT NULL,
            total_price      REAL    NOT NULL,
            status           TEXT    NOT NULL DEFAULT 'pending',
            shipping_address TEXT,
            notes            TEXT,
            created_at       TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            order_id        INTEGER,
            invoice_number  TEXT    UNIQUE NOT NULL,
            amount          REAL    NOT NULL,
            tax             REAL    NOT NULL DEFAULT 0,
            status          TEXT    NOT NULL DEFAULT 'unpaid',
            due_date        TEXT,
            payment_details TEXT,
            created_at      TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id)  REFERENCES users(id),
            FOREIGN KEY (order_id) REFERENCES orders(id)
        );

        CREATE TABLE IF NOT EXISTS documents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            filename        TEXT    NOT NULL,
            content_type    TEXT    NOT NULL,
            description     TEXT,
            content         TEXT    NOT NULL,
            is_confidential INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            subject     TEXT    NOT NULL,
            description TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'open',
            priority    TEXT    NOT NULL DEFAULT 'medium',
            category    TEXT,
            resolution  TEXT,
            created_at  TEXT    DEFAULT (datetime('now')),
            updated_at  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    db.commit()
    db.close()


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    if 'user_id' not in session:
        return None
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?',
                      [session['user_id']]).fetchone()


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            [username, hash_password(password)]
        ).fetchone()
        if user:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            flash(f"Welcome back, {user['full_name']}!", 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', app_mode=APP_MODE)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ─── UI routes ────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    db = get_db()
    stats = {
        'orders':    db.execute('SELECT COUNT(*) FROM orders    WHERE user_id=?', [user['id']]).fetchone()[0],
        'invoices':  db.execute('SELECT COUNT(*) FROM invoices  WHERE user_id=?', [user['id']]).fetchone()[0],
        'documents': db.execute('SELECT COUNT(*) FROM documents WHERE user_id=?', [user['id']]).fetchone()[0],
        'tickets':   db.execute('SELECT COUNT(*) FROM tickets   WHERE user_id=?', [user['id']]).fetchone()[0],
    }
    recent_orders = db.execute(
        'SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 5', [user['id']]
    ).fetchall()
    return render_template('dashboard.html', app_mode=APP_MODE, user=user,
                           stats=stats, recent_orders=recent_orders)


@app.route('/profile')
@login_required
def profile_self():
    user = get_current_user()
    return render_template('profile.html', app_mode=APP_MODE,
                           current_user=user, viewed_user=user, is_own=True)


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-001] Profile View — No ownership check
# Any authenticated user can view any other user's profile including
# sensitive fields (salary, SSN, phone, home address) by changing the user_id.
#   Exploit: GET /profile/2   (while logged in as user 3)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/profile/<int:user_id>')
@login_required
def profile_view(user_id):
    current_user = get_current_user()
    db = get_db()
    # [VULN-IDOR-001]: user_id parameter is trusted directly — no ownership check!
    viewed_user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    if not viewed_user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))
    is_own = (current_user['id'] == user_id)
    return render_template('profile.html', app_mode=APP_MODE,
                           current_user=current_user, viewed_user=viewed_user,
                           is_own=is_own)


@app.route('/orders')
@login_required
def orders_list():
    user = get_current_user()
    db = get_db()
    orders = db.execute(
        'SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC', [user['id']]
    ).fetchall()
    return render_template('orders.html', app_mode=APP_MODE, user=user, orders=orders)


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-002] Order Detail — No ownership check
# Any authenticated user can view any order by changing the order_id.
#   Exploit: GET /orders/5   (while logged in as a different user)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/orders/<int:order_id>')
@login_required
def order_detail(order_id):
    user = get_current_user()
    db = get_db()
    # [VULN-IDOR-002]: No check that order belongs to the logged-in user
    order = db.execute('SELECT * FROM orders WHERE id = ?', [order_id]).fetchone()
    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('orders_list'))
    owner = db.execute('SELECT full_name, username FROM users WHERE id=?',
                       [order['user_id']]).fetchone()
    return render_template('order_detail.html', app_mode=APP_MODE,
                           user=user, order=order, owner=owner)


@app.route('/invoices')
@login_required
def invoices_list():
    user = get_current_user()
    db = get_db()
    invoices = db.execute(
        'SELECT * FROM invoices WHERE user_id=? ORDER BY created_at DESC', [user['id']]
    ).fetchall()
    return render_template('invoices.html', app_mode=APP_MODE, user=user, invoices=invoices)


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-003] Invoice Detail — No ownership check
# Any authenticated user can view any invoice by changing the invoice_id,
# exposing payment details and financial information of other users.
#   Exploit: GET /invoices/3
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/invoices/<int:invoice_id>')
@login_required
def invoice_detail(invoice_id):
    user = get_current_user()
    db = get_db()
    # [VULN-IDOR-003]: No ownership check
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', [invoice_id]).fetchone()
    if not invoice:
        flash('Invoice not found.', 'danger')
        return redirect(url_for('invoices_list'))
    owner = db.execute('SELECT full_name, username FROM users WHERE id=?',
                       [invoice['user_id']]).fetchone()
    order = None
    if invoice['order_id']:
        order = db.execute('SELECT * FROM orders WHERE id=?',
                           [invoice['order_id']]).fetchone()
    return render_template('invoice_detail.html', app_mode=APP_MODE,
                           user=user, invoice=invoice, owner=owner, order=order)


@app.route('/documents')
@login_required
def documents_list():
    user = get_current_user()
    db = get_db()
    docs = db.execute(
        'SELECT * FROM documents WHERE user_id=? ORDER BY created_at DESC', [user['id']]
    ).fetchall()
    return render_template('documents.html', app_mode=APP_MODE, user=user, docs=docs)


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-004] Document View — No ownership check
# Any authenticated user can read confidential documents belonging to other
# users by enumerating the document ID.
#   Exploit: GET /documents/4
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/documents/<int:doc_id>')
@login_required
def document_detail(doc_id):
    user = get_current_user()
    db = get_db()
    # [VULN-IDOR-004]: No ownership check — confidential docs exposed
    doc = db.execute('SELECT * FROM documents WHERE id = ?', [doc_id]).fetchone()
    if not doc:
        flash('Document not found.', 'danger')
        return redirect(url_for('documents_list'))
    owner = db.execute('SELECT full_name, username FROM users WHERE id=?',
                       [doc['user_id']]).fetchone()
    return render_template('document_detail.html', app_mode=APP_MODE,
                           user=user, doc=doc, owner=owner)


@app.route('/tickets')
@login_required
def tickets_list():
    user = get_current_user()
    db = get_db()
    tickets = db.execute(
        'SELECT * FROM tickets WHERE user_id=? ORDER BY created_at DESC', [user['id']]
    ).fetchall()
    return render_template('tickets.html', app_mode=APP_MODE, user=user, tickets=tickets)


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-005] Ticket Detail — No ownership check
# Any authenticated user can read any support ticket, potentially exposing
# internal discussions, resolutions, and private user issues.
#   Exploit: GET /tickets/2
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/tickets/<int:ticket_id>')
@login_required
def ticket_detail(ticket_id):
    user = get_current_user()
    db = get_db()
    # [VULN-IDOR-005]: No ownership check
    ticket = db.execute('SELECT * FROM tickets WHERE id = ?', [ticket_id]).fetchone()
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('tickets_list'))
    owner = db.execute('SELECT full_name, username FROM users WHERE id=?',
                       [ticket['user_id']]).fetchone()
    return render_template('ticket_detail.html', app_mode=APP_MODE,
                           user=user, ticket=ticket, owner=owner)


# ─── REST API routes ──────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-006] API: Get User Profile — No ownership check
# Returns full user record including salary and SSN for any user_id.
#   Exploit: GET /api/users/1  (returns alice's salary, SSN, contact info)
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def api_get_user(user_id):
    db = get_db()
    # [VULN-IDOR-006]: No ownership or role check — full record returned
    user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(dict(user))


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-007] API: Update User Profile — No ownership check
# Any authenticated user can overwrite any other user's profile data,
# including their email, phone, and even role (privilege escalation).
#   Exploit: PUT /api/users/1  {"role": "admin"}
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def api_update_user(user_id):
    db = get_db()
    # [VULN-IDOR-007]: No ownership check — any user can update any profile
    user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json() or {}
    allowed_fields = ['full_name', 'email', 'phone', 'address', 'role', 'department']
    updates = {k: v for k, v in data.items() if k in allowed_fields}

    if updates:
        set_clause = ', '.join(f'{k} = ?' for k in updates)
        values = list(updates.values()) + [user_id]
        db.execute(f'UPDATE users SET {set_clause} WHERE id = ?', values)
        db.commit()

    updated = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    return jsonify({'message': 'User updated', 'user': dict(updated)})


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-008] API: Get Order — No ownership check
#   Exploit: GET /api/orders/1
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/orders/<int:order_id>', methods=['GET'])
@login_required
def api_get_order(order_id):
    db = get_db()
    # [VULN-IDOR-008]: No ownership check
    order = db.execute('SELECT * FROM orders WHERE id = ?', [order_id]).fetchone()
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    return jsonify(dict(order))


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-009] API: Get Invoice — No ownership check
#   Exploit: GET /api/invoices/1
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/invoices/<int:invoice_id>', methods=['GET'])
@login_required
def api_get_invoice(invoice_id):
    db = get_db()
    # [VULN-IDOR-009]: No ownership check — payment_details exposed
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', [invoice_id]).fetchone()
    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404
    return jsonify(dict(invoice))


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-010] API: Get Document — No ownership check
#   Exploit: GET /api/documents/1
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/documents/<int:doc_id>', methods=['GET'])
@login_required
def api_get_document(doc_id):
    db = get_db()
    # [VULN-IDOR-010]: No ownership check — confidential content exposed
    doc = db.execute('SELECT * FROM documents WHERE id = ?', [doc_id]).fetchone()
    if not doc:
        return jsonify({'error': 'Document not found'}), 404
    return jsonify(dict(doc))


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-011] API: Get Ticket — No ownership check
#   Exploit: GET /api/tickets/1
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def api_get_ticket(ticket_id):
    db = get_db()
    # [VULN-IDOR-011]: No ownership check
    ticket = db.execute('SELECT * FROM tickets WHERE id = ?', [ticket_id]).fetchone()
    if not ticket:
        return jsonify({'error': 'Ticket not found'}), 404
    return jsonify(dict(ticket))


# ─────────────────────────────────────────────────────────────────────────────
# [VULN-IDOR-012] API: List Users by Role — Mass user enumeration
# Any authenticated user can list all users filtered by any role, exposing
# the full org structure and sensitive data for each user.
#   Exploit: GET /api/users?role=admin  or  GET /api/users
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@login_required
def api_list_users():
    db = get_db()
    role = request.args.get('role')
    # [VULN-IDOR-012]: No role restriction — any user can enumerate all users
    if role:
        users = db.execute('SELECT * FROM users WHERE role = ?', [role]).fetchall()
    else:
        users = db.execute('SELECT * FROM users').fetchall()
    return jsonify([dict(u) for u in users])


# Legitimate list endpoints — returning only current user's own data
@app.route('/api/orders', methods=['GET'])
@login_required
def api_list_orders():
    db = get_db()
    orders = db.execute('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC',
                        [session['user_id']]).fetchall()
    return jsonify([dict(o) for o in orders])


@app.route('/api/invoices', methods=['GET'])
@login_required
def api_list_invoices():
    db = get_db()
    invoices = db.execute('SELECT * FROM invoices WHERE user_id=? ORDER BY created_at DESC',
                          [session['user_id']]).fetchall()
    return jsonify([dict(i) for i in invoices])


@app.route('/api/documents', methods=['GET'])
@login_required
def api_list_documents():
    db = get_db()
    docs = db.execute('SELECT * FROM documents WHERE user_id=? ORDER BY created_at DESC',
                      [session['user_id']]).fetchall()
    return jsonify([dict(d) for d in docs])


@app.route('/api/tickets', methods=['GET'])
@login_required
def api_list_tickets():
    db = get_db()
    tickets = db.execute('SELECT * FROM tickets WHERE user_id=? ORDER BY created_at DESC',
                         [session['user_id']]).fetchall()
    return jsonify([dict(t) for t in tickets])


# Health check
@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'app': 'vulnerable', 'port': 5001})


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
        print("[*] Database initialized. Run seed_data.py to populate test data.")
    else:
        init_db()  # Ensures schema is up to date
    print("[*] Starting VULNERABLE application on http://127.0.0.1:5001")
    print("[!] This application contains intentional IDOR vulnerabilities for training.")
    app.run(host='127.0.0.1', port=5001, debug=True)
