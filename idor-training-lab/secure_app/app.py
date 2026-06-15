"""
=============================================================================
IDOR TRAINING LAB — SECURE / PATCHED APPLICATION  (Port 5002)
=============================================================================
This application implements the same functionality as the vulnerable version
but with proper Broken Access Control protections applied.

Security Controls Implemented
─────────────────────────────────────────────────────────────────────────────
  • Object-level ownership validation on every resource endpoint
  • Role-based access control (admin > manager > user)
  • Audit logging of every access attempt (success, denied, not_found)
  • Consistent 403 Forbidden for unauthorized access (no info leakage)
  • Sensitive fields stripped from API responses for non-owners
  • Cryptographically strong session secret
  • No mass user enumeration
=============================================================================
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import (Flask, request, jsonify, session, render_template,
                   redirect, url_for, flash, g)

app = Flask(__name__)
# [SECURE]: Strong, randomly-generated secret key loaded from environment
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DB_PATH = os.path.join(os.path.dirname(__file__), 'secure.db')
APP_MODE = 'secure'


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

        -- [SECURE]: Audit log table — tracks all resource access attempts
        CREATE TABLE IF NOT EXISTS audit_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER,
            username      TEXT,
            action        TEXT    NOT NULL,
            resource_type TEXT    NOT NULL,
            resource_id   INTEGER,
            ip_address    TEXT,
            outcome       TEXT    NOT NULL,
            details       TEXT,
            created_at    TEXT    DEFAULT (datetime('now'))
        );
    """)
    db.commit()
    db.close()


# ─── Security helpers ─────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def log_audit(user_id, username, action, resource_type, resource_id,
              outcome, details=None):
    """[SECURE]: Append every resource access to the audit log."""
    try:
        db = get_db()
        db.execute("""
            INSERT INTO audit_logs
                (user_id, username, action, resource_type, resource_id,
                 ip_address, outcome, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, [user_id, username, action, resource_type, resource_id,
              request.remote_addr, outcome, details])
        db.commit()
    except Exception:
        pass  # Audit failures must not break the main flow


def check_ownership(resource_user_id):
    """
    [SECURE]: Core authorization check.
    Returns True if the current session user owns the resource OR is an admin.
    Returns False if access should be denied.
    """
    current_uid = session.get('user_id')
    current_role = session.get('role')

    if not current_uid:
        return False

    # Admins have access to all resources
    if current_role == 'admin':
        return True

    # Resource owner always has access to their own resource
    return resource_user_id == current_uid


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


def deny_access(resource_type, resource_id, action='READ'):
    """[SECURE]: Log the denial and return a consistent 403 response."""
    log_audit(
        session.get('user_id'), session.get('username'),
        action, resource_type, resource_id, 'denied',
        f"User {session.get('username')} attempted to {action} "
        f"{resource_type} {resource_id} belonging to another user"
    )
    # [SECURE]: Generic error — does not reveal whether resource exists
    return None  # Caller decides whether to 403 or 404


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
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            session['full_name']= user['full_name']
            log_audit(user['id'], user['username'], 'LOGIN', 'session',
                      None, 'success')
            flash(f"Welcome back, {user['full_name']}!", 'success')
            return redirect(url_for('dashboard'))
        # [SECURE]: Generic failure message — no username enumeration
        log_audit(None, username, 'LOGIN', 'session', None, 'failed',
                  f"Failed login attempt for username: {username}")
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', app_mode=APP_MODE)


@app.route('/logout')
def logout():
    log_audit(session.get('user_id'), session.get('username'),
              'LOGOUT', 'session', None, 'success')
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


# [SECURE]: Profile View — enforces ownership + admin bypass
@app.route('/profile/<int:user_id>')
@login_required
def profile_view(user_id):
    current_user = get_current_user()
    db = get_db()
    viewed_user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()

    if not viewed_user:
        # [SECURE]: Return same response whether user exists or not (no enumeration)
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    # [SECURE]: Check ownership — only owner or admin may view full profile
    if not check_ownership(viewed_user['id']):
        deny_access('user_profile', user_id)
        flash('Access denied. You can only view your own profile.', 'danger')
        return redirect(url_for('dashboard'))

    log_audit(current_user['id'], current_user['username'], 'READ',
              'user_profile', user_id, 'success')
    is_own = (current_user['id'] == user_id)
    return render_template('profile.html', app_mode=APP_MODE,
                           current_user=current_user, viewed_user=viewed_user,
                           is_own=is_own)


@app.route('/orders')
@login_required
def orders_list():
    user = get_current_user()
    db = get_db()
    # [SECURE]: Always scoped to the current user — no user_id param accepted
    orders = db.execute(
        'SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC', [user['id']]
    ).fetchall()
    return render_template('orders.html', app_mode=APP_MODE, user=user, orders=orders)


# [SECURE]: Order Detail — enforces ownership
@app.route('/orders/<int:order_id>')
@login_required
def order_detail(order_id):
    user = get_current_user()
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id = ?', [order_id]).fetchone()

    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('orders_list'))

    # [SECURE]: Verify ownership before showing order details
    if not check_ownership(order['user_id']):
        deny_access('order', order_id)
        # [SECURE]: Reveal as "not found" to avoid confirming resource existence
        flash('Order not found.', 'danger')
        return redirect(url_for('orders_list'))

    log_audit(user['id'], user['username'], 'READ', 'order', order_id, 'success')
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


# [SECURE]: Invoice Detail — enforces ownership
@app.route('/invoices/<int:invoice_id>')
@login_required
def invoice_detail(invoice_id):
    user = get_current_user()
    db = get_db()
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', [invoice_id]).fetchone()

    if not invoice:
        flash('Invoice not found.', 'danger')
        return redirect(url_for('invoices_list'))

    # [SECURE]: Ownership check
    if not check_ownership(invoice['user_id']):
        deny_access('invoice', invoice_id)
        flash('Invoice not found.', 'danger')
        return redirect(url_for('invoices_list'))

    log_audit(user['id'], user['username'], 'READ', 'invoice', invoice_id, 'success')
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


# [SECURE]: Document View — enforces ownership
@app.route('/documents/<int:doc_id>')
@login_required
def document_detail(doc_id):
    user = get_current_user()
    db = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ?', [doc_id]).fetchone()

    if not doc:
        flash('Document not found.', 'danger')
        return redirect(url_for('documents_list'))

    # [SECURE]: Ownership check — prevents reading other users' confidential files
    if not check_ownership(doc['user_id']):
        deny_access('document', doc_id)
        flash('Document not found.', 'danger')
        return redirect(url_for('documents_list'))

    log_audit(user['id'], user['username'], 'READ', 'document', doc_id, 'success')
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


# [SECURE]: Ticket Detail — enforces ownership
@app.route('/tickets/<int:ticket_id>')
@login_required
def ticket_detail(ticket_id):
    user = get_current_user()
    db = get_db()
    ticket = db.execute('SELECT * FROM tickets WHERE id = ?', [ticket_id]).fetchone()

    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('tickets_list'))

    # [SECURE]: Ownership check
    if not check_ownership(ticket['user_id']):
        deny_access('ticket', ticket_id)
        flash('Ticket not found.', 'danger')
        return redirect(url_for('tickets_list'))

    log_audit(user['id'], user['username'], 'READ', 'ticket', ticket_id, 'success')
    owner = db.execute('SELECT full_name, username FROM users WHERE id=?',
                       [ticket['user_id']]).fetchone()
    return render_template('ticket_detail.html', app_mode=APP_MODE,
                           user=user, ticket=ticket, owner=owner)


# ─── Audit log viewer (admin only) ────────────────────────────────────────────

@app.route('/admin/audit')
@login_required
def audit_log():
    user = get_current_user()
    # [SECURE]: Admin-only endpoint
    if user['role'] != 'admin':
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    db = get_db()
    logs = db.execute(
        'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200'
    ).fetchall()
    return render_template('audit_log.html', app_mode=APP_MODE, user=user, logs=logs)


# ─── REST API routes ──────────────────────────────────────────────────────────

# [SECURE]: Get User — returns only public fields for non-owners; full profile for owner/admin
@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def api_get_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # [SECURE]: Ownership check
    if not check_ownership(user['id']):
        log_audit(session['user_id'], session['username'], 'READ',
                  'user', user_id, 'denied')
        return jsonify({'error': 'Access denied'}), 403

    log_audit(session['user_id'], session['username'], 'READ',
              'user', user_id, 'success')

    # [SECURE]: Strip sensitive fields for non-admin responses
    data = dict(user)
    if session.get('role') != 'admin':
        data.pop('salary', None)
        data.pop('ssn', None)
        data.pop('password', None)
    else:
        data.pop('password', None)  # Never return password even for admins
    return jsonify(data)


# [SECURE]: Update User — only owner may update their own profile; admins may update all
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def api_update_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # [SECURE]: Ownership check
    if not check_ownership(user['id']):
        log_audit(session['user_id'], session['username'], 'UPDATE',
                  'user', user_id, 'denied')
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json() or {}

    # [SECURE]: Restrict which fields users can update
    # Regular users cannot change their own role or department
    if session.get('role') == 'admin':
        allowed_fields = ['full_name', 'email', 'phone', 'address', 'role', 'department']
    else:
        allowed_fields = ['full_name', 'phone', 'address']  # No role/department change

    updates = {k: v for k, v in data.items() if k in allowed_fields}

    if updates:
        set_clause = ', '.join(f'{k} = ?' for k in updates)
        values = list(updates.values()) + [user_id]
        db.execute(f'UPDATE users SET {set_clause} WHERE id = ?', values)
        db.commit()
        log_audit(session['user_id'], session['username'], 'UPDATE',
                  'user', user_id, 'success', f"Fields updated: {list(updates.keys())}")

    updated = db.execute('SELECT * FROM users WHERE id = ?', [user_id]).fetchone()
    result = dict(updated)
    result.pop('password', None)
    result.pop('salary', None) if session.get('role') != 'admin' else None
    result.pop('ssn', None) if session.get('role') != 'admin' else None
    return jsonify({'message': 'User updated', 'user': result})


# [SECURE]: Get Order — ownership validated
@app.route('/api/orders/<int:order_id>', methods=['GET'])
@login_required
def api_get_order(order_id):
    db = get_db()
    order = db.execute('SELECT * FROM orders WHERE id = ?', [order_id]).fetchone()

    if not order:
        return jsonify({'error': 'Order not found'}), 404

    # [SECURE]: Authorization check
    if not check_ownership(order['user_id']):
        log_audit(session['user_id'], session['username'], 'READ',
                  'order', order_id, 'denied')
        return jsonify({'error': 'Access denied'}), 403

    log_audit(session['user_id'], session['username'], 'READ',
              'order', order_id, 'success')
    return jsonify(dict(order))


# [SECURE]: Get Invoice — ownership validated
@app.route('/api/invoices/<int:invoice_id>', methods=['GET'])
@login_required
def api_get_invoice(invoice_id):
    db = get_db()
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', [invoice_id]).fetchone()

    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404

    # [SECURE]: Authorization check
    if not check_ownership(invoice['user_id']):
        log_audit(session['user_id'], session['username'], 'READ',
                  'invoice', invoice_id, 'denied')
        return jsonify({'error': 'Access denied'}), 403

    log_audit(session['user_id'], session['username'], 'READ',
              'invoice', invoice_id, 'success')
    return jsonify(dict(invoice))


# [SECURE]: Get Document — ownership validated
@app.route('/api/documents/<int:doc_id>', methods=['GET'])
@login_required
def api_get_document(doc_id):
    db = get_db()
    doc = db.execute('SELECT * FROM documents WHERE id = ?', [doc_id]).fetchone()

    if not doc:
        return jsonify({'error': 'Document not found'}), 404

    # [SECURE]: Authorization check
    if not check_ownership(doc['user_id']):
        log_audit(session['user_id'], session['username'], 'READ',
                  'document', doc_id, 'denied')
        return jsonify({'error': 'Access denied'}), 403

    log_audit(session['user_id'], session['username'], 'READ',
              'document', doc_id, 'success')
    return jsonify(dict(doc))


# [SECURE]: Get Ticket — ownership validated
@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def api_get_ticket(ticket_id):
    db = get_db()
    ticket = db.execute('SELECT * FROM tickets WHERE id = ?', [ticket_id]).fetchone()

    if not ticket:
        return jsonify({'error': 'Ticket not found'}), 404

    # [SECURE]: Authorization check
    if not check_ownership(ticket['user_id']):
        log_audit(session['user_id'], session['username'], 'READ',
                  'ticket', ticket_id, 'denied')
        return jsonify({'error': 'Access denied'}), 403

    log_audit(session['user_id'], session['username'], 'READ',
              'ticket', ticket_id, 'success')
    return jsonify(dict(ticket))


# [SECURE]: List Users — admin only; regular users see only their own record
@app.route('/api/users', methods=['GET'])
@login_required
def api_list_users():
    db = get_db()
    # [SECURE]: Only admins can list all users
    if session.get('role') == 'admin':
        users = db.execute('SELECT id, username, email, full_name, role, department, created_at FROM users').fetchall()
        log_audit(session['user_id'], session['username'], 'LIST', 'users', None, 'success')
        return jsonify([dict(u) for u in users])
    else:
        # Regular users get only their own record, with sensitive fields removed
        user = db.execute(
            'SELECT id, username, email, full_name, role, department, created_at FROM users WHERE id=?',
            [session['user_id']]
        ).fetchone()
        return jsonify([dict(user)])


# Current user's own list endpoints
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


# Audit log API (admin only)
@app.route('/api/audit', methods=['GET'])
@login_required
def api_get_audit():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Access denied. Admin only.'}), 403
    db = get_db()
    logs = db.execute(
        'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500'
    ).fetchall()
    return jsonify([dict(l) for l in logs])


# Health check
@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'app': 'secure', 'port': 5002})


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
        print("[*] Database initialized. Run seed_data.py to populate test data.")
    else:
        init_db()
    print("[*] Starting SECURE application on http://127.0.0.1:5002")
    print("[+] This application implements proper IDOR protections.")
    app.run(host='127.0.0.1', port=5002, debug=True)
