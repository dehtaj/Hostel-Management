import calendar
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
from functools import wraps
import db
import os
import secrets
import csv
import io
import re
import uuid
from mysql.connector import IntegrityError
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
_secret_key = os.getenv("SECRET_KEY", "").strip()
if len(_secret_key) < 32:
    raise RuntimeError("SECRET_KEY must be configured with at least 32 random characters.")
app.secret_key = _secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "1") == "1",
)


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.context_processor
def inject_runtime_flags():
    return {
        "razorpay_enabled": bool(os.getenv("RAZORPAY_KEY_ID", "").strip() and os.getenv("RAZORPAY_KEY_SECRET", "").strip())
    }


@app.before_request
def protect_state_changing_requests():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if request.endpoint == "razorpay_webhook":
        return None
    expected = session.get("_csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        return jsonify({"error": "CSRF validation failed."}), 400
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response



def audit(action, entity_type, entity_id=None, details=None):
    """Append an audit event. The audit table is part of the single fresh-install database schema."""
    try:
        db.query(
            "INSERT INTO audit_logs (actor_user_id, action, entity_type, entity_id, details) VALUES (%s,%s,%s,%s,%s)",
            (session.get("user_id"), action, entity_type, str(entity_id) if entity_id is not None else None,
             json.dumps(details or {}, ensure_ascii=False, default=str)),
            commit=True,
        )
    except Exception:
        # Do not silently claim the event was logged; log the failure for the operator.
        app.logger.exception("Audit event could not be stored: %s %s", action, entity_type)


def make_receipt_no():
    """Create a human-friendly, unique receipt number for each recorded payment."""
    return f"RCT-{date.today().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


def calculate_fee_status(amount, paid, due_date):
    """Return the only valid fee status from immutable bill amount + active payments."""
    amount = Decimal(str(amount)).quantize(Decimal("0.01"))
    paid = Decimal(str(paid or 0)).quantize(Decimal("0.01"))
    if paid >= amount:
        return "paid"
    return "overdue" if due_date < date.today() else "pending"


def razorpay_client():
    """Load Razorpay only when online payments are actually used.

    Razorpay is optional for local/admin use; the app must start normally
    without a Razorpay account or credentials.
    """
    key_id = os.getenv("RAZORPAY_KEY_ID", "").strip()
    key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
    if not key_id or not key_secret:
        raise RuntimeError("Online payments are not configured yet. You can continue using manual fee collection, or add Razorpay credentials when ready.")
    try:
        import razorpay
    except ImportError as exc:
        raise RuntimeError("Razorpay SDK is not installed. Run: python -m pip install -r requirements.txt") from exc
    return razorpay.Client(auth=(key_id, key_secret)), key_id


def settle_razorpay_order(order_id, payment_id):
    """Idempotently settle a verified order and update legacy fee/payment records atomically."""
    conn = db.get_conn()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM payment_orders WHERE order_id=%s FOR UPDATE", (order_id,))
        order = cur.fetchone()
        if not order:
            raise ValueError("Payment order was not found.")
        if order["status"] == "paid":
            conn.commit()
            return False
        cur.execute("SELECT * FROM fees WHERE id=%s FOR UPDATE", (order["fee_id"],))
        fee = cur.fetchone()
        if not fee:
            raise ValueError("Fee record was not found.")
        cur.execute("SELECT COALESCE(SUM(amount_paid),0) AS paid FROM payments WHERE fee_id=%s AND voided_at IS NULL", (fee["id"],))
        paid_so_far = Decimal(str(cur.fetchone()["paid"] or 0))
        amount = Decimal(int(order["amount_paise"])) / Decimal(100)
        balance = Decimal(str(fee["amount"])) - paid_so_far
        if amount <= 0 or amount > balance:
            raise ValueError("Verified payment amount does not match the remaining fee balance.")
        receipt_no = make_receipt_no()
        cur.execute("INSERT INTO payments (fee_id, amount_paid, method, receipt_no, paid_on, created_at) VALUES (%s,%s,'Razorpay',%s,CURDATE(),NOW())",
                    (fee["id"], str(amount), receipt_no))
        new_paid = paid_so_far + amount
        today = date.today()
        status = "paid" if new_paid >= Decimal(str(fee["amount"])) else ("overdue" if fee["due_date"] < today else "pending")
        cur.execute("UPDATE fees SET status=%s WHERE id=%s", (status, fee["id"]))
        cur.execute("UPDATE payment_orders SET status='paid', payment_id=%s, paid_at=NOW() WHERE id=%s",
                    (payment_id, order["id"]))
        conn.commit()
        audit("razorpay_payment_settled", "payment", payment_id, {"fee_id": fee["id"], "order_id": order_id, "payment_id": payment_id, "amount": str(amount), "receipt_no": receipt_no})
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        if cur is not None:
            cur.close()
        conn.close()


# ---------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            allowed = set(role) if isinstance(role, (tuple, list, set)) else ({role} if role else None)
            if allowed and session.get("role") not in allowed:
                flash("You don't have access to that page.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/health")
def health():
    """Lightweight deployment health check; verifies Flask and database reachability."""
    try:
        row = db.query("SELECT 1 AS ok", fetchone=True)
        return jsonify({"status": "ok", "database": bool(row and row.get("ok") == 1)}), 200
    except Exception:
        app.logger.exception("Health check database failure")
        return jsonify({"status": "degraded", "database": False}), 503


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    try:
        admin = db.query("SELECT id FROM users WHERE role='admin' LIMIT 1", fetchone=True)
    except Exception as exc:
        return render_template("db_error.html", error="The database is temporarily unavailable. Please try again later."), 503
    return redirect(url_for("login") if admin else url_for("setup"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Create the first admin account with credentials chosen by the owner."""
    try:
        admin = db.query("SELECT id FROM users WHERE role='admin' LIMIT 1", fetchone=True)
    except Exception as exc:
        return render_template("db_error.html", error="The database is temporarily unavailable. Please try again later."), 503
    if admin:
        flash("Admin account already exists. Please sign in.", "info")
        return redirect(url_for("login"))
    # First-admin setup is intentionally local-only. This removes a setup secret
    # from the UI while preventing a remote visitor from claiming the first admin.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return render_template("db_error.html", error="Initial administrator setup is available only from the local machine."), 403
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "danger")
        elif len(password) < 8:
            flash("Use a password with at least 8 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            try:
                db.query(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s,%s,'admin')",
                    (username, generate_password_hash(password)), commit=True,
                )
                audit("admin_created", "user", db.query("SELECT id FROM users WHERE username=%s", (username,), fetchone=True)["id"])
                flash("Admin account created. Please sign in.", "success")
                return redirect(url_for("login"))
            except Exception:
                app.logger.exception("Admin account creation failed")
                flash("Could not create the admin account. Please check the server logs.", "danger")
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            user = db.query("SELECT * FROM users WHERE username=%s", (username,), fetchone=True)
        except Exception:
            return render_template("db_error.html", error="The database is temporarily unavailable. Please try again later."), 503
        now = datetime.now()
        if user and user.get("locked_until") and user["locked_until"] > now:
            flash("Too many failed attempts. Try again later.", "danger")
            return render_template("login.html")
        if user and check_password_hash(user["password_hash"], password):
            if user["role"] == "student":
                profile = db.query("SELECT lifecycle_status FROM students WHERE user_id=%s", (user["id"],), fetchone=True)
                if profile and profile.get("lifecycle_status") != "active":
                    flash("This student account is inactive. Contact the hostel administrator.", "danger")
                    return render_template("login.html")
            db.query("UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE id=%s", (user["id"],), commit=True)
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            audit("login", "user", user["id"])
            return redirect(url_for("dashboard"))
        if user:
            db.query(
                """UPDATE users
                   SET failed_login_attempts=failed_login_attempts+1,
                       locked_until=CASE WHEN failed_login_attempts+1 >= 5 THEN DATE_ADD(NOW(), INTERVAL 15 MINUTE) ELSE locked_until END
                   WHERE id=%s AND (locked_until IS NULL OR locked_until <= NOW())""",
                (user["id"],), commit=True
            )
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/account", methods=["GET", "POST"])
@login_required("admin")
def account():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        user = db.query("SELECT * FROM users WHERE id=%s", (session["user_id"],), fetchone=True)
        if not user or not check_password_hash(user["password_hash"], current):
            flash("Current password is incorrect.", "danger")
        elif len(new_username) < 3:
            flash("Username must contain at least 3 characters.", "danger")
        elif new_password and len(new_password) < 8:
            flash("New password must contain at least 8 characters.", "danger")
        elif new_password != confirm:
            flash("New passwords do not match.", "danger")
        else:
            try:
                if new_password:
                    db.query("UPDATE users SET username=%s, password_hash=%s WHERE id=%s",
                             (new_username, generate_password_hash(new_password), user["id"]), commit=True)
                else:
                    db.query("UPDATE users SET username=%s WHERE id=%s", (new_username, user["id"]), commit=True)
                session["username"] = new_username
                flash("Account updated successfully.", "success")
                return redirect(url_for("account"))
            except Exception as exc:
                app.logger.exception("Account update failed")
                flash("Could not update the account. Please check the server logs.", "danger")
    return render_template("account.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/staff", methods=["GET", "POST"])
@login_required("admin")
def staff_management():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        if role not in ("warden", "accountant", "maintenance"):
            flash("Choose a valid staff role.", "danger")
        elif len(username) < 3 or len(password) < 8:
            flash("Username must be 3+ characters and password 8+ characters.", "danger")
        else:
            try:
                uid = db.query("INSERT INTO users (username,password_hash,role) VALUES (%s,%s,%s)",
                               (username, generate_password_hash(password), role), commit=True)
                audit("staff_user_created", "user", uid, {"role": role})
                flash("Staff login created. Share credentials securely.", "success")
                return redirect(url_for("staff_management"))
            except IntegrityError:
                flash("That username already exists.", "danger")
    staff = db.query("SELECT id,username,role,created_at FROM users WHERE role IN ('warden','accountant','maintenance') ORDER BY role,username")
    return render_template("staff.html", staff=staff)


@app.route("/staff/<int:uid>/edit", methods=["POST"])
@login_required("admin")
def edit_staff(uid):
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "")
    new_password = request.form.get("password", "")
    if role not in ("warden", "accountant", "maintenance"):
        flash("Choose a valid staff role.", "danger")
        return redirect(url_for("staff_management"))
    if len(username) < 3 or len(username) > 50:
        flash("Username must be between 3 and 50 characters.", "danger")
        return redirect(url_for("staff_management"))
    if new_password and len(new_password) < 8:
        flash("New password must contain at least 8 characters.", "danger")
        return redirect(url_for("staff_management"))

    existing = db.query(
        "SELECT id,username,role FROM users WHERE id=%s AND role IN ('warden','accountant','maintenance')",
        (uid,), fetchone=True
    )
    if not existing:
        flash("Staff account not found.", "danger")
        return redirect(url_for("staff_management"))

    # Server-side dirty check: a blind Save with no actual change is a no-op.
    changes = {}
    if username != existing["username"]:
        changes["username"] = {"from": existing["username"], "to": username}
    if role != existing["role"]:
        changes["role"] = {"from": existing["role"], "to": role}
    if not new_password and not changes:
        flash("No changes to save.", "info")
        return redirect(url_for("staff_management"))

    try:
        if new_password:
            db.query(
                "UPDATE users SET username=%s, role=%s, password_hash=%s WHERE id=%s",
                (username, role, generate_password_hash(new_password), uid), commit=True
            )
            changes["password"] = "changed"
        else:
            db.query("UPDATE users SET username=%s, role=%s WHERE id=%s", (username, role, uid), commit=True)
        audit("staff_user_updated", "user", uid, changes)
        flash("Staff details updated.", "success")
    except IntegrityError:
        flash("That username already exists.", "danger")
    return redirect(url_for("staff_management"))


@app.route("/staff/<int:uid>/role", methods=["POST"])
@login_required("admin")
def update_staff_role(uid):
    # Backward-compatible endpoint: route old forms through the same no-op-safe rules.
    existing = db.query("SELECT id,username,role FROM users WHERE id=%s AND role IN ('warden','accountant','maintenance')", (uid,), fetchone=True)
    role = request.form.get("role", "")
    if not existing or role not in ("warden", "accountant", "maintenance"):
        flash("Choose a valid staff role.", "danger")
    elif role == existing["role"]:
        flash("No changes to save.", "info")
    else:
        db.query("UPDATE users SET role=%s WHERE id=%s", (role, uid), commit=True)
        audit("staff_role_updated", "user", uid, {"role": role})
        flash("Staff role updated.", "success")
    return redirect(url_for("staff_management"))


# ---------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------
@app.route("/dashboard")
@login_required()
def dashboard():
    if session["role"] == "student":
        return redirect(url_for("student_dashboard"))
    if session["role"] != "admin":
        role = session.get("role", "staff")
        links = {
            "warden": [("Students", "students"), ("Rooms", "rooms"), ("Attendance", "attendance"), ("Complaints", "complaints"), ("Visitors", "visitors")],
            "accountant": [("Fees", "fees"), ("Reports", "reports")],
            "maintenance": [("Complaints & Tasks", "complaints")],
        }.get(role, [])
        return render_template("staff_dashboard.html", role=role, links=links)

    total_students = db.query("SELECT COUNT(*) c FROM students WHERE lifecycle_status IS NULL OR lifecycle_status <> 'inactive'", fetchone=True)["c"]
    # Count active allocations as source of truth; stored rooms.occupied may be stale.
    room_stats = db.query(
        """SELECT COUNT(*) rooms, COALESCE(SUM(r.capacity),0) beds,
                  COALESCE(SUM(COALESCE(a.active_count,0)),0) occupied
           FROM rooms r
           LEFT JOIN (SELECT room_id, COUNT(*) active_count FROM allocations
                      WHERE is_active=TRUE GROUP BY room_id) a ON a.room_id=r.id
           WHERE r.is_active=TRUE""",
        fetchone=True,
    )
    fee_stats = db.query(
        """SELECT
             COALESCE((SELECT SUM(p.amount_paid) FROM payments p WHERE p.voided_at IS NULL),0) AS paid,
             COALESCE((
                 SELECT SUM(GREATEST(f.amount - COALESCE((SELECT SUM(p2.amount_paid) FROM payments p2
                                                          WHERE p2.fee_id=f.id AND p2.voided_at IS NULL),0),0))
                 FROM fees f
                 JOIN students fs ON fs.id=f.student_id
                 WHERE (fs.lifecycle_status IS NULL OR fs.lifecycle_status <> 'inactive')
                   AND f.status IN ('pending','overdue')
             ),0) AS outstanding,
             COALESCE((
                 SELECT SUM(GREATEST(f.amount - COALESCE((SELECT SUM(p3.amount_paid) FROM payments p3
                                                          WHERE p3.fee_id=f.id AND p3.voided_at IS NULL),0),0))
                 FROM fees f
                 JOIN students fs ON fs.id=f.student_id
                 WHERE (fs.lifecycle_status IS NULL OR fs.lifecycle_status <> 'inactive')
                   AND f.status='overdue'
             ),0) AS overdue,
             COALESCE((
                 SELECT COUNT(*)
                 FROM fees f2
                 JOIN students fs2 ON fs2.id=f2.student_id
                 WHERE (fs2.lifecycle_status IS NULL OR fs2.lifecycle_status <> 'inactive')
                   AND f2.status IN ('pending','overdue')
             ),0) AS active_due_count
        """,
        fetchone=True,
    )
    fee_stats["paid"] = float(fee_stats["paid"] or 0)
    fee_stats["outstanding"] = float(fee_stats["outstanding"] or 0)
    fee_stats["total"] = fee_stats["paid"] + fee_stats["outstanding"]
    fee_stats["overdue"] = float(fee_stats.get("overdue") or 0)
    fee_stats["pending"] = max(fee_stats["outstanding"] - fee_stats["overdue"], 0)
    complaint_stats = db.query(
        """SELECT
             COUNT(*) total,
             SUM(status='pending') open,
             SUM(status='in_progress') in_progress,
             SUM(status='resolved') resolved
           FROM complaints""",
        fetchone=True,
    )
    today = date.today()
    # Attendance is a CURRENT-student metric. Historical attendance rows for
    # archived students stay in the database for audit/history, but must not
    # affect today's dashboard numbers.
    att_stats = db.query(
        """SELECT
             COALESCE(SUM(a.status='present'),0) present,
             COALESCE(SUM(a.status='absent'),0) absent
           FROM attendance a
           JOIN students s ON s.id=a.student_id
           WHERE a.date=%s
             AND (s.lifecycle_status IS NULL OR s.lifecycle_status <> 'inactive')""",
        (today,), fetchone=True,
    )

    # Operational alerts are calculated from live database records.
    pending_leave = db.query("SELECT COUNT(*) c FROM leave_requests WHERE status='pending'", fetchone=True)["c"]
    pending_passes = db.query("SELECT COUNT(*) c FROM gate_passes WHERE status='pending'", fetchone=True)["c"]
    overdue_count = db.query(
        """SELECT COUNT(*) c FROM fees f JOIN students s ON s.id=f.student_id
           WHERE (s.lifecycle_status IS NULL OR s.lifecycle_status <> 'inactive')
             AND (f.status='overdue' OR (f.status='pending' AND f.due_date < CURDATE()))""",
        fetchone=True
    )["c"]
    maintenance_count = db.query("SELECT COUNT(*) c FROM complaints WHERE status IN ('pending','in_progress')", fetchone=True)["c"]

    beds = room_stats["beds"] or 0
    occupied = room_stats["occupied"] or 0

    return render_template(
        "dashboard.html",
        total_students=total_students,
        rooms=room_stats["rooms"] or 0,
        beds=beds,
        occupied=occupied,
        vacant=beds - occupied,
        occ_pct=round((occupied / beds) * 100) if beds else 0,
        fee_stats=fee_stats,
        fee_pct=round((fee_stats["paid"] / fee_stats["total"]) * 100) if fee_stats["total"] else 0,
        complaint_stats=complaint_stats,
        att_present=att_stats["present"] or 0,
        att_absent=att_stats["absent"] or 0,
        pending_leave=pending_leave or 0,
        pending_passes=pending_passes or 0,
        overdue_count=overdue_count or 0,
        maintenance_count=maintenance_count or 0,
    )


@app.route("/student/dashboard")
@login_required("student")
def student_dashboard():
    student = db.query("SELECT * FROM students WHERE user_id=%s", (session["user_id"],), fetchone=True)
    room = db.query(
        """SELECT r.* FROM allocations a JOIN rooms r ON a.room_id=r.id
           WHERE a.student_id=%s AND a.is_active=TRUE""",
        (student["id"],), fetchone=True,
    ) if student else None
    fees = db.query("SELECT * FROM fees WHERE student_id=%s ORDER BY due_date DESC", (student["id"],)) if student else []
    complaints = db.query("SELECT * FROM complaints WHERE student_id=%s AND deleted_at IS NULL ORDER BY created_at DESC", (student["id"],)) if student else []
    return render_template("student_dashboard.html", student=student, room=room, fees=fees, complaints=complaints)


# ---------------------------------------------------------------
# Students (admin)
# ---------------------------------------------------------------
@app.route("/students", methods=["GET", "POST"])
@login_required(("admin", "warden"))
def students():
    if request.method == "POST":
        code = request.form["student_code"].strip()
        name = request.form["name"].strip()
        course = request.form["course"]
        year = request.form["year"]
        phone = request.form["phone"]
        email = request.form["email"]
        username = request.form["username"].strip()
        password = request.form["password"]

        # Validate before inserting so duplicate usernames/codes show a friendly message.
        if len(username) < 3 or len(password) < 8:
            flash("Student username must be at least 3 characters and password at least 8 characters.", "danger")
            return redirect(url_for("students"))
        if db.query("SELECT id FROM users WHERE username=%s LIMIT 1", (username,), fetchone=True):
            flash("That login username already exists. Please choose a different username.", "danger")
            return redirect(url_for("students"))
        if db.query("SELECT id FROM students WHERE student_code=%s LIMIT 1", (code,), fetchone=True):
            flash("That student code already exists. Please use a unique student code.", "danger")
            return redirect(url_for("students"))
        conn = None
        cur = None
        try:
            conn = db.get_conn()
            conn.start_transaction()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s,%s,'student')",
                (username, generate_password_hash(password)),
            )
            user_id = cur.lastrowid
            cur.execute(
                """INSERT INTO students (user_id, student_code, name, course, year, phone, email)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (user_id, code, name, course, year, phone, email),
            )
            conn.commit()
            audit("student_created", "student", cur.lastrowid, {"student_code": code, "name": name})
            flash("Student added successfully. Share the login credentials securely.", "success")
        except IntegrityError as exc:
            conn.rollback()
            # Handles duplicate submissions/race conditions even if pre-checks passed.
            if getattr(exc, "errno", None) == 1062:
                message = str(exc)
                if "username" in message.lower():
                    flash("Username already exists. Choose a different login username.", "danger")
                else:
                    flash("Student code already exists. Choose a different student code.", "danger")
            else:
                flash("Could not add student because of a database constraint. Check the entered details.", "danger")
        except Exception:
            if conn is not None:
                conn.rollback()
            flash("Could not add student. Check the required fields and database connection, then try again.", "danger")
        finally:
            if cur is not None:
                cur.close()
            if conn is not None:
                conn.close()
        return redirect(url_for("students"))

    search = request.args.get("q", "").strip()
    show_archived = request.args.get("show", "") == "archived"
    status_clause = "lifecycle_status='inactive'" if show_archived else "(lifecycle_status IS NULL OR lifecycle_status<>'inactive')"
    params = ()
    sql = f"SELECT * FROM students WHERE {status_clause}"
    if search:
        sql += " AND (name LIKE %s OR student_code LIKE %s OR course LIKE %s OR phone LIKE %s)"
        params = (f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%")
    sql += " ORDER BY id DESC"
    rows = db.query(sql, params)
    return render_template("students.html", students=rows, search=search, show_archived=show_archived)


@app.route("/students/bulk-export", methods=["POST"])
@login_required("admin")
def bulk_export_students():
    ids = []
    for raw in request.form.getlist("student_ids"):
        try:
            value = int(raw)
            if value > 0 and value not in ids:
                ids.append(value)
        except (TypeError, ValueError):
            continue
    if not ids:
        flash("Select at least one student to export.", "warning")
        return redirect(url_for("students"))
    placeholders = ",".join(["%s"] * len(ids))
    rows = db.query(f"SELECT student_code,name,course,year,phone,email FROM students WHERE id IN ({placeholders}) ORDER BY name", tuple(ids))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["student_code", "name", "course", "year", "phone", "email"])
    for row in rows:
        writer.writerow([row.get(k) for k in ("student_code", "name", "course", "year", "phone", "email")])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=smarthostel_selected_students.csv"
    return response


@app.route("/students/<int:sid>/edit", methods=["POST"])
@login_required(("admin", "warden"))
def edit_student(sid):
    code = request.form.get("student_code", "").strip()
    name = request.form.get("name", "").strip()
    course = request.form.get("course", "").strip()
    year = request.form.get("year", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    new_password = request.form.get("password", "")
    if session.get("role") != "admin":
        new_password = ""
    student = db.query("SELECT id, user_id FROM students WHERE id=%s", (sid,), fetchone=True)
    if not student:
        flash("Student record not found.", "danger")
        return redirect(url_for("students"))
    if not code or not name:
        flash("Student code and name are required.", "danger")
        return redirect(url_for("students"))
    if new_password and len(new_password) < 8:
        flash("New password must contain at least 8 characters.", "danger")
        return redirect(url_for("students"))
    try:
        duplicate = db.query("SELECT id FROM students WHERE student_code=%s AND id<>%s LIMIT 1", (code, sid), fetchone=True)
        if duplicate:
            flash("That student code is already in use.", "danger")
            return redirect(url_for("students"))
        db.query("UPDATE students SET student_code=%s,name=%s,course=%s,year=%s,phone=%s,email=%s WHERE id=%s",
                 (code,name,course,year,phone,email,sid), commit=True)
        if new_password and student.get("user_id"):
            db.query("UPDATE users SET password_hash=%s WHERE id=%s",
                     (generate_password_hash(new_password), student["user_id"]), commit=True)
        audit("student_updated", "student", sid, {"student_code": code})
        flash("Student details updated successfully.", "success")
    except IntegrityError:
        flash("Could not update: student code or another unique field already exists.", "danger")
    except Exception:
        flash("Could not update student. Check the database connection and entered details.", "danger")
    return redirect(url_for("students"))


@app.route("/students/<int:sid>/delete", methods=["POST"])
@login_required(("admin", "warden"))
def delete_student(sid):
    """Archive a student safely; close any active room allocation in the same transaction."""
    conn = db.get_conn()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, user_id, lifecycle_status, name FROM students WHERE id=%s FOR UPDATE", (sid,))
        student = cur.fetchone()
        if not student:
            raise ValueError("Student record not found.")
        if student.get("lifecycle_status") == "inactive":
            raise ValueError("Student is already archived. Open Archived students to restore the record.")

        cur.execute("SELECT id, room_id FROM allocations WHERE student_id=%s AND is_active=TRUE LIMIT 1 FOR UPDATE", (sid,))
        alloc = cur.fetchone()
        if alloc:
            cur.execute("UPDATE allocations SET is_active=FALSE, vacated_on=%s WHERE id=%s", (date.today(), alloc["id"]))
            cur.execute("UPDATE rooms SET occupied=GREATEST(occupied-1,0) WHERE id=%s", (alloc["room_id"],))

        cur.execute("UPDATE students SET lifecycle_status='inactive', archived_at=NOW() WHERE id=%s", (sid,))
        conn.commit()
        audit("student_archived", "student", sid, {"user_id": student.get("user_id"), "allocation_id": alloc.get("id") if alloc else None})
        if alloc:
            flash(f"{student['name']} was archived and their room was released.", "success")
        else:
            flash("Student archived. Historical records were preserved.", "success")
    except ValueError as exc:
        conn.rollback()
        flash(str(exc), "warning")
    except Exception:
        conn.rollback()
        app.logger.exception("Could not archive student")
        flash("Could not archive the student. No changes were saved.", "danger")
    finally:
        if cur is not None:
            cur.close()
        conn.close()
    return redirect(url_for("students"))


@app.route("/students/<int:sid>/restore", methods=["POST"])
@login_required("admin")
def restore_student(sid):
    student = db.query("SELECT id, lifecycle_status FROM students WHERE id=%s", (sid,), fetchone=True)
    if not student:
        flash("Student record not found.", "warning")
    elif student.get("lifecycle_status") != "inactive":
        flash("Student is not archived.", "info")
    else:
        db.query("UPDATE students SET lifecycle_status='active', archived_at=NULL WHERE id=%s", (sid,), commit=True)
        audit("student_restored", "student", sid, {"previous_status": "inactive", "new_status": "active"})
        flash("Student restored.", "success")
    return redirect(url_for("students"))


# ---------------------------------------------------------------
# Rooms (admin)
# ---------------------------------------------------------------
@app.route("/rooms", methods=["GET", "POST"])
@login_required(("admin", "warden"))
def rooms():
    if request.method == "POST":
        room_number = request.form.get("room_number", "").strip()
        room_type = request.form.get("room_type", "Standard").strip()
        block_name = request.form.get("block_name", "Block A").strip() or "Block A"
        floor_raw = request.form.get("floor_id", "").strip()
        try:
            capacity = int(request.form.get("capacity", "0"))
            floor_id = int(floor_raw) if floor_raw else None
            if not room_number or capacity < 1:
                raise ValueError
            db.query(
                "INSERT INTO rooms (room_number, room_type, capacity, block_name, floor_id, is_active) VALUES (%s,%s,%s,%s,%s,TRUE)",
                (room_number, room_type, capacity, block_name, floor_id), commit=True,
            )
            room = db.query("SELECT id FROM rooms WHERE room_number=%s", (room_number,), fetchone=True)
            audit("room_created", "room", room["id"], {"room_number": room_number, "capacity": capacity, "block_name": block_name, "floor_id": floor_id})
            flash("Room created", "success")
        except ValueError:
            flash("Enter a room number and capacity of at least 1.", "danger")
        except Exception as exc:
            app.logger.exception("Room creation failed")
            flash("Could not create the room. Please check the server logs.", "danger")
        return redirect(url_for("rooms"))

    room_q = request.args.get("q", "").strip()
    selected_blocks = [b.strip() for b in request.args.getlist("block") if b.strip()]
    floor_raw = request.args.get("floor", "").strip()
    try:
        floor_filter = int(floor_raw) if floor_raw else None
    except ValueError:
        floor_filter = None

    where = ["r.is_active=TRUE", "(r.room_number LIKE %s OR r.room_type LIKE %s)"]
    params = [f"%{room_q}%", f"%{room_q}%"]
    if selected_blocks:
        where.append("r.block_name IN (" + ",".join(["%s"] * len(selected_blocks)) + ")")
        params.extend(selected_blocks)
    if floor_filter:
        where.append("r.floor_id=%s")
        params.append(floor_filter)

    all_rooms = db.query(
        f"""SELECT r.id, r.room_number, r.room_type, r.capacity, r.block_name, r.floor_id,
                  f.floor_name, f.floor_number, f.building_name, f.status AS floor_status,
                  COALESCE(a.active_count,0) AS occupied
           FROM rooms r
           LEFT JOIN floors f ON f.id=r.floor_id
           LEFT JOIN (SELECT room_id, COUNT(*) active_count FROM allocations
                      WHERE is_active=TRUE GROUP BY room_id) a ON a.room_id=r.id
           WHERE {' AND '.join(where)}
           ORDER BY r.block_name, COALESCE(f.floor_number,999), r.room_number""", tuple(params)
    )
    floors = db.query("SELECT * FROM floors ORDER BY building_name, floor_number")
    blocks = db.query("SELECT DISTINCT block_name FROM rooms WHERE is_active=TRUE AND block_name IS NOT NULL AND block_name<>'' ORDER BY block_name")

    students_unassigned = db.query(
        """SELECT s.* FROM students s
           LEFT JOIN allocations a ON s.id=a.student_id AND a.is_active=TRUE
           WHERE a.id IS NULL
             AND (s.lifecycle_status IS NULL OR s.lifecycle_status <> 'inactive')
           ORDER BY s.name"""
    )
    occupants = db.query("""SELECT a.id AS allocation_id,a.room_id,s.name,s.student_code FROM allocations a JOIN students s ON s.id=a.student_id WHERE a.is_active=TRUE AND (s.lifecycle_status IS NULL OR s.lifecycle_status<>'inactive') ORDER BY s.name""")
    by_room = {}
    for person in occupants:
        by_room.setdefault(person["room_id"], []).append(person)

    # Build the visual floor sections shown in the screenshot-inspired UI.
    sections = []
    section_map = {}
    for room in all_rooms:
        key = (room.get("block_name") or "Block A", room.get("floor_id") or 0)
        if key not in section_map:
            section_map[key] = {
                "block": key[0],
                "floor_id": room.get("floor_id"),
                "floor_name": room.get("floor_name") or "Unassigned floor",
                "floor_number": room.get("floor_number"),
                "building_name": room.get("building_name") or "Main",
                "rooms": [],
            }
            sections.append(section_map[key])
        section_map[key]["rooms"].append(room)

    for section in sections:
        section["occupied"] = sum(int(r.get("occupied") or 0) for r in section["rooms"])
        section["capacity"] = sum(int(r.get("capacity") or 0) for r in section["rooms"])
        section["available"] = max(section["capacity"] - section["occupied"], 0)
        section["blocked"] = sum(1 for r in section["rooms"] if r.get("floor_status") == "maintenance")

    total_capacity = sum(int(r.get("capacity") or 0) for r in all_rooms)
    total_occupied = sum(int(r.get("occupied") or 0) for r in all_rooms)
    return render_template(
        "rooms.html", rooms=all_rooms, students=students_unassigned, search=room_q, occupants=by_room,
        floors=floors, blocks=blocks, selected_blocks=selected_blocks, floor_filter=floor_filter,
        room_sections=sections, total_capacity=total_capacity, total_occupied=total_occupied,
    )


@app.route("/rooms/<int:room_id>/edit", methods=["POST"])
@login_required(("admin", "warden"))
def edit_room(room_id):
    room_number = request.form.get("room_number", "").strip()
    room_type = request.form.get("room_type", "").strip()
    block_name = request.form.get("block_name", "Block A").strip() or "Block A"
    floor_raw = request.form.get("floor_id", "").strip()
    try:
        capacity = int(request.form.get("capacity", "0"))
        floor_id = int(floor_raw) if floor_raw else None
        room = db.query("SELECT id,is_active FROM rooms WHERE id=%s", (room_id,), fetchone=True)
        occupied = db.query(
            "SELECT COUNT(*) AS n FROM allocations WHERE room_id=%s AND is_active=TRUE",
            (room_id,), fetchone=True,
        )
        if not room:
            flash("Room not found.", "danger")
        elif not room.get("is_active", True):
            flash("Archived rooms cannot be edited.", "warning")
        elif not room_number or not room_type or capacity < 1:
            flash("Fill all fields; capacity must be at least 1.", "danger")
        elif capacity < int((occupied or {}).get("n", 0)):
            flash("Capacity cannot be lower than the current occupied beds.", "danger")
        else:
            db.query(
                "UPDATE rooms SET room_number=%s, room_type=%s, capacity=%s, block_name=%s, floor_id=%s WHERE id=%s",
                (room_number, room_type, capacity, block_name, floor_id, room_id), commit=True,
            )
            flash("Room details updated.", "success")
    except ValueError:
        flash("Capacity must be a whole number.", "danger")
    except Exception as exc:
        app.logger.exception("Room update failed")
        flash("Could not update the room. Please check the server logs.", "danger")
    return redirect(url_for("rooms"))


@app.route("/rooms/allocate", methods=["POST"])
@login_required(("admin", "warden"))
def allocate_room():
    try:
        student_id = int(request.form.get("student_id", "0"))
        room_id = int(request.form.get("room_id", "0"))
        if student_id < 1 or room_id < 1:
            raise ValueError("Choose a student and a room.")
        allocation_id = db.allocate_room_safely(student_id, room_id)
        audit("room_allocated", "allocation", allocation_id, {"student_id": student_id, "room_id": room_id})
        flash("Room allocated successfully.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    except Exception:
        app.logger.exception("Room allocation failed")
        flash("Could not allocate room. No changes were saved; please retry.", "danger")
    return redirect(url_for("rooms"))

@app.route("/rooms/vacate/<int:alloc_id>", methods=["POST"])
@login_required(("admin", "warden"))
def vacate_room(alloc_id):
    """Vacate a bed atomically so allocation and room occupancy cannot diverge."""
    conn = db.get_conn()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, room_id FROM allocations WHERE id=%s AND is_active=TRUE FOR UPDATE",
            (alloc_id,),
        )
        alloc = cur.fetchone()
        if not alloc:
            raise ValueError("Active allocation not found.")
        cur.execute(
            "UPDATE allocations SET is_active=FALSE, vacated_on=%s WHERE id=%s AND is_active=TRUE",
            (date.today(), alloc_id),
        )
        if cur.rowcount != 1:
            raise ValueError("Allocation was already vacated.")
        cur.execute(
            "UPDATE rooms SET occupied = GREATEST(occupied - 1, 0) WHERE id=%s",
            (alloc["room_id"],),
        )
        conn.commit()
        audit("room_vacated", "allocation", alloc_id, {"room_id": alloc["room_id"]})
        flash("Room vacated. Student remains active.", "success")
    except ValueError as exc:
        conn.rollback()
        flash(str(exc), "danger")
    except Exception:
        conn.rollback()
        app.logger.exception("Could not vacate room")
        flash("Could not vacate the room. No changes were saved.", "danger")
    finally:
        if cur is not None:
            cur.close()
        conn.close()
    return redirect(url_for("rooms"))


@app.route("/rooms/remove-student/<int:alloc_id>", methods=["POST"])
@login_required(("admin", "warden"))
def remove_student_from_room(alloc_id):
    """Remove a resident from a room and archive the student in one transaction."""
    conn = db.get_conn()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT a.id, a.room_id, a.student_id, s.name, s.user_id, s.lifecycle_status
               FROM allocations a
               JOIN students s ON s.id=a.student_id
               WHERE a.id=%s AND a.is_active=TRUE
               FOR UPDATE""",
            (alloc_id,),
        )
        alloc = cur.fetchone()
        if not alloc:
            raise ValueError("This student is no longer allocated to the room.")

        cur.execute(
            "UPDATE allocations SET is_active=FALSE, vacated_on=%s WHERE id=%s",
            (date.today(), alloc_id),
        )
        cur.execute(
            "UPDATE rooms SET occupied=GREATEST(occupied-1,0) WHERE id=%s",
            (alloc["room_id"],),
        )
        cur.execute(
            "UPDATE students SET lifecycle_status='inactive', archived_at=NOW() WHERE id=%s",
            (alloc["student_id"],),
        )
        conn.commit()

        audit(
            "student_removed_and_archived",
            "student",
            alloc["student_id"],
            {
                "allocation_id": alloc_id,
                "room_id": alloc["room_id"],
                "user_id": alloc.get("user_id"),
            },
        )
        flash(f"{alloc['name']} was removed from the room and moved to Archive.", "success")
    except ValueError as exc:
        conn.rollback()
        flash(str(exc), "warning")
    except Exception:
        conn.rollback()
        app.logger.exception("Could not remove and archive room resident")
        flash("Could not remove the student. No changes were saved.", "danger")
    finally:
        if cur is not None:
            cur.close()
        conn.close()
    return redirect(url_for("rooms"))


# ---------------------------------------------------------------
# Fees & Payments (admin)
# ---------------------------------------------------------------
@app.route("/fees/students/<int:sid>/monthly-fee", methods=["POST"])
@login_required("admin")
def update_monthly_fee(sid):
    raw = request.form.get("monthly_fee", "").strip()
    try:
        amount = Decimal(raw).quantize(Decimal("0.01"))
        if amount < 0 or amount > Decimal("99999999.99"):
            raise ValueError
        student = db.query(
            "SELECT id, name, monthly_fee FROM students WHERE id=%s AND (lifecycle_status IS NULL OR lifecycle_status='active')",
            (sid,), fetchone=True
        )
        if not student:
            raise ValueError("Active student not found.")
        old_amount = Decimal(str(student.get("monthly_fee") or 0)).quantize(Decimal("0.01"))
        if old_amount == amount:
            flash("No change was needed; the monthly fee is already set to that amount.", "info")
            return redirect(url_for("fees"))
        conn = db.get_conn()
        cur = None
        try:
            conn.start_transaction()
            cur = conn.cursor()
            cur.execute("SELECT monthly_fee FROM students WHERE id=%s AND (lifecycle_status IS NULL OR lifecycle_status='active') FOR UPDATE", (sid,))
            locked = cur.fetchone()
            if not locked:
                raise ValueError("Active student not found.")
            cur.execute("UPDATE students SET monthly_fee=%s WHERE id=%s", (amount, sid))
            cur.execute(
                "INSERT INTO monthly_fee_history (student_id, old_amount, new_amount, effective_from, changed_by) VALUES (%s,%s,%s,CURDATE(),%s)",
                (sid, old_amount, amount, session["user_id"]),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if cur is not None:
                cur.close()
            conn.close()
        audit("monthly_fee_updated", "student", sid, {"old_amount": str(old_amount), "new_amount": str(amount)})
        flash(f"Monthly fee for {student['name']} changed from ₹{old_amount:.2f} to ₹{amount:.2f}. Existing bills were not changed.", "success")
    except (InvalidOperation, ValueError):
        flash("Enter a valid monthly fee from ₹0.00 to ₹99,999,999.99.", "danger")
    except Exception:
        app.logger.exception("Monthly fee update failed")
        flash("Could not update the monthly fee. No changes were saved.", "danger")
    return redirect(url_for("fees"))

@app.route("/fees", methods=["GET", "POST"])
@login_required(("admin", "accountant"))
def fees():
    if request.method == "POST":
        try:
            action = request.form.get("action", "single_bill")
            if action == "generate_month":
                billing_month_raw = request.form.get("billing_month", "").strip()
                due_day = int(request.form.get("due_day", "10"))
                if not re.fullmatch(r"\d{4}-\d{2}", billing_month_raw):
                    raise ValueError("Choose a valid billing month.")
                if not 1 <= due_day <= 31:
                    raise ValueError("Due day must be between 1 and 31.")
                billing_month = datetime.strptime(billing_month_raw, "%Y-%m").date().replace(day=1)
                current_month = date.today().replace(day=1)
                if billing_month < current_month:
                    raise ValueError("New monthly bills can only be generated for the current or a future month.")

                conn = db.get_conn()
                cur = None
                try:
                    conn.start_transaction()
                    cur = conn.cursor(dictionary=True)
                    cur.execute(
                        "INSERT IGNORE INTO monthly_billing_runs (billing_month, due_day, generated_by, generated_at) VALUES (%s,%s,%s,NOW())",
                        (billing_month, due_day, session["user_id"]),
                    )
                    cur.execute("SELECT id, due_day FROM monthly_billing_runs WHERE billing_month=%s FOR UPDATE", (billing_month,))
                    run = cur.fetchone()
                    if not run:
                        raise ValueError("Could not lock the monthly billing run.")
                    # A rerun is intentionally safe: existing bills are never overwritten.
                    run_due_day = int(run["due_day"] or due_day)
                    last_day = calendar.monthrange(billing_month.year, billing_month.month)[1]
                    effective_due_day = min(run_due_day, last_day)
                    cur.execute(
                        """SELECT id, name, monthly_fee FROM students
                           WHERE (lifecycle_status IS NULL OR lifecycle_status='active')
                             AND monthly_fee IS NOT NULL AND monthly_fee > 0
                           ORDER BY id FOR UPDATE"""
                    )
                    active_students = cur.fetchall()
                    created = 0
                    skipped = 0
                    due_date = billing_month.replace(day=effective_due_day)
                    for student in active_students:
                        cur.execute("SELECT id FROM fees WHERE student_id=%s AND billing_month=%s LIMIT 1 FOR UPDATE", (student["id"], billing_month))
                        if cur.fetchone():
                            skipped += 1
                            continue
                        cur.execute(
                            """INSERT INTO fees (student_id, amount, due_date, billing_month, bill_type, status)
                               VALUES (%s,%s,%s,%s,'monthly','pending')""",
                            (student["id"], Decimal(str(student["monthly_fee"])).quantize(Decimal("0.01")), due_date, billing_month),
                        )
                        created += 1
                    conn.commit()
                    audit("monthly_bills_generated", "billing_run", billing_month.isoformat(), {
                        "created": created, "skipped": skipped, "billing_month": billing_month.isoformat(), "due_day": effective_due_day
                    })
                    flash(f"{created} monthly bill(s) generated for {billing_month.strftime('%B %Y')}. Existing bills were preserved.", "success")
                except IntegrityError:
                    conn.rollback()
                    flash("That billing month is already protected by the database. Existing bills were left unchanged.", "warning")
                except Exception:
                    conn.rollback()
                    app.logger.exception("Monthly bill generation failed")
                    flash("Monthly bill generation failed. No partial changes were saved.", "danger")
                finally:
                    if cur is not None:
                        cur.close()
                    conn.close()
                return redirect(url_for("fees"))

            # Manual bills are deliberately one-off unless an explicit billing month is supplied.
            try:
                student_id = int(request.form.get("student_id", "0"))
            except (TypeError, ValueError):
                student_id = 0
            amount = Decimal(request.form.get("amount", "0")).quantize(Decimal("0.01"))
            due_date_raw = request.form.get("due_date", "").strip()
            billing_month_raw = request.form.get("billing_month", "").strip()
            if student_id < 1 or amount <= 0 or amount > Decimal("99999999.99") or not due_date_raw:
                raise ValueError("Enter an active student, a positive amount and a due date.")
            due = datetime.strptime(due_date_raw, "%Y-%m-%d").date()
            # One-time adjustments are deliberately separate from recurring monthly bills.
            # They never accept a billing month, so a correction can never accidentally
            # consume the unique monthly-bill slot for a student.
            if billing_month_raw:
                raise ValueError("One-time bills do not use a billing month. Generate monthly bills from the Monthly Billing panel.")
            student = db.query("SELECT id FROM students WHERE id=%s AND lifecycle_status='active'", (student_id,), fetchone=True)
            if not student:
                raise ValueError("Fees can only be created for an active student.")
            fee_id = db.query(
                "INSERT INTO fees (student_id, amount, due_date, billing_month, bill_type, status) VALUES (%s,%s,%s,NULL,'one_time','pending')",
                (student_id, amount, due), commit=True
            )
            audit("fee_created", "fee", fee_id, {"amount": str(amount), "bill_type": "one_time", "due_date": due.isoformat()})
            flash("Fee bill created successfully.", "success")
        except (ValueError, InvalidOperation):
            flash("Enter valid student, amount, due date and billing month details.", "danger")
        except Exception:
            app.logger.exception("Fee creation failed")
            flash("Could not create the fee bill. No changes were saved.", "danger")
        return redirect(url_for("fees"))

    # Recompute status from the ledger before rendering so the UI cannot drift from reality.
    db.query(
        """UPDATE fees f SET status=CASE
           WHEN COALESCE((SELECT SUM(p.amount_paid) FROM payments p WHERE p.fee_id=f.id AND p.voided_at IS NULL),0) >= f.amount THEN 'paid'
           WHEN f.due_date < CURDATE() THEN 'overdue' ELSE 'pending' END""", commit=True
    )
    fee_q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "all").strip().lower()
    if status_filter not in {"all", "pending", "overdue", "paid"}:
        status_filter = "all"
    clauses = ["s.lifecycle_status='active'"]
    params = []
    if status_filter != "all":
        clauses.append("f.status=%s")
        params.append(status_filter)
    if fee_q:
        clauses.append("(s.name LIKE %s OR s.student_code LIKE %s OR DATE_FORMAT(f.billing_month,'%%Y-%%m') LIKE %s OR f.id LIKE %s OR f.bill_type LIKE %s)")
        q = f"%{fee_q}%"
        params.extend([q, q, q, q, q])
    fee_rows = db.query(
        f"""SELECT f.*, s.name AS student_name, s.student_code,
                  COALESCE((SELECT SUM(p.amount_paid) FROM payments p WHERE p.fee_id=f.id AND p.voided_at IS NULL),0) AS paid_amount,
                  GREATEST(f.amount - COALESCE((SELECT SUM(p2.amount_paid) FROM payments p2 WHERE p2.fee_id=f.id AND p2.voided_at IS NULL),0),0) AS balance
           FROM fees f JOIN students s ON f.student_id=s.id
           WHERE {' AND '.join(clauses)}
           ORDER BY CASE f.status WHEN 'overdue' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, COALESCE(f.billing_month,f.due_date) DESC, f.id DESC""", tuple(params)
    )
    recent_payments = db.query(
        """SELECT p.id,p.amount_paid,p.paid_on,p.method,p.payment_reference,p.receipt_no,p.created_at,
                  s.name AS student_name,s.student_code,f.id AS fee_id,f.billing_month
           FROM payments p JOIN fees f ON f.id=p.fee_id JOIN students s ON s.id=f.student_id
           WHERE p.voided_at IS NULL AND p.amount_paid > 0 AND s.lifecycle_status='active'
           ORDER BY p.id DESC LIMIT 30"""
    )
    voided_payments = db.query(
        """SELECT p.id,p.amount_paid,p.paid_on,p.method,p.payment_reference,p.receipt_no,p.voided_at,p.void_reason,
                  s.name AS student_name,s.student_code,f.id AS fee_id,f.billing_month,u.username AS voided_by_username
           FROM payments p JOIN fees f ON f.id=p.fee_id JOIN students s ON s.id=f.student_id
           LEFT JOIN users u ON u.id=p.voided_by
           WHERE p.voided_at IS NOT NULL ORDER BY p.voided_at DESC LIMIT 20"""
    )
    all_students = db.query("SELECT id,name,student_code,monthly_fee FROM students WHERE lifecycle_status='active' ORDER BY name")
    collection = db.query("SELECT COALESCE(SUM(amount_paid),0) AS paid FROM payments WHERE voided_at IS NULL", fetchone=True)
    outstanding = db.query(
        """SELECT COALESCE(SUM(GREATEST(f.amount-COALESCE((SELECT SUM(p.amount_paid) FROM payments p WHERE p.fee_id=f.id AND p.voided_at IS NULL),0),0)),0) AS due
           FROM fees f JOIN students s ON s.id=f.student_id
           WHERE s.lifecycle_status='active' AND f.status IN ('pending','overdue')""", fetchone=True
    )
    paid_bills = db.query("SELECT COUNT(*) AS n FROM fees f JOIN students s ON s.id=f.student_id WHERE f.status='paid' AND s.lifecycle_status='active'", fetchone=True)
    pending_bills = db.query("SELECT COUNT(*) AS n FROM fees f JOIN students s ON s.id=f.student_id WHERE f.status='pending' AND s.lifecycle_status='active'", fetchone=True)
    overdue_bills = db.query("SELECT COUNT(*) AS n FROM fees f JOIN students s ON s.id=f.student_id WHERE f.status='overdue' AND s.lifecycle_status='active'", fetchone=True)
    current_billing_month = date.today().replace(day=1).isoformat()
    last_day = calendar.monthrange(date.today().year, date.today().month)[1]
    month_end = date.today().replace(day=last_day).isoformat()
    response = make_response(render_template(
        "fees.html", fees=fee_rows, students=all_students, search=fee_q, status_filter=status_filter,
        collection=collection["paid"] or 0, outstanding=outstanding["due"] or 0,
        recent_payments=recent_payments, voided_payments=voided_payments,
        paid_bill_count=paid_bills["n"] or 0, pending_bill_count=pending_bills["n"] or 0, overdue_bill_count=overdue_bills["n"] or 0,
        current_billing_month=current_billing_month, current_period_start=current_billing_month, current_period_end=month_end
    ))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/fees/payments/<int:payment_id>/void", methods=["POST"])
@login_required("admin")
def void_payment(payment_id):
    """Financial correction: void a payment instead of destroying its audit history."""
    reason = request.form.get("reason", "").strip()
    if len(reason) < 5 or len(reason) > 255:
        flash("Enter a correction reason (5–255 characters).", "danger")
        return redirect(url_for("fees"))

    conn = db.get_conn()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        # Lock the fee first, matching pay_fee()'s lock order. This avoids a
        # payment/void deadlock when a correction races with a collection.
        cur.execute(
            "SELECT id, amount, due_date FROM fees WHERE id=(SELECT fee_id FROM payments WHERE id=%s) FOR UPDATE",
            (payment_id,),
        )
        fee = cur.fetchone()
        if not fee:
            raise ValueError("Payment or fee record not found.")
        cur.execute(
            "SELECT * FROM payments WHERE id=%s FOR UPDATE",
            (payment_id,),
        )
        payment = cur.fetchone()
        if not payment:
            raise ValueError("Payment record not found.")
        if payment["voided_at"] is not None:
            raise ValueError("This payment has already been voided.")

        cur.execute(
            """UPDATE payments
               SET voided_at=NOW(), voided_by=%s, void_reason=%s
               WHERE id=%s AND voided_at IS NULL""",
            (session["user_id"], reason, payment_id),
        )
        if cur.rowcount != 1:
            raise ValueError("Payment was already corrected by another request.")

        cur.execute(
            """SELECT COALESCE(SUM(amount_paid),0) AS paid
               FROM payments WHERE fee_id=%s AND voided_at IS NULL""",
            (payment["fee_id"],),
        )
        paid = Decimal(str(cur.fetchone()["paid"] or 0))
        status = calculate_fee_status(fee["amount"], paid, fee["due_date"])
        cur.execute("UPDATE fees SET status=%s WHERE id=%s", (status, payment["fee_id"]))
        conn.commit()
        audit("payment_voided", "payment", payment_id, {
            "fee_id": payment["fee_id"], "amount": str(payment["amount_paid"]), "reason": reason, "receipt_no": payment.get("receipt_no")
        })
        flash("Payment voided. Collection totals and the fee balance were recalculated.", "success")
    except ValueError as exc:
        conn.rollback()
        flash(str(exc), "danger")
    except Exception:
        conn.rollback()
        app.logger.exception("Payment void failed")
        flash("Could not correct the payment. No changes were saved.", "danger")
    finally:
        if cur is not None:
            cur.close()
        conn.close()
    return redirect(url_for("fees"))


@app.route("/fees/<int:fee_id>/pay", methods=["POST"])
@login_required(("admin", "accountant"))
def pay_fee(fee_id):
    conn = db.get_conn()
    cur = None
    try:
        amount = Decimal(request.form.get("amount_paid", "0")).quantize(Decimal("0.01"))
        method = request.form.get("method", "Cash").strip() or "Cash"
        payment_reference = request.form.get("payment_reference", "").strip()
        if amount <= 0 or amount > Decimal("99999999.99"):
            raise ValueError("Payment amount must be greater than zero.")
        allowed_methods = {"Cash", "UPI", "Bank Transfer", "Card", "Other"}
        if method not in allowed_methods:
            raise ValueError("Choose a valid payment method.")
        if len(payment_reference) > 100:
            raise ValueError("Payment reference must be 100 characters or fewer.")
        if method in {"UPI", "Bank Transfer", "Card"} and not payment_reference:
            raise ValueError("Enter the transaction/reference number for this payment method.")

        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        cur.execute("""SELECT f.*, s.lifecycle_status, s.name AS student_name
                       FROM fees f JOIN students s ON s.id=f.student_id WHERE f.id=%s FOR UPDATE""", (fee_id,))
        fee = cur.fetchone()
        if not fee:
            raise ValueError("Fee record not found.")
        if fee.get("lifecycle_status") != "active":
            raise ValueError("Collections are allowed only for active students. Use historical records for checked-out or transferred students.")
        cur.execute("SELECT COALESCE(SUM(amount_paid),0) AS paid FROM payments WHERE fee_id=%s AND voided_at IS NULL", (fee_id,))
        paid_so_far = Decimal(str(cur.fetchone()["paid"] or 0))
        balance = (Decimal(str(fee["amount"])) - paid_so_far).quantize(Decimal("0.01"))
        if balance <= 0:
            raise ValueError("This fee is already fully paid.")
        if amount > balance:
            raise ValueError(f"Payment exceeds remaining balance of ₹{balance:.2f}.")
        receipt_no = make_receipt_no()
        cur.execute(
            "INSERT INTO payments (fee_id, amount_paid, method, payment_reference, receipt_no, paid_on, created_at) VALUES (%s,%s,%s,%s,%s,CURDATE(),NOW())",
            (fee_id, amount, method, payment_reference or None, receipt_no),
        )
        payment_id = cur.lastrowid
        new_paid = (paid_so_far + amount).quantize(Decimal("0.01"))
        new_status = calculate_fee_status(fee["amount"], new_paid, fee["due_date"])
        cur.execute("UPDATE fees SET status=%s WHERE id=%s", (new_status, fee_id))
        conn.commit()
        audit("manual_payment_recorded", "payment", payment_id, {"fee_id": fee_id, "amount": str(amount), "method": method, "payment_reference": payment_reference or None, "receipt_no": receipt_no})
        flash(f"Payment recorded. Receipt {receipt_no}.", "success")
    except ValueError as exc:
        conn.rollback()
        flash(str(exc), "danger")
    except Exception:
        conn.rollback()
        app.logger.exception("Payment recording failed")
        flash("Could not record payment. No changes were saved; please retry.", "danger")
    finally:
        if cur is not None:
            cur.close()
        conn.close()
    return redirect(url_for("fees"))


# ---------------------------------------------------------------
# Razorpay online payments (optional; requires .env keys and the corresponding database tables in the single schema)
# ---------------------------------------------------------------
@app.route("/fees/<int:fee_id>/razorpay/order", methods=["POST"])
@login_required(("admin", "accountant"))
def razorpay_create_order(fee_id):
    try:
        client, key_id = razorpay_client()
        fee = db.query("SELECT * FROM fees WHERE id=%s", (fee_id,), fetchone=True)
        if not fee:
            raise ValueError("Fee record not found.")
        paid = db.query("SELECT COALESCE(SUM(amount_paid),0) AS paid FROM payments WHERE fee_id=%s AND voided_at IS NULL", (fee_id,), fetchone=True)
        balance = (Decimal(str(fee["amount"])) - Decimal(str(paid["paid"] or 0))).quantize(Decimal("0.01"))
        if balance <= 0:
            raise ValueError("This fee is already fully paid.")
        paise = int(balance * 100)
        order = client.order.create(data={"amount": paise, "currency": "INR", "receipt": f"fee-{fee_id}-{int(datetime.now().timestamp())}", "notes": {"fee_id": str(fee_id)}})
        db.query("INSERT INTO payment_orders (fee_id, order_id, amount_paise, created_by) VALUES (%s,%s,%s,%s)",
                 (fee_id, order["id"], paise, session["user_id"]), commit=True)
        audit("razorpay_order_created", "fee", fee_id, {"order_id": order["id"], "amount_paise": paise})
        return jsonify({"key_id": key_id, "order_id": order["id"], "amount": paise, "currency": "INR", "name": "SmartHostel", "description": f"Fee payment #{fee_id}"})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("Razorpay order creation failed")
        return jsonify({"error": str(exc) if os.getenv("FLASK_DEBUG") == "1" else "Could not create payment order. Check Razorpay configuration."}), 500


@app.route("/fees/razorpay/verify", methods=["POST"])
@login_required(("admin", "accountant"))
def razorpay_verify():
    payload = request.get_json(silent=True) or {}
    order_id = str(payload.get("razorpay_order_id", ""))
    payment_id = str(payload.get("razorpay_payment_id", ""))
    signature = str(payload.get("razorpay_signature", ""))
    if not all((order_id, payment_id, signature)):
        return jsonify({"error": "Missing Razorpay verification fields."}), 400
    try:
        client, _ = razorpay_client()
        client.utility.verify_payment_signature({"razorpay_order_id": order_id, "razorpay_payment_id": payment_id, "razorpay_signature": signature})
        settle_razorpay_order(order_id, payment_id)
        return jsonify({"status": "paid"})
    except Exception:
        app.logger.exception("Razorpay signature verification/settlement failed")
        return jsonify({"error": "Payment could not be verified. Do not mark it paid manually; check the Razorpay dashboard."}), 400


@app.route("/webhooks/razorpay", methods=["POST"])
def razorpay_webhook():
    secret = os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()
    signature = request.headers.get("X-Razorpay-Signature", "")
    event_id = request.headers.get("X-Razorpay-Event-Id", "")
    raw = request.get_data()
    if not secret or not signature or not event_id:
        return jsonify({"error": "Webhook is not configured or required headers are missing."}), 400
    expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify({"error": "Invalid webhook signature."}), 400
    try:
        body = json.loads(raw.decode("utf-8"))
        event_type = str(body.get("event", "unknown"))
        if event_type == "payment.captured":
            entity = body.get("payload", {}).get("payment", {}).get("entity", {})
            order_id = entity.get("order_id")
            payment_id = entity.get("id")
            if order_id and payment_id:
                # Settle before recording event so a transient DB failure can be retried by Razorpay.
                settle_razorpay_order(str(order_id), str(payment_id))
        db.query("INSERT INTO gateway_webhook_events (gateway_event_id, event_type) VALUES (%s,%s)",
                 (event_id, event_type), commit=True)
    except IntegrityError:
        return jsonify({"status": "duplicate_ignored"}), 200
    except Exception:
        app.logger.exception("Could not process Razorpay webhook")
        return jsonify({"error": "Webhook processing failed; provider may retry."}), 500
    return jsonify({"status": "accepted"}), 200


@app.route("/audit")
@login_required("admin")
def audit_view():
    rows = db.query("""SELECT a.*, u.username FROM audit_logs a
                       LEFT JOIN users u ON u.id=a.actor_user_id
                       ORDER BY a.created_at DESC LIMIT 250""")
    for row in rows:
        try:
            row["details_pretty"] = json.dumps(json.loads(row.get("details") or "{}"), ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            row["details_pretty"] = str(row.get("details") or "—")
        row["action_label"] = row.get("action", "").replace("_", " ").title()
    return render_template("audit.html", audit_rows=rows)


# ---------------------------------------------------------------
# Attendance (admin)
# ---------------------------------------------------------------
@app.route("/attendance", methods=["GET", "POST"])
@login_required(("admin", "warden"))
def attendance():
    selected_date = request.args.get("date", str(date.today()))

    if request.method == "POST":
        att_date = request.form["date"]
        student_ids = request.form.getlist("student_id")
        statuses = request.form.getlist("status")
        for sid, st in zip(student_ids, statuses):
            eligible = db.query(
                "SELECT id FROM students WHERE id=%s AND (lifecycle_status IS NULL OR lifecycle_status<>'inactive')",
                (sid,), fetchone=True
            )
            if not eligible or st not in ("present", "absent"):
                continue
            db.query(
                """INSERT INTO attendance (student_id, date, status) VALUES (%s,%s,%s)
                   ON DUPLICATE KEY UPDATE status=%s""",
                (sid, att_date, st, st), commit=True,
            )
        flash("Attendance saved", "success")
        return redirect(url_for("attendance", date=att_date))

    all_students = db.query("SELECT * FROM students WHERE lifecycle_status IS NULL OR lifecycle_status<>'inactive' ORDER BY name")
    existing = db.query("SELECT student_id, status FROM attendance WHERE date=%s", (selected_date,))
    existing_map = {e["student_id"]: e["status"] for e in existing}
    return render_template(
        "attendance.html", students=all_students, existing_map=existing_map, selected_date=selected_date
    )


# ---------------------------------------------------------------
# Complaints
# ---------------------------------------------------------------
@app.route("/complaints", methods=["GET", "POST"])
@login_required()
def complaints():
    if request.method == "POST":
        if session["role"] == "student":
            student = db.query("SELECT id FROM students WHERE user_id=%s", (session["user_id"],), fetchone=True)
            db.query(
                "INSERT INTO complaints (student_id, title, description, priority) VALUES (%s,%s,%s,%s)",
                (student["id"], request.form["title"], request.form["description"], request.form["priority"]),
                commit=True,
            )
            audit("complaint_created", "complaint", db.query("SELECT id FROM complaints WHERE student_id=%s ORDER BY id DESC LIMIT 1", (student["id"],), fetchone=True)["id"], {"title": request.form["title"]})
            flash("Complaint submitted", "success")
        return redirect(url_for("complaints"))

    complaint_q = request.args.get("q", "").strip()
    if session["role"] == "admin":
        rows = db.query(
            """SELECT c.*, s.name AS student_name FROM complaints c
               JOIN students s ON c.student_id=s.id
               WHERE c.deleted_at IS NULL
                 AND (c.title LIKE %s OR c.status LIKE %s OR s.name LIKE %s)
               ORDER BY c.created_at DESC""", (f"%{complaint_q}%", f"%{complaint_q}%", f"%{complaint_q}%")
        )
    else:
        student = db.query("SELECT id FROM students WHERE user_id=%s", (session["user_id"],), fetchone=True)
        rows = db.query("SELECT * FROM complaints WHERE student_id=%s AND deleted_at IS NULL ORDER BY created_at DESC", (student["id"],)) if student else []
    return render_template("complaints.html", complaints=rows)


@app.route("/complaints/<int:cid>/status", methods=["POST"])
@login_required(("admin", "warden", "maintenance"))
def update_complaint_status(cid):
    new_status = request.form["status"]
    if new_status not in ("pending", "in_progress", "resolved"):
        flash("Invalid complaint status.", "danger")
        return redirect(url_for("complaints"))
    db.query("UPDATE complaints SET status=%s WHERE id=%s AND deleted_at IS NULL", (new_status, cid), commit=True)
    audit("complaint_status_changed", "complaint", cid, {"status": new_status})
    return redirect(url_for("complaints"))


# ---------------------------------------------------------------
# Visitors (admin)
# ---------------------------------------------------------------
@app.route("/visitors", methods=["GET", "POST"])
@login_required(("admin", "warden"))
def visitors():
    if request.method == "POST":
        db.query(
            "INSERT INTO visitors (visitor_name, purpose, student_id) VALUES (%s,%s,%s)",
            (request.form["visitor_name"], request.form["purpose"], request.form["student_id"]),
            commit=True,
        )
        audit("visitor_checked_in", "visitor", db.query("SELECT id FROM visitors ORDER BY id DESC LIMIT 1", fetchone=True)["id"], {"student_id": request.form["student_id"]})
        flash("Visitor checked in", "success")
        return redirect(url_for("visitors"))

    rows = db.query(
        """SELECT v.*, s.name AS student_name FROM visitors v
           JOIN students s ON v.student_id=s.id ORDER BY v.check_in DESC"""
    )
    all_students = db.query("SELECT id, name FROM students WHERE lifecycle_status IS NULL OR lifecycle_status<>'inactive' ORDER BY name")
    return render_template("visitors.html", visitors=rows, students=all_students)


@app.route("/visitors/<int:vid>/checkout", methods=["POST"])
@login_required(("admin", "warden"))
def checkout_visitor(vid):
    db.query("UPDATE visitors SET check_out=%s WHERE id=%s AND check_out IS NULL", (datetime.now(), vid), commit=True)
    audit("visitor_checked_out", "visitor", vid)
    return redirect(url_for("visitors"))


# ---------------------------------------------------------------
# Reports (admin)
# ---------------------------------------------------------------


# ---------------------------------------------------------------
# Leave requests and gate passes
# Included in the single fresh-install database schema.
# ---------------------------------------------------------------
@app.route("/inventory", methods=["GET", "POST"])
@login_required(("admin", "warden"))
def inventory():
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "floor":
                name = request.form.get("floor_name", "").strip()
                number = int(request.form.get("floor_number", "0"))
                building = request.form.get("building_name", "Main").strip() or "Main"
                if not name or number < 0: raise ValueError("Enter a floor name and valid floor number.")
                floor_id = db.query("INSERT INTO floors (floor_name,floor_number,building_name) VALUES (%s,%s,%s)", (name,number,building), commit=True)
                audit("floor_created", "floor", floor_id, {"name":name,"number":number,"building":building})
                flash("Floor added.", "success")
            elif action == "bed":
                room_id = int(request.form.get("room_id", "0")); bed_no = request.form.get("bed_number", "").strip()
                if room_id < 1 or not bed_no: raise ValueError("Choose a room and enter a bed number.")
                bed_id = db.query("INSERT INTO beds (room_id,bed_number) VALUES (%s,%s)", (room_id,bed_no), commit=True)
                audit("bed_created", "bed", bed_id, {"room_id":room_id,"bed_number":bed_no})
                flash("Bed added to inventory.", "success")
            else: raise ValueError("Unknown inventory action.")
        except ValueError as exc: flash(str(exc), "danger")
        except Exception:
            app.logger.exception("Inventory update failed")
            flash("Could not save inventory item. Check the database schema and duplicate floor/bed numbers.", "danger")
        return redirect(url_for("inventory"))
    floors = db.query("SELECT * FROM floors ORDER BY building_name,floor_number")
    beds = db.query("SELECT b.*,r.room_number FROM beds b JOIN rooms r ON r.id=b.room_id WHERE r.is_active=TRUE ORDER BY r.room_number,b.bed_number")
    rooms_list = db.query("SELECT id,room_number FROM rooms WHERE is_active=TRUE ORDER BY room_number")
    return render_template("inventory.html", floors=floors, beds=beds, rooms=rooms_list)



@app.route("/inventory/floors/<int:fid>/edit", methods=["POST"])
@login_required(("admin", "warden"))
def edit_floor(fid):
    name=request.form.get("floor_name","").strip(); building=request.form.get("building_name","Main").strip() or "Main"
    try:
        number=int(request.form.get("floor_number","-1")); status=request.form.get("status","active")
        if not name or number < 0 or status not in ("active","maintenance"): raise ValueError
        db.query("UPDATE floors SET floor_name=%s,floor_number=%s,building_name=%s,status=%s WHERE id=%s",(name,number,building,status,fid),commit=True)
        audit("floor_updated","floor",fid,{"name":name,"status":status}); flash("Floor updated.","success")
    except Exception: flash("Could not update floor. Check required fields and duplicate floor number.","danger")
    return redirect(url_for("inventory"))

@app.route("/inventory/floors/<int:fid>/delete", methods=["POST"])
@login_required("admin")
def delete_floor(fid):
    floor=db.query("SELECT id,floor_name,floor_number,building_name,status FROM floors WHERE id=%s",(fid,),fetchone=True)
    if not floor:
        flash("Floor not found.","warning")
    else:
        # Floors are currently standalone inventory records; rooms are not linked to floors.
        db.query("DELETE FROM floors WHERE id=%s",(fid,),commit=True)
        audit("floor_deleted","floor",fid,{"name":floor["floor_name"],"number":floor["floor_number"],"building":floor["building_name"],"status":floor["status"]})
        flash("Floor deleted.","success")
    return redirect(url_for("inventory"))

@app.route("/inventory/beds/<int:bid>/edit", methods=["POST"])
@login_required(("admin", "warden"))
def edit_bed(bid):
    number = request.form.get("bed_number", "").strip()
    status = request.form.get("status", "")
    room_raw = request.form.get("room_id", "").strip()
    try:
        room_id = int(room_raw)
    except (TypeError, ValueError):
        room_id = 0
    if not number or len(number) > 20 or room_id < 1 or status not in ("available", "blocked", "maintenance"):
        flash("Enter a valid room, bed number and status.", "danger")
        return redirect(url_for("inventory"))
    try:
        existing = db.query("SELECT id,room_id,bed_number,status FROM beds WHERE id=%s", (bid,), fetchone=True)
        room = db.query("SELECT id,room_number,is_active FROM rooms WHERE id=%s", (room_id,), fetchone=True)
        if not existing:
            flash("Bed not found.", "warning")
        elif not room or not room.get("is_active", True):
            flash("The selected room is not active.", "danger")
        else:
            db.query("UPDATE beds SET room_id=%s,bed_number=%s,status=%s WHERE id=%s", (room_id, number, status, bid), commit=True)
            audit("bed_updated", "bed", bid, {
                "old_room_id": existing["room_id"], "old_bed_number": existing["bed_number"],
                "old_status": existing["status"], "room_id": room_id, "bed_number": number, "status": status
            })
            flash("Bed updated successfully.", "success")
    except Exception:
        app.logger.exception("Bed update failed")
        flash("Could not update bed. The room/bed combination may already exist.", "danger")
    return redirect(url_for("inventory"))

@app.route("/inventory/beds/<int:bid>/delete", methods=["POST"])
@login_required("admin")
def delete_bed(bid):
    try:
        bed=db.query("SELECT id,room_id,bed_number,status FROM beds WHERE id=%s",(bid,),fetchone=True)
        if not bed:
            flash("Bed not found.","warning")
        else:
            db.query("DELETE FROM beds WHERE id=%s",(bid,),commit=True)
            audit("bed_deleted","bed",bid,{"room_id":bed["room_id"],"bed_number":bed["bed_number"],"status":bed["status"]})
            flash("Bed deleted.","success")
    except Exception:
        app.logger.exception("Bed deletion blocked or failed")
        flash("Bed could not be deleted because it may be linked to other records.","danger")
    return redirect(url_for("inventory"))

@app.route("/rooms/<int:room_id>/delete", methods=["POST"])
@login_required("admin")
def delete_room(room_id):
    """Remove an empty room without destroying historical allocation data."""
    conn = db.get_conn()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, room_number, is_active FROM rooms WHERE id=%s FOR UPDATE", (room_id,))
        room = cur.fetchone()
        if not room:
            raise ValueError("Room not found.")
        if not room.get("is_active", True):
            raise ValueError("Room is already removed.")

        cur.execute("SELECT id FROM allocations WHERE room_id=%s AND is_active=TRUE LIMIT 1", (room_id,))
        if cur.fetchone():
            raise ValueError("Room still has active students. Remove or reassign them first.")

        cur.execute("SELECT id FROM allocations WHERE room_id=%s LIMIT 1", (room_id,))
        has_history = cur.fetchone() is not None
        cur.execute("SELECT id FROM beds WHERE room_id=%s LIMIT 1", (room_id,))
        has_beds = cur.fetchone() is not None

        if has_history:
            # Keep the room row because allocation history references it. Hide it from operations.
            cur.execute("UPDATE rooms SET is_active=FALSE, occupied=0 WHERE id=%s", (room_id,))
            action = "room_archived"
        else:
            # No students and no history: safe hard delete. Beds can be removed with the room.
            if has_beds:
                cur.execute("DELETE FROM beds WHERE room_id=%s", (room_id,))
            cur.execute("DELETE FROM rooms WHERE id=%s", (room_id,))
            action = "room_deleted"
        conn.commit()
        audit(action, "room", room_id, {"room_number": room.get("room_number"), "had_history": has_history, "had_beds": has_beds})
        flash("Room removed successfully. Historical allocation data was preserved." if has_history else "Empty room deleted successfully.", "success")
    except ValueError as exc:
        conn.rollback()
        flash(str(exc), "warning")
    except Exception:
        conn.rollback()
        app.logger.exception("Room removal failed")
        flash("Room could not be removed. No changes were saved.", "danger")
    finally:
        if cur is not None:
            cur.close()
        conn.close()
    return redirect(url_for("rooms"))


@app.route("/leave", methods=["GET", "POST"])
@login_required(("admin", "warden", "student"))
def leave_requests():
    role = session.get("role")
    if request.method == "POST":
        if role != "student":
            flash("Only students can submit leave requests.", "danger")
            return redirect(url_for("leave_requests"))
        student = db.query("SELECT id FROM students WHERE user_id=%s", (session["user_id"],), fetchone=True)
        try:
            start = date.fromisoformat(request.form.get("start_date", ""))
            end = date.fromisoformat(request.form.get("end_date", ""))
            reason = request.form.get("reason", "").strip()
            if not student or end < start or not reason:
                raise ValueError("Check the dates and enter a reason.")
            db.query("INSERT INTO leave_requests (student_id,start_date,end_date,reason) VALUES (%s,%s,%s,%s)",
                     (student["id"], start, end, reason), commit=True)
            audit("leave_requested", "student", student["id"], {"start": str(start), "end": str(end)})
            flash("Leave request submitted.", "success")
        except ValueError as exc:
            flash(str(exc) or "Invalid dates.", "danger")
        except Exception:
            app.logger.exception("Leave request failed")
            flash("Could not submit leave request. Ensure the final database schema is installed.", "danger")
        return redirect(url_for("leave_requests"))
    if role == "student":
        student = db.query("SELECT id FROM students WHERE user_id=%s", (session["user_id"],), fetchone=True)
        rows = db.query("SELECT l.*,s.name FROM leave_requests l JOIN students s ON s.id=l.student_id WHERE l.student_id=%s AND l.deleted_at IS NULL ORDER BY l.created_at DESC", (student["id"],)) if student else []
    else:
        rows = db.query("SELECT l.*,s.name FROM leave_requests l JOIN students s ON s.id=l.student_id WHERE l.deleted_at IS NULL ORDER BY l.created_at DESC")
    return render_template("requests.html", kind="leave", rows=rows)

@app.route("/leave/<int:request_id>/review", methods=["POST"])
@login_required(("admin", "warden"))
def review_leave(request_id):
    status = request.form.get("status")
    if status not in ("approved", "rejected"):
        flash("Invalid decision.", "danger")
    else:
        db.query("UPDATE leave_requests SET status=%s, reviewed_by=%s, reviewed_at=NOW() WHERE id=%s AND status='pending' AND deleted_at IS NULL",
                 (status, session["user_id"], request_id), commit=True)
        audit("leave_" + status, "leave_request", request_id)
        flash("Leave request reviewed.", "success")
    return redirect(url_for("leave_requests"))

@app.route("/gate-passes", methods=["GET", "POST"])
@login_required(("admin", "warden", "student"))
def gate_passes():
    role = session.get("role")
    if request.method == "POST":
        if role != "student":
            flash("Only students can request a gate pass.", "danger")
            return redirect(url_for("gate_passes"))
        student = db.query("SELECT id FROM students WHERE user_id=%s", (session["user_id"],), fetchone=True)
        try:
            destination = request.form.get("destination", "").strip()
            reason = request.form.get("reason", "").strip()
            out_time = datetime.fromisoformat(request.form.get("out_time", ""))
            expected = datetime.fromisoformat(request.form.get("expected_return", ""))
            if not student or not destination or not reason or expected <= out_time:
                raise ValueError("Enter all details and a return time after departure.")
            db.query("INSERT INTO gate_passes (student_id,destination,reason,out_time,expected_return) VALUES (%s,%s,%s,%s,%s)",
                     (student["id"], destination, reason, out_time, expected), commit=True)
            audit("gate_pass_requested", "student", student["id"], {"destination": destination})
            flash("Gate pass request submitted.", "success")
        except ValueError as exc:
            flash(str(exc) or "Invalid date/time.", "danger")
        except Exception:
            app.logger.exception("Gate pass request failed")
            flash("Could not submit gate pass. Ensure the final database schema is installed.", "danger")
        return redirect(url_for("gate_passes"))
    if role == "student":
        student = db.query("SELECT id FROM students WHERE user_id=%s", (session["user_id"],), fetchone=True)
        rows = db.query("SELECT g.*,s.name FROM gate_passes g JOIN students s ON s.id=g.student_id WHERE g.student_id=%s AND g.deleted_at IS NULL ORDER BY g.created_at DESC", (student["id"],)) if student else []
    else:
        rows = db.query("SELECT g.*,s.name FROM gate_passes g JOIN students s ON s.id=g.student_id WHERE g.deleted_at IS NULL ORDER BY g.created_at DESC")
    return render_template("requests.html", kind="gate", rows=rows)

@app.route("/gate-passes/<int:pass_id>/review", methods=["POST"])
@login_required(("admin", "warden"))
def review_gate_pass(pass_id):
    status = request.form.get("status")
    if status not in ("approved", "rejected"):
        flash("Invalid decision.", "danger")
    else:
        db.query("UPDATE gate_passes SET status=%s, reviewed_by=%s, reviewed_at=NOW() WHERE id=%s AND status='pending' AND deleted_at IS NULL",
                 (status, session["user_id"], pass_id), commit=True)
        audit("gate_pass_" + status, "gate_pass", pass_id)
        flash("Gate pass reviewed.", "success")
    return redirect(url_for("gate_passes"))

@app.route("/gate-passes/<int:pass_id>/return", methods=["POST"])
@login_required(("admin", "warden"))
def gate_pass_return(pass_id):
    db.query("UPDATE gate_passes SET status='returned', actual_return=NOW() WHERE id=%s AND status='approved' AND deleted_at IS NULL", (pass_id,), commit=True)
    audit("gate_pass_returned", "gate_pass", pass_id)
    flash("Return recorded.", "success")
    return redirect(url_for("gate_passes"))



@app.route("/admin/leave/<int:request_id>/delete", methods=["POST"])
@login_required(("admin",))
def delete_leave_request(request_id):
    row = db.query("SELECT id,status FROM leave_requests WHERE id=%s", (request_id,), fetchone=True)
    if not row:
        flash("Leave request not found.", "warning")
    else:
        db.query("UPDATE leave_requests SET deleted_at=NOW(), status='cancelled' WHERE id=%s AND deleted_at IS NULL", (request_id,), commit=True)
        audit("leave_request_archived", "leave_request", request_id, {"previous_status": row["status"]})
        flash("Leave request archived. Historical information was preserved.", "success")
    return redirect(url_for("leave_requests"))

@app.route("/admin/gate-pass/<int:pass_id>/delete", methods=["POST"])
@login_required(("admin",))
def delete_gate_pass(pass_id):
    row = db.query("SELECT id,status FROM gate_passes WHERE id=%s", (pass_id,), fetchone=True)
    if not row:
        flash("Gate pass not found.", "warning")
    else:
        db.query("UPDATE gate_passes SET deleted_at=NOW(), status='cancelled' WHERE id=%s AND deleted_at IS NULL", (pass_id,), commit=True)
        audit("gate_pass_archived", "gate_pass", pass_id, {"previous_status": row["status"]})
        flash("Gate pass archived. Historical information was preserved.", "success")
    return redirect(url_for("gate_passes"))

@app.route("/admin/complaint/<int:cid>/delete", methods=["POST"])
@login_required(("admin",))
def delete_complaint(cid):
    row = db.query("SELECT id,status FROM complaints WHERE id=%s", (cid,), fetchone=True)
    if not row:
        flash("Complaint not found.", "warning")
    else:
        db.query("UPDATE complaints SET deleted_at=NOW(), status='resolved' WHERE id=%s AND deleted_at IS NULL", (cid,), commit=True)
        audit("complaint_archived", "complaint", cid, {"previous_status": row["status"]})
        flash("Complaint archived. Historical information was preserved.", "success")
    return redirect(url_for("complaints"))

@app.route("/fees/payments/<int:payment_id>/receipt")
@login_required(("admin", "accountant"))
def payment_receipt(payment_id):
    payment = db.query(
        """SELECT p.*, f.amount AS bill_amount, f.due_date, f.billing_month, f.bill_type,
                  s.name AS student_name, s.student_code, s.phone, s.email,
                  u.username AS voided_by_username
           FROM payments p
           JOIN fees f ON f.id=p.fee_id
           JOIN students s ON s.id=f.student_id
           LEFT JOIN users u ON u.id=p.voided_by
           WHERE p.id=%s""",
        (payment_id,), fetchone=True
    )
    if not payment:
        abort(404)
    return render_template("payment_receipt.html", payment=payment)

@app.route("/reports")
@login_required(("admin", "warden", "accountant"))
def reports():
    monthly_fees = db.query(
        """SELECT DATE_FORMAT(paid_on,'%Y-%m') month, SUM(amount_paid) total
           FROM payments WHERE voided_at IS NULL GROUP BY month ORDER BY month"""
    )
    attendance_summary = db.query(
        """SELECT s.name, SUM(a.status='present') present, SUM(a.status='absent') absent
           FROM students s LEFT JOIN attendance a ON s.id=a.student_id
           WHERE s.lifecycle_status IS NULL OR s.lifecycle_status<>'inactive'
           GROUP BY s.id ORDER BY s.name"""
    )
    complaint_report = db.query(
        "SELECT status, COUNT(*) c FROM complaints WHERE deleted_at IS NULL GROUP BY status"
    )
    return render_template(
        "reports.html",
        monthly_fees=monthly_fees,
        attendance_summary=attendance_summary,
        complaint_report=complaint_report,
    )



@app.route("/reports/export/<kind>")
@login_required(("admin", "warden", "accountant"))
def export_report(kind):
    if kind == "fees" and session.get("role") not in ("admin", "accountant"):
        abort(403)
    queries = {
        "occupancy": ("SELECT room_number, room_type, capacity, occupied FROM (SELECT r.room_number,r.room_type,r.capacity,COALESCE(a.n,0) occupied FROM rooms r LEFT JOIN (SELECT room_id,COUNT(*) n FROM allocations WHERE is_active=TRUE GROUP BY room_id) a ON a.room_id=r.id WHERE r.is_active=TRUE) x ORDER BY room_number", ()),
        "fees": ("SELECT s.name,f.amount,f.due_date,f.status FROM fees f JOIN students s ON s.id=f.student_id ORDER BY f.due_date", ()),
        "maintenance": ("SELECT title,priority,status,created_at FROM complaints ORDER BY created_at DESC", ()),
    }
    if kind not in queries:
        abort(404)
    rows = db.query(*queries[kind])
    output = io.StringIO()
    writer = csv.writer(output)
    if rows:
        writer.writerow(rows[0].keys())
        for row in rows: writer.writerow([row[k] for k in row.keys()])
    else:
        writer.writerow(["No records"])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename=smarthostel_{kind}.csv"
    return response

# ---------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template("db_error.html", error="The page you requested could not be found."), 404


@app.errorhandler(500)
def internal_error(error):
    app.logger.exception("Unhandled application error")
    return render_template("db_error.html", error="Something went wrong on the server. No financial transaction should be assumed successful unless the app confirmed it."), 500


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
