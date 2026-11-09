# SmartHostel — Final Resume-Ready Release

A Flask + MySQL hostel-management platform with role-based operations, room/inventory workflows, monthly billing, audited payment corrections, optional Razorpay payments, CSRF protection, transaction-safe allocation/payment flows, and responsive UI.

## One-time fresh database setup

**This final release has ONE SQL file only:** `FRESH_DATABASE.sql`.

> ⚠️ `FRESH_DATABASE.sql` is the safe schema setup and does not drop an existing database. If you want a clean reset, back up first and use `RESET_DATABASE.sql` explicitly.

1. Open MySQL Workbench.
2. Open `FRESH_DATABASE.sql`.
3. Execute the complete file once.
4. Confirm that the result lists the expected SmartHostel tables.
5. Do not run any migration files; there are none in this final package.

## VS Code / Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python test_db.py
python -m compileall -q .
python smoke_test.py
python test_hardening.py
python app.py
```

Open `http://127.0.0.1:5000`.

On the first run, `/setup` creates the first administrator. The setup page is available only from the local machine and only while no admin exists. There is no hard-coded admin password.

## Database connection

The final package uses:

```text
DB_NAME=smarthostel_management
DB_HOST=127.0.0.1
DB_PORT=3307
```

If MySQL Workbench uses another port, put that exact port in `.env`.

## Fees architecture

- Each active student has a recurring `monthly_fee`.
- Monthly bills are identified by `student_id + billing_month`.
- A database unique key prevents duplicate student/month bills.
- Changing a student's monthly fee affects future bills; historical bills remain unchanged.
- Monthly generation is transactional and idempotent.
- Payments are checked against the remaining balance while the fee row is locked.
- Financial corrections use **void**, not destructive deletion.
- Voided payments remain visible in payment history and audit records but are excluded from collection totals.
- Dashboard totals recalculate from non-voided payments.
- Razorpay settlement is signature-verified and idempotent.

## Security / integrity

- CSRF validation for state-changing requests.
- Secure session cookie configuration.
- Security response headers.
- Password hashing with Werkzeug.
- Role-based route authorization.
- Parameterized MySQL queries.
- Transaction + row-lock protection for room allocation and fee payments.
- Audit logging for important administrative actions.
- Sensitive exports restricted by role.
- No application secrets are shipped in `.env`.
- Database constraints validate positive financial amounts and preserve referential integrity.

## Optional Razorpay

Razorpay is optional. Manual fee collection works without it.

Set these only in your private `.env` when you are ready:

```text
RAZORPAY_KEY_ID=
RAZORPAY_KEY_SECRET=
RAZORPAY_WEBHOOK_SECRET=
```

Use Razorpay Test Mode before production. Never put the secret in templates, JavaScript, Git, or the ZIP.

## Resume value

This project demonstrates:

- Flask MVC-style application structure
- MySQL relational modelling and foreign keys
- Role-based authorization
- Financial data integrity and auditability
- Transaction/concurrency handling
- Payment gateway verification
- CSRF/security hardening
- Responsive operational UI
- Automated smoke/static regression tests
- Production-oriented environment configuration
