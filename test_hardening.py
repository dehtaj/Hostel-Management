"""Static regression checks for the hardened SmartHostel release."""
from pathlib import Path
import ast
import re

ROOT = Path(__file__).resolve().parent
APP = (ROOT / "app.py").read_text(encoding="utf-8")
SCHEMA = (ROOT / "FRESH_DATABASE.sql").read_text(encoding="utf-8")
FEES = (ROOT / "templates" / "fees.html").read_text(encoding="utf-8")

# Syntax must compile.
ast.parse(APP)

required_app_markers = [
    'monthly_billing_runs',
    'billing_month',
    'void_payment',
    'voided_at IS NULL',
    'monthly_fee',
    'payment_voided',
    'Strict-Transport-Security',
    'failed_login_attempts',
    'locked_until',
    'request.remote_addr not in ("127.0.0.1", "::1")',
]
for marker in required_app_markers:
    assert marker in APP, f"Missing application hardening marker: {marker}"

assert not (ROOT / 'migrations').exists(), 'Legacy migration directory should not ship in the final one-file database package.'
assert 'ADMIN_SETUP_KEY' not in APP
assert 'setup_key' not in (ROOT / 'templates' / 'setup.html').read_text(encoding='utf-8')

required_schema_markers = [
    'monthly_fee DECIMAL(10,2)',
    'billing_month DATE',
    'voided_at DATETIME',
    'receipt_no VARCHAR(40)',
    'CREATE TABLE monthly_fee_history',
    'due_day TINYINT UNSIGNED',
    'void_reason VARCHAR(255)',
    'CREATE TABLE monthly_billing_runs',
    'UNIQUE KEY uq_monthly_billing_month',
    'UNIQUE KEY uq_fee_student_month',
    'CREATE TABLE audit_logs',
    'CREATE TABLE payment_orders',
    'CREATE TABLE gateway_webhook_events',
    'failed_login_attempts INT NOT NULL DEFAULT 0',
]
for marker in required_schema_markers:
    assert marker in SCHEMA, f"Missing schema marker: {marker}"

required_ui_markers = [
    'Generate bills for this month',
    'update_monthly_fee',
    'void_payment',
    'Reason (required)',
    'RECEIPTS',
]
for marker in required_ui_markers:
    assert marker in FEES, f"Missing Fees UI marker: {marker}"

# Every state-changing route must have the CSRF middleware in the source.
assert 'def protect_state_changing_requests' in APP
assert 'X-CSRF-Token' in APP

# The application entry point must be last so all routes are registered.
main_pos = APP.rfind('if __name__ == "__main__":')
assert main_pos > APP.find('@app.route("/reports/export/<kind>")')

# Sensitive exports are scoped.
assert '@login_required("admin")\ndef bulk_export_students' in APP
assert 'if kind == "fees" and session.get("role") not in ("admin", "accountant")' in APP


required_finance_markers = [
    'payment_reference VARCHAR(100)',
    "s.lifecycle_status='active'",
    "One-time bills do not use a billing month",
    'def payment_receipt',
    'deleted_at DATETIME NULL',
    'payment_reference',
]
for marker in required_finance_markers:
    assert marker in (APP + SCHEMA), f"Missing finance hardening marker: {marker}"

print("PASS: hardened SmartHostel static regression checks")
