# SmartHostel Security Hardening

This build includes the critical security/integrity patches applied during the hardening pass.

## Required deployment configuration

1. Copy `.env.example` to `.env`.
2. Set a unique `SECRET_KEY` with at least 32 random characters.
3. Set a unique `(removed)` before first-admin setup.
4. Set real database credentials; do not use the credentials from any development copy.
5. Keep `FLASK_DEBUG=0` in production.
6. Keep `COOKIE_SECURE=1` when serving over HTTPS. For local plain-HTTP development only, set it to `0`.
7. If Razorpay is enabled, configure its key and webhook secrets separately.

## Critical fixes

- Added server-side CSRF protection for all state-changing requests. Razorpay webhooks are exempt because they use provider signature verification; Razorpay browser requests send the CSRF token in a header.
- Changed logout from GET to CSRF-protected POST.
- Removed the real `.env` from the distributable package. Secrets must be supplied through the deployment environment.
- Application startup now fails closed if `SECRET_KEY` is missing or shorter than 32 characters.
- Production-safe defaults: debug disabled and secure session cookies enabled by default.
- Manual fee payment now locks the fee row and records the payment plus fee-status update in one database transaction, preventing concurrent overpayment races.
- Room vacating now updates the allocation and room occupancy in one transaction.
- Added basic security response headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
- Replaced user-visible raw database exception messages with generic errors while retaining server-side logging.

## Verification performed

- Python `compileall` completed successfully.
- Every POST HTML form was checked to contain exactly one CSRF token.
- `.env` was removed from the deliverable; only `.env.example` remains.
- Debug defaults and the development secret fallback were checked.

A full runtime integration test requires the project's Python dependencies and a test database. The packaging environment could not download missing Python packages because outbound package-network access was unavailable.


## Monthly billing + financial correction hardening

- Added per-student recurring monthly fee configuration.
- Added explicit billing month to invoices.
- Added transactional/idempotent monthly bill generation guarded by a unique billing-run month.
- Added admin-only payment voiding with mandatory correction reason and retained audit metadata.
- Collection, outstanding and report totals exclude voided payments.
- Historical invoices are not rewritten when a student's recurring monthly fee changes.
- Added offline regression checks in `test_hardening.py`.
- Apply `FRESH_DATABASE.sql` after the previous migrations.
