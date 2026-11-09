# SmartHostel A-Z Final Change Log

## Financial integrity
- Monthly billing is keyed by `(student_id, billing_month)`.
- Monthly generation is idempotent and concurrency-safe: an existing billing run is locked and re-used so later runs can fill newly eligible students instead of incorrectly refusing the entire month.
- One-off bills can have `billing_month = NULL`, preventing the monthly unique key from blocking legitimate multiple one-off charges.
- Payment collection locks the fee row before calculating the balance.
- Payment voiding uses the same fee-first lock order, reducing deadlock risk under concurrent collection/correction requests.
- Voided payments are retained for audit history and excluded from collection/balance calculations.
- Historical monthly bills are not rewritten when a student's recurring fee changes.

## Database integrity
- Fresh schema includes `monthly_fee`, `billing_month`, payment correction fields, monthly billing runs, supporting indexes and the student/month unique key.
- `FRESH_DATABASE.sql` repairs common existing-database states, including the `voided_reason` -> `void_reason` naming mismatch.
- Existing databases should inspect duplicate student/month bills before enabling the unique index.

## Security
- CSRF protection for state-changing requests.
- Role-based financial correction permissions.
- Parameterized SQL throughout the application.
- Secure password hashing and session cookie controls.
- Security response headers.
- Razorpay settlement remains server-verified and idempotent.

## Resume-ready engineering points
- Transactional financial state transitions.
- Idempotent monthly job semantics.
- Database-level uniqueness for accounting periods.
- Audit-preserving financial corrections rather than destructive deletes.
- Concurrency-aware row locking.
- Backward-compatible database upgrade path.
- Automated regression/static verification.
