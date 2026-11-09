# SmartHostel — A→Z Security, Integrity & Resume Audit

## Executive result

The uploaded build was **not fully production-ready** despite already containing several useful hardening patches.
The largest functional gap was the Fees module: it had no enforced monthly billing lifecycle, no safe payment correction workflow, and could create duplicate bills for the same student/month.

This release adds the missing accounting workflow and strengthens several adjacent controls.

## Fixed in this release

### Critical / high-impact
1. **Monthly billing lifecycle**
   - Per-student recurring `monthly_fee`.
   - Explicit billing month on every generated/one-off bill.
   - One generation run per month with a database uniqueness guard.
   - Future monthly fee changes do not rewrite historical invoices.
   - Generation is transactional: no half-generated month.

2. **Duplicate monthly bills**
   - Application-level student + billing-month duplicate check.
   - Monthly generation is idempotency-protected by `monthly_billing_runs`.
   - Recommended database unique key is documented for already-populated databases.

3. **Payment correction**
   - Added admin-only payment voiding with mandatory reason.
   - Voided payments remain visible in history.
   - Voided payments are excluded from collected totals and fee balances.
   - Fee status is recalculated after correction.
   - Correction is audited with actor, payment, amount and reason.

4. **Dashboard/accounting correctness**
   - Collection totals exclude voided payments.
   - Outstanding totals exclude voided payments.
   - Overdue amount is no longer incorrectly reported as all outstanding dues.

5. **Payment concurrency**
   - Existing row-locking for manual collection retained.
   - Payment correction also locks the payment/fee state before recalculation.
   - Razorpay settlement continues to lock the gateway order and fee.

6. **Student creation atomicity**
   - User account + student profile are now created in one transaction, preventing orphan login accounts if the second insert fails.

7. **Sensitive export scope**
   - Bulk student CSV export is admin-only.
   - Financial report export is restricted to admin/accountant.

8. **Security headers**
   - Existing CSRF/session protections retained.
   - Added Permissions-Policy.
   - HSTS is emitted on HTTPS responses.

9. **Application startup**
   - All Flask routes are registered before the `app.run()` block, fixing the previous route-registration ordering bug.

## Important existing protections verified

- CSRF validation on POST/PUT/PATCH/DELETE.
- Logout is POST-only.
- Strong SECRET_KEY is required.
- Debug is disabled by default.
- Secure/HttpOnly/SameSite session settings exist.
- Student self-registration is not exposed.
- Archived students cannot receive new allocations/collections.
- Room allocation uses transactional row locking.
- Razorpay browser verification uses provider signature verification.
- Razorpay webhook uses HMAC signature + event-id idempotency.
- Raw database errors are not intentionally shown to users.

## Remaining / recommended production backlog

These are deliberately documented rather than falsely marked complete:

### High
- **Login brute-force/rate limiting:** not implemented as a distributed, database-backed control.
- **Initial-admin setup race:** setup should use a one-time installation lock/table for multi-process deployments.
- **Razorpay end-to-end live verification:** requires merchant test credentials and a reachable HTTPS webhook.
- **Existing duplicate billing data:** inspect and resolve duplicates before adding the optional hard database unique key.
- **Financial refunds:** payment voiding is implemented; gateway refund/reversal workflow is not yet implemented.
- **Database backups/restore drills:** application code cannot guarantee operational backups.

### Medium
- Complaint/leave/gate-pass records still have hard-delete admin actions; consider soft-delete retention for full auditability.
- Input length/range validation can be expanded consistently across every operational form.
- Login/password policy can be strengthened with password history, MFA and lockout/rate-limit controls.
- Pagination should be added to large students/visitors/requests/payment-history tables.
- Bed-level allocation is present as inventory but is not fully integrated with the legacy room-level allocation model.
- Floors exist independently from rooms in the current lifecycle model.
- Automated integration tests against a real MySQL test database are still required.

## Resume-level engineering story

This project can now be described around:
- Transaction-safe hostel operations.
- Role-based access control and CSRF protection.
- Monthly invoice generation with idempotency/concurrency controls.
- Auditable financial correction workflow.
- Payment gateway verification and webhook idempotency.
- Lifecycle-aware student archiving.
- Database-backed operational dashboards.
- Responsive role-specific UI.
- Automated static verification and documented migration strategy.

## Acceptance checklist

### Fees
- [ ] Set monthly fee for student.
- [ ] Generate current month.
- [ ] Generate same month again → blocked.
- [ ] Change monthly fee → only future bills use the new amount.
- [ ] Record full payment → bill leaves dues.
- [ ] Record partial payment → balance is exact.
- [ ] Void payment → collection and balance immediately recalculate.
- [ ] Void same payment twice → blocked.
- [ ] Two concurrent payments cannot over-collect.
- [ ] Historical bill remains after new month starts.

### Security
- [ ] CSRF on every state-changing browser request.
- [ ] Student cannot see another student's complaints/requests/dashboard.
- [ ] Accountant cannot void financial history.
- [ ] Warden cannot export the full student CSV.
- [ ] Warden cannot export the financial report.
- [ ] Production uses HTTPS + secure cookies.
- [ ] Secrets are supplied through environment configuration.

