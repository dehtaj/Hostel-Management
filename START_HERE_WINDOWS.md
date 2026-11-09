# SmartHostel — Start Here (Windows / VS Code)

## Fresh-install path

1. Extract the ZIP and open the `smartfinal` folder in VS Code.
2. Create the environment:
   `py -m venv .venv`
3. Activate it:
   `\.venv\Scripts\Activate.ps1`
4. Install packages:
   `python -m pip install -r requirements.txt`
5. In MySQL Workbench, create/select the database you intend to use.
6. Execute `FRESH_DATABASE.sql` once against that **new/empty database**.
7. Copy `.env.example` to `.env` and set DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and a private SECRET_KEY.
8. Run `python test_db.py`.
9. Run `python test_hardening.py`.
10. Run `python smoke_test.py`.
11. Run `python app.py`.
12. Open `http://127.0.0.1:5000/setup` and create the first admin.

## Existing-data safety

- Do not run `RESET_DATABASE.sql` unless you intentionally want a destructive reset.
- Keep a MySQL Workbench export of any existing database before changing databases.
- This release does not silently migrate or delete an existing database.
- If you need existing data moved into the new schema, do that as a separate verified migration; do not overwrite the old database first.

## Local MySQL

The sample configuration supports MySQL on port `3307`, but always use the port shown by MySQL Workbench (`SELECT @@port;`).

## Finance

The Fees & Payments page is designed around an immutable bill + payment ledger:
- monthly bills are idempotent and duplicate-protected;
- one-time bills are separate from monthly bills;
- active payments have receipt numbers;
- UPI/bank/card collections require a transaction/reference number;
- payments are corrected by admin-only voiding, never hard-deleted;
- printable receipts are available from Recent Payments;
- monthly fee changes affect future bills only.
