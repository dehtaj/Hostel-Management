# Protect existing SmartHostel data before installing the fresh database

The safe schema file does not drop databases. **Do not run it against an old populated schema expecting it to migrate that data.** Back up old data first, then create a new empty database or use `RESET_DATABASE.sql` only after verifying the backup.

## Windows / MySQL Workbench

1. Open MySQL Workbench and connect to the same MySQL instance used by SmartHostel.
2. Export the existing `smarthostel_management` database with **Server → Data Export**.
3. Select **Dump Structure and Data**, include all tables, and save the `.sql` dump somewhere outside this project folder.
4. Verify the dump file exists before dropping the old database.
5. Only then run `FRESH_DATABASE.sql` for the clean installation.

## Command-line alternative

If `mysqldump` is installed:

```powershell
mysqldump -h localhost -P 3307 -u root -p --single-transaction --routines --triggers smarthostel_management > smarthostel_backup.sql
```

Use the actual values from `.env` if your host, port, user, or database name differ.

## Important accounting behavior

- Existing payments are **never hard-deleted by the Fees & Payments UI**.
- A correction uses **Void payment**, records who corrected it and why, and keeps the original payment row for audit/history.
- Existing monthly bills are not overwritten when a new monthly billing run is repeated.
- Changing a student's monthly fee affects bills generated after the change; previously issued bills keep their original amount.
