# SmartHostel Final Setup

## Fresh install — one SQL file

1. Back up any old data you need.
2. Open MySQL Workbench.
3. Open **`FRESH_DATABASE.sql`**.
4. Execute the **entire file once**.
5. It deletes the old `hostel_management` and `smarthostel_management` databases and creates a clean `smarthostel_management` database with the complete application schema.
6. There are **no migration files** in this final package.
7. Copy `.env.example` to `.env` and enter your MySQL password.
8. Generate fresh `SECRET_KEY` and `(removed)` values.
9. Install dependencies and run `python app.py`.
10. Open `/setup` and create your administrator.

## Important

`FRESH_DATABASE.sql` does not drop databases. Still, run it only against a new/empty database because its CREATE TABLE statements expect the fresh schema.
