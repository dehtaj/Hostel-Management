# SmartHostel Floors & Beds UI Patch — Execution Steps

## Important: existing data is preserved
This patch does **not** require any SQL migration and does **not** run DROP/DELETE/TRUNCATE against the database.

Do NOT run `FRESH_DATABASE.sql` for this patch if you want to keep the data currently in `smarthostel_management`.

## 1. Stop SmartHostel
In the terminal running Flask, press `Ctrl+C`.

## 2. Back up the current project folder
Make a copy of your current SmartHostel project folder before replacing the application files.

## 3. Extract this ZIP
Extract the ZIP to a new folder.

## 4. Keep your database settings
The included `.env` is configured for the current local setup:
- Host: `127.0.0.1`
- Port: `3307`
- User: `root`
- Database: `smarthostel_management`

If your existing project already has a working `.env`, keep that working file.

## 5. Do NOT execute SQL
Do not run `FRESH_DATABASE.sql`, old migrations, DROP DATABASE, or DELETE statements as part of this UI patch.

## 6. Install/refresh Python packages
Open PowerShell in the extracted project folder:

```powershell
.venv\Scripts\activate
pip install -r requirements.txt
```

## 7. Optional safe code check

```powershell
python -m compileall -q .
```

## 8. Start the application

```powershell
python app.py
```

Open:

`http://127.0.0.1:5000`

## 9. Check Floors & Beds
Open **Floors & Beds**.

Existing records should still be present. Each floor/bed now has a clean **Edit** button instead of permanently displayed input fields.

### Floor edit
Edit:
- Building
- Floor number
- Floor name
- Status

### Bed edit
Edit:
- Room
- Bed number
- Status

Only the record you explicitly save is updated.

## 10. Do not test with Delete
Because you asked to preserve saved data, use **Edit** only while verifying the patch. No delete operation is needed.
