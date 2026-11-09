# SmartHostel Premium UI — VS Code & SQL Guide

## What changed

- Unified premium visual language across the shared admin/staff/student experience.
- Consistent 42px primary controls and 36px compact controls.
- Responsive navigation and layouts for laptop, tablet and phone widths.
- Premium indigo/violet accent, neutral surfaces, semantic success/warning/danger states.
- Cleaner tables, cards, forms, alerts, modals and empty states.
- Student dashboard now uses the same design system.
- Student logout uses the protected POST flow from the shared shell.

## VS Code steps

### 1. Extract and open

Extract the ZIP, then in VS Code choose **File → Open Folder** and select the project folder.

### 2. Open the terminal

Use **Terminal → New Terminal**.

### 3. Create a virtual environment

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Command Prompt:

```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Configure `.env`

Copy `.env.example` to `.env` and enter your own MySQL and payment credentials. Do not commit `.env`.

### 5. Database

The Premium UI itself needs **no SQL execution**.

For a fresh install, execute `FRESH_DATABASE.sql` in MySQL Workbench.
For an existing install, execute `FRESH_DATABASE.sql` once.

Optional monthly-fee metadata is provided as:

`FRESH_DATABASE.sql`

Run it only if you want the database to store a billing month for fee records.

### 6. Start

```powershell
python app.py
```

Then open the Flask address shown in the terminal.

### 7. UI test

In Chrome press `F12`, then **Toggle device toolbar**. Test at approximately 390px, 768px and 1366px widths.

Check every page for:

- equal button heights
- no horizontal page overflow
- tables scrolling inside their containers
- readable headings and labels
- usable forms on mobile
- visible focus states
- navigation remaining accessible

## SQL rule

Do not use Python to modify the database. Use the provided `.sql` files in MySQL Workbench or the MySQL CLI. Python is only used to start/test the Flask application.
