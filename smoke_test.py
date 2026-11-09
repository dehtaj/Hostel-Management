"""Offline smoke checks for SmartHostel. No MySQL connection is required."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parent
required = ["app.py", "db.py", "FRESH_DATABASE.sql", "templates/base.html", "templates/rooms.html", "templates/students.html", "static/css/style.css"]
missing = [p for p in required if not (ROOT / p).exists()]
if missing:
    raise SystemExit("Missing required files: " + ", ".join(missing))

env = Environment(loader=FileSystemLoader(ROOT / "templates"), undefined=StrictUndefined)
for template in ("base.html", "rooms.html", "students.html", "dashboard.html"):
    env.get_template(template)

source = (ROOT / "app.py").read_text(encoding="utf-8")
for marker in ("remove_student_from_room", "health", "student_archived"):
    if marker not in source:
        raise SystemExit(f"Expected application marker missing: {marker}")

print("PASS: file, template, and application smoke checks")
