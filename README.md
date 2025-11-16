# Capstone: SQL Injection and XSS Prevention

A minimal Flask project demonstrating practical defenses for SQL Injection (SQLi) and Cross-Site Scripting (XSS), plus basic authentication and role-based access control (RBAC). This repository was created as a hands-on capstone to identify vulnerabilities, apply fixes, and verify protections using automated tests.

## Project highlights
- Secure user model with password hashing.
- Authentication using Flask-Login and a simple RBAC decorator for admin-only pages.
- Input validation with WTForms and CSRF protection via Flask-WTF.
- Data access via SQLAlchemy ORM to avoid string-concatenated SQL.
- Templates use Jinja2 auto-escaping to prevent XSS.
- Pytest tests simulate SQLi and XSS payloads to verify defenses.

## Files
- `app.py` — Main Flask application (user model, auth, search endpoint, RBAC decorator).
- `templates/` — Jinja2 templates (`index.html`, `login.html`, `register.html`, `search.html`, `admin.html`).
- `tests/test_security.py` — Pytest tests for SQLi and XSS attempts.
- `requirements.txt` — Python dependencies.
- `VULNERABILITY_SUMMARY.md` — Short report of findings and fixes.

## Setup (Windows / PowerShell)
1. Make sure Python 3.8+ is installed and available on PATH.
2. Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r .\\requirements.txt
```

3. Initialize the database and start the app:

```powershell
# create DB and run
python app.py
```

The app will run on http://127.0.0.1:5000 by default.

## Running tests
From the project root (with the venv active) run:

```powershell
python -m pytest -q
```

Tests include:
- `test_sql_injection_search` — attempts SQL injection through the `/search` query parameter and asserts it does not expose all users.
- `test_xss_user_display_escaped` — creates a user with a script tag in the username and checks the rendered output is escaped.

## Security decisions and rationale
- SQL Injection: Using SQLAlchemy ORM (and its parameter binding) avoids manual SQL string composition and prevents classic SQLi.
- XSS: Jinja2 auto-escapes variables by default; templates do not call `|safe` on user content.
- Input validation: WTForms enforces length and character whitelist for the username to reduce malicious inputs.
- CSRF: Flask-WTF is enabled to protect form endpoints from CSRF attacks.
- Authentication: Passwords are hashed with Werkzeug's recommended methods; Flask-Login manages sessions.

This is a minimal Flask app demonstrating secure input handling, role-based access control, and tests for SQL injection and XSS.

Files:
- `app.py` - Flask application with user model, auth, and a search endpoint.
- `templates/` - Jinja2 templates (auto-escaped by default).
- `tests/test_security.py` - pytest tests that exercise SQLi and XSS attempts.

How to run:
1. Create a virtual environment and install dependencies from `requirements.txt`.
2. Run `python app.py` to start the server.
3. Run `pytest -q` to run the tests.

Notes: This is a teaching skeleton. Change `SECRET_KEY` and DB for production.

