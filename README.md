Capstone: SQL Injection and XSS Prevention

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
