Patient Management System (Flask, SQLite) - Extended
===================================================

This updated package adds:
- CSV import/export for patients and notes.
- Pagination, searching, and gender filter on patient listing.
- Registration flow with email verification token (SMTP or console fallback).
- Improved security headers via Flask-Talisman and environment SECRET_KEY support.

Quick start:
1. Create a virtual environment:
   python -m venv venv
   source venv/bin/activate   (Linux/macOS) or venv\Scripts\activate (Windows)

2. Install requirements:
   pip install -r requirements.txt

3. Initialize the database and create sample users:
   python init_db.py

   Default sample accounts created:
   - doctor1 / Password123 (role: doctor)
   - nurse1  / Password123  (role: nurse)
   - admin   / AdminPass123 (role: admin)

4. (Optional) Configure email sending by setting environment vars:
   - MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_USE_TLS

   If not configured, verification links will be printed to the server console.

5. Run the app:
   python app.py
   Open http://127.0.0.1:5000 in your browser.

Production notes:
- Set SECRET_KEY environment variable instead of using the default.
- Run behind a real WSGI server (gunicorn/uWSGI) and terminate TLS at a reverse proxy (nginx).
- Configure MAIL_* environment variables to enable real email delivery.
- Consider adding a 'confirmed' flag on users and blocking access until verified.
