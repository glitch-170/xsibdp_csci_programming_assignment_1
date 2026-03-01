# XS IBDP Computer Science Programming Assignment #1

This repository implements a small Flask authentication system used for the assignment:
- Registration with server-side password policy and hashed password storage (bcrypt)
- Login with account lockout after repeated failed attempts
- SQLite database for persistent storage via SQLAlchemy
- Bootstrap-based frontend with flash messages and a client-side password strength meter

Quick start:
1. Create and activate a Python virtual environment.
2. Install dependencies: pip install -r requirements.txt
3. Run: python app.py
4. Open http://127.0.0.1:5000 in your browser.

Resources:
- Flask documentation: https://flask.palletsprojects.com/
- Flask-WTF: https://flask-wtf.readthedocs.io/
- Flask-Login: https://flask-login.readthedocs.io/
- Flask-Bcrypt: https://flask-bcrypt.readthedocs.io/
- SQLAlchemy: https://www.sqlalchemy.org/

Notes:
- Replace SECRET_KEY in app.py with a secure random value for production.
- This project demonstrates password hashing, basic account lockout, and separation of concerns suitable for the higher-grade criteria.
