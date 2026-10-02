from functools import wraps

import pyotp
from flask import flash, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import execute, fetch_one


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)


def create_user(name, email, password):
    secret = pyotp.random_base32()
    user_id = execute(
        """
        INSERT INTO users (name, email, password_hash, role, totp_secret, two_factor_enabled)
        VALUES (%s, %s, %s, 'student', %s, FALSE)
        """,
        (name.strip(), email.strip().lower(), hash_password(password), secret),
    )
    return user_id, secret


def get_user_by_email(email):
    return fetch_one("SELECT * FROM users WHERE email = %s", (email.strip().lower(),))


def get_user_by_id(user_id):
    return fetch_one("SELECT * FROM users WHERE id = %s", (user_id,))


def verify_totp(secret, token):
    return pyotp.TOTP(secret).verify(token, valid_window=1)


def current_user():
    user_id = session.get("user_id")
    return get_user_by_id(user_id) if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user["role"] not in roles:
                flash("Access denied by role-based access control.", "danger")
                return redirect(url_for("student_dashboard" if user else "login"))
            return view(*args, **kwargs)

        return wrapped

    return decorator
