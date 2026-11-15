"""
Auth routes — registration, login, logout.
"""
from __future__ import annotations
from datetime import datetime
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, session)
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from app.models.security_policy import AuditLog

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _log_audit(user_id, action, ip=None):
    log = AuditLog(user_id=user_id, action=action,
                   resource_type="auth",
                   ip_address=ip or request.remote_addr)
    db.session.add(log)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        if not email or not password:
            flash("Email and password are required.", "danger")
            return render_template("auth/login.html")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "danger")
            _log_audit(None, f"Failed login attempt for email: {email}")
            return render_template("auth/login.html")

        if not user.is_active:
            flash("Your account has been deactivated. Contact an administrator.", "warning")
            return render_template("auth/login.html")

        login_user(user, remember=remember)
        user.last_login = datetime.utcnow()
        db.session.commit()
        _log_audit(user.id, f"User logged in: {user.email}")

        next_page = request.args.get("next")
        if next_page and next_page.startswith("/"):
            return redirect(next_page)
        return redirect(url_for("dashboard.index"))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not email or "@" not in email:
            errors.append("Please enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        if User.query.filter_by(email=email).first():
            errors.append("An account with this email already exists.")
        if User.query.filter_by(username=username).first():
            errors.append("This username is already taken.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template("auth/register.html",
                                   username=username, email=email)

        user = User(username=username, email=email, role="user", is_active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        _log_audit(user.id, f"New user registered: {user.email}")
        flash("Account created! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    _log_audit(current_user.id, f"User logged out: {current_user.email}")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
