"""
SecureFlow Flask Application Factory
"""
from __future__ import annotations

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_cors import CORS

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Load config
    if config is None:
        from config.config import get_config
        cfg = get_config()
        app.config.from_object(cfg)
        cfg.init_app(app)
    elif isinstance(config, dict):
        # Testing: direct dict override
        app.config.update(config)
    else:
        cfg = config
        app.config.from_object(cfg)
        if hasattr(cfg, "init_app"):
            cfg.init_app(app)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    CORS(app)

    # Flask-Login settings
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access SecureFlow."
    login_manager.login_message_category = "warning"

    with app.app_context():
        # Import ALL models so SQLAlchemy can resolve relationships
        from app.models.user import User  # noqa: F401
        from app.models.repository import Repository  # noqa: F401
        from app.models.pipeline_run import PipelineRun  # noqa: F401
        from app.models.scan import Scan  # noqa: F401
        from app.models.vulnerability import Vulnerability  # noqa: F401
        from app.models.security_policy import (  # noqa: F401
            SecurityPolicy, SecurityReport, Notification,
            AuditLog, ScanComparison,
        )

        # Register blueprints
        from app.routes.auth import auth_bp
        from app.routes.dashboard import dashboard_bp
        from app.routes.repositories import repos_bp
        from app.routes.scans import scans_bp
        from app.routes.vulnerabilities import vulns_bp
        from app.routes.reports import reports_bp
        from app.routes.policies import policies_bp
        from app.routes.admin import admin_bp
        from app.routes.api import api_bp

        app.register_blueprint(auth_bp)
        app.register_blueprint(dashboard_bp)
        app.register_blueprint(repos_bp)
        app.register_blueprint(scans_bp)
        app.register_blueprint(vulns_bp)
        app.register_blueprint(reports_bp)
        app.register_blueprint(policies_bp)
        app.register_blueprint(admin_bp)
        app.register_blueprint(api_bp, url_prefix="/api")

        # Create all tables
        db.create_all()

        # Seed admin user and default policies
        _seed_defaults(app)

    # Health check endpoint
    @app.route("/health")
    def health():
        return {"status": "healthy", "app": "SecureFlow", "version": "1.0.0"}, 200

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template
        return render_template("errors/403.html"), 403

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        from flask import render_template
        return render_template("errors/500.html"), 500

    return app


def _seed_defaults(app):
    """Create admin user and default security policies on first run."""
    from app.models.user import User
    from app.models.security_policy import SecurityPolicy

    # Create admin user
    admin_email = app.config.get("ADMIN_EMAIL", "admin@secureflow.local")
    admin_password = app.config.get("ADMIN_PASSWORD", "Admin@SecureFlow1")

    if not User.query.filter_by(email=admin_email).first():
        admin = User(
            username="admin",
            email=admin_email,
            role="admin",
            is_active=True,
        )
        admin.set_password(admin_password)
        db.session.add(admin)

    # Create default security policies
    default_policies = [
        {
            "name": "block_critical",
            "description": "Block deployment when critical vulnerabilities are detected",
            "severity": "critical",
            "action": "block",
            "threshold": 1,
            "enabled": True,
        },
        {
            "name": "block_secrets",
            "description": "Block deployment when exposed secrets are detected",
            "severity": "secret",
            "action": "block",
            "threshold": 1,
            "enabled": True,
        },
        {
            "name": "warn_high",
            "description": "Warn when high severity vulnerabilities are detected",
            "severity": "high",
            "action": "warn",
            "threshold": 1,
            "enabled": True,
        },
        {
            "name": "warn_medium",
            "description": "Warn when medium severity vulnerabilities are detected",
            "severity": "medium",
            "action": "warn",
            "threshold": 3,
            "enabled": True,
        },
    ]

    for policy_data in default_policies:
        if not SecurityPolicy.query.filter_by(name=policy_data["name"]).first():
            policy = SecurityPolicy(**policy_data)
            db.session.add(policy)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
