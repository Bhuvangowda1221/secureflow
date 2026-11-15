"""Reports, Policies, Admin blueprints."""
from __future__ import annotations
import os
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, send_file, abort)
from flask_login import login_required, current_user
from app import db
from app.models.security_policy import SecurityPolicy, SecurityReport
from app.models.scan import Scan
from app.models.repository import Repository
from app.models.user import User
from app.models.security_policy import AuditLog
from app.services.report_service import ReportService

# ── Reports ──────────────────────────────────────────────────────────────────
reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    if current_user.is_admin:
        # Admins see all reports
        reports = (SecurityReport.query
                   .order_by(SecurityReport.created_at.desc())
                   .all())
        scans = (Scan.query
                 .filter(Scan.status == "completed")
                 .order_by(Scan.created_at.desc())
                 .all())
    else:
        reports = (SecurityReport.query
                   .join(Repository)
                   .filter(Repository.owner_id == current_user.id)
                   .order_by(SecurityReport.created_at.desc())
                   .all())
        scans = (Scan.query.join(Repository)
                 .filter(Repository.owner_id == current_user.id,
                         Scan.status == "completed")
                 .order_by(Scan.created_at.desc())
                 .all())
    return render_template("reports/index.html",
                           reports=reports, scans=scans,
                           page_title="Security Reports")


@reports_bp.route("/generate/<int:scan_id>", methods=["POST"])
@login_required
def generate(scan_id):
    scan = db.get_or_404(Scan, scan_id)
    # Admin can generate for any scan; regular users only their own repos
    if not current_user.is_admin:
        if not scan.repository or scan.repository.owner_id != current_user.id:
            abort(403)
    report_type = request.form.get("report_type", "pdf")
    if report_type not in ("pdf", "json", "csv"):
        flash("Invalid report type.", "danger")
        return redirect(url_for("reports.index"))
    try:
        report = ReportService.generate(scan_id, current_user.id, report_type)
        flash(f"{report_type.upper()} report generated! Click Download to save it.", "success")
        return redirect(url_for("reports.index"))
    except Exception as e:
        flash(f"Report generation failed: {str(e)}", "danger")
        return redirect(url_for("reports.index"))


@reports_bp.route("/<int:report_id>/download")
@login_required
def download(report_id):
    report = db.get_or_404(SecurityReport, report_id)
    if report.repository.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    # Resolve to absolute path
    file_path = report.file_path
    if not os.path.isabs(file_path):
        from flask import current_app
        file_path = os.path.join(
            os.path.dirname(os.path.dirname(current_app.root_path)),
            file_path
        )
        # Fallback: try relative to CWD
        if not os.path.exists(file_path):
            file_path = os.path.abspath(report.file_path)
    if not os.path.exists(file_path):
        flash(f"Report file not found on disk. Please regenerate the report.", "danger")
        return redirect(url_for("reports.index"))
    mime_types = {"pdf": "application/pdf",
                  "json": "application/json", "csv": "text/csv"}
    return send_file(
        file_path,
        as_attachment=True,
        mimetype=mime_types.get(report.report_type, "application/octet-stream"),
        download_name=os.path.basename(file_path),
    )


# ── Policies ─────────────────────────────────────────────────────────────────
policies_bp = Blueprint("policies", __name__, url_prefix="/policies")


@policies_bp.route("/")
@login_required
def index():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))
    policies = SecurityPolicy.query.order_by(SecurityPolicy.id).all()
    return render_template("policies/index.html",
                           policies=policies, page_title="Security Policies")


@policies_bp.route("/<int:policy_id>/update", methods=["POST"])
@login_required
def update(policy_id):
    if not current_user.is_admin:
        abort(403)
    policy = db.get_or_404(SecurityPolicy, policy_id)
    policy.action = request.form.get("action", policy.action)
    policy.threshold = int(request.form.get("threshold", policy.threshold))
    policy.enabled = request.form.get("enabled") == "on"
    db.session.commit()
    flash(f"Policy '{policy.name}' updated.", "success")
    return redirect(url_for("policies.index"))


# ── Admin ─────────────────────────────────────────────────────────────────────
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin():
    if not current_user.is_admin:
        abort(403)


@admin_bp.route("/")
@login_required
def index():
    _require_admin()
    users = User.query.order_by(User.created_at.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all()
    total_repos = Repository.query.count()
    total_scans = Scan.query.count()
    return render_template(
        "admin/index.html",
        users=users, audit_logs=audit_logs,
        total_repos=total_repos, total_scans=total_scans,
        page_title="Admin Panel",
    )


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
def toggle_user(user_id):
    _require_admin()
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("Cannot deactivate your own account.", "warning")
        return redirect(url_for("admin.index"))
    user.is_active = not user.is_active
    db.session.commit()
    action = "activated" if user.is_active else "deactivated"
    flash(f"User '{user.username}' {action}.", "success")
    return redirect(url_for("admin.index"))
