"""Vulnerability management routes."""
from __future__ import annotations
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.vulnerability import Vulnerability
from app.models.repository import Repository
from app.models.security_policy import AuditLog

vulns_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")


@vulns_bp.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "")
    scanner = request.args.get("scanner", "")
    repo_id = request.args.get("repo_id", type=int)
    status = request.args.get("status", "open")

    query = (Vulnerability.query.join(Repository)
             .filter(Repository.owner_id == current_user.id))

    if search:
        query = query.filter(Vulnerability.title.ilike(f"%{search}%"))
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if scanner:
        query = query.filter(Vulnerability.scanner == scanner)
    if repo_id:
        query = query.filter(Vulnerability.repository_id == repo_id)
    if status:
        query = query.filter(Vulnerability.status == status)

    vulns = query.order_by(Vulnerability.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False)

    repos = Repository.query.filter_by(owner_id=current_user.id).all()
    return render_template(
        "vulnerabilities/index.html",
        vulns=vulns, repos=repos,
        search=search, severity=severity,
        scanner=scanner, selected_repo=repo_id, status=status,
        page_title="Vulnerabilities",
    )


@vulns_bp.route("/<int:vuln_id>")
@login_required
def detail(vuln_id):
    vuln = db.get_or_404(Vulnerability, vuln_id)
    if vuln.repository.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("vulnerabilities.index"))
    return render_template("vulnerabilities/detail.html",
                           vuln=vuln, page_title=vuln.title[:60])


@vulns_bp.route("/<int:vuln_id>/resolve", methods=["POST"])
@login_required
def resolve(vuln_id):
    vuln = db.get_or_404(Vulnerability, vuln_id)
    if vuln.repository.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("vulnerabilities.index"))
    vuln.status = "resolved"
    vuln.resolved_at = datetime.utcnow()
    vuln.resolved_by_id = current_user.id
    log = AuditLog(user_id=current_user.id, action=f"Resolved vulnerability {vuln_id}",
                   resource_type="vulnerability", resource_id=vuln_id)
    db.session.add(log)
    db.session.commit()
    flash("Vulnerability marked as resolved.", "success")
    return redirect(request.referrer or url_for("vulnerabilities.index"))


@vulns_bp.route("/<int:vuln_id>/accept", methods=["POST"])
@login_required
def accept(vuln_id):
    vuln = db.get_or_404(Vulnerability, vuln_id)
    if vuln.repository.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("vulnerabilities.index"))
    vuln.status = "accepted"
    vuln.resolved_by_id = current_user.id
    db.session.commit()
    flash("Vulnerability risk accepted.", "info")
    return redirect(request.referrer or url_for("vulnerabilities.index"))


@vulns_bp.route("/<int:vuln_id>/false-positive", methods=["POST"])
@login_required
def mark_false_positive(vuln_id):
    vuln = db.get_or_404(Vulnerability, vuln_id)
    if vuln.repository.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("vulnerabilities.index"))
    vuln.status = "false_positive"
    vuln.resolved_by_id = current_user.id
    db.session.commit()
    flash("Vulnerability marked as false positive.", "info")
    return redirect(request.referrer or url_for("vulnerabilities.index"))
