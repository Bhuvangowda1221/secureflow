"""Dashboard routes — main statistics and overview."""
from __future__ import annotations
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models.scan import Scan
from app.models.repository import Repository
from app.models.vulnerability import Vulnerability
from app.models.security_policy import Notification

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("auth.login"))


@dashboard_bp.route("/dashboard")
@login_required
def index():
    # ── Stats ───────────────────────────────────────────────────────────────
    total_repos = Repository.query.filter_by(owner_id=current_user.id).count()
    total_scans = Scan.query.join(Repository).filter(
        Repository.owner_id == current_user.id).count()

    # Vulnerability counts across all scans for this user
    vulns_q = (Vulnerability.query
               .join(Repository)
               .filter(Repository.owner_id == current_user.id))
    total_vulns = vulns_q.count()
    critical_count = vulns_q.filter(Vulnerability.severity == "critical").count()
    high_count = vulns_q.filter(Vulnerability.severity == "high").count()
    medium_count = vulns_q.filter(Vulnerability.severity == "medium").count()
    low_count = vulns_q.filter(Vulnerability.severity == "low").count()

    # Pipeline stats
    scans_q = Scan.query.join(Repository).filter(
        Repository.owner_id == current_user.id,
        Scan.status == "completed")
    successful_pipelines = scans_q.filter(Scan.gate_decision == "passed").count()
    failed_pipelines = scans_q.filter(Scan.gate_decision == "failed").count()

    # Overall security score (average of latest scan per repo)
    repos = Repository.query.filter_by(owner_id=current_user.id).all()
    scores = [r.security_score for r in repos if r.security_score is not None]
    overall_score = round(sum(scores) / len(scores)) if scores else None

    stats = {
        "total_repos": total_repos,
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "successful_pipelines": successful_pipelines,
        "failed_pipelines": failed_pipelines,
        "overall_score": overall_score,
    }

    # Recent scans
    recent_scans = (Scan.query
                    .join(Repository)
                    .filter(Repository.owner_id == current_user.id)
                    .order_by(Scan.created_at.desc())
                    .limit(10)
                    .all())

    # Recent vulnerabilities
    recent_vulns = (Vulnerability.query
                    .join(Repository)
                    .filter(Repository.owner_id == current_user.id,
                            Vulnerability.status == "open")
                    .order_by(Vulnerability.created_at.desc())
                    .limit(8)
                    .all())

    # Repository health list
    repo_health = (Repository.query
                   .filter_by(owner_id=current_user.id)
                   .order_by(Repository.security_score.asc().nullslast())
                   .all())

    # Unread notifications count
    unread_count = Notification.query.filter_by(
        user_id=current_user.id, is_read=False).count()

    return render_template(
        "dashboard/index.html",
        stats=stats,
        recent_scans=recent_scans,
        recent_vulns=recent_vulns,
        repo_health=repo_health,
        unread_count=unread_count,
        page_title="Dashboard",
    )
