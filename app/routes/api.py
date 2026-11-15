"""REST API Blueprint — JSON endpoints for dashboard, repos, scans, vulns."""
from __future__ import annotations
import json
import hashlib
import hmac
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
from app import db
from app.models.scan import Scan
from app.models.repository import Repository
from app.models.vulnerability import Vulnerability
from app.models.security_policy import (SecurityPolicy, SecurityReport,
                                         Notification)
from app.services.scan_service import ScanService

api_bp = Blueprint("api", __name__)


def _ok(data, status=200):
    return jsonify({"success": True, "data": data}), status


def _err(message, status=400):
    return jsonify({"success": False, "error": message}), status


# ── Health ────────────────────────────────────────────────────────────────────
@api_bp.route("/health")
def health():
    return _ok({"status": "healthy", "version": "1.0.0"})


# ── Dashboard ─────────────────────────────────────────────────────────────────
@api_bp.route("/dashboard/summary")
@login_required
def dashboard_summary():
    total_repos = Repository.query.filter_by(owner_id=current_user.id).count()
    total_scans = Scan.query.join(Repository).filter(
        Repository.owner_id == current_user.id).count()
    vulns_q = Vulnerability.query.join(Repository).filter(
        Repository.owner_id == current_user.id)
    repos = Repository.query.filter_by(owner_id=current_user.id).all()
    scores = [r.security_score for r in repos if r.security_score is not None]
    return _ok({
        "total_repos": total_repos,
        "total_scans": total_scans,
        "total_vulns": vulns_q.count(),
        "critical": vulns_q.filter(Vulnerability.severity == "critical").count(),
        "high": vulns_q.filter(Vulnerability.severity == "high").count(),
        "medium": vulns_q.filter(Vulnerability.severity == "medium").count(),
        "low": vulns_q.filter(Vulnerability.severity == "low").count(),
        "overall_score": round(sum(scores) / len(scores)) if scores else None,
    })


@api_bp.route("/dashboard/charts")
@login_required
def dashboard_charts():
    # Severity distribution
    vulns_q = Vulnerability.query.join(Repository).filter(
        Repository.owner_id == current_user.id)
    severity_dist = {
        "critical": vulns_q.filter(Vulnerability.severity == "critical").count(),
        "high": vulns_q.filter(Vulnerability.severity == "high").count(),
        "medium": vulns_q.filter(Vulnerability.severity == "medium").count(),
        "low": vulns_q.filter(Vulnerability.severity == "low").count(),
    }

    # Scan history (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    scans_last30 = (Scan.query.join(Repository)
                    .filter(Repository.owner_id == current_user.id,
                            Scan.created_at >= thirty_days_ago)
                    .order_by(Scan.created_at.asc())
                    .all())
    scan_labels = []
    scan_counts = []
    scores_over_time = []
    # Group by day
    from collections import defaultdict
    day_map = defaultdict(list)
    for s in scans_last30:
        day = s.created_at.strftime("%b %d")
        day_map[day].append(s)
    for day, day_scans in sorted(day_map.items()):
        scan_labels.append(day)
        scan_counts.append(len(day_scans))
        sc = [s.security_score for s in day_scans if s.security_score]
        scores_over_time.append(round(sum(sc) / len(sc)) if sc else 0)

    # Pipeline stats (last 30 days)
    pipeline_passed = (Scan.query.join(Repository)
                       .filter(Repository.owner_id == current_user.id,
                               Scan.gate_decision == "passed",
                               Scan.created_at >= thirty_days_ago).count())
    pipeline_failed = (Scan.query.join(Repository)
                       .filter(Repository.owner_id == current_user.id,
                               Scan.gate_decision == "failed",
                               Scan.created_at >= thirty_days_ago).count())

    # Scanner distribution
    scanner_dist = {}
    for scanner in ["bandit", "pip-audit", "gitleaks", "trivy", "sonarqube"]:
        scanner_dist[scanner] = (vulns_q
                                  .filter(Vulnerability.scanner == scanner)
                                  .count())

    return _ok({
        "severity_dist": severity_dist,
        "scan_history": {"labels": scan_labels, "counts": scan_counts},
        "scores_over_time": {"labels": scan_labels, "scores": scores_over_time},
        "pipeline_stats": {"passed": pipeline_passed, "failed": pipeline_failed},
        "scanner_dist": scanner_dist,
    })


# ── Repositories ──────────────────────────────────────────────────────────────
@api_bp.route("/repositories", methods=["GET"])
@login_required
def list_repos():
    repos = Repository.query.filter_by(owner_id=current_user.id).all()
    return _ok([r.to_dict() for r in repos])


@api_bp.route("/repositories", methods=["POST"])
@login_required
def add_repo():
    import re
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    pattern = re.compile(r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$')
    if not pattern.match(url):
        return _err("Invalid GitHub repository URL.", 400)
    if Repository.query.filter_by(url=url.removesuffix(".git")).first():
        return _err("Repository already connected.", 409)
    parts = url.removesuffix(".git").rstrip("/").split("/")
    repo = Repository(name=f"{parts[-2]}/{parts[-1]}", url=url.removesuffix(".git"),
                      owner_id=current_user.id)
    db.session.add(repo)
    db.session.commit()
    return _ok(repo.to_dict(), 201)


@api_bp.route("/repositories/<int:repo_id>", methods=["GET"])
@login_required
def get_repo(repo_id):
    repo = db.get_or_404(Repository, repo_id)
    if repo.owner_id != current_user.id and not current_user.is_admin:
        return _err("Forbidden.", 403)
    return _ok(repo.to_dict())


@api_bp.route("/repositories/<int:repo_id>", methods=["DELETE"])
@login_required
def delete_repo(repo_id):
    repo = db.get_or_404(Repository, repo_id)
    if repo.owner_id != current_user.id and not current_user.is_admin:
        return _err("Forbidden.", 403)
    db.session.delete(repo)
    db.session.commit()
    return _ok({"deleted": repo_id})


# ── Scans ─────────────────────────────────────────────────────────────────────
@api_bp.route("/scans", methods=["POST"])
@login_required
def trigger_scan():
    data = request.get_json() or {}
    repo_id = data.get("repository_id")
    if not repo_id:
        return _err("repository_id is required.", 400)
    repo = db.get_or_404(Repository, repo_id)
    if repo.owner_id != current_user.id and not current_user.is_admin:
        return _err("Forbidden.", 403)
    scan = ScanService.trigger_scan(
        repo_id=repo_id, user_id=current_user.id,
        trigger_type="manual", branch=data.get("branch", repo.default_branch),
        app=current_app._get_current_object(),
    )
    return _ok(scan.to_dict(), 202)


@api_bp.route("/scans", methods=["GET"])
@login_required
def list_scans():
    scans = (Scan.query.join(Repository)
             .filter(Repository.owner_id == current_user.id)
             .order_by(Scan.created_at.desc()).limit(50).all())
    return _ok([s.to_dict() for s in scans])


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    scan = db.get_or_404(Scan, scan_id)
    if scan.repository.owner_id != current_user.id and not current_user.is_admin:
        return _err("Forbidden.", 403)
    data = scan.to_dict()
    data["pipeline_stages"] = [s.to_dict() for s in scan.pipeline_runs.all()]
    return _ok(data)


@api_bp.route("/scans/<int:scan_id>/results", methods=["GET"])
@login_required
def scan_results(scan_id):
    scan = db.get_or_404(Scan, scan_id)
    if scan.repository.owner_id != current_user.id and not current_user.is_admin:
        return _err("Forbidden.", 403)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    data = scan.to_dict()
    data["vulnerabilities"] = [v.to_dict() for v in vulns]
    data["pipeline_stages"] = [s.to_dict() for s in scan.pipeline_runs.all()]
    return _ok(data)


# ── Vulnerabilities ───────────────────────────────────────────────────────────
@api_bp.route("/vulnerabilities", methods=["GET"])
@login_required
def list_vulns():
    q = Vulnerability.query.join(Repository).filter(
        Repository.owner_id == current_user.id)
    if request.args.get("severity"):
        q = q.filter(Vulnerability.severity == request.args["severity"])
    if request.args.get("scanner"):
        q = q.filter(Vulnerability.scanner == request.args["scanner"])
    if request.args.get("status"):
        q = q.filter(Vulnerability.status == request.args["status"])
    vulns = q.order_by(Vulnerability.created_at.desc()).limit(100).all()
    return _ok([v.to_dict() for v in vulns])


@api_bp.route("/vulnerabilities/<int:vuln_id>", methods=["GET"])
@login_required
def get_vuln(vuln_id):
    v = db.get_or_404(Vulnerability, vuln_id)
    if v.repository.owner_id != current_user.id and not current_user.is_admin:
        return _err("Forbidden.", 403)
    return _ok(v.to_dict())


@api_bp.route("/vulnerabilities/<int:vuln_id>", methods=["PATCH"])
@login_required
def update_vuln(vuln_id):
    v = db.get_or_404(Vulnerability, vuln_id)
    if v.repository.owner_id != current_user.id and not current_user.is_admin:
        return _err("Forbidden.", 403)
    data = request.get_json() or {}
    allowed_statuses = ("open", "resolved", "accepted", "false_positive")
    if "status" in data and data["status"] in allowed_statuses:
        v.status = data["status"]
        if data["status"] == "resolved":
            v.resolved_at = datetime.utcnow()
            v.resolved_by_id = current_user.id
    db.session.commit()
    return _ok(v.to_dict())


# ── Notifications ─────────────────────────────────────────────────────────────
@api_bp.route("/notifications", methods=["GET"])
@login_required
def list_notifications():
    notifs = (Notification.query
              .filter_by(user_id=current_user.id)
              .order_by(Notification.created_at.desc())
              .limit(20).all())
    unread = Notification.query.filter_by(
        user_id=current_user.id, is_read=False).count()
    return _ok({"notifications": [n.to_dict() for n in notifs],
                "unread_count": unread})


@api_bp.route("/notifications/<int:notif_id>/read", methods=["POST"])
@login_required
def mark_read(notif_id):
    n = db.get_or_404(Notification, notif_id)
    if n.user_id != current_user.id:
        return _err("Forbidden.", 403)
    n.is_read = True
    db.session.commit()
    return _ok({"read": True})


# ── Policies ──────────────────────────────────────────────────────────────────
@api_bp.route("/policies", methods=["GET"])
@login_required
def list_policies():
    policies = SecurityPolicy.query.all()
    return _ok([p.to_dict() for p in policies])


@api_bp.route("/policies/<int:policy_id>", methods=["PUT"])
@login_required
def update_policy(policy_id):
    if not current_user.is_admin:
        return _err("Admin only.", 403)
    p = db.get_or_404(SecurityPolicy, policy_id)
    data = request.get_json() or {}
    if "action" in data and data["action"] in ("block", "warn", "allow"):
        p.action = data["action"]
    if "threshold" in data:
        p.threshold = int(data["threshold"])
    if "enabled" in data:
        p.enabled = bool(data["enabled"])
    db.session.commit()
    return _ok(p.to_dict())


# ── Reports ───────────────────────────────────────────────────────────────────
@api_bp.route("/reports", methods=["GET"])
@login_required
def list_reports():
    rpts = (SecurityReport.query.join(Repository)
            .filter(Repository.owner_id == current_user.id)
            .order_by(SecurityReport.created_at.desc()).all())
    return _ok([r.to_dict() for r in rpts])


# ── GitHub Webhook ────────────────────────────────────────────────────────────
@api_bp.route("/github/webhook", methods=["POST"])
def github_webhook():
    """Receive GitHub push/PR webhooks and trigger scans."""
    secret = current_app.config.get("GITHUB_WEBHOOK_SECRET", "")
    if secret:
        sig = request.headers.get("X-Hub-Signature-256", "")
        body = request.get_data()
        expected = "sha256=" + hmac.new(
            secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return _err("Invalid signature.", 401)

    data = request.get_json() or {}
    repo_url = data.get("repository", {}).get("html_url", "")
    if not repo_url:
        return _ok({"message": "No repository in payload."})

    repo = Repository.query.filter_by(url=repo_url).first()
    if not repo:
        return _ok({"message": "Repository not connected to SecureFlow."})

    ScanService.trigger_scan(
        repo_id=repo.id,
        user_id=repo.owner_id,
        trigger_type="webhook",
        branch=data.get("ref", "").split("/")[-1] or repo.default_branch,
        app=current_app._get_current_object(),
    )
    return _ok({"message": "Scan triggered."})
