"""Scan management routes."""
from __future__ import annotations
import json
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.scan import Scan
from app.models.repository import Repository
from app.models.vulnerability import Vulnerability
from app.models.security_policy import ScanComparison
from app.services.risk_score_service import RiskScoreService

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")


@scans_bp.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    repo_id = request.args.get("repo_id", type=int)
    status = request.args.get("status", "")

    query = (Scan.query.join(Repository)
             .filter(Repository.owner_id == current_user.id))
    if repo_id:
        query = query.filter(Scan.repository_id == repo_id)
    if status:
        query = query.filter(Scan.status == status)

    scans = query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)

    repos = Repository.query.filter_by(owner_id=current_user.id).all()
    return render_template("scans/index.html",
                           scans=scans, repos=repos,
                           selected_repo=repo_id, selected_status=status,
                           page_title="Scan History")


@scans_bp.route("/<int:scan_id>")
@login_required
def detail(scan_id):
    scan = db.get_or_404(Scan, scan_id)
    repo = scan.repository
    if repo.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("scans.index"))

    pipeline_stages = scan.pipeline_runs.all()
    vulns = (Vulnerability.query
             .filter_by(scan_id=scan_id)
             .order_by(Vulnerability.severity)
             .all())

    gate_reasons = []
    if scan.gate_reasons:
        try:
            gate_reasons = json.loads(scan.gate_reasons)
        except json.JSONDecodeError:
            gate_reasons = [scan.gate_reasons]

    # Score breakdown
    score_data = None
    if scan.security_score is not None:
        score_data = RiskScoreService.calculate(
            critical=scan.critical_count,
            high=scan.high_count,
            medium=scan.medium_count,
            low=scan.low_count,
            secrets=scan.secrets_count,
        )

    return render_template(
        "scans/detail.html",
        scan=scan,
        repo=repo,
        pipeline_stages=pipeline_stages,
        vulns=vulns,
        gate_reasons=gate_reasons,
        score_data=score_data,
        page_title=f"Scan #{scan.id}",
    )


@scans_bp.route("/compare", methods=["GET", "POST"])
@login_required
def compare():
    repos = Repository.query.filter_by(owner_id=current_user.id).all()
    all_scans = (Scan.query.join(Repository)
                 .filter(Repository.owner_id == current_user.id,
                         Scan.status == "completed")
                 .order_by(Scan.created_at.desc())
                 .all())

    comparison = None
    baseline = None
    target = None

    if request.method == "POST":
        baseline_id = request.form.get("baseline_id", type=int)
        target_id = request.form.get("target_id", type=int)

        if not baseline_id or not target_id or baseline_id == target_id:
            flash("Please select two different scans to compare.", "warning")
        else:
            baseline = db.get_or_404(Scan, baseline_id)
            target = db.get_or_404(Scan, target_id)

            score_delta = (target.security_score or 0) - (baseline.security_score or 0)
            vuln_delta = target.total_vulnerabilities - baseline.total_vulnerabilities

            comparison = {
                "score_delta": score_delta,
                "vuln_delta": vuln_delta,
                "baseline": baseline,
                "target": target,
                "improved": score_delta > 0,
                "critical_delta": target.critical_count - baseline.critical_count,
                "high_delta": target.high_count - baseline.high_count,
                "medium_delta": target.medium_count - baseline.medium_count,
                "low_delta": target.low_count - baseline.low_count,
            }

    return render_template(
        "scans/compare.html",
        all_scans=all_scans,
        comparison=comparison,
        baseline=baseline,
        target=target,
        page_title="Compare Scans",
    )
