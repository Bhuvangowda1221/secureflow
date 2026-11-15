"""Repository management routes."""
from __future__ import annotations
import re
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, jsonify)
from flask_login import login_required, current_user
from app import db
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.services.scan_service import ScanService
from app.services.github_service import GitHubService
from flask import current_app

repos_bp = Blueprint("repositories", __name__, url_prefix="/repositories")

GITHUB_URL_PATTERN = re.compile(
    r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$'
)


@repos_bp.route("/")
@login_required
def index():
    repos = (Repository.query
             .filter_by(owner_id=current_user.id)
             .order_by(Repository.created_at.desc())
             .all())
    return render_template("repositories/index.html",
                           repos=repos, page_title="Repositories")


@repos_bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        url = request.form.get("url", "").strip().rstrip("/")
        description = request.form.get("description", "").strip()

        if not url:
            flash("Repository URL is required.", "danger")
            return render_template("repositories/add.html", page_title="Add Repository")

        if not GITHUB_URL_PATTERN.match(url):
            flash("Please enter a valid GitHub repository URL "
                  "(e.g. https://github.com/owner/repo).", "danger")
            return render_template("repositories/add.html", url=url,
                                   description=description, page_title="Add Repository")

        # Normalize URL (remove .git suffix)
        clean_url = url.removesuffix(".git")

        if Repository.query.filter_by(url=clean_url).first():
            flash("This repository is already connected.", "warning")
            return redirect(url_for("repositories.index"))

        # Extract owner/name from URL
        parts = clean_url.rstrip("/").split("/")
        repo_name = f"{parts[-2]}/{parts[-1]}"

        # Try fetching GitHub metadata
        github_token = current_app.config.get("GITHUB_TOKEN", "")
        gh = GitHubService(github_token)
        try:
            info = gh.get_repo_info(parts[-2], parts[-1])
            language = info.get("language")
            default_branch = info.get("default_branch", "main")
            is_private = info.get("private", False)
            github_id = info.get("id")
            if not description:
                description = info.get("description") or ""
        except Exception:
            language = None
            default_branch = "main"
            is_private = False
            github_id = None

        repo = Repository(
            name=repo_name,
            url=clean_url,
            description=description,
            owner_id=current_user.id,
            github_id=github_id,
            default_branch=default_branch,
            language=language,
            is_private=is_private,
        )
        db.session.add(repo)
        db.session.commit()
        flash(f"Repository '{repo_name}' connected successfully!", "success")
        return redirect(url_for("repositories.detail", repo_id=repo.id))

    return render_template("repositories/add.html", page_title="Add Repository")


@repos_bp.route("/<int:repo_id>")
@login_required
def detail(repo_id):
    repo = db.get_or_404(Repository, repo_id)
    if repo.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("repositories.index"))

    scans = (Scan.query.filter_by(repository_id=repo_id)
             .order_by(Scan.created_at.desc()).limit(20).all())
    recent_vulns = (Vulnerability.query
                    .filter_by(repository_id=repo_id, status="open")
                    .order_by(Vulnerability.created_at.desc())
                    .limit(10).all())
    critical = Vulnerability.query.filter_by(
        repository_id=repo_id, severity="critical", status="open").count()
    high = Vulnerability.query.filter_by(
        repository_id=repo_id, severity="high", status="open").count()
    medium = Vulnerability.query.filter_by(
        repository_id=repo_id, severity="medium", status="open").count()
    low = Vulnerability.query.filter_by(
        repository_id=repo_id, severity="low", status="open").count()

    return render_template(
        "repositories/detail.html",
        repo=repo, scans=scans, recent_vulns=recent_vulns,
        critical=critical, high=high, medium=medium, low=low,
        page_title=repo.name,
    )


@repos_bp.route("/<int:repo_id>/scan", methods=["POST"])
@login_required
def trigger_scan(repo_id):
    repo = db.get_or_404(Repository, repo_id)
    if repo.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("repositories.index"))

    scan = ScanService.trigger_scan(
        repo_id=repo_id,
        user_id=current_user.id,
        trigger_type="manual",
        branch=repo.default_branch,
        app=current_app._get_current_object(),
    )
    flash(f"Scan #{scan.id} started for {repo.name}!", "success")
    return redirect(url_for("scans.detail", scan_id=scan.id))


@repos_bp.route("/<int:repo_id>/delete", methods=["POST"])
@login_required
def delete(repo_id):
    repo = db.get_or_404(Repository, repo_id)
    if repo.owner_id != current_user.id and not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for("repositories.index"))
    name = repo.name
    db.session.delete(repo)
    db.session.commit()
    flash(f"Repository '{name}' removed.", "info")
    return redirect(url_for("repositories.index"))
