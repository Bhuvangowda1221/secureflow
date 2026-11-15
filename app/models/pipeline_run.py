"""PipelineRun model — individual CI/CD stage records."""
from __future__ import annotations
from datetime import datetime
from app import db


class PipelineRun(db.Model):
    __tablename__ = "pipeline_runs"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    stage_name = db.Column(db.String(100), nullable=False)
    stage_order = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    # status: 'pending' | 'running' | 'passed' | 'failed' | 'skipped'
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    output_log = db.Column(db.Text, nullable=True)
    error_log = db.Column(db.Text, nullable=True)
    github_run_id = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    STAGE_ICONS = {
        "checkout": "fa-code-branch",
        "setup_python": "fa-python",
        "install_deps": "fa-box",
        "run_tests": "fa-vial",
        "bandit": "fa-shield-halved",
        "pip_audit": "fa-magnifying-glass",
        "gitleaks": "fa-key",
        "trivy_fs": "fa-folder-open",
        "build_docker": "fa-docker",
        "trivy_image": "fa-layer-group",
        "sonarqube": "fa-chart-bar",
        "security_gate": "fa-gate",
        "generate_reports": "fa-file-alt",
        "upload_artifacts": "fa-upload",
        "deploy": "fa-rocket",
    }

    @property
    def icon(self) -> str:
        return self.STAGE_ICONS.get(self.stage_name, "fa-circle")

    @property
    def duration_display(self) -> str:
        if not self.duration_seconds:
            return "—"
        if self.duration_seconds < 60:
            return f"{self.duration_seconds}s"
        mins, secs = divmod(self.duration_seconds, 60)
        return f"{mins}m {secs}s"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "stage_name": self.stage_name,
            "stage_order": self.stage_order,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "output_log": self.output_log,
            "error_log": self.error_log,
        }

    def __repr__(self) -> str:
        return f"<PipelineRun stage={self.stage_name} status={self.status}>"
