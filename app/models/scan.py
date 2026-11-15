"""Scan model — tracks each security scan run."""
from __future__ import annotations
import uuid
from datetime import datetime
from app import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    scan_uuid = db.Column(db.String(36), unique=True, nullable=False,
                          default=lambda: str(uuid.uuid4()))
    repository_id = db.Column(db.Integer, db.ForeignKey("repositories.id"), nullable=False)
    triggered_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    # status: 'pending' | 'running' | 'completed' | 'failed'
    trigger_type = db.Column(db.String(20), nullable=False, default="manual")
    # trigger_type: 'manual' | 'push' | 'pr' | 'scheduled' | 'webhook'
    branch = db.Column(db.String(100), nullable=True)
    commit_hash = db.Column(db.String(40), nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    security_score = db.Column(db.Integer, nullable=True)  # 0-100
    total_vulnerabilities = db.Column(db.Integer, nullable=False, default=0)
    critical_count = db.Column(db.Integer, nullable=False, default=0)
    high_count = db.Column(db.Integer, nullable=False, default=0)
    medium_count = db.Column(db.Integer, nullable=False, default=0)
    low_count = db.Column(db.Integer, nullable=False, default=0)
    secrets_count = db.Column(db.Integer, nullable=False, default=0)
    pipeline_status = db.Column(db.String(20), nullable=True)
    # pipeline_status: 'passed' | 'failed' | 'blocked'
    gate_decision = db.Column(db.String(20), nullable=True)
    # gate_decision: 'passed' | 'failed'
    gate_reasons = db.Column(db.Text, nullable=True)  # JSON string
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    vulnerabilities = db.relationship("Vulnerability", backref="scan", lazy="dynamic",
                                       foreign_keys="Vulnerability.scan_id")
    pipeline_runs = db.relationship("PipelineRun", backref="scan", lazy="dynamic",
                                     foreign_keys="PipelineRun.scan_id")
    triggered_by = db.relationship("User", foreign_keys=[triggered_by_id])

    @property
    def duration_display(self) -> str:
        if not self.duration_seconds:
            return "—"
        if self.duration_seconds < 60:
            return f"{self.duration_seconds}s"
        mins, secs = divmod(self.duration_seconds, 60)
        return f"{mins}m {secs}s"

    @property
    def status_badge_class(self) -> str:
        return {
            "pending": "secondary",
            "running": "primary",
            "completed": "success",
            "failed": "danger",
        }.get(self.status, "secondary")

    def to_dict(self) -> dict:
        import json
        return {
            "id": self.id,
            "scan_uuid": self.scan_uuid,
            "repository_id": self.repository_id,
            "status": self.status,
            "trigger_type": self.trigger_type,
            "branch": self.branch,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "security_score": self.security_score,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "secrets_count": self.secrets_count,
            "pipeline_status": self.pipeline_status,
            "gate_decision": self.gate_decision,
            "gate_reasons": json.loads(self.gate_reasons) if self.gate_reasons else [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Scan {self.scan_uuid[:8]} [{self.status}]>"
