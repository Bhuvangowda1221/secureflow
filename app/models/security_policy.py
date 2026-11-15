"""Security Policy model — configurable deployment gate rules."""
from __future__ import annotations
from datetime import datetime
from app import db


class SecurityPolicy(db.Model):
    __tablename__ = "security_policies"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(500), nullable=False, default="")
    severity = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(20), nullable=False, default="warn")
    # action: 'block' | 'warn' | 'allow'
    threshold = db.Column(db.Integer, nullable=False, default=1)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "action": self.action,
            "threshold": self.threshold,
            "enabled": self.enabled,
        }

    def __repr__(self) -> str:
        return f"<SecurityPolicy {self.name} [{self.action}]>"


class SecurityReport(db.Model):
    __tablename__ = "security_reports"

    id = db.Column(db.Integer, primary_key=True)
    report_uuid = db.Column(db.String(36), unique=True, nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    repository_id = db.Column(db.Integer, db.ForeignKey("repositories.id"), nullable=False)
    generated_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    report_type = db.Column(db.String(20), nullable=False)  # 'pdf' | 'json' | 'csv'
    file_path = db.Column(db.String(500), nullable=False)
    file_size_bytes = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    scan = db.relationship("Scan", foreign_keys=[scan_id])
    repository = db.relationship("Repository", foreign_keys=[repository_id])
    generated_by = db.relationship("User", foreign_keys=[generated_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "report_uuid": self.report_uuid,
            "scan_id": self.scan_id,
            "repository_id": self.repository_id,
            "report_type": self.report_type,
            "file_size_bytes": self.file_size_bytes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False, default="info")
    severity = db.Column(db.String(20), nullable=False, default="info")
    # severity: 'danger' | 'warning' | 'success' | 'info'
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    related_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    related_repo_id = db.Column(db.Integer, db.ForeignKey("repositories.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type,
            "severity": self.severity,
            "is_read": self.is_read,
            "related_scan_id": self.related_scan_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(200), nullable=False)
    resource_type = db.Column(db.String(100), nullable=True)
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "details": self.details,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanComparison(db.Model):
    __tablename__ = "scan_comparisons"

    id = db.Column(db.Integer, primary_key=True)
    baseline_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    target_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    score_delta = db.Column(db.Integer, nullable=True)
    vuln_delta = db.Column(db.Integer, nullable=True)
    new_vulnerabilities = db.Column(db.Integer, nullable=False, default=0)
    fixed_vulnerabilities = db.Column(db.Integer, nullable=False, default=0)
    comparison_data = db.Column(db.Text, nullable=True)  # JSON
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    baseline_scan = db.relationship("Scan", foreign_keys=[baseline_scan_id])
    target_scan = db.relationship("Scan", foreign_keys=[target_scan_id])
