"""Repository model — connected GitHub repositories."""
from __future__ import annotations
from datetime import datetime
from app import db


class Repository(db.Model):
    __tablename__ = "repositories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(500), nullable=False, unique=True)
    description = db.Column(db.String(1000), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    github_id = db.Column(db.Integer, nullable=True)
    default_branch = db.Column(db.String(100), nullable=False, default="main")
    language = db.Column(db.String(100), nullable=True)
    is_private = db.Column(db.Boolean, nullable=False, default=False)
    last_scanned_at = db.Column(db.DateTime, nullable=True)
    security_score = db.Column(db.Integer, nullable=True)  # 0-100
    health_status = db.Column(db.String(20), nullable=False, default="unknown")
    # health_status: 'healthy' | 'at_risk' | 'critical' | 'unknown'
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    # Relationships
    scans = db.relationship("Scan", backref="repository", lazy="dynamic",
                            foreign_keys="Scan.repository_id")
    vulnerabilities = db.relationship("Vulnerability", backref="repository",
                                       lazy="dynamic",
                                       foreign_keys="Vulnerability.repository_id")

    @property
    def health_color(self) -> str:
        return {
            "healthy": "success",
            "at_risk": "warning",
            "critical": "danger",
            "unknown": "secondary",
        }.get(self.health_status, "secondary")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "owner_id": self.owner_id,
            "default_branch": self.default_branch,
            "language": self.language,
            "is_private": self.is_private,
            "last_scanned_at": self.last_scanned_at.isoformat() if self.last_scanned_at else None,
            "security_score": self.security_score,
            "health_status": self.health_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Repository {self.name}>"
