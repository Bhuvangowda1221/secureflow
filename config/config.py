"""
SecureFlow Configuration Module
Loads settings from environment variables with safe defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if it exists
BASE_DIR = Path(__file__).resolve().parent.parent
env_file = BASE_DIR / ".env"
if env_file.exists():
    load_dotenv(env_file)
else:
    load_dotenv(BASE_DIR / ".env.example")


class Config:
    """Base configuration shared by all environments."""

    # ── Flask Core ────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get(
        "SECRET_KEY", "dev-secret-key-change-in-production-please"
    )
    FLASK_ENV: str = os.environ.get("FLASK_ENV", "development")

    # ── Database ──────────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'secureflow.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # ── CSRF ──────────────────────────────────────────────────────────────────
    WTF_CSRF_ENABLED: bool = os.environ.get("WTF_CSRF_ENABLED", "True") == "True"
    WTF_CSRF_SECRET_KEY: str = os.environ.get(
        "WTF_CSRF_SECRET_KEY", SECRET_KEY + "-csrf"
    )

    # ── Session Security ──────────────────────────────────────────────────────
    SESSION_COOKIE_SECURE: bool = (
        os.environ.get("SESSION_COOKIE_SECURE", "False") == "True"
    )
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: int = 3600  # 1 hour

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATELIMIT_DEFAULT: str = os.environ.get(
        "RATELIMIT_DEFAULT", "200 per day;50 per hour"
    )
    RATELIMIT_STORAGE_URL: str = "memory://"

    # ── GitHub Integration ────────────────────────────────────────────────────
    GITHUB_TOKEN: str = os.environ.get("GITHUB_TOKEN", "")
    GITHUB_WEBHOOK_SECRET: str = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    GITHUB_API_BASE: str = "https://api.github.com"

    # ── SonarQube ─────────────────────────────────────────────────────────────
    SONARQUBE_URL: str = os.environ.get("SONARQUBE_URL", "http://localhost:9000")
    SONARQUBE_TOKEN: str = os.environ.get("SONARQUBE_TOKEN", "")
    SONARQUBE_PROJECT_KEY: str = os.environ.get("SONARQUBE_PROJECT_KEY", "secureflow")

    # ── Scanner Paths ─────────────────────────────────────────────────────────
    BANDIT_PATH: str = os.environ.get("BANDIT_PATH", "bandit")
    GITLEAKS_PATH: str = os.environ.get("GITLEAKS_PATH", "gitleaks")
    TRIVY_PATH: str = os.environ.get("TRIVY_PATH", "trivy")
    PIP_AUDIT_PATH: str = os.environ.get("PIP_AUDIT_PATH", "pip-audit")

    # ── Application Directories ───────────────────────────────────────────────
    SCAN_WORKSPACE: Path = Path(
        os.environ.get("SCAN_WORKSPACE", str(BASE_DIR / "scan_workspace"))
    )
    REPORTS_DIR: Path = Path(
        os.environ.get("REPORTS_DIR", str(BASE_DIR / "reports"))
    )
    MAX_CONCURRENT_SCANS: int = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))

    # ── Admin Bootstrap ───────────────────────────────────────────────────────
    ADMIN_EMAIL: str = os.environ.get("ADMIN_EMAIL", "admin@secureflow.local")
    ADMIN_PASSWORD: str = os.environ.get("ADMIN_PASSWORD", "Admin@SecureFlow1")

    # ── Flask Port ────────────────────────────────────────────────────────────
    FLASK_PORT: int = int(os.environ.get("FLASK_PORT", "5000"))

    @classmethod
    def init_app(cls, app):
        """Create required directories on startup."""
        cls.SCAN_WORKSPACE.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (BASE_DIR / "instance").mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config() -> Config:
    """Return the appropriate config class based on FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
