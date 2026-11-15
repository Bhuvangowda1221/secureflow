# SecureFlow — DevSecOps Pipeline Platform

<div align="center">

![SecureFlow Banner](https://img.shields.io/badge/SecureFlow-DevSecOps%20Platform-58a6ff?style=for-the-badge&logo=shield&logoColor=white)

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1.1-000000?style=flat&logo=flask)](https://flask.palletsprojects.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-red?style=flat)](https://sqlalchemy.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

**Detect Early. Secure Always. Deploy Confidently.**

*An intelligent DevSecOps automation platform that integrates security scanning, vulnerability tracking, and deployment protection into your CI/CD pipeline.*

</div>

---

## Overview

SecureFlow is a full-stack DevSecOps platform built for the subject **Fundamentals of DevOps**. It provides automated security analysis of Python codebases by running multiple security scanners, tracking vulnerabilities, enforcing configurable security gate policies, and generating professional reports — all from a modern dark-themed web dashboard.

### Key Features

| Feature | Description |
|---------|-------------|
| **15-Stage CI/CD Pipeline** | Automated checkout → tests → SAST → SCA → secrets → container → gate → deploy |
| **Multi-Scanner Integration** | Bandit (SAST), pip-audit (SCA), Gitleaks (secrets), Trivy (containers), SonarQube |
| **Security Gate** | Policy-driven deployment blocker — block on critical/secrets, warn on high/medium |
| **Risk Score Engine** | Weighted 0–100 security score with penalty algorithm and trend tracking |
| **Vulnerability Tracking** | Full lifecycle: detect → review → resolve/accept/false-positive |
| **Report Generation** | PDF, JSON, and CSV reports with one click |
| **REST API** | Full JSON API for CI/CD integration and external tooling |
| **GitHub Actions Pipeline** | 8-stage workflow with Bandit, pip-audit, Gitleaks, Trivy |

---

## Architecture

```
secure_flow/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── models/                  # SQLAlchemy models
│   │   ├── user.py              # User + authentication
│   │   ├── repository.py        # GitHub repositories
│   │   ├── scan.py              # Scan sessions
│   │   ├── pipeline_run.py      # 15-stage pipeline runs
│   │   ├── vulnerability.py     # Vulnerability findings
│   │   └── security_policy.py   # Policies, reports, audit logs
│   ├── routes/                  # Flask blueprints
│   │   ├── auth.py              # /auth — login/register
│   │   ├── dashboard.py         # /dashboard
│   │   ├── repositories.py      # /repositories
│   │   ├── scans.py             # /scans
│   │   ├── vulnerabilities.py   # /vulnerabilities
│   │   ├── reports.py           # /reports + policies_bp + admin_bp
│   │   └── api.py               # /api — full REST API
│   ├── scanners/                # Security scanner integrations
│   │   ├── bandit_scanner.py    # Python SAST (Bandit)
│   │   ├── pip_audit_scanner.py # Dependency CVE scan
│   │   ├── gitleaks_scanner.py  # Secret detection
│   │   ├── trivy_scanner.py     # Container/filesystem scan
│   │   └── sonarqube_scanner.py # Code quality + SonarQube
│   ├── services/
│   │   ├── scan_service.py      # 15-stage pipeline orchestrator
│   │   ├── risk_score_service.py # Weighted score algorithm
│   │   ├── report_service.py    # PDF/JSON/CSV generation
│   │   └── github_service.py    # GitHub API integration
│   ├── security/
│   │   └── gate.py              # Security gate engine
│   ├── templates/               # Jinja2 dark-theme templates
│   └── static/                  # CSS + JavaScript
│       ├── css/main.css
│       └── js/{main,dashboard}.js
├── config/config.py             # Environment configuration
├── tests/                       # Pytest test suite (45+ tests)
├── sample-app/
│   ├── vulnerable/app.py        # Demo: intentionally vulnerable
│   └── secure/app.py            # Demo: secure implementation
├── .github/workflows/
│   └── devsecops.yml            # 8-stage GitHub Actions pipeline
├── Dockerfile                   # Production multi-stage build
├── docker-compose.yml           # App + SonarQube
└── requirements.txt
```

---

## Quick Start

### Prerequisites

- Python 3.11+ (tested on 3.14)
- Git 2.x
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/secure_flow.git
cd secure_flow

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment (optional)
copy .env.example .env
# Edit .env with your settings

# 5. Run the application
python run.py
```

Open **http://localhost:5000** in your browser.

**Default admin credentials:**
- Email: `admin@secureflow.local`
- Password: `Admin@SecureFlow1`

---

## Usage Guide

### 1. Connect a Repository

1. Click **"+ Add Repository"** on the dashboard
2. Enter a GitHub URL: `https://github.com/owner/repo`
3. Click **"Connect Repository"**

### 2. Trigger a Security Scan

1. Go to **Repositories**
2. Click **"Scan"** on any repository
3. Watch the 15-stage pipeline run in real-time on the scan detail page

The scan pipeline runs these stages:
```
checkout → setup_python → install_deps → run_tests → bandit
→ pip_audit → gitleaks → trivy_fs → build_docker → trivy_image
→ sonarqube → security_gate → generate_reports → upload_artifacts → deploy
```

### 3. Review Vulnerabilities

Navigate to **Vulnerabilities** to see all findings. For each vulnerability you can:
- **Resolve** — mark as fixed
- **Accept Risk** — acknowledge and accept
- **False Positive** — dismiss as not applicable

### 4. Security Gate

After each scan, the Security Gate evaluates your findings against configured policies:

| Policy | Action | Trigger |
|--------|--------|---------|
| `block_critical` | **BLOCK** | Any critical vulnerability |
| `block_secrets` | **BLOCK** | Any exposed secret |
| `warn_high` | Warn | Any high severity finding |
| `warn_medium` | Warn | ≥3 medium findings |

Configure policies at **Admin → Security Policies**.

### 5. Download Reports

From any completed scan, download:
- **PDF** — Full formatted security report
- **JSON** — Machine-readable for integration
- **CSV** — Spreadsheet-compatible vulnerability list

---

## Security Gate Logic

The gate evaluates scan results against enabled policies:

```python
# Risk Score Algorithm (0-100)
score = 100
score -= min(critical_count * 20, 60)   # max -60
score -= min(high_count * 10, 30)        # max -30
score -= min(medium_count * 3, 15)       # max -15
score -= min(low_count * 1, 5)           # max -5
score -= min(secrets_count * 25, 50)     # max -50
score = max(0, score)
```

| Score Range | Category |
|-------------|----------|
| 90–100 | Excellent |
| 75–89 | Good |
| 60–74 | Fair |
| 40–59 | Poor |
| 0–39 | Critical Risk |

---

## REST API

Base URL: `http://localhost:5000/api`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/dashboard/summary` | GET | Aggregated stats |
| `/api/dashboard/charts` | GET | Chart data |
| `/api/repositories` | GET/POST | List / add repos |
| `/api/repositories/{id}` | GET/DELETE | Repo detail / delete |
| `/api/scans` | GET/POST | List / trigger scans |
| `/api/scans/{id}` | GET | Scan detail + stages |
| `/api/vulnerabilities` | GET | List vulns (filtered) |
| `/api/policies` | GET/POST | List / update policies |
| `/api/notifications` | GET | User notifications |
| `/api/webhook` | POST | GitHub webhook trigger |

### Example: Trigger a scan via API

```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"repository_id": 1, "trigger_type": "api"}'
```

---

## Running Tests

```bash
# Activate venv first
venv\Scripts\activate

# Run all tests
python -m pytest tests/ -v

# Run specific test files
python -m pytest tests/test_security_gate.py -v
python -m pytest tests/test_api.py -v

# With coverage report
python -m pytest tests/ --cov=app --cov-report=html
# Open htmlcov/index.html in browser
```

---

## CI/CD Pipeline (GitHub Actions)

The `.github/workflows/devsecops.yml` runs automatically on every push/PR:

```
Stage 1: Setup Python + Install deps
Stage 2: Run pytest + coverage
Stage 3: Bandit SAST scan
Stage 4: pip-audit dependency scan
Stage 5: Gitleaks secret detection
Stage 6: Trivy filesystem scan
Stage 7: Security Gate decision (blocks merge if critical findings)
Stage 8: Consolidated security report artifact
```

---

## Demo — Vulnerable vs. Secure

The `sample-app/` directory contains two Flask applications:

**`sample-app/vulnerable/app.py`** — Contains intentional security issues:
- Hardcoded API keys and passwords (B105, B106)
- SQL injection via f-string queries (B608)
- Command injection with `shell=True` (B602)
- Insecure deserialization with `pickle.loads()` (B301)
- Arbitrary code execution via `eval()` (B307)
- Weak MD5 password hashing (B303)
- Cryptographically weak `random.randint()` token (B311)
- YAML unsafe load (B506)
- Flask debug mode enabled (B201)

**`sample-app/secure/app.py`** — Demonstrates the fixes:
- Environment variable for secret key
- Parameterized SQL queries
- Subprocess with list args, no `shell=True`
- JSON instead of pickle
- `ast.literal_eval()` instead of `eval()`
- PBKDF2-SHA256 password hashing
- `secrets.token_urlsafe()` for tokens
- `yaml.safe_load()`

---

## Configuration

Key environment variables (see `.env.example`):

```bash
SECRET_KEY=your-very-secret-key-here
DATABASE_URL=sqlite:///secureflow.db
ADMIN_EMAIL=admin@secureflow.local
ADMIN_PASSWORD=Admin@SecureFlow1
FLASK_ENV=development

# Optional integrations
GITHUB_TOKEN=ghp_your_github_token
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=your_sonar_token
```

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11+, Flask 3.1, SQLAlchemy 2.x |
| **Frontend** | Bootstrap 5.3, Chart.js 4, Font Awesome 6 |
| **Database** | SQLite (dev), PostgreSQL (prod) |
| **Auth** | Flask-Login, Werkzeug password hashing |
| **Security** | Flask-WTF CSRF, Flask-Limiter rate limiting |
| **SAST** | Bandit, SonarQube |
| **SCA** | pip-audit |
| **Secrets** | Gitleaks |
| **Container** | Trivy |
| **Reports** | ReportLab (PDF), Python csv/json |
| **CI/CD** | GitHub Actions |
| **Testing** | pytest, pytest-cov, pytest-flask |

---

## Academic Context

This project was developed as a mini-project for the subject **Fundamentals of DevOps** as part of a Bachelor of Technology in Computer Science and Engineering program.

It demonstrates:
1. **DevSecOps integration** — Security scanning embedded in CI/CD (not bolted on)
2. **Shift-left security** — Vulnerabilities caught before deployment
3. **Security Gate pattern** — Policy-driven deployment protection
4. **Risk scoring** — Quantitative security measurement
5. **Full-stack development** — Backend + frontend + API + tests + documentation

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with the DevSecOps principle: <strong>Secure by Design, Automated by Default.</strong>
</div>
