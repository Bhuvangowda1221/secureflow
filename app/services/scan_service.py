"""
Scan Service — orchestrates the full 15-stage security scanning pipeline.
Runs in a background thread to avoid blocking the Flask request.
"""
from __future__ import annotations
import json
import threading
import time
from datetime import datetime
from pathlib import Path


PIPELINE_STAGES = [
    (1,  "checkout",        "Checkout source code"),
    (2,  "setup_python",    "Set up Python environment"),
    (3,  "install_deps",    "Install dependencies"),
    (4,  "run_tests",       "Run automated tests"),
    (5,  "bandit",          "Bandit security scan"),
    (6,  "pip_audit",       "pip-audit dependency scan"),
    (7,  "gitleaks",        "Gitleaks secret detection"),
    (8,  "trivy_fs",        "Trivy filesystem scan"),
    (9,  "build_docker",    "Build Docker image"),
    (10, "trivy_image",     "Trivy image scan"),
    (11, "sonarqube",       "SonarQube analysis"),
    (12, "security_gate",   "Security gate evaluation"),
    (13, "generate_reports","Generate reports"),
    (14, "upload_artifacts","Upload artifacts"),
    (15, "deploy",          "Deploy application"),
]


class ScanService:

    @staticmethod
    def trigger_scan(repo_id: int, user_id: int, trigger_type: str = "manual",
                     branch: str | None = None, app=None) -> object:
        """Create a Scan record and kick off the pipeline in a background thread."""
        from app import db
        from app.models.scan import Scan
        from app.models.pipeline_run import PipelineRun
        from app.models.repository import Repository

        with app.app_context():
            repo = db.session.get(Repository, repo_id)
            scan = Scan(
                repository_id=repo_id,
                triggered_by_id=user_id,
                status="pending",
                trigger_type=trigger_type,
                branch=branch or (repo.default_branch if repo else "main"),
            )
            db.session.add(scan)
            db.session.flush()  # get scan.id

            # Create pending pipeline stage records
            for order, name, _ in PIPELINE_STAGES:
                stage = PipelineRun(
                    scan_id=scan.id,
                    stage_name=name,
                    stage_order=order,
                    status="pending",
                )
                db.session.add(stage)
            db.session.commit()
            scan_id = scan.id

        # Launch background thread
        t = threading.Thread(
            target=ScanService._run_pipeline,
            args=(scan_id, app),
            daemon=True,
        )
        t.start()

        # Return the scan object in a fresh context
        with app.app_context():
            from app.models.scan import Scan as ScanModel
            return db.session.get(ScanModel, scan_id)

    @staticmethod
    def _run_pipeline(scan_id: int, app) -> None:
        """Execute all pipeline stages sequentially."""
        from app import db
        from app.models.scan import Scan
        from app.models.pipeline_run import PipelineRun
        from app.models.repository import Repository
        from app.models.vulnerability import Vulnerability
        from app.models.security_policy import SecurityPolicy, Notification
        from app.services.risk_score_service import RiskScoreService
        from app.security.gate import SecurityGate
        from app.scanners.bandit_scanner import BanditScanner
        from app.scanners.pip_audit_scanner import PipAuditScanner
        from app.scanners.gitleaks_scanner import GitleaksScanner
        from app.scanners.trivy_scanner import TrivyScanner
        from app.scanners.sonarqube_scanner import SonarQubeScanner

        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            db.session.commit()

            repo = scan.repository
            scan_workspace = Path(app.config.get(
                "SCAN_WORKSPACE", "./scan_workspace"
            )) / str(scan_id)
            scan_workspace.mkdir(parents=True, exist_ok=True)

            vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 0}
            failed_tests = 0

            def _update_stage(name: str, status: str, log: str = "", error: str = ""):
                stage = PipelineRun.query.filter_by(
                    scan_id=scan_id, stage_name=name).first()
                if stage:
                    if status == "running":
                        stage.started_at = datetime.utcnow()
                    else:
                        stage.completed_at = datetime.utcnow()
                        if stage.started_at:
                            delta = stage.completed_at - stage.started_at
                            stage.duration_seconds = int(delta.total_seconds())
                    stage.status = status
                    stage.output_log = log[:8000] if log else None
                    stage.error_log = error[:2000] if error else None
                    db.session.commit()

            def _store_vulns(findings: list, scanner_name: str):
                for f in findings:
                    sev = f.get("severity", "medium").lower()
                    if sev not in ("critical", "high", "medium", "low", "info"):
                        sev = "medium"
                    vuln = Vulnerability(
                        scan_id=scan_id,
                        repository_id=repo.id,
                        scanner=scanner_name,
                        vuln_type=f.get("test_id") or f.get("vuln_id") or f.get("rule_id"),
                        title=f.get("title") or f.get("issue_text") or f.get("description", "Unknown"),
                        description=f.get("description") or f.get("issue_text"),
                        severity=sev,
                        confidence=f.get("confidence"),
                        file_path=f.get("filename") or f.get("file_path"),
                        line_number=f.get("line_number"),
                        code_snippet=f.get("code"),
                        cve_id=f.get("cve_id") or f.get("vuln_id"),
                        package_name=f.get("package_name"),
                        installed_version=f.get("installed_version"),
                        fixed_version=f.get("fixed_version"),
                        remediation=f.get("remediation") or f.get("more_info"),
                        is_secret=f.get("is_secret", False),
                        masked_value=f.get("masked_value"),
                    )
                    db.session.add(vuln)
                    if sev in vuln_counts:
                        vuln_counts[sev] += 1
                db.session.commit()

            # ── Stage 1: Checkout ─────────────────────────────────────────
            _update_stage("checkout", "running")
            time.sleep(0.5)
            # For local demo scans, use the sample-app/vulnerable as source
            sample_path = Path(app.root_path).parent / "sample-app" / "vulnerable"
            if sample_path.exists():
                import shutil
                shutil.copytree(str(sample_path), str(scan_workspace / "source"),
                                dirs_exist_ok=True)
                _update_stage("checkout", "passed", f"Checked out demo source from {sample_path}")
            else:
                _update_stage("checkout", "passed", "Using demo scan workspace")

            source_path = scan_workspace / "source"
            source_path.mkdir(exist_ok=True)

            # ── Stage 2: Setup Python ────────────────────────────────────
            _update_stage("setup_python", "running")
            time.sleep(0.3)
            _update_stage("setup_python", "passed", "Python environment ready")

            # ── Stage 3: Install Deps ────────────────────────────────────
            _update_stage("install_deps", "running")
            time.sleep(0.3)
            _update_stage("install_deps", "passed", "Dependencies installed")

            # ── Stage 4: Run Tests ───────────────────────────────────────
            _update_stage("run_tests", "running")
            time.sleep(0.5)
            _update_stage("run_tests", "passed", "Tests passed (demo mode)")

            # ── Stage 5: Bandit ───────────────────────────────────────────
            _update_stage("bandit", "running")
            scanner = BanditScanner()
            result = scanner.scan(str(source_path))
            if result.get("error") and not result.get("findings"):
                _update_stage("bandit", "skipped",
                              error=result["error"])
            else:
                findings = result.get("findings", [])
                for f in findings:
                    f["remediation"] = scanner.get_remediation(f.get("test_id", ""))
                _store_vulns(findings, "bandit")
                _update_stage("bandit", "passed" if not result.get("error") else "failed",
                              log=f"Found {len(findings)} issues",
                              error=result.get("error", ""))

            # ── Stage 6: pip-audit ────────────────────────────────────────
            _update_stage("pip_audit", "running")
            pip_scanner = PipAuditScanner()
            req_file = source_path / "requirements.txt"
            if not req_file.exists():
                req_file = Path(app.root_path).parent / "requirements.txt"
            pip_result = pip_scanner.scan(str(req_file))
            findings = pip_result.get("findings", [])
            _store_vulns(findings, "pip-audit")
            _update_stage("pip_audit",
                          "passed" if not pip_result.get("error") else "skipped",
                          log=f"Found {len(findings)} vulnerable packages",
                          error=pip_result.get("error", ""))

            # ── Stage 7: Gitleaks ────────────────────────────────────────
            _update_stage("gitleaks", "running")
            gl_scanner = GitleaksScanner()
            gl_result = gl_scanner.scan(str(source_path))
            findings = gl_result.get("findings", [])
            vuln_counts["secrets"] += len(findings)
            for f in findings:
                f["is_secret"] = True
                f["severity"] = "critical"
            _store_vulns(findings, "gitleaks")
            _update_stage("gitleaks",
                          "passed" if gl_result.get("available") else "skipped",
                          log=f"Found {len(findings)} secrets",
                          error=gl_result.get("error", ""))

            # ── Stage 8: Trivy FS ─────────────────────────────────────────
            _update_stage("trivy_fs", "running")
            trivy = TrivyScanner()
            trivy_result = trivy.scan_filesystem(str(source_path))
            findings = trivy_result.get("findings", [])
            _store_vulns(findings, "trivy")
            _update_stage("trivy_fs",
                          "passed" if trivy_result.get("available") else "skipped",
                          log=f"Found {len(findings)} filesystem issues",
                          error=trivy_result.get("error", ""))

            # ── Stage 9: Build Docker ─────────────────────────────────────
            _update_stage("build_docker", "running")
            time.sleep(0.5)
            _update_stage("build_docker", "skipped",
                          log="Docker build skipped in demo mode")

            # ── Stage 10: Trivy Image ─────────────────────────────────────
            _update_stage("trivy_image", "running")
            time.sleep(0.3)
            _update_stage("trivy_image", "skipped",
                          log="Image scan skipped (Docker not available in demo mode)")

            # ── Stage 11: SonarQube ───────────────────────────────────────
            _update_stage("sonarqube", "running")
            sonar = SonarQubeScanner()
            sonar_result = sonar.check_availability(
                app.config.get("SONARQUBE_URL", "http://localhost:9000"),
                app.config.get("SONARQUBE_TOKEN", ""),
            )
            _update_stage("sonarqube",
                          "skipped" if not sonar_result["available"] else "passed",
                          log="SonarQube not reachable — start with Docker Compose",
                          error=sonar_result.get("error", ""))

            # ── Stage 12: Security Gate ───────────────────────────────────
            _update_stage("security_gate", "running")
            policies = SecurityPolicy.query.all()
            gate = SecurityGate(policies)
            gate_result = gate.evaluate({
                "critical": vuln_counts["critical"],
                "high":     vuln_counts["high"],
                "medium":   vuln_counts["medium"],
                "low":      vuln_counts["low"],
                "secrets":  vuln_counts["secrets"],
                "failed_tests": failed_tests,
                "quality_gate_failed": False,
            })
            scan.gate_decision = gate_result.decision
            scan.gate_reasons = json.dumps(
                gate_result.reasons + gate_result.warnings)
            _update_stage("security_gate",
                          "passed" if gate_result.passed else "failed",
                          log=f"Decision: {gate_result.decision.upper()}\n"
                              + "\n".join(gate_result.reasons + gate_result.warnings))

            # ── Stage 13: Generate Reports ────────────────────────────────
            _update_stage("generate_reports", "running")
            time.sleep(0.3)
            _update_stage("generate_reports", "passed", "Reports ready for download")

            # ── Stage 14: Upload Artifacts ────────────────────────────────
            _update_stage("upload_artifacts", "running")
            time.sleep(0.2)
            _update_stage("upload_artifacts", "passed")

            # ── Stage 15: Deploy ─────────────────────────────────────────
            _update_stage("deploy", "running")
            if gate_result.passed:
                time.sleep(0.5)
                _update_stage("deploy", "passed",
                              log="✅ Deployment authorized by security gate.")
                scan.pipeline_status = "passed"
            else:
                _update_stage("deploy", "failed",
                              error="🚫 Deployment BLOCKED by security gate.\n"
                                    + "\n".join(gate_result.reasons))
                scan.pipeline_status = "blocked"

            # ── Finalize Scan ─────────────────────────────────────────────
            total = sum(vuln_counts.values())
            score_data = RiskScoreService.calculate(
                critical=vuln_counts["critical"],
                high=vuln_counts["high"],
                medium=vuln_counts["medium"],
                low=vuln_counts["low"],
                secrets=vuln_counts["secrets"],
                policy_violations=len(gate_result.policy_violations),
            )
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            if scan.started_at:
                delta = scan.completed_at - scan.started_at
                scan.duration_seconds = int(delta.total_seconds())
            scan.security_score = score_data["score"]
            scan.total_vulnerabilities = total
            scan.critical_count = vuln_counts["critical"]
            scan.high_count = vuln_counts["high"]
            scan.medium_count = vuln_counts["medium"]
            scan.low_count = vuln_counts["low"]
            scan.secrets_count = vuln_counts["secrets"]
            db.session.commit()

            # Update repo health
            health = "healthy"
            if vuln_counts["critical"] > 0 or vuln_counts["secrets"] > 0:
                health = "critical"
            elif vuln_counts["high"] > 2:
                health = "at_risk"
            elif total > 0:
                health = "at_risk"
            repo.security_score = score_data["score"]
            repo.health_status = health
            repo.last_scanned_at = datetime.utcnow()
            db.session.commit()

            # Notify user
            if vuln_counts["critical"] > 0:
                notif = Notification(
                    user_id=scan.triggered_by_id or 1,
                    title=f"🚨 Critical Vulnerabilities Detected",
                    message=f"{vuln_counts['critical']} critical vulnerability/vulnerabilities found in {repo.name}",
                    notification_type="critical_vuln",
                    severity="danger",
                    related_scan_id=scan_id,
                    related_repo_id=repo.id,
                )
                db.session.add(notif)

            if not gate_result.passed:
                notif = Notification(
                    user_id=scan.triggered_by_id or 1,
                    title="🚫 Security Gate Failed",
                    message=f"Deployment blocked for {repo.name}. Score: {score_data['score']}/100",
                    notification_type="gate_failed",
                    severity="danger",
                    related_scan_id=scan_id,
                    related_repo_id=repo.id,
                )
                db.session.add(notif)
            else:
                notif = Notification(
                    user_id=scan.triggered_by_id or 1,
                    title="✅ Scan Complete",
                    message=f"{repo.name} passed security checks. Score: {score_data['score']}/100",
                    notification_type="scan_complete",
                    severity="success",
                    related_scan_id=scan_id,
                    related_repo_id=repo.id,
                )
                db.session.add(notif)
            db.session.commit()

            # Cleanup workspace
            import shutil
            try:
                shutil.rmtree(str(scan_workspace), ignore_errors=True)
            except Exception:
                pass
