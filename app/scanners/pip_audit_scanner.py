import subprocess
import json
import shutil
from pathlib import Path


class PipAuditScanner:
    """
    Integration with pip-audit for Python dependency vulnerability scanning.

    pip-audit queries the OSV/PyPI Advisory Database for known CVEs in
    installed packages or packages listed in a requirements file.
    """

    def __init__(self, pip_audit_path: str = 'pip-audit'):
        self.pip_audit_path = pip_audit_path

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if pip-audit binary is on PATH."""
        return shutil.which(self.pip_audit_path) is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, cmd: list, timeout: int = 180) -> tuple:
        """
        Execute *cmd* and return (stdout, stderr, returncode).
        Returns ('', error_msg, -1) on timeout or OS error.
        """
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            return '', 'pip-audit scan timed out (>180s)', -1
        except FileNotFoundError:
            return '', f'{self.pip_audit_path}: command not found', -1
        except Exception as exc:
            return '', str(exc), -1

    def _parse_output(self, raw: str) -> list:
        """
        Parse pip-audit JSON output and normalise into a flat findings list.

        pip-audit JSON schema (--format json):
        {
          "dependencies": [
            {
              "name": "...",
              "version": "...",
              "vulns": [
                {
                  "id": "PYSEC-...",
                  "aliases": ["CVE-..."],
                  "description": "...",
                  "fix_versions": ["..."]
                }
              ]
            }
          ]
        }
        """
        findings = []
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return findings

        for dep in data.get('dependencies', []):
            pkg_name = dep.get('name', 'unknown')
            version = dep.get('version', 'unknown')
            for vuln in dep.get('vulns', []):
                vuln_id = vuln.get('id', '')
                aliases = vuln.get('aliases', [])
                # Prefer CVE alias when available
                cve_id = next(
                    (a for a in aliases if a.upper().startswith('CVE-')),
                    vuln_id,
                )
                description = vuln.get('description', '')
                fix_versions = vuln.get('fix_versions', [])

                # pip-audit does not expose per-vuln severity in its standard
                # JSON output; we default to 'high' as a conservative choice.
                severity = 'high'

                findings.append({
                    'package_name': pkg_name,
                    'version': version,
                    'vuln_id': cve_id,
                    'aliases': aliases,
                    'description': description,
                    'fix_versions': fix_versions,
                    'severity': severity,
                    'scanner': 'pip-audit',
                })
        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_requirements(self, requirements_path: str) -> dict:
        """
        Scan a specific requirements file for known vulnerabilities.

        Args:
            requirements_path: Absolute or relative path to requirements.txt

        Returns:
            {
                'findings': list,
                'error': str | None,
                'raw_output': str,
                'scanner': 'pip-audit',
            }
        """
        if not self.is_available():
            return {
                'findings': [],
                'error': 'pip-audit not installed. Run: pip install pip-audit',
                'raw_output': '',
                'scanner': 'pip-audit',
            }

        req_file = Path(requirements_path)
        if not req_file.exists():
            return {
                'findings': [],
                'error': f'Requirements file not found: {requirements_path}',
                'raw_output': '',
                'scanner': 'pip-audit',
            }

        cmd = [
            self.pip_audit_path,
            '--format', 'json',
            '-r', str(req_file),
        ]
        stdout, stderr, returncode = self._run(cmd)

        raw = stdout or stderr
        if returncode == -1:
            return {
                'findings': [],
                'error': stderr,
                'raw_output': raw,
                'scanner': 'pip-audit',
            }

        findings = self._parse_output(raw)
        # returncode 1 means vulnerabilities were found — that is expected
        return {
            'findings': findings,
            'error': None,
            'raw_output': raw,
            'scanner': 'pip-audit',
        }

    def scan_environment(self) -> dict:
        """
        Scan all packages installed in the current Python environment.

        Returns:
            {
                'findings': list,
                'error': str | None,
                'raw_output': str,
                'scanner': 'pip-audit',
            }
        """
        if not self.is_available():
            return {
                'findings': [],
                'error': 'pip-audit not installed. Run: pip install pip-audit',
                'raw_output': '',
                'scanner': 'pip-audit',
            }

        cmd = [self.pip_audit_path, '--format', 'json']
        stdout, stderr, returncode = self._run(cmd)

        raw = stdout or stderr
        if returncode == -1:
            return {
                'findings': [],
                'error': stderr,
                'raw_output': raw,
                'scanner': 'pip-audit',
            }

        findings = self._parse_output(raw)
        return {
            'findings': findings,
            'error': None,
            'raw_output': raw,
            'scanner': 'pip-audit',
        }

    # Convenience alias matching the generic scanner interface used by services
    def scan(self, target_path: str) -> dict:
        """
        Auto-detect whether *target_path* is a file or directory.

        - If it is a file (e.g. requirements.txt) → scan_requirements()
        - If it is a directory → look for requirements.txt inside it
        - Fallback → scan current environment
        """
        p = Path(target_path)
        if p.is_file():
            return self.scan_requirements(str(p))
        if p.is_dir():
            req = p / 'requirements.txt'
            if req.exists():
                return self.scan_requirements(str(req))
        return self.scan_environment()
