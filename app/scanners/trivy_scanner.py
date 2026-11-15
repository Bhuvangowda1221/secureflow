import subprocess
import json
import shutil
from pathlib import Path


class TrivyScanner:
    """
    Integration with Trivy for container image and filesystem vulnerability scanning.

    Trivy scans:
    - Filesystem paths (OS packages, language deps, IaC misconfigs)
    - Docker/OCI images (OS packages + application libs)

    Only HIGH and CRITICAL findings are returned by default.

    Download: https://github.com/aquasecurity/trivy/releases
    """

    INSTALL_MSG = (
        'Trivy is not installed or not on PATH. '
        'Download the binary for your OS from '
        'https://github.com/aquasecurity/trivy/releases '
        'and place it in a directory that is on your PATH. '
        'Or install via: brew install trivy  /  apt install trivy.'
    )

    def __init__(self, trivy_path: str = 'trivy', severity: str = 'HIGH,CRITICAL'):
        self.trivy_path = trivy_path
        self.severity = severity

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the trivy binary can be found on PATH."""
        return shutil.which(self.trivy_path) is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, cmd: list, timeout: int = 300) -> tuple:
        """Execute *cmd* and return (stdout, stderr, returncode)."""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            return '', 'Trivy scan timed out', -1
        except FileNotFoundError:
            return '', f'{self.trivy_path}: command not found', -1
        except Exception as exc:
            return '', str(exc), -1

    def _parse_trivy_json(self, raw: str) -> list:
        """
        Parse Trivy's JSON output and normalise into a flat findings list.

        Trivy JSON schema (--format json):
        {
          "Results": [
            {
              "Target": "...",
              "Type": "...",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-...",
                  "PkgName": "...",
                  "InstalledVersion": "...",
                  "FixedVersion": "...",
                  "Severity": "HIGH",
                  "Title": "...",
                  "Description": "..."
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

        for result in data.get('Results', []):
            target = result.get('Target', '')
            for vuln in (result.get('Vulnerabilities') or []):
                findings.append({
                    'vuln_id': vuln.get('VulnerabilityID', ''),
                    'pkg_name': vuln.get('PkgName', ''),
                    'installed_version': vuln.get('InstalledVersion', ''),
                    'fixed_version': vuln.get('FixedVersion', ''),
                    'severity': vuln.get('Severity', '').lower(),
                    'title': vuln.get('Title', ''),
                    'description': vuln.get('Description', ''),
                    'target': target,
                    'scanner': 'trivy',
                })
        return findings

    def _not_available_response(self, context: str = '') -> dict:
        return {
            'findings': [],
            'error': self.INSTALL_MSG,
            'raw_output': '',
            'scanner': 'trivy',
            'available': False,
            'context': context,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_filesystem(self, path: str) -> dict:
        """
        Scan a local filesystem path for vulnerabilities.

        Args:
            path: Directory or file path to scan.

        Returns:
            {
                'findings': list[dict],
                'error': str | None,
                'raw_output': str,
                'scanner': 'trivy',
                'available': bool,
            }
        """
        if not self.is_available():
            return self._not_available_response('filesystem')

        cmd = [
            self.trivy_path,
            'fs',
            '--format', 'json',
            '--severity', self.severity,
            str(path),
        ]
        stdout, stderr, returncode = self._run(cmd)
        raw = stdout or stderr

        if returncode == -1:
            return {
                'findings': [],
                'error': stderr,
                'raw_output': raw,
                'scanner': 'trivy',
                'available': True,
            }

        findings = self._parse_trivy_json(stdout)
        return {
            'findings': findings,
            'error': None,
            'raw_output': raw,
            'scanner': 'trivy',
            'available': True,
        }

    def scan_image(self, image_name: str) -> dict:
        """
        Scan a Docker/OCI container image for vulnerabilities.

        Args:
            image_name: Image reference, e.g. 'nginx:latest' or 'myapp:1.0.0'

        Returns:
            {
                'findings': list[dict],
                'error': str | None,
                'raw_output': str,
                'scanner': 'trivy',
                'available': bool,
            }
        """
        if not self.is_available():
            return self._not_available_response('image')

        cmd = [
            self.trivy_path,
            'image',
            '--format', 'json',
            '--severity', self.severity,
            image_name,
        ]
        stdout, stderr, returncode = self._run(cmd)
        raw = stdout or stderr

        if returncode == -1:
            return {
                'findings': [],
                'error': stderr,
                'raw_output': raw,
                'scanner': 'trivy',
                'available': True,
            }

        findings = self._parse_trivy_json(stdout)
        return {
            'findings': findings,
            'error': None,
            'raw_output': raw,
            'scanner': 'trivy',
            'available': True,
        }

    # Convenience alias — defaults to filesystem scan
    def scan(self, target_path: str) -> dict:
        """Scan a filesystem path (alias for scan_filesystem)."""
        return self.scan_filesystem(target_path)
