import subprocess
import json
import shutil
import tempfile
import os
from pathlib import Path


class GitleaksScanner:
    """
    Integration with Gitleaks for detecting hard-coded secrets and credentials.

    Gitleaks is an open-source SAST tool that scans git repos (and plain
    directories with --no-git) for secrets such as API keys, tokens, and
    passwords using a comprehensive rule set.

    Download: https://github.com/zricethezav/gitleaks/releases
    """

    INSTALL_MSG = (
        'Gitleaks is not installed or not on PATH. '
        'Download the binary for your OS from '
        'https://github.com/zricethezav/gitleaks/releases '
        'and place it in a directory that is on your PATH.'
    )

    def __init__(self, gitleaks_path: str = 'gitleaks'):
        self.gitleaks_path = gitleaks_path

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the gitleaks binary can be found on PATH."""
        return shutil.which(self.gitleaks_path) is not None

    # ------------------------------------------------------------------
    # Secret masking
    # ------------------------------------------------------------------

    @staticmethod
    def _mask(value: str) -> str:
        """
        Partially mask a secret value.

        Reveals the first 4 characters and replaces the remainder with
        '****' so the finding is identifiable without exposing the full
        secret in reports or logs.
        """
        if not value:
            return '****'
        visible = value[:4]
        return f'{visible}****'

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------

    def scan(self, target_path: str) -> dict:
        """
        Run gitleaks against *target_path* in no-git mode (plain directory).

        Returns:
            {
                'findings': list[dict],
                'error': str | None,
                'raw_output': str,
                'scanner': 'gitleaks',
                'available': bool,
            }

        Each finding dict:
            rule_id, description, file, line_start,
            match (masked), secret (masked), commit, author
        """
        if not self.is_available():
            return {
                'findings': [],
                'error': self.INSTALL_MSG,
                'raw_output': '',
                'scanner': 'gitleaks',
                'available': False,
            }

        # Write the JSON report to a temp file so we can parse it cleanly.
        tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json', prefix='gitleaks_')
        os.close(tmp_fd)

        try:
            cmd = [
                self.gitleaks_path,
                'detect',
                '--source', str(target_path),
                '--report-format', 'json',
                '--report-path', tmp_path,
                '--no-git',
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            # gitleaks exits with code 1 when secrets are found — expected.
            raw_output = result.stdout + result.stderr

            # Read the JSON report (may be empty if no findings)
            report_data = []
            if os.path.exists(tmp_path):
                with open(tmp_path, 'r', encoding='utf-8') as fh:
                    content = fh.read().strip()
                if content and content != 'null':
                    try:
                        report_data = json.loads(content)
                        if not isinstance(report_data, list):
                            report_data = []
                    except json.JSONDecodeError:
                        pass

            findings = []
            for item in report_data:
                raw_match = item.get('Match', '') or item.get('match', '')
                raw_secret = item.get('Secret', '') or item.get('secret', '')
                findings.append({
                    'rule_id': item.get('RuleID', '') or item.get('rule_id', ''),
                    'description': item.get('Description', '') or item.get('description', ''),
                    'file': item.get('File', '') or item.get('file', ''),
                    'line_start': item.get('StartLine', 0) or item.get('line_start', 0),
                    'match': self._mask(raw_match),
                    'secret': self._mask(raw_secret),
                    'commit': item.get('Commit', '') or item.get('commit', ''),
                    'author': item.get('Author', '') or item.get('author', ''),
                    'scanner': 'gitleaks',
                })

            return {
                'findings': findings,
                'error': None,
                'raw_output': raw_output,
                'scanner': 'gitleaks',
                'available': True,
            }

        except subprocess.TimeoutExpired:
            return {
                'findings': [],
                'error': 'Gitleaks scan timed out (>120s)',
                'raw_output': '',
                'scanner': 'gitleaks',
                'available': True,
            }
        except Exception as exc:
            return {
                'findings': [],
                'error': str(exc),
                'raw_output': '',
                'scanner': 'gitleaks',
                'available': True,
            }
        finally:
            # Always clean up the temp report file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
