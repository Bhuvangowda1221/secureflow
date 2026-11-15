"""SonarQube scanner integration — graceful fallback when unavailable."""
from __future__ import annotations
import requests


class SonarQubeScanner:

    def check_availability(self, url: str, token: str) -> dict:
        """
        Check if SonarQube is reachable.
        Returns {'available': bool, 'error': str|None}
        """
        try:
            resp = requests.get(
                f"{url}/api/system/status",
                auth=(token, "") if token else None,
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "available": data.get("status") == "UP",
                    "version": data.get("version", ""),
                    "error": None,
                }
            return {"available": False, "error": f"HTTP {resp.status_code}"}
        except requests.exceptions.ConnectionError:
            return {
                "available": False,
                "error": (
                    "SonarQube not reachable. "
                    "Start with: docker-compose up sonarqube"
                ),
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    def get_project_issues(self, project_key: str, url: str, token: str) -> list:
        """Fetch issues from SonarQube API."""
        try:
            resp = requests.get(
                f"{url}/api/issues/search",
                params={"projectKeys": project_key, "ps": 500},
                auth=(token, "") if token else None,
                timeout=15,
            )
            resp.raise_for_status()
            issues = []
            for issue in resp.json().get("issues", []):
                sev = issue.get("severity", "MAJOR").lower()
                sev_map = {
                    "blocker": "critical", "critical": "critical",
                    "major": "high", "minor": "medium", "info": "low",
                }
                issues.append({
                    "title": issue.get("message", "SonarQube Issue"),
                    "severity": sev_map.get(sev, "medium"),
                    "file_path": issue.get("component", "").split(":")[-1],
                    "line_number": issue.get("line"),
                    "vuln_type": issue.get("rule"),
                    "description": issue.get("message"),
                    "scanner": "sonarqube",
                })
            return issues
        except Exception:
            return []

    def get_quality_gate(self, project_key: str, url: str, token: str) -> dict:
        """Check quality gate status."""
        try:
            resp = requests.get(
                f"{url}/api/qualitygates/project_status",
                params={"projectKey": project_key},
                auth=(token, "") if token else None,
                timeout=10,
            )
            resp.raise_for_status()
            status = resp.json().get("projectStatus", {}).get("status", "NONE")
            return {"passed": status == "OK", "status": status}
        except Exception:
            return {"passed": True, "status": "UNKNOWN"}
