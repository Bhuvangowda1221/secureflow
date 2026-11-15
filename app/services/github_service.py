"""
GitHub API service — repository info fetching, URL parsing, cloning.
"""
from __future__ import annotations
import re
import subprocess
from pathlib import Path
import requests


class GitHubService:
    API_BASE = "https://api.github.com"

    def __init__(self, token: str = ""):
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def get_repo_info(self, owner: str, repo_name: str) -> dict:
        """Fetch repository metadata from GitHub API."""
        url = f"{self.API_BASE}/repos/{owner}/{repo_name}"
        resp = requests.get(url, headers=self.headers, timeout=10)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def parse_github_url(url: str) -> tuple[str, str]:
        """
        Parse owner and repo name from a GitHub URL.
        Returns (owner, repo_name) or raises ValueError.
        """
        pattern = re.compile(
            r'github\.com[/:](?P<owner>[\w\-\.]+)/(?P<repo>[\w\-\.]+?)(?:\.git)?/?$'
        )
        match = pattern.search(url)
        if not match:
            raise ValueError(f"Cannot parse GitHub URL: {url}")
        return match.group("owner"), match.group("repo")

    @staticmethod
    def validate_repo_url(url: str) -> bool:
        """Return True if the URL looks like a valid GitHub repo URL."""
        pattern = re.compile(
            r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+(?:\.git)?/?$'
        )
        return bool(pattern.match(url))

    def clone_repo(self, url: str, target_dir: Path) -> bool:
        """
        Clone a git repository to target_dir.
        Returns True on success, False on failure.
        """
        if target_dir.exists():
            import shutil
            shutil.rmtree(target_dir)
        try:
            # Build authenticated URL if token available
            clone_url = url
            if self.token and "github.com" in url:
                clone_url = url.replace(
                    "https://github.com",
                    f"https://{self.token}@github.com",
                )
            result = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(target_dir)],
                capture_output=True, text=True, timeout=120
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_latest_commit(self, owner: str, repo: str) -> str:
        """Return the SHA of the latest commit on the default branch."""
        url = f"{self.API_BASE}/repos/{owner}/{repo}/commits"
        resp = requests.get(url, headers=self.headers,
                            params={"per_page": 1}, timeout=10)
        resp.raise_for_status()
        commits = resp.json()
        return commits[0]["sha"] if commits else ""
