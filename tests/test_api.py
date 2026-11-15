"""Tests for REST API endpoints."""
import pytest
import json


class TestAPIHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["status"] == "healthy"


class TestAPIRepositories:
    def test_list_repos_requires_auth(self, client):
        resp = client.get("/api/repositories")
        # Redirect to login or 401
        assert resp.status_code in (302, 401)

    def test_list_repos_authenticated(self, auth_client):
        resp = auth_client.get("/api/repositories")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert isinstance(data["data"], list)

    def test_add_repo_invalid_url(self, auth_client):
        resp = auth_client.post("/api/repositories",
                                json={"url": "not-a-github-url"},
                                content_type="application/json")
        assert resp.status_code == 400

    def test_add_repo_valid_url(self, auth_client):
        resp = auth_client.post("/api/repositories",
                                json={"url": "https://github.com/testowner/apitestrepo"},
                                content_type="application/json")
        assert resp.status_code in (201, 409)  # 409 if already exists


class TestAPIScans:
    def test_list_scans(self, auth_client):
        resp = auth_client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert isinstance(data["data"], list)

    def test_trigger_scan_no_repo(self, auth_client):
        resp = auth_client.post("/api/scans",
                                json={},
                                content_type="application/json")
        assert resp.status_code == 400

    def test_trigger_scan_invalid_repo(self, auth_client):
        resp = auth_client.post("/api/scans",
                                json={"repository_id": 99999},
                                content_type="application/json")
        assert resp.status_code == 404


class TestAPIVulnerabilities:
    def test_list_vulns(self, auth_client):
        resp = auth_client.get("/api/vulnerabilities")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True

    def test_list_vulns_filtered_by_severity(self, auth_client):
        resp = auth_client.get("/api/vulnerabilities?severity=critical")
        assert resp.status_code == 200


class TestAPIPolicies:
    def test_list_policies(self, auth_client):
        resp = auth_client.get("/api/policies")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert isinstance(data["data"], list)
        # At least the default policies should exist
        if data["data"]:
            policy = data["data"][0]
            assert "name" in policy
            assert "action" in policy


class TestAPINotifications:
    def test_list_notifications(self, auth_client):
        resp = auth_client.get("/api/notifications")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "notifications" in data["data"]
        assert "unread_count" in data["data"]


class TestAPIDashboard:
    def test_dashboard_summary(self, auth_client):
        resp = auth_client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        summary = data["data"]
        assert "total_repos" in summary
        assert "total_vulns" in summary
        assert "critical" in summary

    def test_dashboard_charts(self, auth_client):
        resp = auth_client.get("/api/dashboard/charts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        charts = data["data"]
        assert "severity_dist" in charts
        assert "scan_history" in charts
        assert "pipeline_stats" in charts
