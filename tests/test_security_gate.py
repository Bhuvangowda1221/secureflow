"""Tests for security gate and risk score services."""
import pytest
from app.security.gate import SecurityGate, GateResult
from app.services.risk_score_service import RiskScoreService


class TestRiskScoreService:
    def test_perfect_score(self):
        result = RiskScoreService.calculate()
        assert result["score"] == 100
        assert result["category"] == "Excellent"

    def test_critical_vulns_deduct_score(self):
        result = RiskScoreService.calculate(critical=1)
        assert result["score"] == 80  # -20 for 1 critical

    def test_critical_max_cap(self):
        result = RiskScoreService.calculate(critical=100)  # 100 * 20 = 2000, capped at 60
        assert result["score"] == 40  # 100 - 60 = 40

    def test_all_severity_levels(self):
        result = RiskScoreService.calculate(critical=1, high=2, medium=3, low=4)
        # -20 (crit) -20 (high: 2*10) -9 (med: 3*3) -4 (low: 4*1) = 100-53 = 47
        assert result["score"] == 47

    def test_secrets_deduction(self):
        result = RiskScoreService.calculate(secrets=1)
        assert result["score"] == 75  # -25 per secret

    def test_secrets_capped(self):
        result = RiskScoreService.calculate(secrets=10)  # 250, capped at 50
        assert result["score"] == 50

    def test_score_never_negative(self):
        result = RiskScoreService.calculate(
            critical=100, high=100, medium=100, low=100, secrets=100
        )
        assert result["score"] == 0

    def test_score_categories(self):
        assert RiskScoreService.calculate()["category"] == "Excellent"
        assert RiskScoreService.calculate(critical=1, high=2)["category"] in (
            "Fair", "Poor", "Good", "Critical Risk"
        )

    def test_comparison(self):
        result = RiskScoreService.compare_scores(60, 80)
        assert result["delta"] == 20
        assert result["improved"] is True
        assert result["percentage_change"] == pytest.approx(33.3, rel=.05)

    def test_breakdown_has_entries(self):
        result = RiskScoreService.calculate(critical=2, high=1)
        assert "Critical Vulnerabilities" in result["breakdown"]
        assert result["breakdown"]["Critical Vulnerabilities"]["count"] == 2

    def test_explanation_string(self):
        result = RiskScoreService.calculate(critical=1)
        assert "Starting score: 100" in result["explanation"]
        assert "Final score:" in result["explanation"]


class MockPolicy:
    """Lightweight policy mock for gate tests."""
    def __init__(self, name, severity, action, threshold=1, enabled=True):
        self.name = name
        self.severity = severity
        self.action = action
        self.threshold = threshold
        self.enabled = enabled


class TestSecurityGate:
    def _default_policies(self):
        return [
            MockPolicy("block_critical", "critical", "block", 1),
            MockPolicy("block_secrets",  "secret",   "block", 1),
            MockPolicy("warn_high",      "high",     "warn",  1),
            MockPolicy("warn_medium",    "medium",   "warn",  3),
        ]

    def test_no_vulns_passes(self):
        gate = SecurityGate(self._default_policies())
        result = gate.evaluate({"critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 0})
        assert result.passed is True
        assert result.decision == "passed"

    def test_critical_vuln_blocks(self):
        gate = SecurityGate(self._default_policies())
        result = gate.evaluate({"critical": 1, "high": 0, "medium": 0, "low": 0, "secrets": 0})
        assert result.passed is False
        assert result.decision == "failed"
        assert "block_critical" in result.policy_violations

    def test_secrets_blocks(self):
        gate = SecurityGate(self._default_policies())
        result = gate.evaluate({"critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 1})
        assert result.passed is False
        assert "block_secrets" in result.policy_violations

    def test_high_only_warns(self):
        gate = SecurityGate(self._default_policies())
        result = gate.evaluate({"critical": 0, "high": 5, "medium": 0, "low": 0, "secrets": 0})
        assert result.passed is True  # warn, not block
        assert len(result.warnings) > 0

    def test_failed_tests_blocks(self):
        gate = SecurityGate(self._default_policies())
        result = gate.evaluate({"critical": 0, "high": 0, "medium": 0, "low": 0,
                                "secrets": 0, "failed_tests": 1})
        assert result.passed is False

    def test_quality_gate_blocks(self):
        gate = SecurityGate(self._default_policies())
        result = gate.evaluate({"critical": 0, "high": 0, "medium": 0, "low": 0,
                                "secrets": 0, "quality_gate_failed": True})
        assert result.passed is False

    def test_disabled_policy_ignored(self):
        policies = [MockPolicy("block_critical", "critical", "block", 1, enabled=False)]
        gate = SecurityGate(policies)
        result = gate.evaluate({"critical": 5, "secrets": 0, "high": 0, "medium": 0, "low": 0})
        assert result.passed is True  # policy disabled

    def test_threshold_respected(self):
        policies = [MockPolicy("block_critical", "critical", "block", 3)]  # threshold = 3
        gate = SecurityGate(policies)
        # 2 critical — below threshold of 3
        result = gate.evaluate({"critical": 2, "secrets": 0, "high": 0, "medium": 0, "low": 0})
        assert result.passed is True
        # 3 critical — at threshold
        result2 = gate.evaluate({"critical": 3, "secrets": 0, "high": 0, "medium": 0, "low": 0})
        assert result2.passed is False

    def test_gate_result_to_dict(self):
        gate = SecurityGate(self._default_policies())
        result = gate.evaluate({"critical": 1, "high": 0, "medium": 0, "low": 0, "secrets": 0})
        d = result.to_dict()
        assert "passed" in d
        assert "decision" in d
        assert "reasons" in d
        assert isinstance(d["policy_violations"], list)
