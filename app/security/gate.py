"""
Security Gate Engine — evaluates scan results against configured policies
and decides whether deployment should be blocked.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


@dataclass
class GateResult:
    passed: bool
    decision: str          # 'passed' | 'failed'
    reasons: List[str]
    warnings: List[str]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    secrets_count: int
    policy_violations: List[str]

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "decision": self.decision,
            "reasons": self.reasons,
            "warnings": self.warnings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "secrets_count": self.secrets_count,
            "policy_violations": self.policy_violations,
        }


class SecurityGate:
    """
    Evaluates scan results against SecurityPolicy rules.
    Returns a GateResult that controls whether deployment proceeds.
    """

    def __init__(self, policies: list):
        """Accept a list of SecurityPolicy ORM objects."""
        self.policies = {p.name: p for p in policies}

    def evaluate(self, scan_results: dict) -> GateResult:
        """
        scan_results keys:
            critical, high, medium, low, secrets,
            failed_tests, quality_gate_failed
        """
        reasons: List[str] = []
        warnings: List[str] = []
        violations: List[str] = []
        passed = True

        c = scan_results.get("critical", 0)
        h = scan_results.get("high", 0)
        m = scan_results.get("medium", 0)
        lo = scan_results.get("low", 0)
        s = scan_results.get("secrets", 0)
        failed_tests = scan_results.get("failed_tests", 0)
        qg_failed = scan_results.get("quality_gate_failed", False)

        def _check(policy_name: str, count: int, label: str):
            nonlocal passed
            p = self.policies.get(policy_name)
            if not p or not p.enabled:
                return
            if count >= p.threshold:
                if p.action == "block":
                    passed = False
                    reasons.append(
                        f"🚫 BLOCKED: {count} {label} "
                        f"(threshold: {p.threshold}, policy: {p.name})"
                    )
                    violations.append(policy_name)
                elif p.action == "warn":
                    warnings.append(
                        f"⚠️  WARNING: {count} {label} detected. "
                        f"Review before deploying."
                    )

        _check("block_critical", c, "critical vulnerability/vulnerabilities")
        _check("block_secrets",  s, "exposed secret(s)")
        _check("warn_high",      h, "high severity vulnerability/vulnerabilities")
        _check("warn_medium",    m, "medium severity vulnerability/vulnerabilities")

        # Failed tests always block
        if failed_tests > 0:
            passed = False
            reasons.append(
                f"🚫 BLOCKED: {failed_tests} automated test(s) failed. "
                "All tests must pass before deployment."
            )
            violations.append("failed_tests")

        # SonarQube quality gate
        if qg_failed:
            passed = False
            reasons.append(
                "🚫 BLOCKED: SonarQube quality gate failed. "
                "Code quality requirements are not met."
            )
            violations.append("quality_gate")

        return GateResult(
            passed=passed,
            decision="passed" if passed else "failed",
            reasons=reasons,
            warnings=warnings,
            critical_count=c,
            high_count=h,
            medium_count=m,
            low_count=lo,
            secrets_count=s,
            policy_violations=violations,
        )
