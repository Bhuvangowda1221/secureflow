"""
Risk Score Service — penalty-based security score from 0-100.
Algorithm is fully documented and deterministic.
"""
from __future__ import annotations
from dataclasses import dataclass


PENALTIES = {
    "critical": {"per_finding": 20, "max_deduction": 60},
    "high":     {"per_finding": 10, "max_deduction": 30},
    "medium":   {"per_finding": 3,  "max_deduction": 15},
    "low":      {"per_finding": 1,  "max_deduction": 5},
    "secret":   {"per_finding": 25, "max_deduction": 50},
    "policy":   {"per_finding": 10, "max_deduction": 20},
    "quality_gate_failed": 15,
}

CATEGORIES = [
    (90, "Excellent",     "#3fb950"),
    (75, "Good",          "#58a6ff"),
    (50, "Fair",          "#d29922"),
    (25, "Poor",          "#f0883e"),
    (0,  "Critical Risk", "#f85149"),
]


class RiskScoreService:

    @staticmethod
    def calculate(
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        secrets: int = 0,
        policy_violations: int = 0,
        quality_gate_failed: bool = False,
        previous_score: int | None = None,
    ) -> dict:
        """
        Calculate a security score out of 100.
        Returns a fully-explained breakdown dict.
        """
        score = 100
        breakdown = {}

        def _deduct(label: str, count: int, key: str) -> int:
            cfg = PENALTIES[key]
            raw = count * cfg["per_finding"]
            capped = min(raw, cfg["max_deduction"])
            breakdown[label] = {
                "count": count,
                "per_finding": cfg["per_finding"],
                "raw_deduction": raw,
                "capped_deduction": capped,
                "max": cfg["max_deduction"],
            }
            return capped

        score -= _deduct("Critical Vulnerabilities", critical, "critical")
        score -= _deduct("High Vulnerabilities",     high,     "high")
        score -= _deduct("Medium Vulnerabilities",   medium,   "medium")
        score -= _deduct("Low Vulnerabilities",      low,      "low")
        score -= _deduct("Exposed Secrets",          secrets,  "secret")
        score -= _deduct("Policy Violations",        policy_violations, "policy")

        if quality_gate_failed:
            qg_deduction = PENALTIES["quality_gate_failed"]
            score -= qg_deduction
            breakdown["Quality Gate Failed"] = {
                "count": 1, "capped_deduction": qg_deduction,
            }

        score = max(0, min(100, score))

        category, color = RiskScoreService._category(score)

        # Build human-readable explanation
        lines = [f"Starting score: 100"]
        for label, info in breakdown.items():
            if info["count"] > 0:
                lines.append(
                    f"- {label}: {info['count']} × -{info.get('per_finding',0)} = "
                    f"-{info['capped_deduction']} (capped at -{info.get('max', info['capped_deduction'])})"
                )
        lines.append(f"Final score: {score}/100 ({category})")

        result = {
            "score": score,
            "category": category,
            "color": color,
            "breakdown": breakdown,
            "explanation": "\n".join(lines),
            "previous_score": previous_score,
        }

        if previous_score is not None:
            delta = score - previous_score
            result["score_delta"] = delta
            result["improved"] = delta > 0
            if previous_score > 0:
                result["pct_change"] = round((delta / previous_score) * 100, 1)
            else:
                result["pct_change"] = None

        return result

    @staticmethod
    def _category(score: int) -> tuple[str, str]:
        for threshold, name, color in CATEGORIES:
            if score >= threshold:
                return name, color
        return "Critical Risk", "#f85149"

    @staticmethod
    def compare_scores(old_score: int, new_score: int) -> dict:
        delta = new_score - old_score
        pct = round((delta / old_score * 100), 1) if old_score else None
        return {
            "old_score": old_score,
            "new_score": new_score,
            "delta": delta,
            "improved": delta > 0,
            "percentage_change": pct,
        }
