"""EASM risk-scoring engine.

Produces a 0–100 score (higher = better security posture) and an A–F letter
grade, modelled on the methodology used by platforms like BitSight and
SecurityScorecard.

Algorithm overview
------------------
1. Each open vulnerability contributes a base penalty weighted by severity.
2. If a CVSS score is available it adds a small additional penalty (up to +3 pts).
3. A time-based age multiplier (1.0 → 2.0 over 180 days) amplifies the penalty
   for unresolved issues — incentivising timely remediation.
4. Per-severity-tier caps prevent a single category from zeroing the score alone.
5. The final score is ``max(0, 100 − total_capped_deduction)``.

Grade thresholds (tunable via GRADE_THRESHOLDS):
  A  ≥ 90   excellent posture
  B  ≥ 75   good posture
  C  ≥ 60   moderate risk
  D  ≥ 40   significant risk
  F  <  40  critical risk
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Sequence

from .schema import RiskScore, Vulnerability

# ── Tunable constants ─────────────────────────────────────────────────────────

# Base penalty per open vulnerability (deducted from 100)
_SEVERITY_BASE: dict[str, float] = {
    "critical": 15.0,
    "high":      8.0,
    "medium":    3.0,
    "low":       0.5,
    "info":      0.0,
}

# Extra penalty headroom from CVSS score (0–10 maps to 0–3 extra points)
_CVSS_MAX_BONUS: float = 3.0

# Age multiplier range: fresh finding = 1.0×, fully aged = MAX_AGE_MULTIPLIER×
_MAX_AGE_MULTIPLIER: float = 2.0
_AGE_HALF_LIFE_DAYS: int   = 180   # reaches max multiplier at 180 days

# Per-tier caps on total deduction to prevent a single category from zeroing score
_TIER_CAP: dict[str, float] = {
    "critical": 60.0,   # worst case: 4 fully-aged CVSS-10 criticals → score 40
    "high":     30.0,
    "medium":   20.0,
    "low":       5.0,
    "info":      0.0,
}

# Grade thresholds (lower-bound inclusive)
GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (90.0, "A"),
    (75.0, "B"),
    (60.0, "C"),
    (40.0, "D"),
    (0.0,  "F"),
]


# ── Public helpers ────────────────────────────────────────────────────────────

def score_to_grade(score: float) -> str:
    """Map a 0–100 score to an A–F letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _age_multiplier(discovered_at: str, now: datetime) -> float:
    """Return 1.0 (fresh) → _MAX_AGE_MULTIPLIER (fully aged).

    Uses a linear ramp over _AGE_HALF_LIFE_DAYS so the function is
    easy to reason about and tune.
    """
    try:
        ts = discovered_at.rstrip("Z")
        # Handle both naive and offset-aware timestamps
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        days = max(0, (now - dt).days)
    except (ValueError, TypeError, OverflowError):
        days = 0

    progress = min(days / _AGE_HALF_LIFE_DAYS, 1.0)  # 0.0 … 1.0
    return 1.0 + progress * (_MAX_AGE_MULTIPLIER - 1.0)


def _penalty_for(vuln: Vulnerability, now: datetime) -> float:
    """Compute the raw penalty contribution of one open vulnerability."""
    base = _SEVERITY_BASE.get(vuln.severity, 0.0)
    if base == 0.0:
        return 0.0

    # CVSS bonus
    if vuln.cvss_score is not None:
        cvss_norm = max(0.0, min(vuln.cvss_score, 10.0)) / 10.0
        base += cvss_norm * _CVSS_MAX_BONUS

    return base * _age_multiplier(vuln.discovered_at, now)


# ── Main scoring function ────────────────────────────────────────────────────

def score_vulnerabilities(
    vulns: Sequence[Vulnerability],
    *,
    asset_id: str | None = None,
    vendor_label: str | None = None,
    now: datetime | None = None,
) -> RiskScore:
    """Compute a RiskScore from a sequence of Vulnerability objects.

    Only ``status == 'open'`` findings are counted; resolved / accepted /
    false-positive entries are ignored.

    Parameters
    ----------
    vulns:
        All vulnerabilities for the asset or vendor aggregate.
    asset_id:
        UUID of the specific asset being scored (optional — for tagging).
    vendor_label:
        Vendor/org label for aggregate scoring (optional — for tagging).
    now:
        Reference point for age calculation. Defaults to ``datetime.utcnow()``.
    """
    if now is None:
        now = datetime.utcnow()

    open_vulns = [v for v in vulns if v.status == "open"]

    by_severity: dict[str, int] = defaultdict(int)
    raw_deductions: dict[str, float] = defaultdict(float)
    top_candidates: list[tuple[float, dict]] = []  # (penalty, info_dict)
    oldest_days = 0

    for v in open_vulns:
        by_severity[v.severity] += 1
        pen = _penalty_for(v, now)
        raw_deductions[v.severity] += pen

        # Track top issues by impact
        top_candidates.append((pen, {
            "name":     v.name,
            "severity": v.severity,
            "cve":      v.cve,
            "category": v.category,
            "asset":    v.asset,
            "penalty":  round(pen, 2),
        }))

        # Track oldest open finding
        try:
            dt = datetime.fromisoformat(v.discovered_at.rstrip("Z").split("+")[0])
            days = max(0, (now - dt).days)
            oldest_days = max(oldest_days, days)
        except (ValueError, TypeError):
            pass

    # Apply per-tier caps
    deduction_by_severity: dict[str, float] = {}
    total_deduction = 0.0
    for sev, raw in raw_deductions.items():
        capped = min(raw, _TIER_CAP.get(sev, 0.0))
        deduction_by_severity[sev] = round(capped, 2)
        total_deduction += capped

    score = max(0.0, 100.0 - total_deduction)
    score = round(score, 1)

    # Top 5 highest-impact issues
    top_candidates.sort(key=lambda x: x[0], reverse=True)
    top_issues = [info for _, info in top_candidates[:5]]

    return RiskScore(
        score=score,
        grade=score_to_grade(score),
        open_count=len(open_vulns),
        by_severity=dict(by_severity),
        deduction_by_severity=deduction_by_severity,
        total_deduction=round(total_deduction, 2),
        top_issues=top_issues,
        oldest_open_days=oldest_days,
        scored_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        asset_id=asset_id,
        vendor_label=vendor_label,
    )
