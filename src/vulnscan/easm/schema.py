"""Unified Vulnerability schema for EASM data normalization.

All parsers (Nmap, OpenVAS, ZAP, Nuclei) produce ``Vulnerability`` objects.
The scoring engine and API consume only this type — never raw tool output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# ── Type aliases ──────────────────────────────────────────────────────────────

Severity   = Literal["critical", "high", "medium", "low", "info"]
VulnStatus = Literal["open", "resolved", "accepted_risk", "false_positive"]
AssetType  = Literal["ip", "domain", "url", "cidr"]
SourceTool = Literal["nmap", "openvas", "zap", "nuclei", "manual"]

# Numeric weight for sorting; higher = worse.
SEVERITY_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


# ── Core dataclasses ──────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """One normalised finding from any scanner tool.

    ``id`` is a caller-supplied UUID string.
    ``asset`` is the raw string from the scan (IP, hostname, URL).
    ``discovered_at`` / ``last_seen_at`` are ISO-8601 strings (UTC).
    """
    id:           str
    asset:        str            # e.g. "192.168.1.1" or "https://example.com"
    asset_type:   AssetType      # ip | domain | url | cidr
    source_tool:  SourceTool     # nmap | openvas | zap | nuclei | manual
    name:         str            # short title
    description:  str
    severity:     Severity
    category:     str            # open_port | cve | xss | sqli | tls_issue | …
    discovered_at: str           # ISO-8601
    last_seen_at:  str           # ISO-8601

    source_file:  str | None = None   # original input file path/name
    cvss_score:   float | None = None # 0.0–10.0
    cve:          str | None = None   # "CVE-YYYY-NNNNN"
    cwe:          str | None = None   # "CWE-NNN"
    port:         int | None = None
    protocol:     str | None = None   # "tcp" | "udp"
    url:          str | None = None
    evidence:     str | None = None
    remediation:  str | None = None
    resolved_at:  str | None = None
    status:       VulnStatus = "open"


@dataclass
class AssetInfo:
    """A tracked attack-surface asset."""
    id:         str
    identifier: str       # primary key within an org: hostname, IP, CIDR, URL
    asset_type: AssetType
    label:      str | None = None   # friendly name or vendor/org tag
    tags:       list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""


@dataclass
class RiskScore:
    """Point-in-time risk score for one asset (or a vendor aggregate)."""
    score:      float           # 0–100; higher = better security posture
    grade:      str             # A | B | C | D | F
    open_count: int             # total open vulnerabilities counted
    by_severity: dict[str, int] = field(default_factory=dict)   # sev → count
    deduction_by_severity: dict[str, float] = field(default_factory=dict)
    total_deduction: float = 0.0
    top_issues: list[dict] = field(default_factory=list)        # top 5 by impact
    oldest_open_days: int = 0
    scored_at:  str = ""
    asset_id:   str | None = None
    vendor_label: str | None = None
