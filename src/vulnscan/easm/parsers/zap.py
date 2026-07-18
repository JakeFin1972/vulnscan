"""OWASP ZAP JSON output parser.

Handles the JSON format produced by ZAP's built-in report generator and its
REST API (``/JSON/core/view/alerts/``).

Supported document shapes
--------------------------
1. ZAP report JSON::

     {"site": [{"name": "...", "host": "...", "alerts": [...]}]}

2. ZAP API response (direct)::

     {"alerts": [...]}

3. Single alerts array (useful for testing)::

     [{"name": "...", "risk": "High", ...}]

Alert fields consumed
---------------------
name, risk, confidence, description, solution, url, evidence,
cweid, wascid, param, pluginid, reference, instances
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from urllib.parse import urlparse

from ..schema import AssetType, Severity, Vulnerability

# ── Risk level mapping ────────────────────────────────────────────────────────

_RISK_MAP: dict[str, Severity] = {
    "high":          "high",
    "medium":        "medium",
    "low":           "low",
    "informational": "info",
    "info":          "info",
    "false positive": None,  # type: ignore[assignment]  excluded
}

# Categories that should be elevated to critical severity
_CRITICAL_CATEGORIES = frozenset({
    "sqli", "sql_injection", "os_command", "rce",
    "remote_code_execution", "code_injection",
})

# CWE → category mapping (subset of common web vulns)
_CWE_CATEGORY: dict[str, str] = {
    "89":  "sqli",
    "78":  "os_command",
    "79":  "xss",
    "94":  "code_injection",
    "22":  "path_traversal",
    "611": "xxe",
    "918": "ssrf",
    "601": "open_redirect",
    "200": "info_disclosure",
    "352": "csrf",
    "285": "broken_access_control",
    "306": "missing_authentication",
    "319": "cleartext_transmission",
    "327": "weak_crypto",
}

_KEYWORD_CATEGORY: list[tuple[str, str]] = [
    ("sql injection",          "sqli"),
    ("sql",                    "sqli"),
    ("cross site scripting",   "xss"),
    ("xss",                    "xss"),
    ("cross-site scripting",   "xss"),
    ("command injection",      "os_command"),
    ("remote code",            "rce"),
    ("path traversal",         "path_traversal"),
    ("directory traversal",    "path_traversal"),
    ("xml external",           "xxe"),
    ("server side request",    "ssrf"),
    ("open redirect",          "open_redirect"),
    ("csrf",                   "csrf"),
    ("clickjack",              "clickjacking"),
    ("cors",                   "cors_misconfiguration"),
    ("security header",        "missing_security_header"),
    ("content security policy","missing_security_header"),
    ("strict-transport",       "missing_hsts"),
    ("cookie",                 "cookie_misconfiguration"),
    ("ssl",                    "tls_issue"),
    ("tls",                    "tls_issue"),
    ("information disclosure", "info_disclosure"),
    ("error message",          "info_disclosure"),
    ("stack trace",            "info_disclosure"),
    ("authentication",         "broken_auth"),
    ("session",                "session_issue"),
]


def _classify_alert(name: str, cwe_id: str) -> tuple[str, Severity | None]:
    """Return (category, elevated_severity_or_None)."""
    if cwe_id.strip():
        cat = _CWE_CATEGORY.get(cwe_id.strip())
        if cat:
            sev_override = "critical" if cat in _CRITICAL_CATEGORIES else None
            return cat, sev_override  # type: ignore[return-value]

    n = name.lower()
    for keyword, category in _KEYWORD_CATEGORY:
        if keyword in n:
            override = "critical" if category in _CRITICAL_CATEGORIES else None
            return category, override  # type: ignore[return-value]

    return "web_vulnerability", None


def _asset_from_url(url: str) -> tuple[str, AssetType]:
    try:
        p = urlparse(url)
        host = p.netloc or url
        # Strip port
        host = host.split(":")[0]
        if re.fullmatch(r"[\d.]+", host):
            return host, "ip"
        return host, "domain"
    except Exception:
        return url, "url"


# ── Alert → Vulnerability ────────────────────────────────────────────────────

def _alert_to_vuln(alert: dict, default_host: str,
                   now_iso: str, source_file: str | None) -> Vulnerability | None:
    name = (alert.get("name") or "").strip()
    if not name:
        return None

    risk_raw = (alert.get("risk") or "").lower()
    if risk_raw == "false positive":
        return None
    confidence = (alert.get("confidence") or "").lower()
    if confidence == "false positive":
        return None

    base_sev = _RISK_MAP.get(risk_raw)
    if base_sev is None:
        return None

    cwe_id = str(alert.get("cweid") or "").strip()
    category, sev_override = _classify_alert(name, cwe_id)
    sev: Severity = sev_override or base_sev  # type: ignore[assignment]

    url = (alert.get("url") or "").strip()
    asset, atype = _asset_from_url(url or default_host)

    desc = (alert.get("description") or "").strip()
    solution = (alert.get("solution") or "").strip() or None
    evidence = (alert.get("evidence") or "").strip() or None
    param = (alert.get("param") or "").strip()
    if param:
        evidence = (f"param={param!r}" + (f" | {evidence}" if evidence else ""))

    cwe = f"CWE-{cwe_id}" if cwe_id else None

    return Vulnerability(
        id=str(uuid.uuid4()),
        asset=asset,
        asset_type=atype,
        source_tool="zap",
        source_file=source_file,
        name=name,
        description=desc[:800],
        severity=sev,
        category=category,
        cwe=cwe,
        url=url or None,
        evidence=evidence,
        remediation=(solution[:500] if solution else None),
        discovered_at=now_iso,
        last_seen_at=now_iso,
    )


# ── Document shape normaliser ────────────────────────────────────────────────

def _extract_alerts(doc: object) -> list[tuple[str, dict]]:
    """Return [(host, alert_dict), …] from any supported ZAP JSON shape."""
    pairs: list[tuple[str, dict]] = []

    if isinstance(doc, list):
        # Bare alerts array
        for a in doc:
            if isinstance(a, dict):
                pairs.append(("", a))
        return pairs

    if isinstance(doc, dict):
        # Direct API response: {"alerts": [...]}
        if "alerts" in doc:
            for a in doc["alerts"]:
                pairs.append(("", a))
            return pairs

        # Report format: {"site": [{..., "alerts": [...]}]}
        for site in doc.get("site", []):
            if not isinstance(site, dict):
                continue
            host = site.get("host") or site.get("name") or ""
            for a in site.get("alerts", []):
                pairs.append((host, a))
        return pairs

    return pairs


# ── Main parser ───────────────────────────────────────────────────────────────

def parse(content: str, source_file: str | None = None) -> list[Vulnerability]:
    """Parse ZAP JSON *content* and return normalised vulnerabilities."""
    try:
        doc = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid ZAP JSON: {exc}") from exc

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    alert_pairs = _extract_alerts(doc)

    results: list[Vulnerability] = []
    for host, alert in alert_pairs:
        v = _alert_to_vuln(alert, host, now_iso, source_file)
        if v is not None:
            results.append(v)

    return results
