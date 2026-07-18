"""Nuclei JSONL output parser.

Nuclei writes one JSON object per line (JSONL) when invoked with
``nuclei -o output.jsonl -json``.

Nuclei JSON object shape (relevant fields)
------------------------------------------
::

  {
    "template-id":   "CVE-2021-44228",
    "template":      "cves/2021/CVE-2021-44228.yaml",
    "info": {
      "name":        "Apache Log4j RCE",
      "severity":    "critical",
      "description": "...",
      "tags":        ["cve", "log4j", "rce"],
      "classification": {
        "cve-id":        "CVE-2021-44228",
        "cwe-id":        ["CWE-20"],
        "cvss-score":    10.0,
        "cvss-metrics":  "CVSS:3.1/AV:N/…"
      },
      "reference":   ["https://..."],
      "remediation": "Update to Log4j ≥ 2.15.0"
    },
    "type":          "http",
    "host":          "http://target.example.com",
    "matched-at":    "http://target.example.com/api/lookup?q=${jndi:ldap://…}",
    "ip":            "93.184.216.34",
    "timestamp":     "2024-01-01T12:00:00.000000000Z",
    "matcher-status": true,
    "curl-command":  "curl …"
  }

Notes
-----
* Lines that fail to parse as JSON are silently skipped.
* Findings with ``matcher-status == false`` are skipped (template matched
  but Nuclei determined it was not a true positive).
* Severity ``"unknown"`` is mapped to ``"info"``.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from urllib.parse import urlparse

from ..schema import AssetType, Severity, Vulnerability

# ── Severity mapping ──────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}

# ── Tag → category mapping ────────────────────────────────────────────────────

_TAG_CATEGORY: dict[str, str] = {
    "sqli":          "sqli",
    "sql":           "sqli",
    "xss":           "xss",
    "rce":           "rce",
    "lfi":           "path_traversal",
    "rfi":           "path_traversal",
    "ssrf":          "ssrf",
    "xxe":           "xxe",
    "ssti":          "template_injection",
    "csrf":          "csrf",
    "idor":          "broken_access_control",
    "auth-bypass":   "broken_auth",
    "misconfig":     "misconfiguration",
    "exposure":      "info_disclosure",
    "default-login": "default_credentials",
    "takeover":      "subdomain_takeover",
    "redirect":      "open_redirect",
    "cors":          "cors_misconfiguration",
    "ssl":           "tls_issue",
    "tls":           "tls_issue",
    "cve":           "cve",
    "intrusive":     "vulnerability",
    "panel":         "exposed_panel",
    "network":       "network_vulnerability",
    "dns":           "dns_misconfiguration",
    "token":         "sensitive_data_exposure",
    "secret":        "sensitive_data_exposure",
    "api":           "api_vulnerability",
}

_NAME_CATEGORY: list[tuple[str, str]] = [
    ("sql injection",    "sqli"),
    ("cross-site",       "xss"),
    ("remote code",      "rce"),
    ("command inject",   "os_command"),
    ("path traversal",   "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("server-side request", "ssrf"),
    ("xml external",     "xxe"),
    ("default password", "default_credentials"),
    ("default credential","default_credentials"),
    ("exposed",          "info_disclosure"),
    ("disclosure",       "info_disclosure"),
    ("takeover",         "subdomain_takeover"),
    ("misconfigur",      "misconfiguration"),
]


def _classify(template_id: str, tags: list[str], name: str) -> str:
    tid = template_id.lower()
    if re.match(r"cve-\d{4}-\d+", tid):
        return "cve"

    for tag in (t.lower() for t in tags):
        cat = _TAG_CATEGORY.get(tag)
        if cat:
            return cat

    n = name.lower()
    for keyword, cat in _NAME_CATEGORY:
        if keyword in n:
            return cat

    return "vulnerability"


def _asset_from_host(host: str, ip: str | None) -> tuple[str, AssetType]:
    """Resolve the best asset identifier and its type."""
    # Prefer the IP if it's provided and the host is an IP reference
    if ip and re.fullmatch(r"[\d.]+", ip):
        # Still use hostname for the identifier if it's a real hostname
        try:
            p = urlparse(host)
            h = p.netloc or host
            h = h.split(":")[0]
            if re.fullmatch(r"[\d.]+", h):
                return ip, "ip"
            return h, "domain"
        except Exception:
            return ip, "ip"

    try:
        p = urlparse(host)
        h = p.netloc or host
        h = h.split(":")[0]
        if re.fullmatch(r"[\d.]+", h):
            return h, "ip"
        return h, "domain"
    except Exception:
        return host, "url"


def _parse_timestamp(ts: str) -> str:
    """Normalise Nuclei's nanosecond timestamp to ISO-8601 UTC string."""
    # Strip nanoseconds (Go time.Time precision) and timezone suffix
    ts = ts.strip()
    # "2024-01-01T12:00:00.000000000Z" → "2024-01-01T12:00:00"
    ts = re.sub(r"\.\d+", "", ts).rstrip("Z").replace("+00:00", "")
    try:
        datetime.fromisoformat(ts)  # validate
        return ts + "Z"
    except ValueError:
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Line → Vulnerability ─────────────────────────────────────────────────────

def _parse_line(obj: dict, source_file: str | None) -> Vulnerability | None:
    # Skip non-matches
    if not obj.get("matcher-status", True):
        return None

    info = obj.get("info") or {}
    name = (info.get("name") or obj.get("template-id") or "Unknown").strip()
    template_id = (obj.get("template-id") or "").strip()
    tags: list[str] = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    # Severity
    sev_raw = (info.get("severity") or "unknown").lower()
    sev: Severity = _SEVERITY_MAP.get(sev_raw, "info")

    # Classification block
    cls = info.get("classification") or {}
    cve_raw  = cls.get("cve-id") or ""
    cve: str | None = cve_raw.upper() if cve_raw else None
    if cve and not re.match(r"CVE-\d{4}-\d+", cve):
        cve = None

    cvss: float | None = None
    if cls.get("cvss-score") is not None:
        try:
            cvss = float(cls["cvss-score"])
        except (TypeError, ValueError):
            pass

    cwe_raw = cls.get("cwe-id") or ""
    if isinstance(cwe_raw, list):
        cwe_raw = cwe_raw[0] if cwe_raw else ""
    cwe: str | None = str(cwe_raw).strip() or None

    desc = (info.get("description") or "").strip()
    remediation = (info.get("remediation") or "").strip() or None

    host  = (obj.get("host") or "").strip()
    ip    = (obj.get("ip") or "").strip() or None
    matched_at = (obj.get("matched-at") or "").strip()

    asset, atype = _asset_from_host(host, ip)

    ts_raw = obj.get("timestamp") or ""
    discovered_at = _parse_timestamp(ts_raw) if ts_raw else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    category = _classify(template_id, tags, name)

    # Try to pull a port from the matched URL or host
    port: int | None = None
    try:
        p = urlparse(host)
        if p.port:
            port = p.port
    except Exception:
        pass

    return Vulnerability(
        id=str(uuid.uuid4()),
        asset=asset,
        asset_type=atype,
        source_tool="nuclei",
        source_file=source_file,
        name=name,
        description=desc[:800],
        severity=sev,
        category=category,
        cvss_score=cvss,
        cve=cve,
        cwe=cwe,
        port=port,
        url=matched_at or host or None,
        evidence=(
            f"Template: {template_id}"
            + (f" | Matched: {matched_at}" if matched_at else "")
        ),
        remediation=(remediation[:500] if remediation else None),
        discovered_at=discovered_at,
        last_seen_at=discovered_at,
    )


# ── Main parser ───────────────────────────────────────────────────────────────

def parse(content: str, source_file: str | None = None) -> list[Vulnerability]:
    """Parse Nuclei JSONL *content* and return normalised vulnerabilities.

    Each non-blank line is parsed independently; lines that fail to decode
    as JSON are silently skipped so a partial file doesn't abort the import.
    """
    results: list[Vulnerability] = []
    for lineno, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Nuclei sometimes emits progress lines that aren't JSON
            continue
        if not isinstance(obj, dict):
            continue
        v = _parse_line(obj, source_file)
        if v is not None:
            results.append(v)
    return results
