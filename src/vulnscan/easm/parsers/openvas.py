"""OpenVAS / Greenbone Vulnerability Manager XML output parser.

Handles two XML formats produced by GVM:
  1. Direct API output from ``gmp.get_results()``::

       <get_results_response status="200">
         <result id="...">…</result>
       </get_results_response>

  2. Report export format::

       <report>
         <results>
           <result id="...">…</result>
         </results>
       </report>

Each ``<result>`` element becomes one normalised Vulnerability.
Results with a CVSS severity of 0.0 (log / false-positive markers) are
classified as "info" rather than being silently dropped.
"""
from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime

from ..schema import AssetType, Severity, Vulnerability

# ── CVSS → severity ───────────────────────────────────────────────────────────

def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# ── Finding categorisation ────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

_CATEGORY_KEYWORDS: list[tuple[str, str]] = [
    ("default credential", "default_credentials"),
    ("weak password",      "weak_credentials"),
    ("anonymous",          "anonymous_access"),
    ("brute",              "brute_force_susceptible"),
    ("ssl",                "tls_issue"),
    ("tls",                "tls_issue"),
    ("open port",          "open_port"),
    ("service detection",  "service_detection"),
    ("remote code",        "rce"),
    ("command injection",  "os_command"),
    ("sql injection",      "sqli"),
    ("xss",                "xss"),
    ("cross-site",         "xss"),
    ("buffer overflow",    "buffer_overflow"),
    ("heap",               "memory_corruption"),
    ("directory traversal","path_traversal"),
    ("information disclosure", "info_disclosure"),
]


def _classify(name: str, cve: str) -> str:
    if cve:
        return "cve"
    n = name.lower()
    for keyword, category in _CATEGORY_KEYWORDS:
        if keyword in n:
            return category
    return "vulnerability"


def _guess_asset_type(addr: str) -> AssetType:
    if re.fullmatch(r"[\d.]+", addr) or ":" in addr:
        return "ip"
    return "domain"


# ── Result → Vulnerability ────────────────────────────────────────────────────

def _parse_result(result_el: ET.Element, now_iso: str,
                  source_file: str | None) -> Vulnerability | None:
    name = result_el.findtext("name", "").strip()
    if not name:
        return None

    desc      = result_el.findtext("description", "").strip()
    host_raw  = (result_el.findtext("host") or "").strip()
    port_text = result_el.findtext("port", "").strip()

    # CVSS score
    cvss_text = result_el.findtext("severity", "0").strip()
    try:
        cvss = float(cvss_text)
    except ValueError:
        cvss = 0.0

    sev = _cvss_to_severity(cvss)

    # NVT / CVE references
    nvt = result_el.find("nvt")
    cve: str | None = None
    solution: str | None = None
    cwe: str | None = None

    if nvt is not None:
        for ref in nvt.findall("refs/ref"):
            rtype = ref.get("type", "").lower()
            if rtype == "cve" and not cve:
                cve = ref.get("id", "").upper() or None
            if rtype == "cwe" and not cwe:
                cwe = ref.get("id", "") or None
        solution = (nvt.findtext("solution") or "").strip() or None

    # Also check for inline CVE mention in description
    if not cve:
        m = _CVE_RE.search(name + " " + desc)
        if m:
            cve = m.group(0).upper()

    # Port parsing: "443/tcp", "22", "general/tcp"
    port_num: int | None = None
    protocol: str | None = None
    if port_text and port_text not in ("general/tcp", "general/udp", ""):
        parts = port_text.split("/")
        try:
            port_num = int(parts[0])
        except ValueError:
            pass
        if len(parts) > 1:
            protocol = parts[1].lower()

    asset = host_raw or "unknown"
    atype = _guess_asset_type(asset)

    return Vulnerability(
        id=str(uuid.uuid4()),
        asset=asset,
        asset_type=atype,
        source_tool="openvas",
        source_file=source_file,
        name=name,
        description=desc[:800],
        severity=sev,
        category=_classify(name, cve or ""),
        cvss_score=cvss if cvss > 0 else None,
        cve=cve,
        cwe=cwe,
        port=port_num,
        protocol=protocol,
        evidence=f"CVSS: {cvss:.1f}" + (f" | CVE: {cve}" if cve else ""),
        remediation=(solution[:500] if solution else None),
        discovered_at=now_iso,
        last_seen_at=now_iso,
    )


# ── Main parser ───────────────────────────────────────────────────────────────

def parse(content: str, source_file: str | None = None) -> list[Vulnerability]:
    """Parse OpenVAS XML *content* and return normalised vulnerabilities."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid OpenVAS XML: {exc}") from exc

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Support both response wrapper formats
    tag = root.tag
    if tag == "get_results_response":
        result_els = root.findall("result")
    elif tag == "report":
        result_els = root.findall("results/result")
        if not result_els:
            # Some exports nest deeper: <report><report><results>
            result_els = root.findall("report/results/result")
    else:
        # Fallback: search for any <result> elements
        result_els = root.findall(".//result")

    results: list[Vulnerability] = []
    for el in result_els:
        v = _parse_result(el, now_iso, source_file)
        if v is not None:
            results.append(v)

    return results
