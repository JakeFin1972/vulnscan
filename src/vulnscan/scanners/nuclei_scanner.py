"""Nuclei scanner — CVE and template-based vulnerability detection.

Runs the Nuclei CLI as a subprocess and streams JSONL findings back as
DynamicFindings. Nuclei has 10 000+ templates covering:
  - CVE detection (including protocol-level: T3, IIOP, SMB, RDP, …)
  - Exposed panels, misconfigurations, default credentials
  - Technology fingerprinting

Prerequisites:
  nuclei binary in PATH (brew install nuclei  /  go install …)
  nuclei -update-templates  (run once to fetch templates)

Options (passed via the 'nuclei' key in DynamicScanRequest.options):
  severity      list[str]  — filter, e.g. ["critical","high"]  (default: all)
  tags          list[str]  — e.g. ["cve","weblogic","rce"]
  templates     list[str]  — specific template IDs, e.g. ["CVE-2023-21839"]
  rate_limit    int        — requests/sec (default: 150)
  timeout       int        — per-request timeout seconds (default: 10)
  no_interactsh bool       — disable OOB callbacks (default: False)
  scan_timeout  int        — total scan wall-clock timeout seconds (default: 300)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .base import DynamicFinding, Severity

_NUCLEI_BIN: str | None = shutil.which("nuclei")


def _find_nuclei_templates() -> Path | None:
    """Return the nuclei-templates root directory, or None if not found."""
    candidates = [
        Path.home() / "nuclei-templates",
        Path(os.environ.get("HOME", "")) / "nuclei-templates",
        Path("/opt/homebrew/share/nuclei-templates"),
        Path("/usr/local/share/nuclei-templates"),
    ]
    for p in candidates:
        if p.is_dir():
            return p
    return None

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}


def is_available() -> bool:
    return _NUCLEI_BIN is not None


def scan(
    target: str,
    options: dict | None = None,
) -> list[DynamicFinding]:
    """Run Nuclei against *target* and return findings as DynamicFindings.

    Streams JSONL output line-by-line so large scans return progressively.
    Falls back to an info finding if nuclei is not installed or fails.
    """
    if not _NUCLEI_BIN:
        return [DynamicFinding(
            tool="nuclei", target=target,
            name="nuclei not installed",
            description=(
                "Install nuclei: brew install nuclei\n"
                "Update templates: nuclei -update-templates"
            ),
            severity="info", category="scanner_unavailable",
        )]

    opts = options or {}
    severity_filter  = opts.get("severity",   [])     # [] = all
    tag_filter       = opts.get("tags",        [])
    template_ids     = opts.get("templates",   [])
    rate_limit       = int(opts.get("rate_limit",    150))
    no_interactsh    = bool(opts.get("no_interactsh", False))
    scan_timeout     = int(opts.get("scan_timeout",  300))

    # Detect non-HTTP targets (host:port, bare IP, hostname without scheme).
    # Network/TCP templates need a longer per-request timeout and must not have
    # -timeout set too short — nuclei's default (10s) kills most TCP templates.
    _is_network_target = not target.startswith("http")
    per_req_timeout = int(opts.get("timeout", 30 if _is_network_target else 10))

    cmd: list[str] = [
        _NUCLEI_BIN,
        "-target",  target,
        "-j",               # JSONL output to stdout
        "-silent",          # suppress banner / progress to stderr
        "-rl",  str(rate_limit),
        "-timeout", str(per_req_timeout),
    ]

    # For non-HTTP targets (host:port / bare hostname), nuclei silently skips
    # TCP/network protocol templates when tag or severity filters are active.
    # Fix: point nuclei directly at the network templates directory so it always
    # evaluates TCP CVEs (Redis, SMB, RDP, etc.) regardless of filter flags.
    _NUCLEI_TEMPLATES = _find_nuclei_templates()
    if _is_network_target and _NUCLEI_TEMPLATES and not template_ids:
        # network/ covers CVEs and misconfigs for non-HTTP services
        cmd += ["-t", str(_NUCLEI_TEMPLATES / "network")]

    if severity_filter:
        cmd += ["-severity", ",".join(severity_filter)]
    if tag_filter:
        cmd += ["-tags", ",".join(tag_filter)]
    if template_ids:
        for tid in template_ids:
            cmd += ["-id", tid]
    if no_interactsh:
        cmd += ["-no-interactsh"]

    findings: list[DynamicFinding] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            stdout, _ = proc.communicate(timeout=scan_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
            findings.append(DynamicFinding(
                tool="nuclei", target=target,
                name="Nuclei scan timed out",
                description=f"Scan exceeded {scan_timeout}s. Partial results returned.",
                severity="info", category="scanner_error",
            ))

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            finding = _parse_line(line, target)
            if finding:
                findings.append(finding)

    except FileNotFoundError:
        return [DynamicFinding(
            tool="nuclei", target=target,
            name="nuclei binary not found",
            description="Install nuclei: brew install nuclei",
            severity="info", category="scanner_unavailable",
        )]
    except Exception as exc:  # noqa: BLE001
        return [DynamicFinding(
            tool="nuclei", target=target,
            name=f"Nuclei scan error: {type(exc).__name__}",
            description=str(exc)[:500],
            severity="info", category="scanner_error",
        )]

    return findings


def _parse_line(line: str, default_target: str) -> DynamicFinding | None:
    try:
        obj: dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        return None

    info: dict = obj.get("info", {})
    classification: dict = info.get("classification", {})

    severity_raw = info.get("severity", "info").lower()
    severity: Severity = _SEVERITY_MAP.get(severity_raw, "info")

    name        = info.get("name", obj.get("template-id", "Unknown"))
    template_id = obj.get("template-id", "")
    description = info.get("description", "").strip()
    remediation = info.get("remediation", "").strip() or None
    matched_at  = obj.get("matched-at", "") or obj.get("host", default_target)
    extracted   = obj.get("extracted-results", [])

    # cve-id / cwe-id may be null, a string, or a list depending on template
    _cve_raw = classification.get("cve-id") or ""
    cve_id   = (_cve_raw[0] if isinstance(_cve_raw, list) else _cve_raw) or _extract_cve(template_id)
    cvss     = classification.get("cvss-score")
    _cwe_raw = classification.get("cwe-id") or ""
    cwe_str  = ", ".join(_cwe_raw) if isinstance(_cwe_raw, list) else str(_cwe_raw)
    tags     = info.get("tags", [])

    # Build evidence string
    evidence_parts: list[str] = []
    if cvss:
        evidence_parts.append(f"CVSS: {cvss}")
    if cwe_str:
        evidence_parts.append(f"CWE: {cwe_str}")
    if extracted:
        evidence_parts.append("Extracted: " + ", ".join(str(x) for x in extracted[:5]))
    evidence = " | ".join(evidence_parts) if evidence_parts else ""

    # Map to category
    category = _classify(template_id, name, tags, cve_id)

    # Infer port
    port_str = obj.get("port")
    port: int | None = None
    if port_str:
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            pass

    return DynamicFinding(
        tool="nuclei",
        target=matched_at or default_target,
        name=f"{name}" + (f" ({cve_id})" if cve_id else ""),
        description=description[:800] if description else f"Nuclei template match: {template_id}",
        severity=severity,
        category=category,
        evidence=evidence[:400],
        url=matched_at if matched_at.startswith("http") else None,
        port=port,
        cve=cve_id or None,
        remediation=remediation[:400] if remediation else None,
    )


def _extract_cve(template_id: str) -> str:
    """Return 'CVE-YYYY-NNNNN' if the template ID is a CVE id."""
    upper = template_id.upper()
    if upper.startswith("CVE-"):
        return upper
    return ""


def _classify(template_id: str, name: str, tags: list[str], cve: str) -> str:
    if cve:
        return "cve"
    combined = (template_id + " " + name + " " + " ".join(tags)).lower()
    pairs = [
        ("sql",                 "sql_injection"),
        ("xss",                 "xss"),
        ("rce",                 "rce"),
        ("command",             "os_command_injection"),
        ("ssrf",                "ssrf"),
        ("xxe",                 "xxe"),
        ("lfi",                 "path_traversal"),
        ("traversal",           "path_traversal"),
        ("redirect",            "open_redirect"),
        ("deseri",              "unsafe_deserialization"),
        ("default-login",       "default_credentials"),
        ("default-credential",  "default_credentials"),
        ("weak",                "weak_credentials"),
        ("exposure",            "information_disclosure"),
        ("disclosure",          "information_disclosure"),
        ("panel",               "exposed_panel"),
        ("login",               "exposed_panel"),
        ("misconfig",           "misconfiguration"),
        ("cors",                "cors_misconfiguration"),
        ("tls",                 "tls_issue"),
        ("ssl",                 "tls_issue"),
        ("header",              "missing_security_header"),
        ("csrf",                "csrf"),
        ("tech",                "technology_fingerprint"),
        ("detect",              "technology_fingerprint"),
        ("takeover",            "subdomain_takeover"),
    ]
    for kw, cat in pairs:
        if kw in combined:
            return cat
    return "vulnerability"
