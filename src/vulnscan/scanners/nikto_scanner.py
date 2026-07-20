"""Nikto web server scanner.

Checks a URL/host for:
  - Dangerous / interesting files and directories
  - Outdated server software and known CVEs
  - Default credentials and admin interfaces
  - Server misconfiguration (directory listing, HTTP methods, etc.)
  - Security header gaps (complements the built-in http scanner)

Install:
  brew install nikto          # macOS
  apt install nikto           # Debian/Ubuntu

Nikto is invoked with XML output redirected to a temp file, then parsed.
Plain-text stderr (scan progress) is suppressed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .base import DynamicFinding

TOOL = "nikto"


def is_available() -> bool:
    return shutil.which("nikto") is not None


def scan(target: str, options: dict[str, Any] | None = None) -> list[DynamicFinding]:
    """Run Nikto against *target* (URL or host[:port]) and return findings."""
    if not is_available():
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="nikto not installed",
            description=(
                "Install nikto:\n"
                "  brew install nikto         # macOS\n"
                "  apt install nikto          # Debian/Ubuntu"
            ),
            severity="info", category="scanner_unavailable",
        )]

    opts     = options or {}
    timeout  = int(opts.get("timeout", 300))
    tuning   = str(opts.get("tuning", ""))   # nikto -Tuning, e.g. "1234"
    plugins  = str(opts.get("plugins", ""))  # nikto -Plugins

    url = _normalise_url(target)

    tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    tmp.close()
    outfile = Path(tmp.name)

    cmd = [
        "nikto",
        "-h", url,
        "-Format", "xml",
        "-output", str(outfile),
        "-nointeractive",
        "-maxtime", f"{timeout}s",
    ]
    if tuning:
        cmd += ["-Tuning", tuning]
    if plugins:
        cmd += ["-Plugins", plugins]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # outer timeout > nikto -maxtime
        )
    except subprocess.TimeoutExpired:
        outfile.unlink(missing_ok=True)
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="Nikto scan timed out",
            description=f"Nikto did not complete within {timeout}s.",
            severity="info", category="scanner_error",
        )]
    except FileNotFoundError:
        outfile.unlink(missing_ok=True)
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="nikto binary not found",
            description="nikto was not found in PATH at scan time.",
            severity="info", category="scanner_unavailable",
        )]
    except Exception as exc:  # noqa: BLE001
        outfile.unlink(missing_ok=True)
        return [DynamicFinding(
            tool=TOOL, target=target,
            name=f"Nikto error: {type(exc).__name__}",
            description=str(exc)[:400],
            severity="info", category="scanner_error",
        )]

    try:
        content = outfile.read_text(errors="replace")
    except OSError:
        content = ""
    finally:
        outfile.unlink(missing_ok=True)

    if not content.strip():
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="Nikto returned no output",
            description="Nikto produced no XML output. The target may be unreachable.",
            severity="info", category="scanner_info",
        )]

    return _parse_xml(content, target, url)


# ── URL normalisation ─────────────────────────────────────────────────────────

def _normalise_url(target: str) -> str:
    if "://" in target:
        return target
    # host:port — keep as-is; nikto handles it
    return f"http://{target}"


# ── XML parsing ───────────────────────────────────────────────────────────────

# Keyword → (category, severity) pairs — checked in order
_CLASSIFY: list[tuple[str, str, str]] = [
    # Critical
    ("default password",      "default_credentials",    "critical"),
    ("default credential",    "default_credentials",    "critical"),
    ("admin interface",       "admin_exposure",         "critical"),
    ("phpMyAdmin",            "admin_exposure",         "critical"),
    ("wp-login",              "admin_exposure",         "high"),
    (".git",                  "sensitive_file_exposed",  "critical"),
    (".env",                  "sensitive_file_exposed",  "critical"),
    ("backup",                "sensitive_file_exposed",  "high"),
    # High
    ("sql injection",         "sqli",                   "high"),
    ("cross-site script",     "xss",                    "high"),
    ("xss",                   "xss",                    "high"),
    ("remote file inclus",    "rfi",                    "high"),
    ("directory traversal",   "path_traversal",         "high"),
    ("path traversal",        "path_traversal",         "high"),
    ("remote code execut",    "rce",                    "high"),
    ("command injection",     "os_command",             "high"),
    ("arbitrary file",        "sensitive_file_exposed",  "high"),
    ("sensitive file",        "sensitive_file_exposed",  "high"),
    ("directory index",       "directory_listing",      "high"),
    ("directory listing",     "directory_listing",      "high"),
    ("index of /",            "directory_listing",      "high"),
    ("put method",            "dangerous_http_method",  "high"),
    ("delete method",         "dangerous_http_method",  "high"),
    ("webdav",                "dangerous_http_method",  "high"),
    ("cgi",                   "cgi_vulnerability",      "high"),
    ("shellshock",            "cve",                    "critical"),
    # Medium
    ("outdated",              "outdated_software",      "medium"),
    ("obsolete",              "outdated_software",      "medium"),
    ("options method",        "dangerous_http_method",  "medium"),
    ("trace method",          "dangerous_http_method",  "medium"),
    ("debug",                 "misconfiguration",       "medium"),
    ("test page",             "misconfiguration",       "medium"),
    ("phpinfo",               "information_disclosure",  "medium"),
    ("server-status",         "information_disclosure",  "medium"),
    ("stack trace",           "information_disclosure",  "medium"),
    ("error message",         "information_disclosure",  "medium"),
    # Low
    ("version",               "information_disclosure",  "low"),
    ("banner",                "information_disclosure",  "low"),
    ("header",                "missing_security_header", "low"),
    ("cookie",                "insecure_cookie",         "low"),
    ("uncommon header",       "missing_security_header", "low"),
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _classify(desc: str) -> tuple[str, str]:
    """Return (category, severity) for a nikto finding description."""
    dl = desc.lower()
    for keyword, category, severity in _CLASSIFY:
        if keyword.lower() in dl:
            return category, severity
    return "vulnerability", "medium"


def _parse_xml(content: str, target: str, url: str) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Nikto sometimes emits partial XML on timeout — try to salvage items
        try:
            content_fixed = content + "</scandetails></niktoscan>"
            root = ET.fromstring(content_fixed)
        except ET.ParseError as exc:
            return [DynamicFinding(
                tool=TOOL, target=target,
                name="Nikto XML parse error",
                description=f"Could not parse Nikto output: {exc}\nFirst 200 chars: {content[:200]}",
                severity="info", category="scanner_error",
            )]

    for item in root.findall(".//item"):
        desc_el = item.find("description")
        uri_el  = item.find("uri")

        desc = (desc_el.text or "").strip() if desc_el is not None else ""
        uri  = (uri_el.text  or "").strip() if uri_el  is not None else ""

        if not desc:
            continue

        category, severity = _classify(desc)

        # Extract CVE if present
        cve_match = _CVE_RE.search(desc)
        cve = cve_match.group(0).upper() if cve_match else None

        # Build full URL for the finding
        finding_url: str | None = None
        if uri:
            parsed = urllib.parse.urlparse(url)
            finding_url = f"{parsed.scheme}://{parsed.netloc}{uri}"

        # OSVDB reference (informational)
        osvdb = item.get("osvdbid", "") or ""
        evidence = f"OSVDB-{osvdb}" if osvdb and osvdb != "0" else ""
        if cve:
            evidence = f"{cve}" + (f" | {evidence}" if evidence else "")

        findings.append(DynamicFinding(
            tool=TOOL,
            target=target,
            name=_short_title(desc),
            description=desc,
            severity=severity,  # type: ignore[arg-type]
            category=category,
            evidence=evidence,
            url=finding_url,
            cve=cve,
            remediation=_remediation(category),
        ))

    if not findings:
        findings.append(DynamicFinding(
            tool=TOOL, target=target,
            name="Nikto found no issues",
            description="Nikto completed its scan and reported no findings.",
            severity="info", category="scanner_info",
        ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _short_title(desc: str) -> str:
    """Trim description to a one-line title (≤80 chars)."""
    line = desc.splitlines()[0].strip()
    return line[:80] + ("…" if len(line) > 80 else "")


_REMEDIATIONS: dict[str, str] = {
    "default_credentials":    "Change default credentials immediately.",
    "admin_exposure":         "Restrict access to admin interfaces via IP allowlist or authentication.",
    "sensitive_file_exposed": "Remove the file from the webroot or block access via web server config.",
    "directory_listing":      "Disable directory listing in your web server configuration.",
    "dangerous_http_method":  "Disable unused HTTP methods (PUT, DELETE, TRACE, OPTIONS) in server config.",
    "outdated_software":      "Upgrade the server software to the latest stable release.",
    "information_disclosure": "Remove version strings and error details from server responses.",
    "missing_security_header":"Add the appropriate security response header.",
    "insecure_cookie":        "Set Secure, HttpOnly, and SameSite flags on all session cookies.",
    "sqli":                   "Use parameterised queries / prepared statements.",
    "xss":                    "HTML-encode all user-supplied output and apply a Content-Security-Policy.",
    "path_traversal":         "Validate and sanitise file path inputs; use a chroot/sandbox.",
    "rce":                    "Patch immediately and restrict shell execution from web context.",
    "os_command":             "Avoid passing user input to shell commands; use allowlists.",
    "cgi_vulnerability":      "Update or remove the vulnerable CGI script.",
}


def _remediation(category: str) -> str | None:
    return _REMEDIATIONS.get(category)
