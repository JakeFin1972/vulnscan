"""Shared types for dynamic (runtime) scanners.

Static analysis (recon.py + language backends) works on source code.
Dynamic scanners work on live targets — URLs, hosts, MCP servers — and
require external tools (nmap, ZAP, OpenVAS/GVM) or the MCP protocol.

All scanners must:
  • Return [] gracefully when the tool is not installed / not running.
  • Never raise unhandled exceptions — wrap tool errors in DynamicFinding
    entries with severity="info" and category="scanner_error".
  • Honor authorization: the caller is responsible for confirming that the
    target is authorized before invoking a scanner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

TargetType = Literal["url", "host", "mcp"]
ScanTool   = Literal["nmap", "http", "api", "zap", "openvas", "mcp", "nuclei", "sslyze", "subfinder"]
Severity   = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class DynamicFinding:
    tool:        str           # nmap | zap | openvas | mcp
    target:      str           # the scanned target string
    name:        str           # short finding title
    description: str           # human-readable explanation
    severity:    Severity
    category:    str           # open_port | xss | sqli | cve | mcp_exposure | …
    evidence:    str = ""      # raw snippet / URL path / CVE ID
    url:         str | None = None
    port:        int | None = None
    cve:         str | None = None
    remediation: str | None = None


# Severity ramp: higher number = more severe (used for ordering / filtering).
SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}

# ZAP risk → our severity
ZAP_RISK_MAP: dict[str, Severity] = {
    "High":          "high",
    "Medium":        "medium",
    "Low":           "low",
    "Informational": "info",
}

# OpenVAS/CVSS → our severity
def cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:   return "critical"
    if score >= 7.0:   return "high"
    if score >= 4.0:   return "medium"
    if score >= 0.1:   return "low"
    return "info"

# Nmap service name → our severity for "open port" findings
_HIGH_RISK_SERVICES = {
    "telnet", "ftp", "rsh", "rlogin", "exec", "finger", "tftp",
    "rexec", "netbios-ssn", "msrpc", "ms-wbt-server",
}
_MEDIUM_RISK_SERVICES = {
    "ssh", "smtp", "pop3", "imap", "snmp", "rdp", "vnc",
    "mysql", "mssql", "postgresql", "mongodb", "redis", "memcached",
    "elasticsearch", "cassandra", "couchdb",
}

def nmap_service_severity(service_name: str, port: int) -> Severity:
    svc = (service_name or "").lower()
    if svc in _HIGH_RISK_SERVICES:
        return "high"
    if svc in _MEDIUM_RISK_SERVICES:
        return "medium"
    if port in (21, 23, 69, 135, 137, 138, 139, 445):
        return "high"
    return "info"
