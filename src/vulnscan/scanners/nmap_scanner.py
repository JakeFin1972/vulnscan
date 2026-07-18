"""NMAP scanner — port, service, OS, and script-based vulnerability detection.

Wraps the nmap CLI via subprocess; parses XML output for structured results.
Falls back gracefully if nmap is not installed.

Scan profiles:
  quick   — top 100 ports, SYN scan, no scripts            (-sS -F)
  standard— top 1000 ports, SYN scan, version detect       (-sS -sV -T4)
  full    — all ports, SYN scan, version + vuln scripts     (-sS -sV -p- --script=vuln)
  stealth — slow, less noisy (TCP connect, no version)      (-sT -T2)

Run with:  nmap_scanner.scan(target, options)
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any

from .base import DynamicFinding, nmap_service_severity, Severity

_NMAP = shutil.which("nmap")

PROFILES: dict[str, list[str]] = {
    "quick":    ["-sT", "-F",        "-T4", "-n"],
    "standard": ["-sT", "-sV",       "-T4", "-n", "--top-ports", "1000"],
    "full":     ["-sT", "-sV", "-p-", "-T4", "--script=vuln,auth,default"],
    "stealth":  ["-sT", "-T2", "-n"],
}


def is_available() -> bool:
    return _NMAP is not None


def _parse_xml(xml_text: str, target: str) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return [DynamicFinding(
            tool="nmap", target=target,
            name="XML parse error", description=str(exc),
            severity="info", category="scanner_error",
        )]

    for host in root.findall("host"):
        # Resolve address
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        addr = addr_el.get("addr", target) if addr_el is not None else target

        # Host status
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # OS detection
        os_el = host.find("os/osmatch")
        if os_el is not None:
            os_name = os_el.get("name", "")
            accuracy = os_el.get("accuracy", "0")
            findings.append(DynamicFinding(
                tool="nmap", target=addr,
                name=f"OS detected: {os_name}",
                description=f"nmap OS detection: {os_name} (accuracy {accuracy}%)",
                severity="info", category="os_detection",
                evidence=f"OS: {os_name}, accuracy: {accuracy}%",
            ))

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            portid   = int(port_el.get("portid", "0"))
            protocol = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc_el      = port_el.find("service")
            svc_name    = svc_el.get("name",    "") if svc_el is not None else ""
            svc_product = svc_el.get("product", "") if svc_el is not None else ""
            svc_version = svc_el.get("version", "") if svc_el is not None else ""
            svc_banner  = f"{svc_product} {svc_version}".strip()
            tunnel      = (svc_el.get("tunnel", "") if svc_el is not None else "")
            is_ssl      = tunnel == "ssl"

            sev = nmap_service_severity(svc_name, portid)
            label = f"{svc_name}/{protocol}" if svc_name else f"unknown/{protocol}"
            findings.append(DynamicFinding(
                tool="nmap", target=addr,
                name=f"Open port {portid}/{protocol} — {label}",
                description=(
                    f"Port {portid}/{protocol} is open on {addr}. "
                    f"Service: {svc_name or 'unknown'}. "
                    + (f"Banner: {svc_banner}. " if svc_banner else "")
                    + ("TLS/SSL detected." if is_ssl else "")
                ),
                severity=sev,
                category="open_port",
                evidence=f"{portid}/{protocol} {svc_name} {svc_banner}".strip(),
                port=portid,
                remediation=_remediation_for_service(svc_name, portid),
            ))

            # Script output (vuln detection)
            for script in port_el.findall("script"):
                sid    = script.get("id",     "")
                sout   = script.get("output", "")
                script_sev, script_cat = _classify_script(sid, sout)
                if script_sev in ("critical", "high", "medium"):
                    cve = _extract_cve(sout)
                    findings.append(DynamicFinding(
                        tool="nmap", target=addr,
                        name=f"[{sid}] on {portid}/{protocol}",
                        description=sout[:500],
                        severity=script_sev,
                        category=script_cat,
                        evidence=sout[:300],
                        port=portid,
                        cve=cve,
                        remediation="Apply vendor patches; see CVE advisory." if cve else None,
                    ))

        # Host-level scripts
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                sid  = script.get("id",     "")
                sout = script.get("output", "")
                script_sev, script_cat = _classify_script(sid, sout)
                if script_sev != "info":
                    cve = _extract_cve(sout)
                    findings.append(DynamicFinding(
                        tool="nmap", target=addr,
                        name=f"[{sid}] host-level",
                        description=sout[:500],
                        severity=script_sev,
                        category=script_cat,
                        evidence=sout[:300],
                        cve=cve,
                    ))

    return findings


def _extract_cve(text: str) -> str | None:
    m = re.search(r"CVE-\d{4}-\d+", text)
    return m.group(0) if m else None


def _classify_script(script_id: str, output: str) -> tuple[Severity, str]:
    out_lower = output.lower()
    sid_lower = script_id.lower()

    if "vulnerable" in out_lower or "VULNERABLE" in output:
        if ("critical" in out_lower or "cvss: 10" in out_lower or "cvss: 9" in out_lower
                or "smb-vuln" in sid_lower or "ms17-010" in sid_lower
                or "eternalblue" in out_lower or "rce" in out_lower):
            return "critical", "vulnerability"
        return "high", "vulnerability"
    if "auth-bypass" in sid_lower or "default-creds" in sid_lower or "brute" in sid_lower:
        if "valid" in out_lower or "success" in out_lower:
            return "critical", "default_credentials"
        return "medium", "weak_auth"
    if "smb-vuln" in sid_lower or "ms17-010" in sid_lower:
        return "critical", "vulnerability"
    if "ssl" in sid_lower and ("expired" in out_lower or "self-signed" in out_lower):
        return "medium", "tls_issue"
    if "ssl-dh-params" in sid_lower or "ssl-poodle" in sid_lower:
        return "high", "tls_issue"
    return "info", "script_output"


def _remediation_for_service(svc: str, port: int) -> str | None:
    tips: dict[str, str] = {
        "telnet": "Replace Telnet with SSH. Telnet transmits credentials in plaintext.",
        "ftp":    "Replace FTP with SFTP or FTPS. FTP transmits credentials in plaintext.",
        "rsh":    "Disable rsh; use SSH instead.",
        "rlogin": "Disable rlogin; use SSH instead.",
        "snmp":   "Use SNMPv3 with authentication and encryption. Change default community strings.",
        "mysql":  "Restrict MySQL access to localhost or trusted IPs. Use strong passwords.",
        "redis":  "Bind Redis to localhost or require authentication with requirepass.",
        "mongodb": "Enable MongoDB authentication. Bind to localhost unless remote access is needed.",
        "memcached": "Bind memcached to localhost. It has no built-in authentication.",
        "elasticsearch": "Enable Elasticsearch security features (TLS + authentication).",
    }
    return tips.get(svc.lower())


def scan(target: str, profile: str = "standard", extra_args: list[str] | None = None) -> list[DynamicFinding]:
    """Run nmap against `target` with the given profile.

    Returns a list of DynamicFinding. Returns [] with a warning if nmap is not
    installed. Never raises.
    """
    if not is_available():
        print("warning: nmap not found — install with: brew install nmap", file=sys.stderr)
        return [DynamicFinding(
            tool="nmap", target=target,
            name="nmap not installed",
            description="nmap binary not found on PATH. Install with: brew install nmap",
            severity="info", category="scanner_unavailable",
        )]

    args = PROFILES.get(profile, PROFILES["standard"]) + (extra_args or [])
    cmd = [_NMAP, "-oX", "-"] + args + [target]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        if result.returncode not in (0, 1):  # nmap returns 1 for some valid scans
            return [DynamicFinding(
                tool="nmap", target=target,
                name="nmap scan error",
                description=result.stderr[:500] or "nmap exited with non-zero status",
                severity="info", category="scanner_error",
                evidence=f"exit {result.returncode}: {result.stderr[:200]}",
            )]
        return _parse_xml(result.stdout, target)
    except subprocess.TimeoutExpired:
        return [DynamicFinding(
            tool="nmap", target=target,
            name="nmap scan timed out",
            description="nmap scan exceeded the 300-second timeout.",
            severity="info", category="scanner_error",
        )]
    except Exception as exc:  # noqa: BLE001
        return [DynamicFinding(
            tool="nmap", target=target,
            name=f"nmap exception: {type(exc).__name__}",
            description=str(exc),
            severity="info", category="scanner_error",
        )]
