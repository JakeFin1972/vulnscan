"""Nmap XML output parser.

Parses the XML produced by ``nmap -oX output.xml`` and converts it to a
list of normalised :class:`~vulnscan.easm.schema.Vulnerability` objects.

Produces two categories of findings:
  * ``open_port``   — one per open port/service detected
  * ``vulnerability`` — one per script output that indicates a confirmed vuln
    (smb-vuln-*, auth-bypass, ssl-poodle, etc.)
"""
from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from ..schema import AssetType, Severity, SourceTool, Vulnerability

# ── Service severity heuristic ────────────────────────────────────────────────

_HIGH_RISK_SERVICES = frozenset({
    "telnet", "ftp", "rsh", "rlogin", "rexec", "tftp", "finger",
    "chargen", "daytime", "echo",
})
_MEDIUM_RISK_SERVICES = frozenset({
    "ssh", "smtp", "pop3", "imap", "snmp", "vnc",
    "mysql", "mssql", "postgresql", "redis", "mongodb", "memcached",
    "rdp", "smb", "netbios-ssn", "msrpc",
})


def _service_severity(svc: str, port: int) -> Severity:
    s = svc.lower()
    if s in _HIGH_RISK_SERVICES:
        return "high"
    if s in _MEDIUM_RISK_SERVICES:
        return "medium"
    if port in (80, 8080):
        return "low"
    return "info"


def _guess_asset_type(addr: str) -> AssetType:
    # Very simple heuristic: IPv4/IPv6 vs hostname
    if re.fullmatch(r"[\d.]+", addr) or ":" in addr:
        return "ip"
    return "domain"


# ── Script classification ─────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

def _classify_script(script_id: str, output: str) -> tuple[Severity, str, str | None]:
    """Return (severity, category, cve_or_None)."""
    sid   = script_id.lower()
    out   = output.lower()
    cve   = _CVE_RE.search(output)
    cve_s = cve.group(0).upper() if cve else None

    if "vulnerable" in out or "VULNERABLE" in output:
        if ("smb-vuln" in sid or "ms17-010" in sid or "eternalblue" in out
                or "rce" in out or "remote code" in out
                or "cvss: 10" in out or "cvss: 9" in out):
            return "critical", "vulnerability", cve_s
        return "high", "vulnerability", cve_s

    if "auth-bypass" in sid or "default-creds" in sid or "brute" in sid:
        if "valid" in out or "success" in out or "found" in out:
            return "critical", "default_credentials", cve_s
        return "medium", "weak_auth", cve_s

    if "smb-vuln" in sid or "ms17-010" in sid:
        return "critical", "vulnerability", cve_s

    if "ssl" in sid and ("expired" in out or "self-signed" in out):
        return "medium", "tls_issue", cve_s

    if "ssl-dh-params" in sid or "ssl-poodle" in sid:
        return "high", "tls_issue", cve_s

    if cve_s:
        return "medium", "cve", cve_s

    return "info", "script_output", None


# ── Main parser ───────────────────────────────────────────────────────────────

def parse(content: str, source_file: str | None = None) -> list[Vulnerability]:
    """Parse Nmap XML *content* and return normalised vulnerabilities."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}") from exc

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    results: list[Vulnerability] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr", "unknown")
        atype = _guess_asset_type(addr)

        # OS detection (informational only)
        os_name: str | None = None
        for osmatch in host.findall("os/osmatch"):
            acc = int(osmatch.get("accuracy", "0"))
            if acc >= 90:
                os_name = osmatch.get("name")
                break

        # ── Open ports ──────────────────────────────────────────────────────
        for port_el in host.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid   = int(port_el.get("portid", "0"))
            protocol = port_el.get("protocol", "tcp")
            svc_el   = port_el.find("service")
            svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            product  = svc_el.get("product", "") if svc_el is not None else ""
            version  = svc_el.get("version", "") if svc_el is not None else ""

            sev = _service_severity(svc_name, portid)
            banner = " ".join(filter(None, [product, version])).strip()
            desc   = (
                f"Port {portid}/{protocol} is open running {svc_name}"
                + (f" ({banner})" if banner else "")
                + (f". Host OS: {os_name}" if os_name else "")
            )

            results.append(Vulnerability(
                id=str(uuid.uuid4()),
                asset=addr,
                asset_type=atype,
                source_tool="nmap",
                source_file=source_file,
                name=f"Open port {portid}/{protocol} ({svc_name})",
                description=desc,
                severity=sev,
                category="open_port",
                port=portid,
                protocol=protocol,
                evidence=f"{svc_name} {banner}".strip(),
                remediation=(
                    "Close unused ports. Restrict access via firewall rules. "
                    "Ensure services are current and properly configured."
                ),
                discovered_at=now_iso,
                last_seen_at=now_iso,
            ))

            # Port-level scripts
            for script in port_el.findall("script"):
                sid  = script.get("id", "")
                sout = script.get("output", "")
                sev2, cat2, cve2 = _classify_script(sid, sout)
                if sev2 in ("critical", "high", "medium"):
                    results.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        asset=addr,
                        asset_type=atype,
                        source_tool="nmap",
                        source_file=source_file,
                        name=f"NSE script: {sid}",
                        description=sout[:800],
                        severity=sev2,
                        category=cat2,
                        port=portid,
                        protocol=protocol,
                        cve=cve2,
                        evidence=f"Script: {sid} | Output: {sout[:200]}",
                        remediation="Apply relevant vendor patches and review service configuration.",
                        discovered_at=now_iso,
                        last_seen_at=now_iso,
                    ))

        # ── Host-level scripts ───────────────────────────────────────────────
        for script in host.findall("hostscript/script"):
            sid  = script.get("id", "")
            sout = script.get("output", "")
            sev2, cat2, cve2 = _classify_script(sid, sout)
            if sev2 in ("critical", "high", "medium"):
                results.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    asset=addr,
                    asset_type=atype,
                    source_tool="nmap",
                    source_file=source_file,
                    name=f"NSE script: {sid}",
                    description=sout[:800],
                    severity=sev2,
                    category=cat2,
                    cve=cve2,
                    evidence=f"Script: {sid} | Output: {sout[:200]}",
                    remediation="Apply relevant vendor patches and review service configuration.",
                    discovered_at=now_iso,
                    last_seen_at=now_iso,
                ))

    return results
