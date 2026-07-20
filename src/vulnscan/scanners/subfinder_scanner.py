"""Subfinder passive subdomain enumeration scanner.

Queries 50+ passive DNS and certificate transparency sources to discover
subdomains without sending any traffic to the target domain.

Install:
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  # or: brew install subfinder

Usage:
  Subfinder runs against domain targets (host target type). IP addresses
  are skipped — subfinder only works on domain names.

Findings are returned as info-level ``subdomain_discovery`` entries, one per
discovered subdomain. Use the EASM ingest button to register them as assets.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.parse

from .base import DynamicFinding

TOOL = "subfinder"

# Matches IPv4 and IPv6 addresses so we can skip non-domain targets
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"   # IPv4
    r"|"
    r"^[0-9a-f:]+:[0-9a-f:]*$",   # IPv6 (simplified)
    re.IGNORECASE,
)


def is_available() -> bool:
    return shutil.which("subfinder") is not None


def scan(target: str, options: dict | None = None) -> list[DynamicFinding]:
    """Run subfinder against *target* and return one finding per subdomain found."""
    if not is_available():
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="subfinder not installed",
            description=(
                "Install subfinder:\n"
                "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
                "  # or: brew install subfinder"
            ),
            severity="info", category="scanner_unavailable",
        )]

    domain = _extract_domain(target)
    if not domain:
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="Subfinder skipped — not a domain target",
            description=f"'{target}' appears to be an IP address. Subfinder only works on domain names.",
            severity="info", category="scanner_info",
        )]

    opts = options or {}
    timeout   = int(opts.get("timeout", 120))
    resolvers = opts.get("resolvers", "")   # comma-separated custom resolvers

    cmd = ["subfinder", "-d", domain, "-json", "-silent", "-timeout", "30"]
    if resolvers:
        cmd += ["-r", resolvers]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="Subfinder timed out",
            description=f"Subdomain enumeration for '{domain}' did not complete within {timeout}s.",
            severity="info", category="scanner_error",
        )]
    except FileNotFoundError:
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="subfinder binary not found",
            description="subfinder was not found in PATH at scan time.",
            severity="info", category="scanner_unavailable",
        )]
    except Exception as exc:  # noqa: BLE001
        return [DynamicFinding(
            tool=TOOL, target=target,
            name=f"Subfinder error: {type(exc).__name__}",
            description=str(exc)[:400],
            severity="info", category="scanner_error",
        )]

    if proc.returncode not in (0, 1) and not proc.stdout.strip():
        return [DynamicFinding(
            tool=TOOL, target=target,
            name="Subfinder returned no results",
            description=(proc.stderr or "No output from subfinder.")[:400],
            severity="info", category="scanner_info",
        )]

    return _parse_output(proc.stdout, target, domain)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(target: str) -> str | None:
    """Return the bare domain name, or None if target looks like an IP."""
    raw = target
    if "://" in target:
        raw = urllib.parse.urlparse(target).hostname or target
    elif ":" in target:
        raw = target.rsplit(":", 1)[0]

    raw = raw.strip().lower()
    if not raw or _IP_RE.match(raw):
        return None
    return raw


def _parse_output(stdout: str, target: str, domain: str) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    seen: set[str] = set()

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            host   = row.get("host", "").strip().lower()
            source = row.get("source", "")
        except json.JSONDecodeError:
            # Fallback: plain hostname per line
            host   = line.lower()
            source = ""

        if not host or host in seen:
            continue
        seen.add(host)

        findings.append(DynamicFinding(
            tool=TOOL,
            target=target,
            name=f"Subdomain discovered: {host}",
            description=(
                f"Passive DNS enumeration found '{host}' as a subdomain of '{domain}'. "
                "This is an informational finding — use EASM ingest to track it as an asset "
                "and run further scans (nmap, nuclei, sslyze) against it."
            ),
            severity="info",
            category="subdomain_discovery",
            evidence=f"source: {source}" if source else "",
            url=f"https://{host}",
        ))

    if not findings:
        findings.append(DynamicFinding(
            tool=TOOL, target=target,
            name=f"No subdomains found for {domain}",
            description="Subfinder completed but found no subdomains. The domain may have "
                        "minimal external exposure, or passive sources may lack coverage.",
            severity="info", category="scanner_info",
        ))

    return findings
