"""Dynamic scanner registry.

Maps target types to scanner functions. All scanners degrade gracefully when
the underlying tool is not installed or not running.
"""
from __future__ import annotations

from .base import DynamicFinding, TargetType, ScanTool
from . import (
    nmap_scanner, zap_scanner, openvas_scanner, mcp_scanner,
    http_scanner, api_scanner, nuclei_scanner,
    sslyze_scanner, subfinder_scanner,
)


def tool_status() -> dict[str, dict]:
    """Return availability status for each scanner tool."""
    return {
        "nmap":      {"available": nmap_scanner.is_available(),
                      "description": "Port/service/OS/vuln detection (requires nmap binary)"},
        "http":      {"available": True,
                      "description": "HTTP security header, cookie, TLS and sensitive-path checks (built-in)"},
        "api":       {"available": True,
                      "description": "REST API security scanner: discovers OpenAPI spec and tests for injection, XXE, auth bypass (built-in)"},
        "zap":       {"available": zap_scanner.is_available(),
                      "description": "DAST web app scanner (requires ZAP daemon)"},
        "openvas":   {"available": openvas_scanner.is_available(),
                      "description": "Full vulnerability assessment (requires GVM daemon)"},
        "mcp":       {"available": True,
                      "description": "MCP server security probe (built-in, no external tool needed)"},
        "nuclei":    {"available": nuclei_scanner.is_available(),
                      "description": "CVE & template-based scanner — 10 000+ templates incl. protocol-level CVEs (requires nuclei binary)"},
        "sslyze":    {"available": sslyze_scanner.is_available(),
                      "description": "Deep TLS/SSL analysis: deprecated protocols, certificate issues, Heartbleed, ROBOT, CRIME (requires sslyze)"},
        "subfinder": {"available": subfinder_scanner.is_available(),
                      "description": "Passive subdomain enumeration from 50+ sources (requires subfinder binary)"},
    }


def run_dynamic_scan(
    target: str,
    target_type: TargetType,
    tools: list[ScanTool] | None = None,
    options: dict | None = None,
) -> list[DynamicFinding]:
    """Run the requested tools against `target` and aggregate findings.

    `tools`  — subset of available scanner names; defaults to all tools
               appropriate for the target type.
    `options`— per-tool overrides (e.g. {"nuclei": {"tags": ["cve"], "severity": ["critical","high"]}}).
    """
    opts = options or {}

    # Default tool selection by target type
    if tools is None:
        if target_type == "url":
            tools = ["http", "api", "nuclei", "nmap", "openvas", "sslyze", "mcp"]
        elif target_type == "host":
            tools = ["nmap", "nuclei", "openvas", "sslyze", "subfinder"]
        elif target_type == "mcp":
            tools = ["mcp"]
        else:
            tools = ["nmap", "nuclei"]

    findings: list[DynamicFinding] = []

    host_only, target_port = _target_to_host_port(target, target_type)

    for tool in tools:
        tool_opts = opts.get(tool, {})

        if tool == "nmap":
            profile = tool_opts.get("profile", "standard")
            extra   = list(tool_opts.get("extra_args", []))
            if target_port and f"-p{target_port}" not in " ".join(extra) and f"-p {target_port}" not in " ".join(extra):
                extra = [f"-p{target_port}"] + extra
            findings.extend(nmap_scanner.scan(host_only, profile=profile, extra_args=extra))

        elif tool == "http":
            url = target if target.startswith("http") else f"http://{target}"
            findings.extend(http_scanner.scan(url, options=tool_opts))

        elif tool == "api":
            url = target if target.startswith("http") else f"http://{target}"
            findings.extend(api_scanner.scan(url, options=tool_opts))

        elif tool == "zap":
            url = target if target.startswith("http") else f"http://{target}"
            findings.extend(zap_scanner.scan(
                url,
                active=tool_opts.get("active", True),
                ajax_spider=tool_opts.get("ajax_spider", False),
                host=tool_opts.get("host"),
                port=tool_opts.get("port"),
                api_key=tool_opts.get("api_key"),
            ))

        elif tool == "openvas":
            host = _url_to_host(target) if target_type == "url" else target
            ov_opts = opts.get("openvas", {})
            findings.extend(openvas_scanner.scan(
                host,
                host=ov_opts.get("host"),
                port=int(ov_opts["port"]) if ov_opts.get("port") else None,
                socket=ov_opts.get("socket"),
                user=ov_opts.get("user"),
                password=ov_opts.get("password"),
            ))

        elif tool == "mcp":
            url = target if target.startswith("http") else f"http://{target}"
            findings.extend(mcp_scanner.scan(url))

        elif tool == "nuclei":
            findings.extend(nuclei_scanner.scan(target, options=tool_opts))

        elif tool == "sslyze":
            findings.extend(sslyze_scanner.scan(target, options=tool_opts))

        elif tool == "subfinder":
            findings.extend(subfinder_scanner.scan(target, options=tool_opts))

    return findings


def _url_to_host(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.hostname or url


def _target_to_host_port(target: str, target_type: str) -> tuple[str, int | None]:
    """Split 'host:port' or URL into (host, port). Port may be None."""
    if target_type == "url" or target.startswith("http"):
        from urllib.parse import urlparse
        p = urlparse(target if "://" in target else f"http://{target}")
        return (p.hostname or target), p.port
    if ":" in target:
        host, _, port_str = target.rpartition(":")
        try:
            return host, int(port_str)
        except ValueError:
            pass
    return target, None
