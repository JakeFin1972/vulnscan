"""Dynamic scanner registry.

Maps target types to scanner functions. All scanners degrade gracefully when
the underlying tool is not installed or not running.
"""
from __future__ import annotations

from .base import DynamicFinding, TargetType, ScanTool
from . import nmap_scanner, zap_scanner, openvas_scanner, mcp_scanner


def tool_status() -> dict[str, dict]:
    """Return availability status for each scanner tool."""
    return {
        "nmap":    {"available": nmap_scanner.is_available(),
                    "description": "Port/service/OS/vuln detection (requires nmap binary)"},
        "zap":     {"available": zap_scanner.is_available(),
                    "description": "DAST web app scanner (requires ZAP daemon)"},
        "openvas": {"available": openvas_scanner.is_available(),
                    "description": "Full vulnerability assessment (requires GVM daemon)"},
        "mcp":     {"available": True,  # always available — uses httpx
                    "description": "MCP server security probe (built-in, no external tool needed)"},
    }


def run_dynamic_scan(
    target: str,
    target_type: TargetType,
    tools: list[ScanTool] | None = None,
    options: dict | None = None,
) -> list[DynamicFinding]:
    """Run the requested tools against `target` and aggregate findings.

    `tools`  — subset of ["nmap", "zap", "openvas", "mcp"]; defaults to
               all tools appropriate for the target type.
    `options`— per-tool overrides (e.g. {"nmap": {"profile": "full"}}).
    """
    opts = options or {}

    # Default tool selection by target type
    if tools is None:
        if target_type == "url":
            tools = ["zap", "nmap", "mcp"]
        elif target_type == "host":
            tools = ["nmap", "openvas"]
        elif target_type == "mcp":
            tools = ["mcp"]
        else:
            tools = ["nmap"]

    findings: list[DynamicFinding] = []

    for tool in tools:
        tool_opts = opts.get(tool, {})
        if tool == "nmap":
            profile = tool_opts.get("profile", "standard")
            extra   = tool_opts.get("extra_args", [])
            # For URL targets extract the hostname
            host = _url_to_host(target) if target_type == "url" else target
            findings.extend(nmap_scanner.scan(host, profile=profile, extra_args=extra))

        elif tool == "zap":
            if target_type not in ("url",):
                # For host targets synthesize a URL
                url = target if target.startswith("http") else f"http://{target}"
            else:
                url = target
            active = tool_opts.get("active", True)
            ajax   = tool_opts.get("ajax_spider", False)
            findings.extend(zap_scanner.scan(url, active=active, ajax_spider=ajax))

        elif tool == "openvas":
            host = _url_to_host(target) if target_type == "url" else target
            findings.extend(openvas_scanner.scan(host))

        elif tool == "mcp":
            url = target if target.startswith("http") else f"http://{target}"
            findings.extend(mcp_scanner.scan(url))

    return findings


def _url_to_host(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.hostname or url
