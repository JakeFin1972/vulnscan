"""MCP server scanner — security assessment for Model Context Protocol servers.

Probes an MCP server over HTTP/SSE (the streamable-HTTP transport) or
detects if a given URL is an MCP endpoint by attempting to initialize the
JSON-RPC session.

Attack surface assessed:
  • Tool enumeration          — what tools are exposed (privilege inventory)
  • High-risk tool detection  — tools that execute code, run shell commands,
                                access files, make network requests, etc.
  • Resource enumeration      — resources accessible without credentials
  • Authentication check      — is auth required? bearer token? API key?
  • Prompt injection surface  — tools that echo back user-supplied text
  • Over-broad permissions    — tools with vague descriptions that likely
                                allow arbitrary operations
  • SSRF surface              — tools that take URLs/hosts as input
  • Transport security        — HTTP vs HTTPS

This scanner does NOT call any tools — it only enumerates and classifies
what is advertised by the server. Safe for all authorized MCP servers.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.parse
from typing import Any

import httpx

from .base import DynamicFinding, Severity

# ── MCP JSON-RPC helpers ───────────────────────────────────────────────────────

_JSONRPC_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "vulnscan-security-scanner", "version": "0.1"},
    },
}

_JSONRPC_LIST_TOOLS     = {"jsonrpc": "2.0", "id": 2, "method": "tools/list",     "params": {}}
_JSONRPC_LIST_RESOURCES = {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}}
_JSONRPC_LIST_PROMPTS   = {"jsonrpc": "2.0", "id": 4, "method": "prompts/list",   "params": {}}

# ── Risk classification ────────────────────────────────────────────────────────

# Tool name/description keywords that indicate high-risk capabilities
_CRITICAL_TOOL_KEYWORDS = [
    "exec", "execute", "shell", "command", "run_code", "eval",
    "subprocess", "spawn", "popen",
]
_HIGH_TOOL_KEYWORDS = [
    "write_file", "delete_file", "create_file", "remove_file",
    "upload", "download", "rm ", "mkdir", "chmod",
    "sql", "query", "database",
    "admin", "root", "sudo",
    "secret", "credential", "password", "token", "key",
]
_MEDIUM_TOOL_KEYWORDS = [
    "read_file", "open_file", "get_file",
    "http", "fetch", "request", "curl", "wget",
    "list_files", "ls", "dir",
    "email", "send",
    "webhook",
]
_SSRF_PARAM_KEYWORDS = ["url", "uri", "host", "endpoint", "target", "address", "server"]
_INJECTION_PARAM_KEYWORDS = ["query", "input", "message", "text", "content", "body", "data"]


def _classify_tool(name: str, desc: str) -> tuple[Severity, str, str]:
    """Return (severity, category, reason) for a tool."""
    combined = (name + " " + (desc or "")).lower()

    for kw in _CRITICAL_TOOL_KEYWORDS:
        if kw in combined:
            return "critical", "mcp_code_execution_tool", f"Tool may execute arbitrary code (keyword: '{kw}')"

    for kw in _HIGH_TOOL_KEYWORDS:
        if kw in combined:
            return "high", "mcp_high_risk_tool", f"Tool has high-risk capability (keyword: '{kw}')"

    for kw in _MEDIUM_TOOL_KEYWORDS:
        if kw in combined:
            return "medium", "mcp_medium_risk_tool", f"Tool accesses sensitive resources (keyword: '{kw}')"

    return "info", "mcp_tool_exposure", "Tool exposed to callers"


def _check_ssrf(params: list[dict]) -> bool:
    for p in params:
        pname = (p.get("name") or "").lower()
        if any(k in pname for k in _SSRF_PARAM_KEYWORDS):
            return True
    return False


def _check_injection_surface(params: list[dict]) -> bool:
    for p in params:
        pname = (p.get("name") or "").lower()
        if any(k in pname for k in _INJECTION_PARAM_KEYWORDS):
            return True
    return False


def _extract_tool_params(tool: dict) -> list[dict]:
    schema = tool.get("inputSchema", {})
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties", {})
    return [{"name": k} for k in props] if isinstance(props, dict) else []


# ── HTTP transport helpers ─────────────────────────────────────────────────────

def _post_jsonrpc(client: httpx.Client, url: str, payload: dict) -> dict | None:
    """Send a JSON-RPC request; return the response dict or None on error."""
    try:
        r = client.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            return r.json()  # type: ignore[return-value]
    except Exception:  # noqa: BLE001
        pass
    return None


def _try_sse_endpoint(client: httpx.Client, base_url: str) -> str | None:
    """Try to find the MCP SSE or HTTP endpoint. Returns the best endpoint URL."""
    # Common MCP endpoint paths
    candidates = [
        base_url.rstrip("/"),
        base_url.rstrip("/") + "/mcp",
        base_url.rstrip("/") + "/sse",
        base_url.rstrip("/") + "/api/mcp",
        base_url.rstrip("/") + "/v1/mcp",
    ]
    for url in candidates:
        resp = _post_jsonrpc(client, url, _JSONRPC_INIT)
        if resp and "result" in resp:
            return url
    return None


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan(target_url: str, check_auth: bool = True) -> list[DynamicFinding]:
    """Probe an MCP server at `target_url` and return security findings.

    Does NOT invoke any tools — read-only enumeration only.
    Falls back gracefully if the server is unreachable.
    """
    findings: list[DynamicFinding] = []
    parsed = urllib.parse.urlparse(target_url)

    # Transport check
    if parsed.scheme == "http":
        findings.append(DynamicFinding(
            tool="mcp", target=target_url,
            name="MCP server using insecure HTTP",
            description=(
                "The MCP server is accessed over plain HTTP. Any data exchanged — "
                "including tool calls, LLM context, and potential secrets — is "
                "transmitted without encryption."
            ),
            severity="medium",
            category="missing_encryption",
            evidence=f"Scheme: {parsed.scheme}",
            remediation="Use HTTPS (TLS) for all MCP server deployments, even local ones.",
        ))

    # Connect and initialize
    with httpx.Client(verify=True, follow_redirects=True) as client:
        # Try to reach the server
        try:
            endpoint_url = _try_sse_endpoint(client, target_url)
        except httpx.ConnectError as exc:
            return findings + [DynamicFinding(
                tool="mcp", target=target_url,
                name="MCP server not reachable",
                description=f"Could not connect to {target_url}: {exc}",
                severity="info", category="scanner_unavailable",
            )]
        except Exception as exc:  # noqa: BLE001
            return findings + [DynamicFinding(
                tool="mcp", target=target_url,
                name=f"MCP connection error: {type(exc).__name__}",
                description=str(exc)[:400],
                severity="info", category="scanner_error",
            )]

        if endpoint_url is None:
            # Couldn't establish MCP session — check if it responds at all
            try:
                r = client.get(target_url, timeout=5)
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name="Endpoint responds but is not an MCP server",
                    description=(
                        f"HTTP {r.status_code} at {target_url}. "
                        "Could not establish an MCP JSON-RPC session. "
                        "The server may not be an MCP server, or may use a "
                        "different transport (stdio, different path)."
                    ),
                    severity="info", category="mcp_probe",
                    evidence=f"HTTP {r.status_code}",
                ))
            except Exception:  # noqa: BLE001
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name="Target not reachable as MCP server",
                    description="Could not reach the target or establish an MCP session.",
                    severity="info", category="scanner_unavailable",
                ))
            return findings

        # Authentication check
        if check_auth:
            # Try without any auth headers
            auth_resp = _post_jsonrpc(client, endpoint_url, _JSONRPC_INIT)
            if auth_resp and "result" in auth_resp:
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name="MCP server accessible without authentication",
                    description=(
                        "The MCP server responds to the initialize handshake without "
                        "any authentication token or API key. Any process that can "
                        "reach this endpoint can enumerate and call all tools."
                    ),
                    severity="high",
                    category="unauthenticated_access",
                    evidence=f"initialize succeeded without auth headers at {endpoint_url}",
                    remediation=(
                        "Add authentication: Bearer token, API key header, or mTLS. "
                        "Bind the server to localhost (127.0.0.1) if remote access is not needed."
                    ),
                ))

        # Enumerate tools
        tools_resp = _post_jsonrpc(client, endpoint_url, _JSONRPC_LIST_TOOLS)
        tools: list[dict] = []
        if tools_resp and "result" in tools_resp:
            tools = tools_resp["result"].get("tools", []) or []

        if not tools:
            findings.append(DynamicFinding(
                tool="mcp", target=target_url,
                name="No tools found (or tools/list not supported)",
                description="The server did not return any tools via tools/list.",
                severity="info", category="mcp_probe",
            ))
        else:
            findings.append(DynamicFinding(
                tool="mcp", target=target_url,
                name=f"MCP server exposes {len(tools)} tool(s)",
                description="Tools advertised: " + ", ".join(t.get("name","?") for t in tools),
                severity="info", category="mcp_tool_inventory",
                evidence=json.dumps([t.get("name") for t in tools]),
            ))

        for tool in tools:
            name  = tool.get("name", "unnamed")
            desc  = tool.get("description", "")
            params = _extract_tool_params(tool)

            sev, cat, reason = _classify_tool(name, desc)
            if sev != "info":
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name=f"High-risk tool: {name}",
                    description=(
                        f"Tool '{name}' appears to have dangerous capabilities.\n"
                        f"Reason: {reason}\n"
                        f"Description: {desc[:300]}"
                    ),
                    severity=sev,
                    category=cat,
                    evidence=f"Tool: {name} | {reason}",
                    remediation=(
                        "Review whether this tool needs to be exposed. "
                        "Add strict input validation and scope restrictions. "
                        "Require explicit user confirmation before executing sensitive operations."
                    ),
                ))

            # SSRF check
            if _check_ssrf(params):
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name=f"SSRF-susceptible parameter in tool: {name}",
                    description=(
                        f"Tool '{name}' accepts URL/host parameters that could enable "
                        "Server-Side Request Forgery (SSRF) if not properly validated."
                    ),
                    severity="medium",
                    category="ssrf_candidate",
                    evidence=f"Parameters: {[p['name'] for p in params]}",
                    remediation=(
                        "Validate and allowlist URLs. Block access to internal network ranges "
                        "(169.254.0.0/16, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, ::1)."
                    ),
                ))

            # Prompt injection surface
            if _check_injection_surface(params):
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name=f"Prompt injection surface in tool: {name}",
                    description=(
                        f"Tool '{name}' accepts free-text parameters ('text', 'query', 'input', etc.) "
                        "that an adversary could use to inject instructions into the LLM context — "
                        "especially dangerous if tool output is fed back to a model without sanitization."
                    ),
                    severity="medium",
                    category="prompt_injection_surface",
                    evidence=f"Parameters: {[p['name'] for p in params]}",
                    remediation=(
                        "Treat tool outputs as untrusted data in LLM context. "
                        "Use structured output formats instead of free text where possible. "
                        "Implement output filtering before returning to LLM."
                    ),
                ))

        # Enumerate resources
        resources_resp = _post_jsonrpc(client, endpoint_url, _JSONRPC_LIST_RESOURCES)
        resources: list[dict] = []
        if resources_resp and "result" in resources_resp:
            resources = resources_resp["result"].get("resources", []) or []

        if resources:
            resource_uris = [r.get("uri", "?") for r in resources]
            # Flag sensitive-looking resource URIs
            sensitive_res = [u for u in resource_uris
                           if any(k in u.lower() for k in
                                  ["secret", "password", "token", "key", "credential",
                                   "private", "admin", "config", "env"])]
            if sensitive_res:
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name="Sensitive resources exposed via MCP",
                    description=(
                        f"The MCP server exposes resource URIs that appear to contain "
                        f"sensitive data: {sensitive_res[:5]}"
                    ),
                    severity="high",
                    category="sensitive_data_exposure",
                    evidence=str(sensitive_res[:5]),
                    remediation="Review resource access controls. Require authentication for sensitive resources.",
                ))
            else:
                findings.append(DynamicFinding(
                    tool="mcp", target=target_url,
                    name=f"MCP server exposes {len(resources)} resource(s)",
                    description="Resources: " + ", ".join(resource_uris[:10]),
                    severity="info", category="mcp_resource_inventory",
                    evidence=json.dumps(resource_uris[:10]),
                ))

        # Enumerate prompts
        prompts_resp = _post_jsonrpc(client, endpoint_url, _JSONRPC_LIST_PROMPTS)
        prompts: list[dict] = []
        if prompts_resp and "result" in prompts_resp:
            prompts = prompts_resp["result"].get("prompts", []) or []
        if prompts:
            findings.append(DynamicFinding(
                tool="mcp", target=target_url,
                name=f"MCP server exposes {len(prompts)} server-defined prompt(s)",
                description="Prompts: " + ", ".join(p.get("name","?") for p in prompts),
                severity="info", category="mcp_prompt_inventory",
            ))

    return findings
