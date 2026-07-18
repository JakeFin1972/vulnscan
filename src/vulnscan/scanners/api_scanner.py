"""Built-in REST API security scanner.

Discovers an OpenAPI/Swagger spec, then actively probes each endpoint for:
- OS command injection
- Code evaluation / Python eval injection
- SQL injection (error-based)
- Path traversal
- XXE
- Missing authentication (401/403 bypass)
- Sensitive data exposure in responses
- Unauthenticated access to protected endpoints

Uses only httpx (already a dependency).
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

import httpx

from .base import DynamicFinding

TOOL = "api"

# ── OpenAPI spec discovery paths ───────────────────────────────────────────────
_SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/docs/openapi.json", "/api-docs",
    "/swagger-ui/swagger.json",
]

# ── Injection payloads ─────────────────────────────────────────────────────────

# OS command injection — look for uid= in response
_CMD_PAYLOADS = [
    ";id",
    "|id",
    "&&id",
    "`id`",
    "$(id)",
    ";id;",
    "\n/usr/bin/id",
]
_CMD_DETECTION = re.compile(r"uid=\d+\([^)]+\)\s*gid=\d+", re.IGNORECASE)

# Python/JS eval injection — inject arithmetic, look for evaluated result
_EVAL_PAYLOADS = [
    ("7*7", "49"),
    ("3+4", "7"),
    ("__import__('os').popen('id').read()", "uid="),
    ("require('child_process').execSync('id').toString()", "uid="),
]

# SQL injection — error-based detection
_SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1; DROP TABLE--", "1 UNION SELECT NULL--"]
_SQLI_ERRORS = re.compile(
    r"sql|syntax error|mysql|sqlite|postgresql|ora-|jdbc|odbc|"
    r"unterminated quoted|you have an error in your sql",
    re.IGNORECASE,
)

# Path traversal
_TRAVERSAL_PAYLOADS = ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]
_TRAVERSAL_DETECTION = re.compile(r"root:.*:0:0:", re.IGNORECASE)

# XXE
_XXE_PAYLOAD = (
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<query>&xxe;</query>"
)
_XXE_DETECTION = re.compile(r"root:.*:0:0:|nobody:.*:99:", re.IGNORECASE)

# Sensitive data patterns in responses
_SENSITIVE_PATTERNS = [
    (re.compile(r"password[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{4,}", re.I), "Password in response"),
    (re.compile(r"secret[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{4,}", re.I), "Secret in response"),
    (re.compile(r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{4,}", re.I), "API key in response"),
    (re.compile(r"private[_-]?key[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{4,}", re.I), "Private key in response"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", re.I), "Private key material in response"),
]


def is_available() -> bool:
    return True


def scan(url: str, options: dict[str, Any] | None = None) -> list[DynamicFinding]:
    opts = options or {}
    timeout = opts.get("timeout", 15)

    findings: list[DynamicFinding] = []
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        # ── 1. Discover OpenAPI spec ───────────────────────────────────────────
        spec = _discover_spec(client, base)

        if spec:
            findings.append(_finding(
                url, "OpenAPI spec publicly accessible",
                f"The API exposes its full OpenAPI/Swagger specification without authentication. "
                f"This reveals all endpoints, parameters, schemas, and server details to attackers.",
                "low", "information_disclosure",
                evidence=f"Spec found at {spec['_url']}",
                remediation="Restrict access to the API spec in production, or require authentication to view it.",
            ))

            # ── 2. Test each endpoint ──────────────────────────────────────────
            for path, path_item in spec.get("paths", {}).items():
                for method, operation in path_item.items():
                    if method.lower() not in ("get", "post", "put", "patch", "delete"):
                        continue
                    findings.extend(_test_endpoint(
                        client, base, path, method.upper(), operation, timeout,
                    ))
        else:
            # No spec — fall back to probing common paths
            findings.extend(_probe_common_paths(client, base, timeout))

    return findings


# ── Spec discovery ─────────────────────────────────────────────────────────────

def _discover_spec(client: httpx.Client, base: str) -> dict | None:
    for path in _SPEC_PATHS:
        try:
            r = client.get(base + path)
            if r.status_code == 200:
                ct = r.headers.get("content-type", "")
                if "json" in ct or path.endswith(".json"):
                    try:
                        d = r.json()
                        if "paths" in d or "swagger" in d or "openapi" in d:
                            d["_url"] = base + path
                            return d
                    except Exception:
                        pass
        except httpx.RequestError:
            pass
    return None


# ── Per-endpoint testing ───────────────────────────────────────────────────────

def _test_endpoint(
    client: httpx.Client,
    base: str,
    path: str,
    method: str,
    operation: dict,
    timeout: int,
) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    params = operation.get("parameters", [])

    full_url = base + path

    # ── Check if endpoint requires auth ───────────────────────────────────────
    security = operation.get("security")
    if security is None:
        # Try unauthenticated request
        try:
            r = _make_request(client, method, full_url, {})
            if r.status_code == 200:
                # Check for sensitive data in response
                body = r.text
                for pattern, label in _SENSITIVE_PATTERNS:
                    if pattern.search(body):
                        findings.append(_finding(
                            full_url, f"{label} — unauthenticated {method} {path}",
                            f"The endpoint {method} {path} returns sensitive data without requiring authentication.",
                            "critical", "sensitive_data_exposure",
                            evidence=f"HTTP {r.status_code}: {body[:300]}",
                            remediation="Require authentication for this endpoint and remove sensitive fields from responses.",
                        ))
        except httpx.RequestError:
            pass

    # ── Test path parameters for injection ────────────────────────────────────
    path_params = [p for p in params if p.get("in") == "path"]
    query_params = [p for p in params if p.get("in") == "query"]
    header_params = [p for p in params if p.get("in") == "header"]

    # Command injection in path params
    for param in path_params:
        pname = param.get("name", "")
        for payload in _CMD_PAYLOADS:
            test_path = path.replace(f"{{{pname}}}", urllib.parse.quote(payload, safe=""))
            test_url = base + test_path
            try:
                r = _make_request(client, method, test_url, {})
                if _CMD_DETECTION.search(r.text):
                    findings.append(_finding(
                        test_url,
                        f"OS Command Injection in path parameter `{pname}`",
                        f"{method} {path} — the `{pname}` path parameter is passed to a shell command "
                        f"without sanitisation. Payload `{payload}` returned command output.",
                        "critical", "os_command_injection",
                        evidence=f"Payload: {payload}\nResponse: {r.text[:400]}",
                        remediation=f"Never interpolate user input into shell commands. "
                                    f"Use allowlists for the `{pname}` parameter values.",
                    ))
                    break
            except httpx.RequestError:
                pass

        # Python/JS eval injection in path params
        for expr, expected in _EVAL_PAYLOADS:
            test_path = path.replace(f"{{{pname}}}", urllib.parse.quote(expr, safe=""))
            test_url = base + test_path
            try:
                r = _make_request(client, method, test_url, {})
                if expected in r.text:
                    findings.append(_finding(
                        test_url,
                        f"Code Injection (eval) in path parameter `{pname}`",
                        f"{method} {path} — the `{pname}` path parameter is passed to eval() or "
                        f"similar. Expression `{expr}` was evaluated server-side.",
                        "critical", "code_injection",
                        evidence=f"Payload: {expr}\nResponse: {r.text[:400]}",
                        remediation=f"Never pass user input to eval(), exec(), or similar functions. "
                                    f"Validate `{pname}` against a strict allowlist.",
                    ))
                    break
            except httpx.RequestError:
                pass

        # Path traversal in path params
        for payload in _TRAVERSAL_PAYLOADS:
            test_path = path.replace(f"{{{pname}}}", urllib.parse.quote(payload, safe=""))
            test_url = base + test_path
            try:
                r = _make_request(client, method, test_url, {})
                if _TRAVERSAL_DETECTION.search(r.text):
                    findings.append(_finding(
                        test_url,
                        f"Path Traversal in path parameter `{pname}`",
                        f"{method} {path} — the `{pname}` path parameter is used to construct a "
                        f"file-system path without canonicalisation. `/etc/passwd` content was returned.",
                        "critical", "path_traversal",
                        evidence=f"Payload: {payload}\nResponse: {r.text[:400]}",
                        remediation=f"Canonicalise paths with os.path.realpath() and verify the result "
                                    f"starts with the intended base directory. Reject `..` sequences.",
                    ))
                    break
            except httpx.RequestError:
                pass

    # ── Test query parameters ─────────────────────────────────────────────────
    for param in query_params:
        pname = param.get("name", "")

        # Command injection
        for payload in _CMD_PAYLOADS:
            try:
                r = _make_request(client, method, full_url, {pname: payload})
                if _CMD_DETECTION.search(r.text):
                    findings.append(_finding(
                        full_url,
                        f"OS Command Injection in query parameter `{pname}`",
                        f"{method} {path}?{pname}=... — the `{pname}` query parameter is passed "
                        f"to a shell command. Payload `{payload}` returned command output.",
                        "critical", "os_command_injection",
                        evidence=f"Payload: {payload}\nResponse: {r.text[:400]}",
                        remediation=f"Never interpolate query parameters into shell commands. "
                                    f"Use subprocess with array arguments instead of shell=True.",
                    ))
                    break
            except httpx.RequestError:
                pass

        # Eval injection
        for expr, expected in _EVAL_PAYLOADS:
            try:
                r = _make_request(client, method, full_url, {pname: expr})
                if expected in r.text:
                    findings.append(_finding(
                        full_url,
                        f"Code Injection (eval) in query parameter `{pname}`",
                        f"{method} {path}?{pname}=... — the `{pname}` query parameter is passed "
                        f"to eval(). Expression `{expr}` was evaluated.",
                        "critical", "code_injection",
                        evidence=f"Payload: {expr}\nResponse: {r.text[:400]}",
                        remediation=f"Never pass query parameters to eval(). "
                                    f"Validate input against an allowlist.",
                    ))
                    break
            except httpx.RequestError:
                pass

        # SQL injection
        for payload in _SQLI_PAYLOADS:
            try:
                r = _make_request(client, method, full_url, {pname: payload})
                if _SQLI_ERRORS.search(r.text):
                    findings.append(_finding(
                        full_url,
                        f"SQL Injection in query parameter `{pname}`",
                        f"{method} {path}?{pname}=... — the `{pname}` parameter is interpolated "
                        f"into a SQL query. A database error was returned for payload `{payload}`.",
                        "critical", "sql_injection",
                        evidence=f"Payload: {payload}\nResponse: {r.text[:400]}",
                        remediation=f"Use parameterised queries (prepared statements). "
                                    f"Never concatenate user input into SQL strings.",
                    ))
                    break
            except httpx.RequestError:
                pass

    # ── Test POST/PUT body for injection ──────────────────────────────────────
    if method in ("POST", "PUT", "PATCH"):
        # Try XXE if endpoint might accept XML
        try:
            r = client.request(
                method, full_url,
                content=_XXE_PAYLOAD,
                headers={"Content-Type": "application/xml"},
            )
            if _XXE_DETECTION.search(r.text):
                findings.append(_finding(
                    full_url,
                    f"XML External Entity (XXE) Injection — {method} {path}",
                    f"The endpoint accepts XML and resolves external entities. "
                    f"An XXE payload returned /etc/passwd content.",
                    "critical", "xxe_injection",
                    evidence=f"Response: {r.text[:400]}",
                    remediation="Disable DTD processing and external entity resolution on the XML parser. "
                                "Use defusedxml in Python or set XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES=false in Java.",
                ))
        except httpx.RequestError:
            pass

        # Try JSON body injection
        for field_name in ("q", "query", "search", "input", "cmd", "command", "expr", "code", "s"):
            for expr, expected in _EVAL_PAYLOADS:
                try:
                    r = client.request(
                        method, full_url,
                        json={field_name: expr},
                        headers={"Content-Type": "application/json"},
                    )
                    if expected in r.text and r.status_code != 404:
                        findings.append(_finding(
                            full_url,
                            f"Code Injection (eval) in request body field `{field_name}`",
                            f"{method} {path} — the `{field_name}` JSON body field is passed to eval(). "
                            f"Expression `{expr}` was evaluated server-side.",
                            "critical", "code_injection",
                            evidence=f"Field: {field_name}, Payload: {expr}\nResponse: {r.text[:400]}",
                            remediation="Never pass request body fields to eval(). Validate all input.",
                        ))
                        break
                except httpx.RequestError:
                    pass

    return findings


# ── Fallback: probe common vulnerable paths ───────────────────────────────────

def _probe_common_paths(
    client: httpx.Client, base: str, timeout: int,
) -> list[DynamicFinding]:
    findings: list[DynamicFinding] = []
    common = [
        "/admin", "/api/admin", "/debug", "/console",
        "/api/v1/users", "/api/users", "/api/user",
        "/graphql", "/api/graphql",
    ]
    for path in common:
        try:
            r = client.get(base + path)
            if r.status_code == 200:
                for pattern, label in _SENSITIVE_PATTERNS:
                    if pattern.search(r.text):
                        findings.append(_finding(
                            base + path, f"{label} at {path}",
                            f"GET {path} returned HTTP 200 with sensitive data in the response body.",
                            "high", "sensitive_data_exposure",
                            evidence=r.text[:300],
                            remediation="Require authentication and remove sensitive fields from responses.",
                        ))
        except httpx.RequestError:
            pass
    return findings


# ── Request helper ─────────────────────────────────────────────────────────────

def _make_request(
    client: httpx.Client,
    method: str,
    url: str,
    query_params: dict,
) -> httpx.Response:
    if method == "GET":
        return client.get(url, params=query_params)
    elif method == "POST":
        return client.post(url, json=query_params or {})
    elif method == "PUT":
        return client.put(url, json=query_params or {})
    elif method == "PATCH":
        return client.patch(url, json=query_params or {})
    elif method == "DELETE":
        return client.delete(url, params=query_params)
    return client.get(url, params=query_params)


# ── Finding factory ────────────────────────────────────────────────────────────

def _finding(
    url: str,
    name: str,
    description: str,
    severity: str,
    category: str,
    remediation: str | None = None,
    evidence: str | None = None,
) -> DynamicFinding:
    return DynamicFinding(
        tool=TOOL,
        target=url,
        name=name,
        description=description,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        evidence=evidence or "",
        url=url,
        port=None,
        cve=None,
        remediation=remediation,
    )
