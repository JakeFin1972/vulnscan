"""Tests for dynamic scanners (NMAP, ZAP, OpenVAS, MCP) and the dynamic scan API.

All tests are designed to pass without the external tools installed:
  • Scanner availability checks verified.
  • Output parsing verified with fixture data.
  • API endpoints verified with mocked scanner.
  • MCP scanner probed against a local test HTTP server.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from vulnscan.scanners.base import cvss_to_severity, nmap_service_severity
from vulnscan.scanners import nmap_scanner, zap_scanner, openvas_scanner, mcp_scanner


# ──────────────────────────────────────────────────────────────────────────────
# base.py helpers
# ──────────────────────────────────────────────────────────────────────────────

def test_cvss_to_severity():
    from vulnscan.scanners.base import cvss_to_severity
    assert cvss_to_severity(9.5)  == "critical"
    assert cvss_to_severity(7.0)  == "high"
    assert cvss_to_severity(4.0)  == "medium"
    assert cvss_to_severity(1.0)  == "low"
    assert cvss_to_severity(0.0)  == "info"


def test_nmap_service_severity():
    assert nmap_service_severity("telnet", 23)   == "high"
    assert nmap_service_severity("ftp",    21)   == "high"
    assert nmap_service_severity("ssh",    22)   == "medium"
    assert nmap_service_severity("mysql",  3306) == "medium"
    assert nmap_service_severity("redis",  6379) == "medium"
    assert nmap_service_severity("http",   80)   == "info"


# ──────────────────────────────────────────────────────────────────────────────
# NMAP scanner
# ──────────────────────────────────────────────────────────────────────────────

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)"/>
    </hostscript>
  </host>
</nmaprun>"""


def test_nmap_xml_parsing():
    findings = nmap_scanner._parse_xml(_NMAP_XML, "192.168.1.1")
    kinds = [f.category for f in findings]
    # open_port for ssh, telnet, http (port 443 is closed → skipped)
    open_ports = [f for f in findings if f.category == "open_port"]
    assert len(open_ports) == 3

    port_nums = {f.port for f in open_ports}
    assert 22 in port_nums
    assert 23 in port_nums
    assert 80 in port_nums
    assert 443 not in port_nums  # closed

    # Telnet should be high severity
    telnet = next(f for f in open_ports if f.port == 23)
    assert telnet.severity == "high"

    # SSH should be medium
    ssh = next(f for f in open_ports if f.port == 22)
    assert ssh.severity == "medium"

    # Host-level vuln script should produce a critical finding
    vuln = [f for f in findings if f.category == "vulnerability"]
    assert len(vuln) >= 1
    assert vuln[0].severity == "critical"


def test_nmap_missing_returns_info_finding():
    """If nmap is not installed, scan() returns a single info finding."""
    import unittest.mock as mock
    with mock.patch.object(nmap_scanner, "_NMAP", None):
        findings = nmap_scanner.scan("127.0.0.1")
    assert len(findings) == 1
    assert findings[0].category == "scanner_unavailable"
    assert findings[0].severity == "info"


def test_nmap_is_available_reflects_binary():
    available = nmap_scanner.is_available()
    has_nmap = shutil.which("nmap") is not None
    assert available == has_nmap


# ──────────────────────────────────────────────────────────────────────────────
# ZAP scanner
# ──────────────────────────────────────────────────────────────────────────────

def test_zap_alerts_to_findings():
    alerts = [
        {
            "name": "SQL Injection",
            "risk": "High",
            "confidence": "High",
            "description": "SQL injection vulnerability found.",
            "solution": "Use parameterised queries.",
            "url": "http://example.com/api?id=1",
            "evidence": "'1'='1",
            "cweid": "89",
            "wascid": "19",
            "param": "id",
        },
        {
            "name": "Cookie Without Secure Flag",
            "risk": "Low",
            "confidence": "Medium",
            "description": "Cookie missing Secure flag.",
            "solution": "Add Secure attribute.",
            "url": "http://example.com/",
            "evidence": "Set-Cookie: session=abc",
            "cweid": "",
            "wascid": "",
            "param": "",
        },
        {
            "name": "False Alarm",
            "risk": "High",
            "confidence": "False Positive",  # must be excluded
            "description": "This is a false positive.",
            "url": "http://example.com/",
            "cweid": "", "wascid": "", "param": "", "evidence": "", "solution": "",
        },
    ]
    findings = zap_scanner._alerts_to_findings(alerts, "http://example.com")
    # False positive excluded
    names = [f.name for f in findings]
    assert "False Alarm" not in names
    assert any("SQL" in n for n in names)
    # SQL injection should be elevated to critical
    sql = next(f for f in findings if "SQL" in f.name)
    assert sql.severity == "critical"
    assert sql.category == "sql_injection"


def test_zap_unavailable_returns_info():
    """If zaproxy isn't reachable, scan returns a single info finding."""
    import unittest.mock as mock
    with mock.patch.object(zap_scanner, "_ZAP_AVAILABLE", False):
        findings = zap_scanner.scan("http://example.com")
    assert len(findings) == 1
    assert findings[0].category == "scanner_unavailable"


# ──────────────────────────────────────────────────────────────────────────────
# OpenVAS scanner
# ──────────────────────────────────────────────────────────────────────────────

def test_openvas_unavailable_returns_info():
    import unittest.mock as mock
    with mock.patch.object(openvas_scanner, "_GVM_AVAILABLE", False):
        findings = openvas_scanner.scan("10.0.0.1")
    assert len(findings) == 1
    assert findings[0].category == "scanner_unavailable"


def test_openvas_cvss_classification():
    assert openvas_scanner._classify_nvt("", "CVE-2021-44228") == "cve"
    assert openvas_scanner._classify_nvt("Default credentials found", "") == "default_credentials"
    assert openvas_scanner._classify_nvt("SSL Certificate Expired", "")  == "tls_issue"


# ──────────────────────────────────────────────────────────────────────────────
# MCP scanner — local test server
# ──────────────────────────────────────────────────────────────────────────────

# Minimal MCP server that responds to JSON-RPC 2.0 requests
_MCP_TOOLS = [
    {
        "name": "execute_shell",
        "description": "Executes a shell command on the server",
        "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
    },
    {
        "name": "fetch_url",
        "description": "Fetches content from a URL",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
    },
    {
        "name": "read_file",
        "description": "Reads a file from disk",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "search",
        "description": "Search for items",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    },
]

_MCP_RESOURCES = [
    {"uri": "file:///etc/passwd", "name": "passwd"},
    {"uri": "config://secret_key",  "name": "secret"},
]


class _MCPHandler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass  # suppress logging

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self.send_error(400); return

        method = req.get("method", "")
        req_id = req.get("id", 1)

        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}, "resources": {}}, "serverInfo": {"name": "test-mcp", "version": "0.1"}}
        elif method == "tools/list":
            result = {"tools": _MCP_TOOLS}
        elif method == "resources/list":
            result = {"resources": _MCP_RESOURCES}
        elif method == "prompts/list":
            result = {"prompts": []}
        else:
            result = {}

        resp = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


@pytest.fixture(scope="module")
def mcp_server():
    server = HTTPServer(("127.0.0.1", 0), _MCPHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_mcp_detects_no_auth(mcp_server):
    findings = mcp_scanner.scan(mcp_server)
    cats = {f.category for f in findings}
    assert "unauthenticated_access" in cats


def test_mcp_flags_shell_tool(mcp_server):
    findings = mcp_scanner.scan(mcp_server)
    cats = {f.category for f in findings}
    assert "mcp_code_execution_tool" in cats
    shell = next(f for f in findings if f.category == "mcp_code_execution_tool")
    assert shell.severity == "critical"


def test_mcp_flags_ssrf_tool(mcp_server):
    findings = mcp_scanner.scan(mcp_server)
    cats = {f.category for f in findings}
    assert "ssrf_candidate" in cats


def test_mcp_flags_sensitive_resources(mcp_server):
    findings = mcp_scanner.scan(mcp_server)
    cats = {f.category for f in findings}
    assert "sensitive_data_exposure" in cats


def test_mcp_flags_prompt_injection_surface(mcp_server):
    findings = mcp_scanner.scan(mcp_server)
    cats = {f.category for f in findings}
    assert "prompt_injection_surface" in cats


def test_mcp_unreachable():
    findings = mcp_scanner.scan("http://127.0.0.1:1")  # nothing listening
    assert len(findings) >= 1
    assert any(f.category in ("scanner_unavailable", "scanner_error") for f in findings)


def test_mcp_http_transport_warning():
    """HTTP (not HTTPS) should produce a missing_encryption finding."""
    # Use a fake unreachable HTTP URL — the transport check runs before connection
    findings = mcp_scanner.scan("http://127.0.0.1:1")
    transport_findings = [f for f in findings if f.category == "missing_encryption"]
    assert len(transport_findings) == 1
    assert transport_findings[0].severity == "medium"


# ──────────────────────────────────────────────────────────────────────────────
# Dynamic scan API endpoints
# ──────────────────────────────────────────────────────────────────────────────

_BUILTIN_DEFS = Path(__file__).parent.parent / "src" / "vulnscan" / "languages" / "defs"
_BUILTIN_DEF_NAMES = ["csharp.yaml"]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import importlib, shutil
    import vulnscan.api as api_mod

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    defs_dir = tmp_path / "defs"
    defs_dir.mkdir()
    for name in _BUILTIN_DEF_NAMES:
        src = _BUILTIN_DEFS / name
        if src.exists():
            shutil.copy(src, defs_dir / name)

    monkeypatch.setenv("VULNSCAN_DATA_DIR", str(data_dir))
    monkeypatch.setenv("VULNSCAN_DEFS_DIR", str(defs_dir))
    importlib.reload(api_mod)
    api_mod._init_db()

    from fastapi.testclient import TestClient
    with TestClient(api_mod.app, raise_server_exceptions=True) as c:
        yield c


def test_scanners_endpoint(client):
    r = client.get("/scanners")
    assert r.status_code == 200
    body = r.json()
    assert "nmap" in body
    assert "zap" in body
    assert "openvas" in body
    assert "mcp" in body
    # MCP is always available
    assert body["mcp"]["available"] is True


def test_dynamic_scan_requires_authorization(client):
    r = client.post("/dynamic-scans", json={
        "target": "http://example.com",
        "target_type": "url",
        "authorized": False,
    })
    assert r.status_code == 422


def test_dynamic_scan_invalid_target_type(client):
    r = client.post("/dynamic-scans", json={
        "target": "http://example.com",
        "target_type": "floppy_disk",
        "authorized": True,
    })
    assert r.status_code == 422


def test_dynamic_scan_mcp_lifecycle(client, mcp_server):
    """Start a dynamic MCP scan, wait for completion, check findings."""
    r = client.post("/dynamic-scans", json={
        "target": mcp_server,
        "target_type": "mcp",
        "tools": ["mcp"],
        "authorized": True,
    })
    assert r.status_code == 201
    scan_id = r.json()["id"]

    # Poll for completion
    for _ in range(20):
        s = client.get(f"/dynamic-scans/{scan_id}").json()
        if s["status"] in ("done", "error"):
            break
        time.sleep(0.3)

    assert s["status"] == "done", f"scan error: {s.get('error')}"
    assert s["finding_count"] >= 1

    # Findings endpoint
    r2 = client.get(f"/dynamic-findings?scan_id={scan_id}")
    assert r2.status_code == 200
    findings = r2.json()
    assert len(findings) >= 1
    for f in findings:
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert f["tool"] == "mcp"

    # Filter by severity
    r3 = client.get(f"/dynamic-findings?scan_id={scan_id}&severity=critical")
    assert r3.status_code == 200
    for f in r3.json():
        assert f["severity"] == "critical"


def test_list_dynamic_scans(client):
    r = client.get("/dynamic-scans")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_dynamic_scan_not_found(client):
    r = client.get("/dynamic-scans/nonexistent")
    assert r.status_code == 404


def test_health_includes_scanners(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert "scanners" in body
    assert "dynamic_scan_count" in body
