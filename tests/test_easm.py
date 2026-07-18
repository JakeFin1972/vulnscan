"""Tests for the EASM subsystem: parsers, scoring engine, and API endpoints.

All tests run without any external tools installed.  Scanner output is provided
as in-file fixture strings.  API tests use the same isolated-DB pattern as
``test_api.py`` (temp dirs + monkeypatched env vars + module reload).
"""
from __future__ import annotations

import importlib
import io
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# ── Parser fixtures ────────────────────────────────────────────────────────────

_NMAP_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010"
              output="VULNERABLE: Remote Code Execution via EternalBlue (ms17-010)"/>
    </hostscript>
  </host>
</nmaprun>"""

_OPENVAS_XML = """\
<get_results_response status="200" status_text="OK">
  <result id="r1">
    <name>Default Credentials Found</name>
    <description>Admin account uses default password 'admin'.</description>
    <host>192.168.1.100</host>
    <port>8080/tcp</port>
    <severity>9.8</severity>
    <nvt oid="1.3.6.1.4.1.25623.1.0.100001">
      <solution>Change default credentials immediately.</solution>
      <refs>
        <ref type="cve" id="CVE-2022-1234"/>
      </refs>
    </nvt>
  </result>
  <result id="r2">
    <name>SSL Certificate Expired</name>
    <description>The SSL certificate has expired.</description>
    <host>192.168.1.100</host>
    <port>443/tcp</port>
    <severity>4.3</severity>
    <nvt oid="1.3.6.1.4.1.25623.1.0.100002">
      <solution>Renew the SSL certificate.</solution>
    </nvt>
  </result>
  <result id="r3">
    <name>Log</name>
    <description/>
    <host>192.168.1.100</host>
    <port>general/tcp</port>
    <severity>0</severity>
    <nvt oid="1.3.6.1.4.1.25623.1.0.100003"/>
  </result>
</get_results_response>"""

_ZAP_JSON = json.dumps({
    "site": [{
        "name": "http://example.com",
        "host": "example.com",
        "alerts": [
            {
                "name": "SQL Injection",
                "risk": "High",
                "confidence": "High",
                "description": "SQL injection vulnerability detected.",
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
                # False positive — must be excluded
                "name": "Ghost Alert",
                "risk": "High",
                "confidence": "False Positive",
                "description": "Not real.",
                "url": "http://example.com/",
                "cweid": "", "wascid": "", "param": "", "evidence": "",
                "solution": "",
            },
        ],
    }]
})

_NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "CVE-2021-44228",
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "description": "Log4Shell remote code execution.",
            "tags": ["cve", "log4j", "rce"],
            "classification": {
                "cve-id": "CVE-2021-44228",
                "cwe-id": ["CWE-502"],
                "cvss-score": 10.0,
            },
            "remediation": "Upgrade Log4j to 2.15.0 or later.",
        },
        "host": "http://target.example.com",
        "matched-at": "http://target.example.com/api",
        "ip": "93.184.216.34",
        "timestamp": "2024-06-01T12:00:00.000000000Z",
        "matcher-status": True,
    }),
    json.dumps({
        "template-id": "exposed-panel",
        "info": {
            "name": "Admin Panel Exposed",
            "severity": "medium",
            "description": "Admin login page is publicly accessible.",
            "tags": ["panel", "exposure"],
        },
        "host": "http://target.example.com",
        "matched-at": "http://target.example.com/admin",
        "timestamp": "2024-06-01T12:00:01Z",
        "matcher-status": True,
    }),
    json.dumps({
        "template-id": "false-template",
        "info": {"name": "False Match", "severity": "high"},
        "host": "http://target.example.com",
        "timestamp": "2024-06-01T12:00:02Z",
        "matcher-status": False,   # must be excluded
    }),
    "this line is not JSON at all — should be skipped silently",
])


# ══════════════════════════════════════════════════════════════════════════════
# Parser tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNmapParser:
    def test_open_ports_detected(self):
        from vulnscan.easm.parsers.nmap import parse
        vulns = parse(_NMAP_XML)
        open_ports = [v for v in vulns if v.category == "open_port"]
        ports = {v.port for v in open_ports}
        assert 22 in ports
        assert 23 in ports
        assert 443 not in ports          # closed port skipped

    def test_telnet_is_high(self):
        from vulnscan.easm.parsers.nmap import parse
        vulns = parse(_NMAP_XML)
        telnet = next(v for v in vulns if v.port == 23)
        assert telnet.severity == "high"

    def test_ssh_is_medium(self):
        from vulnscan.easm.parsers.nmap import parse
        vulns = parse(_NMAP_XML)
        ssh = next(v for v in vulns if v.port == 22)
        assert ssh.severity == "medium"

    def test_smb_vuln_script_critical(self):
        from vulnscan.easm.parsers.nmap import parse
        vulns = parse(_NMAP_XML)
        vuln_scripts = [v for v in vulns if v.category == "vulnerability"]
        assert len(vuln_scripts) >= 1
        assert vuln_scripts[0].severity == "critical"

    def test_asset_set_correctly(self):
        from vulnscan.easm.parsers.nmap import parse
        vulns = parse(_NMAP_XML)
        assert all(v.asset == "10.0.0.5" for v in vulns)
        assert all(v.asset_type == "ip" for v in vulns)

    def test_source_tool_is_nmap(self):
        from vulnscan.easm.parsers.nmap import parse
        vulns = parse(_NMAP_XML)
        assert all(v.source_tool == "nmap" for v in vulns)

    def test_invalid_xml_raises(self):
        from vulnscan.easm.parsers.nmap import parse
        with pytest.raises(ValueError, match="Invalid Nmap XML"):
            parse("<this is not xml</")

    def test_down_host_skipped(self):
        from vulnscan.easm.parsers.nmap import parse
        xml = """<nmaprun>
          <host>
            <status state="down"/>
            <address addr="1.2.3.4" addrtype="ipv4"/>
          </host>
        </nmaprun>"""
        assert parse(xml) == []


class TestOpenVASParser:
    def test_cvss_to_severity_critical(self):
        from vulnscan.easm.parsers.openvas import parse
        vulns = parse(_OPENVAS_XML)
        cred = next(v for v in vulns if "Default" in v.name)
        assert cred.severity == "critical"
        assert cred.cvss_score == 9.8

    def test_cve_extracted(self):
        from vulnscan.easm.parsers.openvas import parse
        vulns = parse(_OPENVAS_XML)
        cred = next(v for v in vulns if "Default" in v.name)
        assert cred.cve == "CVE-2022-1234"
        assert cred.category == "cve"

    def test_ssl_category(self):
        from vulnscan.easm.parsers.openvas import parse
        vulns = parse(_OPENVAS_XML)
        ssl = next(v for v in vulns if "SSL" in v.name)
        assert ssl.category == "tls_issue"
        assert ssl.severity == "medium"

    def test_port_parsed(self):
        from vulnscan.easm.parsers.openvas import parse
        vulns = parse(_OPENVAS_XML)
        cred = next(v for v in vulns if "Default" in v.name)
        assert cred.port == 8080
        assert cred.protocol == "tcp"

    def test_zero_cvss_is_info(self):
        from vulnscan.easm.parsers.openvas import parse
        vulns = parse(_OPENVAS_XML)
        log = next((v for v in vulns if v.name == "Log"), None)
        # Log result has severity 0 → should be info
        assert log is not None
        assert log.severity == "info"

    def test_report_wrapper_format(self):
        from vulnscan.easm.parsers.openvas import parse
        xml = """<report>
          <results>
            <result id="x">
              <name>Test Vuln</name>
              <description>A test.</description>
              <host>10.1.1.1</host>
              <port>80/tcp</port>
              <severity>7.5</severity>
              <nvt oid="1.2.3"/>
            </result>
          </results>
        </report>"""
        vulns = parse(xml)
        assert len(vulns) == 1
        assert vulns[0].severity == "high"

    def test_invalid_xml_raises(self):
        from vulnscan.easm.parsers.openvas import parse
        with pytest.raises(ValueError, match="Invalid OpenVAS XML"):
            parse("<<not xml>>")


class TestZAPParser:
    def test_sql_injection_critical(self):
        from vulnscan.easm.parsers.zap import parse
        vulns = parse(_ZAP_JSON)
        sql = next(v for v in vulns if "SQL" in v.name)
        # CWE-89 → sqli → elevated to critical
        assert sql.severity == "critical"
        assert sql.category == "sqli"
        assert sql.cwe == "CWE-89"

    def test_false_positive_excluded(self):
        from vulnscan.easm.parsers.zap import parse
        vulns = parse(_ZAP_JSON)
        names = [v.name for v in vulns]
        assert "Ghost Alert" not in names

    def test_low_risk_cookie(self):
        from vulnscan.easm.parsers.zap import parse
        vulns = parse(_ZAP_JSON)
        cookie = next(v for v in vulns if "Cookie" in v.name)
        assert cookie.severity == "low"

    def test_bare_alerts_array(self):
        from vulnscan.easm.parsers.zap import parse
        alerts = json.dumps([{
            "name": "X-Frame-Options Header Not Set",
            "risk": "Medium",
            "confidence": "Medium",
            "description": "Missing clickjacking protection.",
            "solution": "Add X-Frame-Options header.",
            "url": "http://example.com",
            "cweid": "", "wascid": "", "param": "", "evidence": "",
        }])
        vulns = parse(alerts)
        assert len(vulns) == 1
        assert vulns[0].severity == "medium"

    def test_invalid_json_raises(self):
        from vulnscan.easm.parsers.zap import parse
        with pytest.raises(ValueError, match="Invalid ZAP JSON"):
            parse("{not valid json")

    def test_asset_extracted_from_url(self):
        from vulnscan.easm.parsers.zap import parse
        vulns = parse(_ZAP_JSON)
        sql = next(v for v in vulns if "SQL" in v.name)
        assert sql.asset == "example.com"
        assert sql.asset_type == "domain"


class TestNucleiParser:
    def test_log4shell_critical(self):
        from vulnscan.easm.parsers.nuclei import parse
        vulns = parse(_NUCLEI_JSONL)
        log4j = next(v for v in vulns if "Log4j" in v.name or "CVE-2021-44228" in (v.cve or ""))
        assert log4j.severity == "critical"
        assert log4j.cve == "CVE-2021-44228"
        assert log4j.cvss_score == 10.0
        assert log4j.category == "cve"

    def test_false_match_excluded(self):
        from vulnscan.easm.parsers.nuclei import parse
        vulns = parse(_NUCLEI_JSONL)
        names = [v.name for v in vulns]
        assert "False Match" not in names

    def test_invalid_json_lines_skipped(self):
        from vulnscan.easm.parsers.nuclei import parse
        # The fixture already contains a non-JSON line; make sure we get 2 results
        vulns = parse(_NUCLEI_JSONL)
        assert len(vulns) == 2      # Log4Shell + Admin Panel; false match excluded

    def test_admin_panel_medium(self):
        from vulnscan.easm.parsers.nuclei import parse
        vulns = parse(_NUCLEI_JSONL)
        panel = next(v for v in vulns if "Admin Panel" in v.name)
        assert panel.severity == "medium"

    def test_timestamp_normalised(self):
        from vulnscan.easm.parsers.nuclei import parse
        vulns = parse(_NUCLEI_JSONL)
        log4j = next(v for v in vulns if "Log4j" in v.name)
        # Should be parseable as ISO datetime
        assert "2024-06-01" in log4j.discovered_at

    def test_asset_extracted(self):
        from vulnscan.easm.parsers.nuclei import parse
        vulns = parse(_NUCLEI_JSONL)
        assert all(v.asset == "target.example.com" for v in vulns)
        assert all(v.asset_type == "domain" for v in vulns)


# ══════════════════════════════════════════════════════════════════════════════
# Parser dispatcher tests
# ══════════════════════════════════════════════════════════════════════════════

class TestParserDispatcher:
    def test_detects_nmap_xml(self):
        from vulnscan.easm.parsers import parse_file
        vulns = parse_file(content=_NMAP_XML)
        assert any(v.source_tool == "nmap" for v in vulns)

    def test_detects_openvas_xml(self):
        from vulnscan.easm.parsers import parse_file
        vulns = parse_file(content=_OPENVAS_XML)
        assert any(v.source_tool == "openvas" for v in vulns)

    def test_detects_zap_json(self):
        from vulnscan.easm.parsers import parse_file
        vulns = parse_file(content=_ZAP_JSON)
        assert any(v.source_tool == "zap" for v in vulns)

    def test_detects_nuclei_jsonl(self):
        from vulnscan.easm.parsers import parse_file
        vulns = parse_file(content=_NUCLEI_JSONL)
        assert any(v.source_tool == "nuclei" for v in vulns)

    def test_hint_overrides_detection(self):
        from vulnscan.easm.parsers import parse_file
        # Force openvas even though content looks like zap-ish json that won't parse
        with pytest.raises(ValueError):
            parse_file(content=_ZAP_JSON, hint="nmap")   # valid JSON ≠ XML → parse error

    def test_unknown_hint_raises(self):
        from vulnscan.easm.parsers import parse_file
        with pytest.raises(ValueError, match="Unknown tool hint"):
            parse_file(content="<x/>", hint="burpsuite")

    def test_no_source_raises(self):
        from vulnscan.easm.parsers import parse_file
        with pytest.raises(ValueError):
            parse_file()


# ══════════════════════════════════════════════════════════════════════════════
# Scoring engine tests
# ══════════════════════════════════════════════════════════════════════════════

def _make_vuln(**kwargs):
    """Create a minimal Vulnerability for scoring tests."""
    from vulnscan.easm.schema import Vulnerability
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    defaults = dict(
        id="test-id", asset="10.0.0.1", asset_type="ip",
        source_tool="nmap", name="Test", description="",
        severity="info", category="open_port",
        discovered_at=now, last_seen_at=now,
    )
    defaults.update(kwargs)
    return Vulnerability(**defaults)


class TestScoringEngine:
    def test_clean_environment_scores_100(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        rs = score_vulnerabilities([])
        assert rs.score == 100.0
        assert rs.grade == "A"
        assert rs.open_count == 0

    def test_info_only_still_100(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        vulns = [_make_vuln(severity="info")]
        rs = score_vulnerabilities(vulns)
        assert rs.score == 100.0

    def test_single_fresh_critical_is_B_or_worse(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        vulns = [_make_vuln(severity="critical")]
        rs = score_vulnerabilities(vulns)
        # 100 - 15 (base) = 85 → B
        assert rs.score == pytest.approx(85.0, abs=1.0)
        assert rs.grade in ("A", "B")

    def test_critical_with_high_cvss_lowers_further(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        v_no_cvss  = _make_vuln(severity="critical")
        v_with_cvss = _make_vuln(severity="critical", cvss_score=9.8)
        rs_plain = score_vulnerabilities([v_no_cvss])
        rs_cvss  = score_vulnerabilities([v_with_cvss])
        assert rs_cvss.score < rs_plain.score

    def test_old_vuln_penalised_more_than_fresh(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        old_date = (datetime.utcnow() - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        fresh = _make_vuln(severity="high")
        aged  = _make_vuln(severity="high", discovered_at=old_date)
        rs_fresh = score_vulnerabilities([fresh])
        rs_aged  = score_vulnerabilities([aged])
        assert rs_aged.score < rs_fresh.score

    def test_resolved_vulns_excluded(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        open_v    = _make_vuln(severity="critical", status="open")
        resolved  = _make_vuln(severity="critical", status="resolved")
        rs_open   = score_vulnerabilities([open_v])
        rs_resolved = score_vulnerabilities([resolved])
        assert rs_resolved.score == 100.0
        assert rs_open.score < 100.0

    def test_false_positives_excluded(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        fp = _make_vuln(severity="critical", status="false_positive")
        rs = score_vulnerabilities([fp])
        assert rs.score == 100.0

    def test_many_criticals_capped_not_negative(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        vulns = [_make_vuln(severity="critical", cvss_score=10.0) for _ in range(20)]
        rs = score_vulnerabilities(vulns)
        assert rs.score >= 0.0

    def test_grade_F_for_catastrophic_posture(self):
        # F requires exhausting multiple severity tier caps simultaneously.
        # Criticals alone are capped at 60pts deduction (score floor 40 = D).
        # Add aged highs + mediums to push total deduction past 60.
        from vulnscan.easm.scoring import score_vulnerabilities
        old_date = (datetime.utcnow() - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
        vulns = (
            [_make_vuln(severity="critical", cvss_score=10.0, discovered_at=old_date)
             for _ in range(5)]
            + [_make_vuln(severity="high",   cvss_score=9.0, discovered_at=old_date)
               for _ in range(10)]
            + [_make_vuln(severity="medium", cvss_score=7.0, discovered_at=old_date)
               for _ in range(15)]
        )
        rs = score_vulnerabilities(vulns)
        assert rs.grade == "F"
        assert rs.score < 40.0

    def test_breakdown_by_severity_correct(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        vulns = [
            _make_vuln(severity="critical"),
            _make_vuln(severity="high"),
            _make_vuln(severity="high"),
            _make_vuln(severity="medium"),
        ]
        rs = score_vulnerabilities(vulns)
        assert rs.by_severity.get("critical") == 1
        assert rs.by_severity.get("high") == 2
        assert rs.by_severity.get("medium") == 1

    def test_top_issues_populated(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        vulns = [_make_vuln(severity="critical", name=f"Issue-{i}") for i in range(7)]
        rs = score_vulnerabilities(vulns)
        assert len(rs.top_issues) == 5   # capped at top 5

    def test_score_to_grade_thresholds(self):
        from vulnscan.easm.scoring import score_to_grade
        assert score_to_grade(100) == "A"
        assert score_to_grade(90)  == "A"
        assert score_to_grade(89)  == "B"
        assert score_to_grade(75)  == "B"
        assert score_to_grade(74)  == "C"
        assert score_to_grade(60)  == "C"
        assert score_to_grade(59)  == "D"
        assert score_to_grade(40)  == "D"
        assert score_to_grade(39)  == "F"
        assert score_to_grade(0)   == "F"

    def test_vendor_label_tag_on_result(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        rs = score_vulnerabilities([], vendor_label="AcmeCorp")
        assert rs.vendor_label == "AcmeCorp"
        assert rs.asset_id is None

    def test_oldest_open_days_computed(self):
        from vulnscan.easm.scoring import score_vulnerabilities
        old_date = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        vulns = [_make_vuln(severity="high", discovered_at=old_date)]
        rs = score_vulnerabilities(vulns)
        assert rs.oldest_open_days >= 29   # allow 1-day rounding


# ══════════════════════════════════════════════════════════════════════════════
# API endpoint tests (isolated SQLite DB per test)
# ══════════════════════════════════════════════════════════════════════════════

_BUILTIN_DEFS = Path(__file__).parent.parent / "src" / "vulnscan" / "languages" / "defs"
_BUILTIN_DEF_NAMES = ["csharp.yaml"]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import importlib
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


class TestEASMAssets:
    def test_create_asset(self, client):
        r = client.post("/easm/assets", json={
            "identifier": "192.168.1.1",
            "asset_type": "ip",
            "label": "AcmeCorp",
        })
        assert r.status_code == 201
        body = r.json()
        assert body["identifier"] == "192.168.1.1"
        assert "id" in body

    def test_list_assets_empty(self, client):
        r = client.get("/easm/assets")
        assert r.status_code == 200
        assert r.json() == []

    def test_list_assets_after_create(self, client):
        client.post("/easm/assets", json={"identifier": "10.0.0.1", "asset_type": "ip"})
        r = client.get("/easm/assets")
        assert len(r.json()) == 1

    def test_duplicate_asset_409(self, client):
        client.post("/easm/assets", json={"identifier": "10.0.0.1", "asset_type": "ip"})
        r = client.post("/easm/assets", json={"identifier": "10.0.0.1", "asset_type": "ip"})
        assert r.status_code == 409

    def test_get_asset_detail(self, client):
        r = client.post("/easm/assets", json={"identifier": "10.0.0.1", "asset_type": "ip", "label": "Test"})
        aid = r.json()["id"]
        r2 = client.get(f"/easm/assets/{aid}")
        assert r2.status_code == 200
        assert r2.json()["identifier"] == "10.0.0.1"
        assert r2.json()["latest_score"] is None  # not scored yet

    def test_get_asset_not_found(self, client):
        r = client.get("/easm/assets/nonexistent-id")
        assert r.status_code == 404

    def test_invalid_asset_type(self, client):
        r = client.post("/easm/assets", json={"identifier": "x", "asset_type": "floppy"})
        assert r.status_code == 422


class TestEASMIngest:
    def test_ingest_nmap(self, client):
        r = client.post("/easm/ingest", data={
            "asset": "10.0.0.5",
            "asset_type": "ip",
        }, files={"file": ("nmap.xml", _NMAP_XML.encode(), "application/xml")})
        assert r.status_code == 201
        body = r.json()
        assert body["imported"] >= 1
        assert body["asset"] == "10.0.0.5"
        assert body["asset_id"] is not None

    def test_ingest_openvas(self, client):
        r = client.post("/easm/ingest", data={
            "asset": "192.168.1.100",
            "asset_type": "ip",
        }, files={"file": ("openvas.xml", _OPENVAS_XML.encode(), "application/xml")})
        assert r.status_code == 201
        assert r.json()["imported"] >= 1

    def test_ingest_zap(self, client):
        r = client.post("/easm/ingest", data={
            "asset": "example.com",
            "asset_type": "domain",
        }, files={"file": ("zap.json", _ZAP_JSON.encode(), "application/json")})
        assert r.status_code == 201
        assert r.json()["imported"] >= 1

    def test_ingest_nuclei(self, client):
        r = client.post("/easm/ingest", data={
            "asset": "target.example.com",
            "asset_type": "domain",
        }, files={"file": ("nuclei.jsonl", _NUCLEI_JSONL.encode(), "application/json")})
        assert r.status_code == 201
        assert r.json()["imported"] == 2   # false match excluded

    def test_ingest_deduplicates_on_reimport(self, client):
        payload = dict(data={"asset": "10.0.0.5", "asset_type": "ip"},
                       files={"file": ("nmap.xml", _NMAP_XML.encode(), "application/xml")})
        r1 = client.post("/easm/ingest", **payload)
        r2 = client.post("/easm/ingest", **payload)
        assert r1.status_code == 201
        assert r2.status_code == 201
        # Second import: imported=0 (same fingerprints), total_parsed unchanged
        assert r2.json()["imported"] == 0

    def test_ingest_auto_creates_asset(self, client):
        assert client.get("/easm/assets").json() == []
        client.post("/easm/ingest", data={"asset": "172.16.0.1", "asset_type": "ip"},
                    files={"file": ("n.xml", _NMAP_XML.encode(), "text/xml")})
        assets = client.get("/easm/assets").json()
        assert any(a["identifier"] == "172.16.0.1" for a in assets)

    def test_ingest_invalid_file_422(self, client):
        r = client.post("/easm/ingest", data={"asset": "x", "asset_type": "ip"},
                        files={"file": ("bad.xml", b"<<not xml>>", "text/xml")},
                        headers={"Accept": "application/json"})
        assert r.status_code == 422


class TestEASMVulnerabilities:
    def _seed(self, client):
        client.post("/easm/ingest",
                    data={"asset": "10.0.0.5", "asset_type": "ip", "label": "TestCorp"},
                    files={"file": ("nmap.xml", _NMAP_XML.encode(), "text/xml")})
        client.post("/easm/ingest",
                    data={"asset": "10.0.0.5", "asset_type": "ip"},
                    files={"file": ("openvas.xml", _OPENVAS_XML.encode(), "text/xml")})

    def test_list_all(self, client):
        self._seed(client)
        r = client.get("/easm/vulnerabilities")
        assert r.status_code == 200
        assert len(r.json()) >= 2

    def test_filter_by_severity(self, client):
        self._seed(client)
        r = client.get("/easm/vulnerabilities?severity=critical")
        assert r.status_code == 200
        for v in r.json():
            assert v["severity"] == "critical"

    def test_filter_by_tool(self, client):
        self._seed(client)
        r = client.get("/easm/vulnerabilities?tool=nmap")
        assert r.status_code == 200
        for v in r.json():
            assert v["source_tool"] == "nmap"

    def test_filter_by_cve(self, client):
        self._seed(client)
        r = client.get("/easm/vulnerabilities?cve=CVE-2022-1234")
        assert r.status_code == 200
        assert all(v["cve"] == "CVE-2022-1234" for v in r.json())

    def test_update_status_to_resolved(self, client):
        self._seed(client)
        vulns = client.get("/easm/vulnerabilities").json()
        vid = vulns[0]["id"]
        r = client.patch(f"/easm/vulnerabilities/{vid}", json={"status": "resolved"})
        assert r.status_code == 200
        assert r.json()["status"] == "resolved"

    def test_update_status_not_found(self, client):
        r = client.patch("/easm/vulnerabilities/nonexistent", json={"status": "resolved"})
        assert r.status_code == 404

    def test_update_status_invalid(self, client):
        self._seed(client)
        vulns = client.get("/easm/vulnerabilities").json()
        vid = vulns[0]["id"]
        r = client.patch(f"/easm/vulnerabilities/{vid}", json={"status": "ignored"})
        assert r.status_code == 422


class TestEASMScoring:
    def _seed_and_get_asset(self, client, asset="10.0.0.5"):
        r = client.post("/easm/ingest",
                        data={"asset": asset, "asset_type": "ip", "label": "TestCorp"},
                        files={"file": ("nmap.xml", _NMAP_XML.encode(), "text/xml")})
        return r.json()["asset_id"]

    def test_compute_score_returns_grade(self, client):
        aid = self._seed_and_get_asset(client)
        r = client.post(f"/easm/score/{aid}")
        assert r.status_code == 201
        body = r.json()
        assert "score" in body
        assert body["grade"] in ("A", "B", "C", "D", "F")
        assert 0.0 <= body["score"] <= 100.0

    def test_get_score_after_compute(self, client):
        aid = self._seed_and_get_asset(client)
        client.post(f"/easm/score/{aid}")
        r = client.get(f"/easm/score/{aid}")
        assert r.status_code == 200
        assert "breakdown" in r.json()

    def test_get_score_not_scored_yet(self, client):
        aid = self._seed_and_get_asset(client)
        r = client.get(f"/easm/score/{aid}")
        assert r.status_code == 404

    def test_compute_score_asset_not_found(self, client):
        r = client.post("/easm/score/nonexistent")
        assert r.status_code == 404

    def test_score_history_grows(self, client):
        aid = self._seed_and_get_asset(client)
        client.post(f"/easm/score/{aid}")
        client.post(f"/easm/score/{aid}")
        r = client.get(f"/easm/scores/history/{aid}")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_score_history_asset_not_found(self, client):
        r = client.get("/easm/scores/history/nonexistent")
        assert r.status_code == 404

    def test_asset_detail_includes_score_after_compute(self, client):
        aid = self._seed_and_get_asset(client)
        client.post(f"/easm/score/{aid}")
        r = client.get(f"/easm/assets/{aid}")
        assert r.status_code == 200
        assert r.json()["latest_score"] is not None
        assert "grade" in r.json()["latest_score"]

    def test_vendor_score_compute(self, client):
        self._seed_and_get_asset(client, "10.0.0.5")
        self._seed_and_get_asset(client, "10.0.0.6")
        r = client.post("/easm/score/vendor/TestCorp")
        assert r.status_code == 201
        body = r.json()
        assert body["grade"] in ("A", "B", "C", "D", "F")

    def test_vendor_score_no_assets(self, client):
        r = client.post("/easm/score/vendor/Unknown")
        assert r.status_code == 404

    def test_get_vendor_score_after_compute(self, client):
        self._seed_and_get_asset(client)
        client.post("/easm/score/vendor/TestCorp")
        r = client.get("/easm/score/vendor/TestCorp")
        assert r.status_code == 200
        assert "score" in r.json()

    def test_resolved_vulns_improve_score(self, client):
        aid = self._seed_and_get_asset(client)
        r1 = client.post(f"/easm/score/{aid}")
        score_before = r1.json()["score"]

        vulns = client.get("/easm/vulnerabilities?severity=critical").json()
        for v in vulns:
            client.patch(f"/easm/vulnerabilities/{v['id']}", json={"status": "resolved"})

        r2 = client.post(f"/easm/score/{aid}")
        score_after = r2.json()["score"]
        assert score_after >= score_before


class TestEASMDashboard:
    def test_dashboard_empty(self, client):
        r = client.get("/easm/dashboard")
        assert r.status_code == 200
        body = r.json()
        assert body["asset_count"] == 0
        assert body["vuln_count"] == 0
        assert body["open_count"] == 0
        assert body["average_score"] is None

    def test_dashboard_after_ingest(self, client):
        client.post("/easm/ingest",
                    data={"asset": "10.0.0.5", "asset_type": "ip"},
                    files={"file": ("nmap.xml", _NMAP_XML.encode(), "text/xml")})
        r = client.get("/easm/dashboard")
        body = r.json()
        assert body["asset_count"] == 1
        assert body["vuln_count"] >= 1
        assert body["open_count"] >= 1

    def test_dashboard_average_score_after_scoring(self, client):
        r = client.post("/easm/ingest",
                        data={"asset": "10.0.0.5", "asset_type": "ip"},
                        files={"file": ("nmap.xml", _NMAP_XML.encode(), "text/xml")})
        aid = r.json()["asset_id"]
        client.post(f"/easm/score/{aid}")
        body = client.get("/easm/dashboard").json()
        assert body["average_score"] is not None
        assert 0 <= body["average_score"] <= 100

    def test_dashboard_grade_distribution(self, client):
        r = client.post("/easm/ingest",
                        data={"asset": "10.0.0.5", "asset_type": "ip"},
                        files={"file": ("nmap.xml", _NMAP_XML.encode(), "text/xml")})
        aid = r.json()["asset_id"]
        client.post(f"/easm/score/{aid}")
        body = client.get("/easm/dashboard").json()
        assert sum(body["grade_distribution"].values()) == 1
