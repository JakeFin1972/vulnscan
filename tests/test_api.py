"""Tests for vulnscan.api — FastAPI engine.

Uses httpx's TestClient (sync) with isolated data and defs directories so
tests don't touch ~/.vulnscan or the built-in languages/defs/ directory.
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


_BUILTIN_DEFS = Path(__file__).parent.parent / "src" / "vulnscan" / "languages" / "defs"
# Only these well-known built-in files are seeded into the test defs dir.
_BUILTIN_DEF_NAMES = ["csharp.yaml"]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Isolated API client with its own data dir and defs dir."""
    import importlib
    import vulnscan.api as api_mod

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    defs_dir = tmp_path / "defs"
    defs_dir.mkdir()

    # Copy only the known built-in defs (not any leftover test files)
    for name in _BUILTIN_DEF_NAMES:
        src = _BUILTIN_DEFS / name
        if src.exists():
            shutil.copy(src, defs_dir / name)

    monkeypatch.setenv("VULNSCAN_DATA_DIR", str(data_dir))
    monkeypatch.setenv("VULNSCAN_DEFS_DIR", str(defs_dir))
    importlib.reload(api_mod)
    api_mod._init_db()

    with TestClient(api_mod.app, raise_server_exceptions=True) as c:
        yield c


# ── Health ────────────────────────────────────────────────────────────────────

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "scan_count" in body
    assert "language_count" in body


# ── Scans ─────────────────────────────────────────────────────────────────────

def test_start_scan_requires_authorization(client, tmp_path):
    r = client.post("/scans", json={"path": str(tmp_path), "authorized": False})
    assert r.status_code == 422


def test_start_scan_bad_path(client):
    r = client.post("/scans", json={"path": "/no/such/directory/xyz", "authorized": True})
    assert r.status_code == 400


def test_start_and_get_scan(client, tmp_path):
    # Plant a simple Python file so the scan has something to find
    (tmp_path / "app.py").write_text(
        "@app.get('/x')\ndef handler():\n    os.system('ls')\n",
        encoding="utf-8"
    )
    r = client.post("/scans", json={"path": str(tmp_path), "authorized": True})
    assert r.status_code == 201
    scan_id = r.json()["id"]
    assert scan_id

    # Poll for completion (the background task runs in-process with TestClient)
    for _ in range(20):
        r2 = client.get(f"/scans/{scan_id}")
        assert r2.status_code == 200
        if r2.json()["status"] in ("done", "error"):
            break
        time.sleep(0.1)

    body = r2.json()
    assert body["status"] == "done", f"scan ended with: {body}"
    assert body["source_count"] >= 1
    assert body["sink_count"] >= 1


def test_list_scans(client, tmp_path):
    client.post("/scans", json={"path": str(tmp_path), "authorized": True})
    r = client.get("/scans")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) >= 1


def test_get_scan_not_found(client):
    r = client.get("/scans/nonexistent-id")
    assert r.status_code == 404


# ── Findings ──────────────────────────────────────────────────────────────────

def test_findings_for_scan(client, tmp_path):
    (tmp_path / "app.py").write_text(
        "@app.post('/run')\ndef run():\n    os.system('x')\n",
        encoding="utf-8"
    )
    r = client.post("/scans", json={"path": str(tmp_path), "authorized": True})
    scan_id = r.json()["id"]

    for _ in range(20):
        r2 = client.get(f"/scans/{scan_id}")
        if r2.json()["status"] in ("done", "error"):
            break
        time.sleep(0.1)

    r3 = client.get(f"/findings?scan_id={scan_id}")
    assert r3.status_code == 200
    findings = r3.json()
    assert len(findings) >= 1
    for f in findings:
        assert f["scan_id"] == scan_id
        assert "severity" in f
        assert f["severity"] in ("critical", "high", "medium", "low", "info")


def test_findings_severity_filter(client, tmp_path):
    (tmp_path / "app.py").write_text(
        "@app.post('/run')\ndef run():\n    os.system('x')\n",
        encoding="utf-8"
    )
    scan_id = client.post("/scans", json={"path": str(tmp_path), "authorized": True}).json()["id"]
    for _ in range(20):
        if client.get(f"/scans/{scan_id}").json()["status"] in ("done", "error"):
            break
        time.sleep(0.1)

    r = client.get(f"/findings?scan_id={scan_id}&severity=high")
    assert r.status_code == 200
    for f in r.json():
        assert f["severity"] == "high"


# ── Languages ─────────────────────────────────────────────────────────────────

def test_list_languages(client):
    r = client.get("/languages")
    assert r.status_code == 200
    langs = r.json()
    # csharp.yaml is in the defs dir
    names = [l["name"] for l in langs]
    assert "csharp" in names


def test_get_language_csharp(client):
    r = client.get("/languages/csharp")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "csharp"
    assert ".cs" in body["extensions"]
    assert "yaml_content" in body
    assert body["source_count"] > 0
    assert body["sink_count"] > 0


def test_get_language_not_found(client):
    r = client.get("/languages/doesnotexist")
    assert r.status_code == 404


VALID_YAML = """\
name: testlang
extensions: [".tl"]
grammar: tree_sitter_c_sharp
sources:
  - id: entry
    category: http_handler
    match:
      node: method_declaration
      has_attribute: [Endpoint]
sinks:
  - id: danger
    category: os_command
    match:
      node: invocation_expression
      callee_leaf_in: [Execute]
"""

INVALID_YAML = """\
name: badlang
extensions: [".bad"]
grammar: mod
sources:
  - id: s1
    category: not_a_real_category
    match:
      node: foo
sinks: []
"""


def test_create_language_valid(client, tmp_path):
    r = client.post("/languages", json={"name": "testlang", "yaml_content": VALID_YAML})
    assert r.status_code == 201
    assert r.json()["ok"] is True


def test_create_language_invalid_category(client):
    r = client.post("/languages", json={"name": "badlang", "yaml_content": INVALID_YAML})
    assert r.status_code == 422
    assert "category" in r.json()["detail"].lower()


def test_create_language_duplicate(client):
    client.post("/languages", json={"name": "testlang", "yaml_content": VALID_YAML})
    r = client.post("/languages", json={"name": "testlang", "yaml_content": VALID_YAML})
    assert r.status_code == 409


def test_update_language(client):
    client.post("/languages", json={"name": "testlang", "yaml_content": VALID_YAML})
    updated = VALID_YAML.replace("Execute", "RunCommand")
    r = client.put("/languages/testlang", json={"yaml_content": updated})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_update_language_not_found(client):
    r = client.put("/languages/ghost", json={"yaml_content": VALID_YAML})
    assert r.status_code == 404


def test_update_language_name_mismatch(client):
    client.post("/languages", json={"name": "testlang", "yaml_content": VALID_YAML})
    # YAML still says "testlang" but URL says "testlang" — now change the YAML name
    wrong_yaml = VALID_YAML.replace("name: testlang", "name: wrongname")
    r = client.put("/languages/testlang", json={"yaml_content": wrong_yaml})
    assert r.status_code == 422


# ── Runtest ───────────────────────────────────────────────────────────────────

def test_runtest_bad_repo(client):
    r = client.post("/runtest", json={"repo": "/no/such/path", "target": "test_x"})
    assert r.status_code == 400


def test_runtest_passes(client, tmp_path):
    test_file = tmp_path / "test_trivial.py"
    test_file.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    r = client.post("/runtest", json={
        "repo": str(tmp_path),
        "target": str(test_file),
        "framework": "pytest",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] is True
