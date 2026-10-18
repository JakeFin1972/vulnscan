"""Scan cancellation: loop checks, endpoints, and the restart reset."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnscan import cancel
from vulnscan.recon import scan_repo
from vulnscan.scanners import run_dynamic_scan
from tests.test_api import client  # noqa: F401  (isolated API fixture)


def _api():
    import vulnscan.api as api_mod
    return api_mod


def _insert(table: str, scan_id: str, status: str):
    api = _api()
    with api._db() as conn:
        if table == "scans":
            conn.execute("INSERT INTO scans (id, path, status) VALUES (?,?,?)", (scan_id, "/x", status))
        else:
            conn.execute("INSERT INTO dynamic_scans (id, target, target_type, tools, status) VALUES (?,?,?,?,?)",
                         (scan_id, "http://x", "url", "[]", status))


def _status(table: str, scan_id: str) -> dict:
    with _api()._db() as conn:
        return dict(conn.execute(f"SELECT status, finished_at, error FROM {table} WHERE id=?", (scan_id,)).fetchone())


def _wait(table, scan_id, want, secs=5):
    end = time.time() + secs
    while time.time() < end:
        if _status(table, scan_id)["status"] == want:
            return
        time.sleep(0.02)
    raise AssertionError(f"{table} {scan_id} never reached {want}: {_status(table, scan_id)}")


def test_scan_repo_stops_when_asked(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.cs").write_text("class A {}")
    with pytest.raises(cancel.ScanCancelled):
        scan_repo(tmp_path, should_stop=lambda: True)
    assert scan_repo(tmp_path, should_stop=lambda: False) == []


def test_dynamic_scan_stops_between_tools():
    with pytest.raises(cancel.ScanCancelled):
        run_dynamic_scan("http://127.0.0.1:1", "url", tools=["http", "api"], should_stop=lambda: True)


@pytest.mark.parametrize("table,path,runner,patch", [
    ("scans", "/scans", "_run_scan", "build_report"),
    ("dynamic_scans", "/dynamic-scans", "_run_dynamic_scan", "run_dynamic_scan"),
])
def test_cancel_running_scan(client, monkeypatch, table, path, runner, patch):
    api = _api()
    started = threading.Event()

    def slow(*a, should_stop=None, **k):
        should_stop = should_stop or a[-1]  # build_report(root, should_stop) is positional
        started.set()
        while not should_stop():
            time.sleep(0.01)
        raise cancel.ScanCancelled()
    monkeypatch.setattr(api, patch, slow)
    sid = f"{table}-run"
    _insert(table, sid, "pending")
    cancel.register(sid)
    args = (sid, "/x") if table == "scans" else (sid, "http://x", "url", None, None)
    t = threading.Thread(target=getattr(api, runner), args=args)
    t.start()
    assert started.wait(5)
    _wait(table, sid, "running")

    r = client.post(f"{path}/{sid}/cancel")
    assert r.status_code == 200 and r.json() == {"id": sid, "status": "cancelling"}
    t.join(5)
    assert not t.is_alive()
    st = _status(table, sid)
    assert st["status"] == "cancelled" and st["finished_at"]
    assert client.post(f"{path}/{sid}/cancel").status_code == 409


@pytest.mark.parametrize("table,path,runner,args", [
    ("scans", "/scans", "_run_scan", lambda s: (s, "/x")),
    ("dynamic_scans", "/dynamic-scans", "_run_dynamic_scan", lambda s: (s, "http://x", "url", None, None)),
])
def test_cancel_queued_scan_never_runs(client, monkeypatch, table, path, runner, args):
    api = _api()
    monkeypatch.setattr(api, "build_report", lambda *a, **k: pytest.fail("scan must not start"))
    monkeypatch.setattr(api, "run_dynamic_scan", lambda *a, **k: pytest.fail("scan must not start"))
    sid = f"{table}-queued"
    _insert(table, sid, "pending")
    cancel.register(sid)
    r = client.post(f"{path}/{sid}/cancel")
    assert r.json()["status"] == "cancelled"
    getattr(api, runner)(*args(sid))  # the queued task now starts and must bail out
    assert _status(table, sid)["status"] == "cancelled"


def test_cancel_unknown_and_finished(client):
    assert client.post("/scans/nope/cancel").status_code == 404
    assert client.post("/dynamic-scans/nope/cancel").status_code == 404
    _insert("scans", "done1", "done")
    assert client.post("/scans/done1/cancel").status_code == 409


def test_restart_resets_interrupted_scans(client):
    api = _api()
    for table in ("scans", "dynamic_scans"):
        for sid, status in ((f"{table}-r", "running"), (f"{table}-p", "pending"), (f"{table}-c", "cancelling"), (f"{table}-d", "done")):
            _insert(table, sid, status)
    api._reset_interrupted_scans()
    for table in ("scans", "dynamic_scans"):
        for suffix in "rpc":
            st = _status(table, f"{table}-{suffix}")
            assert st["status"] == "cancelled" and st["finished_at"] and "interrupted" in st["error"]
        assert _status(table, f"{table}-d")["status"] == "done"


def test_real_scan_still_completes(client, tmp_path):
    (tmp_path / "a.cs").write_text("class A { void M(){ } }")
    sid = client.post("/scans", json={"path": str(tmp_path), "authorized": True}).json()["id"]
    assert client.get(f"/scans/{sid}").json()["status"] == "done"
