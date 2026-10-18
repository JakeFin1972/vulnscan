import http.client
import json
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from staging_gate import layout as L
from staging_gate.webapp import make_server
from tests.test_staging_gate import DETECT, make_wb

H2_MD = "# H2\n\n## System prompt (v2.0)\n\n```\nYou are H2.\n```\n"
PROFILE = "# P\n\n| EV-ID | Doc | Type | Date |\n|---|---|---|---|\n| EV-02 | std | Policy + procedure | 2025 |\n| EV-04 | export | Config export | 2026 |\n"


@pytest.fixture
def srv(tmp_path):
    wb = make_wb()
    path = tmp_path / "wb.xlsx"
    wb.save(path)
    files = {}
    for name, text in (("h2.md", H2_MD), ("profile.md", PROFILE)):
        (tmp_path / name).write_text(text, encoding="utf-8")
        files[name] = str(tmp_path / name)
    reply = json.dumps({"proposals": [{"sheet": DETECT, "nr": "D.1", "F": "f", "G": "g", "S": 4,
                                       "evidence": ["EV-02", "EV-04"], "confidence": "high"}], "not_scored": []})

    class Fake:
        beta = SimpleNamespace(messages=SimpleNamespace())

    @contextmanager
    def stream(**kw):
        yield SimpleNamespace(get_final_message=lambda: SimpleNamespace(
            stop_reason="end_turn", stop_details=None, content=[SimpleNamespace(type="text", text=reply)]))
    Fake.beta.messages.stream = stream
    server, app = make_server(path, 0, client_factory=lambda: Fake())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield SimpleNamespace(port=server.server_address[1], app=app, files=files, path=path)
    server.shutdown()


def call(s, method, path, body=None, token=True, host=None):
    c = http.client.HTTPConnection("127.0.0.1", s.port, timeout=30)
    h = {"Host": host or f"127.0.0.1:{s.port}", "Content-Type": "application/json"}
    if token:
        h["X-Token"] = s.app.token
    c.request(method, path, json.dumps(body) if body is not None else None, h)
    r = c.getresponse()
    data = r.read()
    return r.status, (json.loads(data) if r.getheader("Content-Type", "").startswith("application/json") else data.decode())


def test_security_checks(srv):
    assert call(srv, "GET", "/api/state", token=False)[0] == 401
    assert call(srv, "GET", "/api/state", host="evil.example:80")[0] == 403
    assert call(srv, "POST", "/api/apply", {}, token=False)[0] == 401
    code, html = call(srv, "GET", "/")
    assert code == 200 and srv.app.token in html and "__TOKEN__" not in html


def test_state_stage_apply_roundtrip(srv):
    code, st = call(srv, "GET", "/api/state")
    assert code == 200 and len(st["staging"]) == 3 and st["controlSheets"]
    code, r = call(srv, "POST", "/api/stage", {"sheet": DETECT, "nr": "D.2", "F": "new state", "G": "next", "S": "2", "T": "4", "U": "5"})
    assert code == 200
    code, st = call(srv, "GET", "/api/state")
    row = [x for x in st["staging"] if x["nr"] == "D.2" and x["rationale"].startswith("manual")][0]
    assert row["S"] == 2 and row["topic"] == ""  # fixture has no topics
    code, r = call(srv, "POST", "/api/apply", {"approvals": {str(row["row"]): "y"}, "applyNow": True})
    assert code == 200 and "Controls applied: 1" in r["message"]
    st = call(srv, "GET", "/api/state")[1]
    assert [x for x in st["staging"] if x["row"] == row["row"]][0]["applied"].endswith("applied")
    assert any(x[10] == "APPLIED" for x in st["changelog"])
    assert st["rollups"][DETECT]["K"][0]["value"] == 2.0


def test_validation_errors(srv):
    assert call(srv, "POST", "/api/stage", {"sheet": DETECT, "nr": "NOPE"})[0] == 400
    assert call(srv, "POST", "/api/stage", {"sheet": DETECT, "nr": "D.1", "S": "9"})[0] == 400
    assert call(srv, "POST", "/api/apply", {"approvals": {"7": "maybe"}})[0] == 400
    assert call(srv, "POST", "/api/apply", {"approvals": {"3": "y"}})[0] == 400  # outside the data rows
    assert call(srv, "POST", "/api/apply", {"riskApprovals": {"7": "y!"}})[0] == 400


def test_lock_and_backup(srv):
    code, r = call(srv, "POST", "/api/lock", {})
    assert code == 200 and "Locked" in r["message"]
    assert (srv.path.parent / "wb.pre-webapp.xlsx").exists()
    assert call(srv, "GET", "/api/state")[1]["passwordOk"] is True


def wait_job(srv):
    for _ in range(100):
        code, j = call(srv, "GET", "/api/job")
        if j["state"] != "running":
            return j
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_h2_job_with_guard(srv):
    body = {"prompt": srv.files["h2.md"], "profile": srv.files["profile.md"], "evidence": srv.files["profile.md"], "sheets": [DETECT]}
    assert call(srv, "POST", "/api/h2", {**body, "prompt": "/nope.md"})[0] == 400
    assert call(srv, "POST", "/api/h2", body)[0] == 200
    j = wait_job(srv)
    assert j["state"] == "done" and "1 proposals written" in j["message"]
    assert any("S lowered 4->3" in n for n in j["notes"])
    st = call(srv, "GET", "/api/state")[1]
    assert st["staging"][-1]["S"] == 3 and "S lowered" in st["staging"][-1]["rationale"]


def test_job_error_is_reported_not_fatal(srv):
    srv.app.client_factory = lambda: (_ for _ in ()).throw(RuntimeError("no key"))
    body = {"prompt": srv.files["h2.md"], "profile": srv.files["profile.md"], "evidence": srv.files["profile.md"]}
    call(srv, "POST", "/api/h2", body)
    j = wait_job(srv)
    assert j["state"] == "error" and "no key" in j["error"]
    assert call(srv, "GET", "/api/state")[0] == 200


def test_head_and_bad_host_message(srv):
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    c.request("HEAD", "/", headers={"Host": f"127.0.0.1:{srv.port}"})
    assert c.getresponse().status == 200
    code, body = call(srv, "GET", "/", host="somewhere.example:9")
    assert code == 403 and "somewhere.example" in body["error"] and "localhost" in body["error"]
