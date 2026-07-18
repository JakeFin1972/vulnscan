"""Tests for vulnscan.recon — the AST source/sink locator and pairing."""
from pathlib import Path

from vulnscan.recon import build_report
from vulnscan.languages.python_backend import scan_file

VULN_APP = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/orders")
def orders():
    oid = request.args.get("id")
    cursor.execute("SELECT * FROM orders WHERE id = " + oid)
    return "ok"

@app.post("/run")
def run_cmd():
    os.system(request.form["cmd"])

@app.get("/safe")
def safe():
    return "no sink here"
'''

SANITIZED_APP = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/orders")
def orders():
    oid = int(request.args.get("id"))
    cursor.execute("SELECT * FROM orders WHERE id = %s", (oid,))
    return "ok"
'''


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_finds_sources_and_sinks(tmp_path):
    _write(tmp_path, "app.py", VULN_APP)
    report = build_report(tmp_path)
    assert report["counts"]["sources"] == 3   # route, post, get
    assert report["counts"]["sinks"] == 2      # cursor.execute, os.system
    cats = {s["category"] for s in report["sinks"]}
    assert cats == {"sql_query", "os_command"}


def test_pairs_are_same_file_and_prioritised(tmp_path):
    _write(tmp_path, "app.py", VULN_APP)
    pairs = build_report(tmp_path)["candidate_pairs"]
    # 3 sources x 2 same-file sinks = 6 pairs, all http_handler priority 0
    assert len(pairs) == 6
    assert all(p["proximity"] == "same_file" for p in pairs)
    assert all(p["priority"] == 0 for p in pairs)


def test_recon_does_not_judge_exploitability(tmp_path):
    # The sanitized app still surfaces the sink as a *candidate*; recon does not
    # (and must not) decide it's safe — that's the Disprove phase's job.
    _write(tmp_path, "app.py", SANITIZED_APP)
    report = build_report(tmp_path)
    assert report["counts"]["sinks"] == 1


def test_skips_vendored_dirs(tmp_path):
    (tmp_path / ".venv").mkdir()
    _write(tmp_path, ".venv/evil.py", "os.system('x')")
    _write(tmp_path, "app.py", "os.system('y')")
    report = build_report(tmp_path)
    assert report["counts"]["sinks"] == 1  # .venv ignored


def test_syntax_error_file_is_skipped(tmp_path):
    bad = _write(tmp_path, "broken.py", "def (:::")
    assert scan_file(bad) == []
