"""Local web app for the staging gate: `python -m staging_gate serve workbook.xlsx`.
Standard library only (http.server). Binds to 127.0.0.1, checks the Host header and requires a
per-run token on every /api call. All workbook writes go through one lock, save atomically, and the
first write of a session makes a backup copy."""
import json
import os
import secrets
import shutil
import tempfile
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import layout as L
from .apply import apply_approved
from .controls import read_controls
from .lock import lock, verify
from .pipeline import run_h2, run_h3
from .rollup import rollup
from .runner import DEFAULT_MODEL
from .xl import cell, first_empty_row, open_wb, s

TOKENS = {"", "y", "n", "y!"}
INDEX = Path(__file__).parent / "web" / "index.html"


def _val(v):
    return None if v is None else (int(v) if isinstance(v, float) and v.is_integer() else v)


class Store:
    """Serialises access to the workbook file."""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.backed_up = False
        self._cache = None

    def _backup(self):
        if not self.backed_up:
            dst = self.path.with_name(self.path.stem + ".pre-webapp" + self.path.suffix)
            shutil.copy2(self.path, dst)
            self.backed_up = True

    def read(self, fn):
        with self.lock:
            return fn(open_wb(self.path))

    def write(self, fn):
        with self.lock:
            self._backup()
            wb = open_wb(self.path)
            out = fn(wb)
            fd, tmp = tempfile.mkstemp(suffix=".xlsx", dir=self.path.parent)
            os.close(fd)
            try:
                wb.save(tmp)
                os.replace(tmp, self.path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            self._cache = None
            return out

    def excel_open(self) -> bool:
        return (self.path.parent / ("~$" + self.path.name)).exists()


# ---------------------------------------------------------------- state
def _lookup(wb, sheet, nr):
    if sheet not in L.CONTROL_SHEETS or sheet not in wb.sheetnames or s(nr) == "":
        return None
    ws = wb[sheet]
    for r in range(L.FIRST_ROW, L.LAST_ROW + 1):
        if s(cell(ws, L.NR_COL, r).value) == s(nr):
            return {"topic": s(cell(ws, L.CTRL_TOPIC_COL, r).value),
                    "curF": s(cell(ws, L.CTRL_CURRENT_STATE_COL, r).value),
                    "curS": _val(cell(ws, "S", r).value), "curT": _val(cell(ws, "T", r).value),
                    "curU": _val(cell(ws, "U", r).value)}
    return None


def build_state(wb, store: Store) -> dict:
    st = wb[L.STAGING]
    c = L.H2_STAGING_COLS
    staging = []
    for r in range(L.STAGING_FIRST_ROW, L.STAGING_FIRST_ROW + L.STAGING_ROWS):
        sheet, nr = cell(st, L.COL_SHEET, r).value, cell(st, L.COL_NR, r).value
        if s(sheet) == "" and s(nr) == "":
            continue
        look = _lookup(wb, s(sheet), nr) or {}
        staging.append({"row": r, "approve": s(cell(st, L.COL_APPROVE, r).value), "sheet": s(sheet),
                        "nr": s(nr), "topic": look.get("topic", "nr not found" if s(sheet) else ""),
                        "F": s(cell(st, c["F"], r).value), "G": s(cell(st, c["G"], r).value),
                        "S": _val(cell(st, c["S"], r).value), "T": _val(cell(st, c["T_proposed"], r).value),
                        "U": _val(cell(st, c["U_proposed"], r).value),
                        "rationale": s(cell(st, c["rationale"], r).value),
                        "evidence": s(cell(st, c["evidence"], r).value),
                        "confidence": s(cell(st, c["confidence"], r).value),
                        "curF": look.get("curF", ""), "curS": look.get("curS"),
                        "applied": s(cell(st, L.COL_STAMP, r).value)})
    sr = wb[L.STAGING_RISKS]
    risks = []
    for r in range(L.RISK_STAGING_FIRST_ROW, L.RISK_STAGING_FIRST_ROW + L.RISK_STAGING_ROWS):
        if s(cell(sr, L.RISK_COL_NAME, r).value) == "":
            continue
        g = lambda col: s(cell(sr, col, r).value)
        risks.append({"row": r, "approve": g("A"), "category": g("B"), "name": g("C"), "current": g("D"),
                      "target": g("E"), "description": g("F"), "action": g("G"), "risk": g("H"),
                      "impact": g("I"), "easiness": g("J"), "owner": g("K"), "maturity": g("L"),
                      "source_rows": g("N"), "basis": g("O"), "confidence": g("P"), "applied": g("Q")})
    log, ws = [], wb[L.CHANGELOG]
    for r in range(ws.max_row, L.LOG_FIRST_ROW - 1, -1):
        if s(cell(ws, "B", r).value):
            log.append([s(cell(ws, col, r).value) for col in "ABCDEFGHIJK"])
        if len(log) >= 60:
            break
    rolls = {}
    for name in L.CONTROL_SHEETS:
        if name in wb.sheetnames:
            rolls[name] = {col: [{"first": b["first"], "last": b["last"], "value": round(b["value"], 2),
                                  "n": len(b["rows"])} for b in rollup(wb, name, src)]
                           for col, src in L.ROLLUP_COLS.items()}
    return {"path": str(store.path), "excelOpen": store.excel_open(),
            "locked": {n: bool(wb[n].protection.sheet) for n in L.LOCKED_SHEETS if n in wb.sheetnames},
            "passwordOk": all(verify(wb[n]) for n in L.LOCKED_SHEETS if n in wb.sheetnames and wb[n].protection.sheet),
            "staging": staging, "risks": risks, "changelog": log, "rollups": rolls,
            "controlSheets": L.CONTROL_SHEETS, "apiKey": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "defaultModel": DEFAULT_MODEL}


# ---------------------------------------------------------------- actions
def do_apply(wb, body):
    st, sr = wb[L.STAGING], wb[L.STAGING_RISKS]
    for key, ws, col, lo, hi in (("approvals", st, L.COL_APPROVE, L.STAGING_FIRST_ROW, L.STAGING_FIRST_ROW + L.STAGING_ROWS),
                                 ("riskApprovals", sr, L.RISK_COL_APPROVE, L.RISK_STAGING_FIRST_ROW,
                                  L.RISK_STAGING_FIRST_ROW + L.RISK_STAGING_ROWS)):
        for row, tok in (body.get(key) or {}).items():
            row = int(row)
            if tok not in TOKENS or not lo <= row < hi:
                raise ValueError(f"bad approval {tok!r} for row {row}")
            if key == "riskApprovals" and tok not in ("", "y", "n"):
                raise ValueError("risk rows take y or n only")
            cell(ws, col, row).value = tok or None
    if body.get("applyNow"):
        return apply_approved(wb).line()
    return "Approvals saved."


def do_stage(wb, b):
    sheet = s(b.get("sheet"))
    if sheet not in L.CONTROL_SHEETS:
        raise ValueError("choose a control sheet")
    nr = s(b.get("nr"))
    if _lookup(wb, sheet, nr) is None:
        raise ValueError(f"nr {nr!r} not found on {sheet}")
    mat = {}
    for k in ("S", "T", "U"):
        v = s(b.get(k))
        if v == "":
            continue
        if not v.isdigit() or not L.MATURITY_RANGE[0] <= int(v) <= L.MATURITY_RANGE[1]:
            raise ValueError(f"{k} must be an integer {L.MATURITY_RANGE[0]}-{L.MATURITY_RANGE[1]}")
        mat[k] = int(v)
    st = wb[L.STAGING]
    r = first_empty_row(st, L.COL_NR, L.STAGING_FIRST_ROW)
    if r >= L.STAGING_FIRST_ROW + L.STAGING_ROWS:
        raise ValueError("Staging is full")
    c = L.H2_STAGING_COLS
    cell(st, L.COL_SHEET, r).value = sheet
    cell(st, L.COL_NR, r).value = int(nr) if nr.isdigit() else nr
    cell(st, c["F"], r).value = s(b.get("F")) or None
    cell(st, c["G"], r).value = s(b.get("G")) or None
    cell(st, c["S"], r).value = mat.get("S")
    cell(st, c["T_proposed"], r).value = mat.get("T")
    cell(st, c["U_proposed"], r).value = mat.get("U")
    cell(st, c["rationale"], r).value = "manual entry (web app)"
    cell(st, c["evidence"], r).value = s(b.get("evidence")) or None
    cell(st, c["confidence"], r).value = s(b.get("confidence")) or None
    return f"Added to Staging row {r}."


class Jobs:
    def __init__(self):
        self.lock = threading.Lock()
        self.state = {"state": "idle"}

    def start(self, name, fn):
        with self.lock:
            if self.state.get("state") == "running":
                raise ValueError("a run is already in progress")
            self.state = {"state": "running", "name": name}

        def go():
            try:
                self.state = {"state": "done", "name": name, **fn()}
            except Exception as e:  # shown to the user; never crash the server
                self.state = {"state": "error", "name": name, "error": f"{type(e).__name__}: {e}"}
                traceback.print_exc()
        threading.Thread(target=go, daemon=True).start()


class App:
    def __init__(self, path, client_factory=None):
        self.store = Store(path)
        self.jobs = Jobs()
        self.token = secrets.token_urlsafe(24)
        self.client_factory = client_factory

    def state(self):
        return self.store.read(lambda wb: build_state(wb, self.store))

    def model_job(self, kind, b):
        def need(k):
            v = s(b.get(k))
            if not v or not Path(v).expanduser().is_file():
                raise ValueError(f"{k}: file not found: {v!r}")
            return str(Path(v).expanduser())
        prompt, profile = need("prompt"), need("profile")
        evidence = need("evidence") if kind == "h2" else None
        sheets = [x for x in (b.get("sheets") or []) if x in L.CONTROL_SHEETS] or None
        model, fb = s(b.get("model")) or DEFAULT_MODEL, bool(b.get("fallbacks", True))

        def work():
            client = self.client_factory() if self.client_factory else None  # errors surface as a job error
            if kind == "h2":
                n, res = self.store.write(lambda wb: run_h2(wb, prompt, profile, evidence, sheets, model, fb, client))
                return {"message": f"{n} proposals written to Staging; {len(res['not_scored'])} not scored; "
                                   f"{len(res['guard_notes'])} guard changes", "notes": res["guard_notes"]}
            n, rej = self.store.write(lambda wb: run_h3(wb, prompt, profile, sheets, model, fb, client))
            return {"message": f"{n} risks imported to Staging-Risks; {len(rej)} rejected", "notes": rej}
        self.jobs.start(kind, work)


def make_handler(app: App, port_ref):
    class H(BaseHTTPRequestHandler):
        server_version = "stagegate"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_HEAD(self):  # health checks / curl -I
            self.send_response(200 if self._host_ok() else 403)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _host_ok(self):
            return self.headers.get("Host", "") in (f"localhost:{port_ref[0]}", f"127.0.0.1:{port_ref[0]}")

        def _guard(self):
            if not self._host_ok():
                seen = self.headers.get("Host", "")
                self._send(403, {"error": f"bad host {seen!r}: open http://localhost:{port_ref[0]}/ or "
                                          f"http://127.0.0.1:{port_ref[0]}/ on the machine running the server"})
                return False
            if self.path.startswith("/api/") and self.headers.get("X-Token") != app.token:
                self._send(401, {"error": "missing or wrong token"})
                return False
            return True

        def do_GET(self):
            if not self._guard():
                return
            if self.path in ("/", "/index.html"):
                html = INDEX.read_text(encoding="utf-8").replace("__TOKEN__", app.token)
                return self._send(200, html.encode(), "text/html; charset=utf-8")
            try:
                if self.path == "/api/state":
                    return self._send(200, app.state())
                if self.path == "/api/job":
                    return self._send(200, app.jobs.state)
            except Exception as e:
                return self._send(500, {"error": f"{type(e).__name__}: {e}"})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                if self.path == "/api/apply":
                    return self._send(200, {"message": app.store.write(lambda wb: do_apply(wb, body))})
                if self.path == "/api/lock":
                    def f(wb):
                        locked, missing = lock(wb)
                        return f"Locked {len(locked)} sheet(s)." + (f" Missing: {', '.join(missing)}." if missing else "")
                    return self._send(200, {"message": app.store.write(f)})
                if self.path == "/api/stage":
                    return self._send(200, {"message": app.store.write(lambda wb: do_stage(wb, body))})
                if self.path in ("/api/h2", "/api/h3"):
                    app.model_job(self.path[-2:], body)
                    return self._send(200, {"message": "started"})
            except (ValueError, PermissionError, KeyError) as e:
                return self._send(400, {"error": f"{type(e).__name__}: {e}"})
            except Exception as e:
                traceback.print_exc()
                return self._send(500, {"error": f"{type(e).__name__}: {e}"})
            self._send(404, {"error": "not found"})
    return H


def make_server(path, port=8780, client_factory=None):
    app = App(path, client_factory)
    ref = [port]
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, ref))
    ref[0] = srv.server_address[1]
    return srv, app


def serve(path, port=8780, open_browser=False):
    srv, app = make_server(path, port)
    port = srv.server_address[1]
    url = f"http://localhost:{port}/"
    print(f"Staging gate for {Path(path).name} is running.")
    print(f"  open  {url}")
    print(f"  or    http://127.0.0.1:{port}/   (use this one if localhost does not load)")
    print("Leave this window open; Ctrl+C stops it.")
    if app.store.excel_open():
        print("WARNING: Excel seems to have this file open. Close it before applying changes.")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
