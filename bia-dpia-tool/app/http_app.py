"""Tiny stdlib-only HTTP application: JSON API + static file serving.

No third-party dependencies (no FastAPI/Flask) so the tool runs anywhere
Python 3 runs, with nothing to `pip install`.
"""

import json
import mimetypes
import os
import re
import socketserver
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import db, scoring

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

ADMIN_COOKIE = "bia_admin_token"

REQUIRED_CONFIG_KEYS = {
    "org_name", "settings", "option_lists", "tools",
    "impact_scale_table", "classification_matrix", "information_assets",
}
REQUIRED_TOOLS = {"bia", "dpia0", "dpia"}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def validate_config(cfg):
    if not isinstance(cfg, dict):
        raise ApiError(400, "Config must be a JSON object.")
    missing = REQUIRED_CONFIG_KEYS - set(cfg.keys())
    if missing:
        raise ApiError(400, f"Config is missing required keys: {sorted(missing)}")
    tools = cfg.get("tools")
    if not isinstance(tools, dict) or (REQUIRED_TOOLS - set(tools.keys())):
        raise ApiError(400, f"Config.tools must contain: {sorted(REQUIRED_TOOLS)}")
    for tool_key, tool in tools.items():
        if not isinstance(tool.get("sections"), list):
            raise ApiError(400, f"tools.{tool_key}.sections must be a list.")
        for section in tool["sections"]:
            if "key" not in section or "questions" not in section:
                raise ApiError(400, f"Every section in tools.{tool_key} needs a 'key' and 'questions'.")
            for q in section["questions"]:
                if "key" not in q or "prompt" not in q or "input_type" not in q:
                    raise ApiError(
                        400,
                        f"Every question needs 'key', 'prompt' and 'input_type' "
                        f"(section {tool_key}.{section.get('key')}).",
                    )
    if not isinstance(cfg.get("option_lists"), dict):
        raise ApiError(400, "Config.option_lists must be an object.")
    if not isinstance(cfg.get("impact_scale_table"), list):
        raise ApiError(400, "Config.impact_scale_table must be a list.")
    if not isinstance(cfg.get("classification_matrix"), list):
        raise ApiError(400, "Config.classification_matrix must be a list.")
    if not isinstance(cfg.get("information_assets"), list):
        raise ApiError(400, "Config.information_assets must be a list.")


def assessment_payload(assessment_id):
    assessment = db.get_assessment(assessment_id)
    if assessment is None:
        raise ApiError(404, "Assessment not found.")
    answers = db.get_answers(assessment_id)
    config = db.get_config()
    results = scoring.compute_results(config, answers)
    return {"assessment": assessment, "answers": answers, "results": results}


def require_admin(handler):
    token = handler.get_cookie(ADMIN_COOKIE)
    if not db.session_valid(token):
        raise ApiError(401, "Admin authentication required.")


# --------------------------------------------------------------- routes ---
# Each entry: (METHOD, compiled regex, handler(handler, match, body) -> (status, payload))

ROUTES = []


def route(method, pattern):
    compiled = re.compile(f"^{pattern}$")

    def deco(fn):
        ROUTES.append((method, compiled, fn))
        return fn

    return deco


@route("GET", r"/api/health")
def health(h, m, body):
    return 200, {"ok": True}


@route("GET", r"/api/config")
def get_config(h, m, body):
    return 200, db.get_config()


@route("GET", r"/api/assessments")
def list_assessments(h, m, body):
    qs = parse_qs(urlparse(h.path).query)
    owner_email = (qs.get("owner_email") or [None])[0]
    if not owner_email:
        return 200, {"assessments": []}
    return 200, {"assessments": db.list_assessments(owner_email=owner_email)}


@route("POST", r"/api/assessments")
def create_assessment(h, m, body):
    aid = db.create_assessment(body or {})
    return 201, assessment_payload(aid)


@route("GET", r"/api/assessments/(?P<id>\d+)")
def get_assessment(h, m, body):
    return 200, assessment_payload(int(m.group("id")))


@route("PUT", r"/api/assessments/(?P<id>\d+)")
def update_assessment(h, m, body):
    aid = int(m.group("id"))
    if db.get_assessment(aid) is None:
        raise ApiError(404, "Assessment not found.")
    db.update_assessment_fields(aid, body or {})
    return 200, assessment_payload(aid)


@route("PUT", r"/api/assessments/(?P<id>\d+)/answers")
def update_answers(h, m, body):
    aid = int(m.group("id"))
    if db.get_assessment(aid) is None:
        raise ApiError(404, "Assessment not found.")
    tool = (body or {}).get("tool", "")
    answers = (body or {}).get("answers", {})
    if not isinstance(answers, dict):
        raise ApiError(400, "answers must be an object.")
    db.upsert_answers(aid, tool, answers)
    return 200, assessment_payload(aid)


@route("POST", r"/api/assessments/(?P<id>\d+)/submit")
def submit_assessment(h, m, body):
    aid = int(m.group("id"))
    if db.get_assessment(aid) is None:
        raise ApiError(404, "Assessment not found.")
    db.submit_assessment(aid)
    return 200, assessment_payload(aid)


@route("POST", r"/api/assessments/(?P<id>\d+)/reopen")
def reopen_assessment(h, m, body):
    aid = int(m.group("id"))
    if db.get_assessment(aid) is None:
        raise ApiError(404, "Assessment not found.")
    db.reopen_assessment(aid)
    return 200, assessment_payload(aid)


@route("DELETE", r"/api/assessments/(?P<id>\d+)")
def delete_assessment_public(h, m, body):
    # Anyone can delete their own draft from the wizard (e.g. "discard").
    aid = int(m.group("id"))
    if db.get_assessment(aid) is None:
        raise ApiError(404, "Assessment not found.")
    db.delete_assessment(aid)
    return 200, {"ok": True}


# ----------------------------------------------------------------- admin ---

@route("POST", r"/api/admin/login")
def admin_login(h, m, body):
    password = (body or {}).get("password", "")
    if not db.verify_admin_password(password):
        raise ApiError(401, "Incorrect password.")
    token = db.create_session()
    h.set_cookie(ADMIN_COOKIE, token)
    return 200, {"ok": True, "default_password": db.is_default_admin_password()}


@route("POST", r"/api/admin/logout")
def admin_logout(h, m, body):
    token = h.get_cookie(ADMIN_COOKIE)
    if token:
        db.destroy_session(token)
    h.clear_cookie(ADMIN_COOKIE)
    return 200, {"ok": True}


@route("GET", r"/api/admin/session")
def admin_session(h, m, body):
    token = h.get_cookie(ADMIN_COOKIE)
    authenticated = db.session_valid(token)
    return 200, {
        "authenticated": authenticated,
        "default_password": db.is_default_admin_password() if authenticated else None,
    }


@route("GET", r"/api/admin/config")
def admin_get_config(h, m, body):
    require_admin(h)
    return 200, db.get_config()


@route("PUT", r"/api/admin/config")
def admin_put_config(h, m, body):
    require_admin(h)
    validate_config(body)
    db.save_config(body)
    return 200, db.get_config()


@route("POST", r"/api/admin/config/reset")
def admin_reset_config(h, m, body):
    require_admin(h)
    return 200, db.reset_config()


@route("PUT", r"/api/admin/password")
def admin_change_password(h, m, body):
    require_admin(h)
    current = (body or {}).get("current_password", "")
    new = (body or {}).get("new_password", "")
    if not db.verify_admin_password(current):
        raise ApiError(401, "Current password is incorrect.")
    if not new or len(new) < 8:
        raise ApiError(400, "New password must be at least 8 characters.")
    db.set_admin_password(new)
    return 200, {"ok": True}


@route("GET", r"/api/admin/assessments")
def admin_list_assessments(h, m, body):
    require_admin(h)
    qs = parse_qs(urlparse(h.path).query)
    status = (qs.get("status") or [None])[0]
    return 200, {"assessments": db.list_assessments(status=status)}


@route("GET", r"/api/admin/assessments/(?P<id>\d+)")
def admin_get_assessment(h, m, body):
    require_admin(h)
    return 200, assessment_payload(int(m.group("id")))


@route("DELETE", r"/api/admin/assessments/(?P<id>\d+)")
def admin_delete_assessment(h, m, body):
    require_admin(h)
    aid = int(m.group("id"))
    if db.get_assessment(aid) is None:
        raise ApiError(404, "Assessment not found.")
    db.delete_assessment(aid)
    return 200, {"ok": True}


# -------------------------------------------------------------- print-out --

def _render_answer(question, answer):
    if not answer:
        return "<em>Not answered</em>"
    value = answer.get("value")
    if isinstance(value, list):
        text = ", ".join(str(v) for v in value) or "<em>Not answered</em>"
    elif value in (None, ""):
        text = "<em>Not answered</em>"
    else:
        text = str(value)
    comment = answer.get("comment")
    if comment:
        text += f"<br><span class='muted'>Comment: {comment}</span>"
    return text


@route("GET", r"/api/assessments/(?P<id>\d+)/print")
def print_assessment(h, m, body):
    aid = int(m.group("id"))
    payload = assessment_payload(aid)
    config = db.get_config()
    a = payload["assessment"]
    answers = payload["answers"]
    results = payload["results"]

    parts = [
        "<html><head><meta charset='utf-8'><title>BIA / DPIA Report</title>",
        "<style>body{font-family:Arial,sans-serif;margin:2em;color:#1a1a1a}",
        "h1{font-size:1.5em}h2{margin-top:2em;border-bottom:2px solid #333}",
        "h3{margin-top:1.5em;color:#333}table{border-collapse:collapse;width:100%;margin:0.5em 0}",
        "td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top;font-size:0.92em}",
        "th{background:#f0f0f0}.muted{color:#666;font-size:0.9em}",
        ".badge{display:inline-block;padding:2px 10px;border-radius:10px;background:#eee;font-weight:bold}",
        "</style></head><body>",
        f"<h1>Business Impact Assessment &amp; DPIA -- {a['project_name'] or '(untitled project)'}</h1>",
        "<table>",
        f"<tr><th>Project name</th><td>{a['project_name']}</td></tr>",
        f"<tr><th>Description</th><td>{a['description']}</td></tr>",
        f"<tr><th>Country/countries/business unit</th><td>{a['countries']}</td></tr>",
        f"<tr><th>Project manager</th><td>{a['project_manager']}</td></tr>",
        f"<tr><th>Solution name</th><td>{a['solution_name']}</td></tr>",
        f"<tr><th>Solution owner</th><td>{a['solution_owner']}</td></tr>",
        f"<tr><th>Completed by</th><td>{a['completed_by']} ({a['completed_by_email']})</td></tr>",
        f"<tr><th>Form date</th><td>{a['form_date']}</td></tr>",
        f"<tr><th>Status</th><td>{a['status']}</td></tr>",
        "</table>",
        "<h2>Protection level (BIA results)</h2><table><tr><th>Aspect</th><th>Maximum impact</th><th>Classification</th><th>Protection profile</th><th>Service level</th></tr>",
    ]
    for cat, entry in results["bia_categories"].items():
        parts.append(
            f"<tr><td>{cat.capitalize()}</td><td>{entry['max_label']}</td>"
            f"<td>{entry.get('classification_label', '') or ''} ({entry.get('classification_code', '') or ''})</td>"
            f"<td>{entry.get('protection_profile', '') or ''}</td><td>{entry.get('service_level', '') or ''}</td></tr>"
        )
    parts.append("</table>")

    dpia_needed = results["dpia_needed"]
    parts.append(
        f"<h2>Is a DPIA needed? <span class='badge'>{dpia_needed['result']}</span></h2><ul>"
        + "".join(f"<li>{r}</li>" for r in dpia_needed["reasons"])
        + "</ul>"
    )

    for tool_key in ("bia", "dpia0", "dpia"):
        tool = config["tools"][tool_key]
        parts.append(f"<h2>{tool['title']}</h2>")
        for section in tool["sections"]:
            parts.append(f"<h3>{section['title']}</h3><table>")
            for q in section["questions"]:
                ans = answers.get(q["key"])
                row = _render_answer(q, ans)
                if q.get("has_risk_register") and ans:
                    risk_bits = []
                    for label, field in (
                        ("Risk identified", "risk_identified"), ("Remediation", "remediation"),
                        ("Likelihood", "likelihood"), ("Consequence", "consequence"),
                        ("Risk owner", "risk_owner"), ("Status", "status"), ("Due date", "due_date"),
                    ):
                        if ans.get(field):
                            risk_bits.append(f"{label}: {ans.get(field)}")
                    if risk_bits:
                        row += "<br><span class='muted'>" + " | ".join(risk_bits) + "</span>"
                parts.append(f"<tr><th style='width:45%'>{q['prompt']}</th><td>{row}</td></tr>")
            parts.append("</table>")

    parts.append("</body></html>")
    html = "".join(parts)
    return 200, ("text/html", html.encode("utf-8"))


# --------------------------------------------------------------- handler ---

class Handler(BaseHTTPRequestHandler):
    server_version = "BIADPIA/1.0"

    def log_message(self, fmt, *args):
        pass

    def get_cookie(self, name):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        jar.load(raw)
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def set_cookie(self, name, value):
        self._set_cookie_header = f"{name}={value}; Path=/; HttpOnly; SameSite=Lax"

    def clear_cookie(self, name):
        self._set_cookie_header = f"{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return None
        raw = self.rfile.read(length)
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise ApiError(400, "Invalid JSON body.")

    def _dispatch(self, method):
        self._set_cookie_header = None
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            try:
                body = self._read_body() if method in ("POST", "PUT", "PATCH") else None
            except ApiError as e:
                return self._send_json(e.status, {"error": e.message})

            for route_method, pattern, fn in ROUTES:
                if route_method != method:
                    continue
                match = pattern.match(path)
                if match:
                    try:
                        status, payload = fn(self, match, body)
                    except ApiError as e:
                        return self._send_json(e.status, {"error": e.message})
                    except Exception as e:  # noqa: BLE001
                        return self._send_json(500, {"error": str(e)})
                    if isinstance(payload, tuple):
                        content_type, raw = payload
                        return self._send_raw(status, content_type, raw)
                    return self._send_json(status, payload)
            return self._send_json(404, {"error": "Not found."})

        if method == "GET":
            return self._serve_static(path)
        return self._send_json(405, {"error": "Method not allowed."})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if getattr(self, "_set_cookie_header", None):
            self.send_header("Set-Cookie", self._set_cookie_header)
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, status, content_type, raw):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        if getattr(self, "_set_cookie_header", None):
            self.send_header("Set-Cookie", self._set_cookie_header)
        self.end_headers()
        self.wfile.write(raw)

    def _serve_static(self, path):
        if path == "/":
            path = "/index.html"
        safe_path = os.path.normpath(path).lstrip("/")
        full_path = os.path.join(STATIC_DIR, safe_path)
        if not full_path.startswith(STATIC_DIR):
            return self._send_json(403, {"error": "Forbidden."})
        if not os.path.isfile(full_path):
            return self._send_json(404, {"error": "Not found."})
        content_type, _ = mimetypes.guess_type(full_path)
        with open(full_path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(host="127.0.0.1", port=8000):
    db.init_db()
    httpd = Server((host, port), Handler)
    print(f"BIA/DPIA tool serving on http://{host}:{port}")
    print(f"Admin console: http://{host}:{port}/admin.html")
    if db.is_default_admin_password():
        print(f"Default admin password is '{db.DEFAULT_ADMIN_PASSWORD}' -- change it in the Admin console immediately.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
