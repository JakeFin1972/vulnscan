"""Tiny stdlib-only HTTP application: JSON API + static file serving.

No third-party dependencies (no FastAPI/Flask) so the tool runs anywhere
Python 3 runs, with nothing to `pip install`.
"""

import json
import mimetypes
import os
import re
import socketserver
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import db, scoring, report as report_mod
from .csv_writer import build_csv
from .docx_writer import build_docx
from .pdf_writer import build_pdf

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

ADMIN_COOKIE = "bia_admin_token"
_SERVING_HTTPS = False  # flipped on by serve() when --cert/--key are given

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
    """Returns the authenticated admin_users row, or raises 401."""
    token = handler.get_cookie(ADMIN_COOKIE)
    admin = db.get_session_admin(token)
    if admin is None:
        raise ApiError(401, "Admin authentication required.")
    return admin


LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 8


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
    body = body or {}
    scope = body.get("scope") or "both"
    if scope not in db.VALID_SCOPES:
        raise ApiError(400, f"scope must be one of {db.VALID_SCOPES}.")
    aid = db.create_assessment({**body, "scope": scope})
    actor = body.get("completed_by_email") or body.get("completed_by") or "anonymous"
    db.log_audit(actor, "assessment.created", target=str(aid), ip=h.client_ip(), details=body.get("project_name"))
    return 201, assessment_payload(aid)


@route("GET", r"/api/assessments/(?P<id>\d+)")
def get_assessment(h, m, body):
    return 200, assessment_payload(int(m.group("id")))


@route("PUT", r"/api/assessments/(?P<id>\d+)")
def update_assessment(h, m, body):
    aid = int(m.group("id"))
    if db.get_assessment(aid) is None:
        raise ApiError(404, "Assessment not found.")
    body = body or {}
    if "scope" in body:
        if body["scope"] not in db.VALID_SCOPES:
            raise ApiError(400, f"scope must be one of {db.VALID_SCOPES}.")
        db.update_scope(aid, body["scope"])
    db.update_assessment_fields(aid, body)
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


def _require_part_in_scope(assessment, part):
    if part not in db.scope_parts(assessment["scope"]):
        raise ApiError(400, f"'{part}' is not in this assessment's scope ('{assessment['scope']}').")


@route("POST", r"/api/assessments/(?P<id>\d+)/submit/(?P<part>bia|dpia)")
def submit_part(h, m, body):
    aid = int(m.group("id"))
    assessment = db.get_assessment(aid)
    if assessment is None:
        raise ApiError(404, "Assessment not found.")
    part = m.group("part")
    _require_part_in_scope(assessment, part)
    db.set_part_status(aid, part, "submitted")
    actor = assessment.get("completed_by_email") or assessment.get("completed_by") or "anonymous"
    db.log_audit(actor, f"assessment.submitted.{part}", target=str(aid), ip=h.client_ip())
    return 200, assessment_payload(aid)


@route("POST", r"/api/assessments/(?P<id>\d+)/reopen/(?P<part>bia|dpia)")
def reopen_part(h, m, body):
    aid = int(m.group("id"))
    assessment = db.get_assessment(aid)
    if assessment is None:
        raise ApiError(404, "Assessment not found.")
    _require_part_in_scope(assessment, m.group("part"))
    db.set_part_status(aid, m.group("part"), "draft")
    return 200, assessment_payload(aid)


@route("DELETE", r"/api/assessments/(?P<id>\d+)")
def delete_assessment_public(h, m, body):
    # Anyone can delete their own draft from the wizard (e.g. "discard").
    aid = int(m.group("id"))
    assessment = db.get_assessment(aid)
    if assessment is None:
        raise ApiError(404, "Assessment not found.")
    db.delete_assessment(aid)
    actor = assessment.get("completed_by_email") or assessment.get("completed_by") or "anonymous"
    db.log_audit(actor, "assessment.deleted", target=str(aid), ip=h.client_ip(), details=assessment.get("project_name"))
    return 200, {"ok": True}


# ----------------------------------------------------------------- admin ---

@route("POST", r"/api/admin/login")
def admin_login(h, m, body):
    ip = h.client_ip()
    if db.count_recent_failed_logins(ip, LOGIN_RATE_LIMIT_WINDOW_SECONDS) >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
        raise ApiError(429, "Too many failed login attempts from this address. Try again later.")

    email = ((body or {}).get("email") or "").strip()
    password = (body or {}).get("password", "")
    admin = db.authenticate_admin(email, password) if email else None
    if admin is None or not admin["active"]:
        db.log_audit(email or "(no email)", "admin.login_failed", ip=ip)
        raise ApiError(401, "Incorrect email or password.")

    token = db.create_session(admin["id"])
    db.touch_admin_login(admin["id"])
    db.log_audit(admin["email"], "admin.login", ip=ip)
    h.set_cookie(ADMIN_COOKIE, token)
    return 200, {"ok": True, "name": admin["name"], "email": admin["email"], "default_password": bool(admin["is_default_password"])}


@route("POST", r"/api/admin/logout")
def admin_logout(h, m, body):
    token = h.get_cookie(ADMIN_COOKIE)
    if token:
        db.destroy_session(token)
    h.clear_cookie(ADMIN_COOKIE)
    return 200, {"ok": True}


@route("GET", r"/api/admin/session")
def admin_session(h, m, body):
    admin = db.get_session_admin(h.get_cookie(ADMIN_COOKIE))
    if admin is None:
        return 200, {"authenticated": False}
    return 200, {
        "authenticated": True,
        "name": admin["name"],
        "email": admin["email"],
        "default_password": bool(admin["is_default_password"]),
    }


@route("GET", r"/api/admin/users")
def admin_list_users(h, m, body):
    require_admin(h)
    return 200, {"users": db.list_admin_users()}


@route("POST", r"/api/admin/users")
def admin_create_user(h, m, body):
    actor = require_admin(h)
    body = body or {}
    name = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    if not name or not email:
        raise ApiError(400, "Name and email are required.")
    if len(password) < 8:
        raise ApiError(400, "Password must be at least 8 characters.")
    try:
        new_id = db.create_admin_user(name, email, password)
    except ValueError as e:
        raise ApiError(400, str(e))
    db.log_audit(actor["email"], "admin.user.created", target=email, ip=h.client_ip())
    return 201, {"users": db.list_admin_users(), "id": new_id}


@route("POST", r"/api/admin/users/(?P<id>\d+)/deactivate")
def admin_deactivate_user(h, m, body):
    actor = require_admin(h)
    target_id = int(m.group("id"))
    if target_id == actor["id"]:
        raise ApiError(400, "You can't deactivate your own account.")
    if db.count_active_admins() <= 1:
        raise ApiError(400, "Can't deactivate the last remaining admin.")
    target = db.get_admin_user(target_id)
    if target is None:
        raise ApiError(404, "Admin user not found.")
    db.set_admin_active(target_id, False)
    db.log_audit(actor["email"], "admin.user.deactivated", target=target["email"], ip=h.client_ip())
    return 200, {"users": db.list_admin_users()}


@route("POST", r"/api/admin/users/(?P<id>\d+)/activate")
def admin_activate_user(h, m, body):
    actor = require_admin(h)
    target_id = int(m.group("id"))
    target = db.get_admin_user(target_id)
    if target is None:
        raise ApiError(404, "Admin user not found.")
    db.set_admin_active(target_id, True)
    db.log_audit(actor["email"], "admin.user.activated", target=target["email"], ip=h.client_ip())
    return 200, {"users": db.list_admin_users()}


@route("GET", r"/api/admin/backup")
def admin_download_backup(h, m, body):
    actor = require_admin(h)
    try:
        data = db.create_backup_bytes()
    except FileNotFoundError as e:
        raise ApiError(404, str(e))
    db.log_audit(actor["email"], "admin.backup.downloaded", ip=h.client_ip())
    filename = f"bia_dpia-backup-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.sqlite3"
    return 200, ("application/x-sqlite3", data, filename)


@route("GET", r"/api/admin/audit-log")
def admin_get_audit_log(h, m, body):
    require_admin(h)
    qs = parse_qs(urlparse(h.path).query)
    limit = min(int((qs.get("limit") or [100])[0]), 500)
    offset = int((qs.get("offset") or [0])[0])
    action = (qs.get("action") or [None])[0]
    return 200, {"entries": db.list_audit_log(limit=limit, offset=offset, action=action)}


@route("GET", r"/api/admin/config")
def admin_get_config(h, m, body):
    require_admin(h)
    return 200, db.get_config()


@route("PUT", r"/api/admin/config")
def admin_put_config(h, m, body):
    actor = require_admin(h)
    validate_config(body)
    db.save_config(body)
    db.log_audit(actor["email"], "config.updated", ip=h.client_ip())
    return 200, db.get_config()


@route("POST", r"/api/admin/config/reset")
def admin_reset_config(h, m, body):
    actor = require_admin(h)
    fresh = db.reset_config()
    db.log_audit(actor["email"], "config.reset", ip=h.client_ip())
    return 200, fresh


@route("PUT", r"/api/admin/password")
def admin_change_password(h, m, body):
    actor = require_admin(h)
    current = (body or {}).get("current_password", "")
    new = (body or {}).get("new_password", "")
    if db.authenticate_admin(actor["email"], current) is None:
        raise ApiError(401, "Current password is incorrect.")
    if not new or len(new) < 8:
        raise ApiError(400, "New password must be at least 8 characters.")
    db.set_admin_password(actor["id"], new)
    db.log_audit(actor["email"], "admin.password_changed", ip=h.client_ip())
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
    actor = require_admin(h)
    aid = int(m.group("id"))
    assessment = db.get_assessment(aid)
    if assessment is None:
        raise ApiError(404, "Assessment not found.")
    db.delete_assessment(aid)
    db.log_audit(actor["email"], "assessment.deleted", target=str(aid), ip=h.client_ip(), details=assessment.get("project_name"))
    return 200, {"ok": True}


# -------------------------------------------------------------- print-out --

def _html_report(report):
    parts = [
        "<html><head><meta charset='utf-8'><title>BIA / DPIA Report</title>",
        "<style>",
        ":root{--navy:#1f3864;--accent:#2f6f9f;--text:#222;--muted:#5b6470;--border:#d7dce2;--zebra:#f5f7fa;}",
        "*{box-sizing:border-box}",
        "body{font-family:-apple-system,Segoe UI,Arial,sans-serif;margin:0;padding:2.5em 3em;color:var(--text);"
        "line-height:1.45;max-width:900px}",
        "header.report-header{border-bottom:3px solid var(--navy);padding-bottom:0.6em;margin-bottom:1.4em;"
        "display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:0.5em}",
        "h1{font-size:1.6em;color:var(--navy);margin:0 0 0.15em}",
        ".org-line{color:var(--muted);font-size:0.95em}",
        ".meta-stamp{color:var(--muted);font-size:0.85em;text-align:right}",
        "h2{font-size:1.2em;margin-top:2.2em;margin-bottom:0.5em;color:var(--navy);"
        "border-bottom:2px solid var(--border);padding-bottom:0.3em}",
        "h3{margin-top:0;margin-bottom:0.6em;color:var(--accent);font-size:1.02em;font-weight:600}",
        "table{border-collapse:collapse;width:100%;margin:0.3em 0 1em}",
        "td,th{border:1px solid var(--border);padding:8px 10px;text-align:left;vertical-align:top;font-size:0.92em}",
        "th{background:var(--navy);color:#fff;font-weight:600}",
        "tbody tr:nth-child(even){background:var(--zebra)}",
        ".muted{color:var(--muted);font-size:0.88em}",
        ".badge{display:inline-block;padding:3px 12px;border-radius:12px;background:var(--accent);"
        "color:#fff;font-weight:600;font-size:0.85em;vertical-align:middle}",
        "@media print{body{padding:1.2cm}a{color:inherit;text-decoration:none}"
        "h2{page-break-after:avoid}tr{page-break-inside:avoid}}",
        "</style></head><body>",
        "<header class='report-header'><div><h1>Business Impact Assessment &amp; DPIA Report</h1>",
        f"<div class='org-line'>{report.get('org_name') or ''}</div></div>",
        f"<div class='meta-stamp'>Generated {report.get('generated_at') or ''}</div></header>",
        "<table><tbody>",
    ]
    for label, value in report["meta"]:
        parts.append(f"<tr><th style='width:38%'>{label}</th><td>{value or ''}</td></tr>")
    parts.append("</tbody></table>")

    if report["protection"]:
        parts.append(
            "<h2>Protection level (BIA results)</h2><table><thead>"
            "<tr><th>Aspect</th><th>Maximum impact</th><th>Classification</th>"
            "<th>Protection profile</th><th>Service level</th></tr></thead><tbody>"
        )
        for p in report["protection"]:
            parts.append(
                f"<tr><td>{p['aspect']}</td><td>{p['max_label']}</td>"
                f"<td>{p['classification']}</td><td>{p['protection_profile']}</td><td>{p['service_level']}</td></tr>"
            )
        parts.append("</tbody></table>")

    if report["dpia_needed"] is not None:
        dn = report["dpia_needed"]
        parts.append(
            f"<h2>Is a DPIA needed? <span class='badge'>{dn['result']}</span></h2><ul>"
            + "".join(f"<li>{r}</li>" for r in dn["reasons"])
            + "</ul>"
        )

    for section in report["sections"]:
        parts.append(f"<h2>{section['tool_title']}</h2><h3>{section['section_title']}</h3><table><tbody>")
        for row in section["rows"]:
            cell = row["answer"] or "<em>Not answered</em>"
            if row["comment"]:
                cell += f"<br><span class='muted'>Comment: {row['comment']}</span>"
            if row["risk"]:
                cell += "<br><span class='muted'>" + " | ".join(f"{k}: {v}" for k, v in row["risk"]) + "</span>"
            id_prefix = f"{row['id']} " if row["id"] else ""
            parts.append(f"<tr><th style='width:45%'>{id_prefix}{row['prompt']}</th><td>{cell}</td></tr>")
        parts.append("</tbody></table>")

    parts.append("</body></html>")
    return "".join(parts)


@route("GET", r"/api/assessments/(?P<id>\d+)/print")
def print_assessment(h, m, body):
    report, _assessment = _export_report(int(m.group("id")))
    html = _html_report(report)
    return 200, ("text/html", html.encode("utf-8"))


def _export_report(aid):
    payload = assessment_payload(aid)
    config = db.get_config()
    return report_mod.build_report(config, payload["assessment"], payload["answers"], payload["results"]), payload["assessment"]


@route("GET", r"/api/assessments/(?P<id>\d+)/export\.csv")
def export_csv(h, m, body):
    report, assessment = _export_report(int(m.group("id")))
    filename = report_mod.report_filename(assessment, "csv")
    return 200, ("text/csv; charset=utf-8", build_csv(report), filename)


@route("GET", r"/api/assessments/(?P<id>\d+)/export\.docx")
def export_docx(h, m, body):
    report, assessment = _export_report(int(m.group("id")))
    filename = report_mod.report_filename(assessment, "docx")
    return 200, ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", build_docx(report), filename)


@route("GET", r"/api/assessments/(?P<id>\d+)/export\.pdf")
def export_pdf(h, m, body):
    report, assessment = _export_report(int(m.group("id")))
    filename = report_mod.report_filename(assessment, "pdf")
    return 200, ("application/pdf", build_pdf(report), filename)


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
        secure = "; Secure" if _SERVING_HTTPS else ""
        self._set_cookie_header = f"{name}={value}; Path=/; HttpOnly; SameSite=Strict{secure}"

    def clear_cookie(self, name):
        secure = "; Secure" if _SERVING_HTTPS else ""
        self._set_cookie_header = f"{name}=; Path=/; HttpOnly; SameSite=Strict{secure}; Max-Age=0"

    def client_ip(self):
        # Trust X-Forwarded-For only if you actually sit behind a reverse
        # proxy that sets it; otherwise this is spoofable by the client.
        # We use the raw socket peer address instead for that reason.
        return self.client_address[0]

    MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB -- generous for a JSON payload, caps memory use

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return None
        if length > self.MAX_BODY_BYTES:
            raise ApiError(413, "Request body too large.")
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
                        content_type, raw, *rest = payload
                        filename = rest[0] if rest else None
                        return self._send_raw(status, content_type, raw, filename)
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

    def _send_raw(self, status, content_type, raw, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
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


def serve(host="127.0.0.1", port=8000, certfile=None, keyfile=None):
    global _SERVING_HTTPS
    db.init_db()
    httpd = Server((host, port), Handler)
    scheme = "http"
    # If a reverse proxy terminates TLS in front of this process (the
    # recommended setup -- see server.py's --cert/--key help text), this
    # process only ever sees plain HTTP itself. Set this env var in that
    # case so the session cookie still gets the Secure attribute; it's a
    # server-side opt-in, not a client-supplied header, so it can't be
    # spoofed by a request.
    if certfile or os.environ.get("BIA_DPIA_FORCE_SECURE_COOKIE") == "1":
        _SERVING_HTTPS = True
    if certfile:
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"BIA/DPIA tool serving on {scheme}://{host}:{port}")
    print(f"Admin console: {scheme}://{host}:{port}/admin.html")
    if db.any_default_password_admin_exists():
        print(
            f"Default admin login is '{db.DEFAULT_ADMIN_EMAIL}' / '{db.DEFAULT_ADMIN_PASSWORD}' "
            "-- change it in the Admin console immediately."
        )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
