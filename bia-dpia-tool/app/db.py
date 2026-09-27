"""SQLite persistence layer. Stdlib only (sqlite3, hashlib, secrets)."""

import copy
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

from . import seed_data

DB_PATH = os.environ.get(
    "BIA_DPIA_DB",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "bia_dpia.sqlite3"),
)

DEFAULT_ADMIN_PASSWORD = os.environ.get("BIA_DPIA_ADMIN_PASSWORD", "ChangeMe!123")

_lock = threading.Lock()
_local = threading.local()


def get_conn():
    conn = getattr(_local, "conn", None)
    if conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _local.conn = conn
    return conn


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()


def init_db():
    with _lock:
        conn = get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                is_default_password INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT DEFAULT '',
                description TEXT DEFAULT '',
                countries TEXT DEFAULT '',
                project_manager TEXT DEFAULT '',
                solution_name TEXT DEFAULT '',
                solution_owner TEXT DEFAULT '',
                completed_by TEXT DEFAULT '',
                completed_by_email TEXT DEFAULT '',
                form_date TEXT DEFAULT '',
                scope TEXT NOT NULL DEFAULT 'both',
                bia_status TEXT NOT NULL DEFAULT 'draft',
                dpia_status TEXT NOT NULL DEFAULT 'draft',
                status TEXT NOT NULL DEFAULT 'draft',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                submitted_at TEXT
            );
            CREATE TABLE IF NOT EXISTS answers (
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                question_key TEXT NOT NULL,
                tool TEXT NOT NULL,
                data TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (assessment_id, question_key)
            );
            """
        )
        conn.commit()
        _migrate_assessments_columns(conn)

        cur = conn.execute("SELECT 1 FROM config WHERE id = 1")
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO config (id, data, updated_at) VALUES (1, ?, ?)",
                (json.dumps(seed_data.DEFAULT_CONFIG), _now()),
            )
            conn.commit()

        cur = conn.execute("SELECT 1 FROM admin WHERE id = 1")
        if cur.fetchone() is None:
            salt = secrets.token_hex(16)
            conn.execute(
                "INSERT INTO admin (id, password_hash, salt, is_default_password, updated_at) VALUES (1, ?, ?, 1, ?)",
                (_hash_password(DEFAULT_ADMIN_PASSWORD, salt), salt, _now()),
            )
            conn.commit()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _migrate_assessments_columns(conn):
    """Adds columns introduced after a DB was first created (SQLite has no
    'ADD COLUMN IF NOT EXISTS'), so older on-disk databases pick them up
    with sane defaults instead of erroring on the next query."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(assessments)")}
    migrations = [
        ("scope", "TEXT NOT NULL DEFAULT 'both'"),
        ("bia_status", "TEXT NOT NULL DEFAULT 'draft'"),
        ("dpia_status", "TEXT NOT NULL DEFAULT 'draft'"),
    ]
    for name, ddl in migrations:
        if name not in existing:
            conn.execute(f"ALTER TABLE assessments ADD COLUMN {name} {ddl}")
    conn.commit()


# ---------------------------------------------------------------- config ---

def get_config():
    conn = get_conn()
    row = conn.execute("SELECT data FROM config WHERE id = 1").fetchone()
    if row is None:
        return copy.deepcopy(seed_data.DEFAULT_CONFIG)
    return json.loads(row["data"])


def save_config(config: dict):
    conn = get_conn()
    with _lock:
        conn.execute(
            "UPDATE config SET data = ?, updated_at = ? WHERE id = 1",
            (json.dumps(config), _now()),
        )
        conn.commit()


def reset_config():
    fresh = copy.deepcopy(seed_data.DEFAULT_CONFIG)
    save_config(fresh)
    return fresh


# ----------------------------------------------------------------- admin ---

def verify_admin_password(password: str) -> bool:
    conn = get_conn()
    row = conn.execute("SELECT password_hash, salt FROM admin WHERE id = 1").fetchone()
    if row is None:
        return False
    return secrets.compare_digest(_hash_password(password, row["salt"]), row["password_hash"])


def is_default_admin_password() -> bool:
    conn = get_conn()
    row = conn.execute("SELECT is_default_password FROM admin WHERE id = 1").fetchone()
    return bool(row and row["is_default_password"])


def set_admin_password(new_password: str):
    conn = get_conn()
    salt = secrets.token_hex(16)
    with _lock:
        conn.execute(
            "UPDATE admin SET password_hash = ?, salt = ?, is_default_password = 0, updated_at = ? WHERE id = 1",
            (_hash_password(new_password, salt), salt, _now()),
        )
        conn.commit()


SESSION_TTL_SECONDS = 8 * 60 * 60


def create_session() -> str:
    token = secrets.token_urlsafe(32)
    conn = get_conn()
    with _lock:
        conn.execute(
            "INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)",
            (token, _now(), time.time() + SESSION_TTL_SECONDS),
        )
        conn.commit()
    return token


def session_valid(token: str) -> bool:
    if not token:
        return False
    conn = get_conn()
    row = conn.execute("SELECT expires_at FROM sessions WHERE token = ?", (token,)).fetchone()
    if row is None:
        return False
    if row["expires_at"] < time.time():
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        return False
    return True


def destroy_session(token: str):
    conn = get_conn()
    with _lock:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


# ----------------------------------------------------------- assessments ---

ASSESSMENT_FIELDS = [
    "project_name", "description", "countries", "project_manager",
    "solution_name", "solution_owner", "completed_by", "completed_by_email",
    "form_date",
]

VALID_SCOPES = ("bia", "dpia", "both")


def scope_parts(scope: str):
    """Which of 'bia'/'dpia' are in scope, given a scope value."""
    return ["bia", "dpia"] if scope == "both" else [scope]


def _overall_status(scope, bia_status, dpia_status):
    parts_status = {"bia": bia_status, "dpia": dpia_status}
    relevant = [parts_status[p] for p in scope_parts(scope)]
    return "submitted" if relevant and all(s == "submitted" for s in relevant) else "draft"


def create_assessment(fields: dict) -> int:
    conn = get_conn()
    now = _now()
    scope = fields.get("scope") or "both"
    values = {k: fields.get(k, "") for k in ASSESSMENT_FIELDS}
    bia_status = "draft" if scope in ("bia", "both") else "not_applicable"
    dpia_status = "draft" if scope in ("dpia", "both") else "not_applicable"
    columns = list(values.keys()) + ["scope", "bia_status", "dpia_status", "status", "created_at", "updated_at"]
    placeholders = ", ".join(["?"] * len(columns))
    with _lock:
        cur = conn.execute(
            f"INSERT INTO assessments ({', '.join(columns)}) VALUES ({placeholders})",
            [*values.values(), scope, bia_status, dpia_status, "draft", now, now],
        )
        conn.commit()
        return cur.lastrowid


def update_assessment_fields(assessment_id: int, fields: dict):
    """Updates plain text fields only. Scope changes go through update_scope()
    since they also need to recompute bia_status/dpia_status/status."""
    updates = {k: v for k, v in fields.items() if k in ASSESSMENT_FIELDS}
    if not updates:
        return
    conn = get_conn()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    with _lock:
        conn.execute(
            f"UPDATE assessments SET {set_clause}, updated_at = ? WHERE id = ?",
            [*updates.values(), _now(), assessment_id],
        )
        conn.commit()


def update_scope(assessment_id: int, new_scope: str):
    row = get_assessment(assessment_id)
    if row is None:
        return

    def resolve(part_status, part_in_new_scope):
        if not part_in_new_scope:
            return "not_applicable"
        return "draft" if part_status == "not_applicable" else part_status

    new_bia = resolve(row["bia_status"], new_scope in ("bia", "both"))
    new_dpia = resolve(row["dpia_status"], new_scope in ("dpia", "both"))
    overall = _overall_status(new_scope, new_bia, new_dpia)
    conn = get_conn()
    now = _now()
    with _lock:
        conn.execute(
            "UPDATE assessments SET scope = ?, bia_status = ?, dpia_status = ?, status = ?, updated_at = ? WHERE id = ?",
            (new_scope, new_bia, new_dpia, overall, now, assessment_id),
        )
        conn.commit()


def get_assessment(assessment_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    return dict(row) if row else None


def list_assessments(owner_email: str = None, status: str = None):
    conn = get_conn()
    query = "SELECT * FROM assessments WHERE 1=1"
    params = []
    if owner_email:
        query += " AND completed_by_email = ?"
        params.append(owner_email)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY updated_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def delete_assessment(assessment_id: int):
    conn = get_conn()
    with _lock:
        conn.execute("DELETE FROM answers WHERE assessment_id = ?", (assessment_id,))
        conn.execute("DELETE FROM assessments WHERE id = ?", (assessment_id,))
        conn.commit()


def set_part_status(assessment_id: int, part: str, status: str):
    """part is 'bia' or 'dpia'; status is 'draft' or 'submitted'."""
    conn = get_conn()
    now = _now()
    column = f"{part}_status"
    with _lock:
        conn.execute(f"UPDATE assessments SET {column} = ?, updated_at = ? WHERE id = ?", (status, now, assessment_id))
        row = conn.execute("SELECT scope, bia_status, dpia_status FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        overall = _overall_status(row["scope"], row["bia_status"], row["dpia_status"])
        if overall == "submitted":
            conn.execute("UPDATE assessments SET status = ?, submitted_at = ? WHERE id = ?", (overall, now, assessment_id))
        else:
            conn.execute("UPDATE assessments SET status = ?, submitted_at = NULL WHERE id = ?", (overall, assessment_id))
        conn.commit()


# --------------------------------------------------------------- answers ---

def upsert_answers(assessment_id: int, tool: str, answers: dict):
    """answers: {question_key: <json-serializable dict>}"""
    conn = get_conn()
    now = _now()
    with _lock:
        for key, value in answers.items():
            conn.execute(
                """INSERT INTO answers (assessment_id, question_key, tool, data, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(assessment_id, question_key)
                   DO UPDATE SET data = excluded.data, tool = excluded.tool, updated_at = excluded.updated_at""",
                (assessment_id, key, tool, json.dumps(value), now),
            )
        conn.execute("UPDATE assessments SET updated_at = ? WHERE id = ?", (now, assessment_id))
        conn.commit()


def get_answers(assessment_id: int) -> dict:
    conn = get_conn()
    rows = conn.execute(
        "SELECT question_key, data FROM answers WHERE assessment_id = ?", (assessment_id,)
    ).fetchall()
    return {r["question_key"]: json.loads(r["data"]) for r in rows}
