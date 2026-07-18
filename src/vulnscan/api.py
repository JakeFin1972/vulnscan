"""vulnscan.api — FastAPI engine for the local web UI and programmatic access.

Endpoints:
  POST   /scans                 start recon+scan on an authorized path
  GET    /scans                 list all scans (history)
  GET    /scans/{id}            scan status + report
  GET    /findings              findings, optionally filtered by scan_id
  GET    /languages             list all language definition backends
  GET    /languages/{name}      single language def with YAML source
  POST   /languages             validate + create a new language definition
  PUT    /languages/{name}      validate + update an existing definition
  POST   /runtest               proxy to the harness (RED/GREEN gate)
  GET    /health                liveness probe

  EASM / Risk Scoring:
  POST   /easm/assets                  register a new asset
  GET    /easm/assets                  list all tracked assets
  GET    /easm/assets/{id}             asset detail + latest score
  POST   /easm/ingest                  upload scanner output file → parse → upsert
  GET    /easm/vulnerabilities         filtered vuln list
  PATCH  /easm/vulnerabilities/{id}    update status (resolve, accept_risk, …)
  POST   /easm/score/{asset_id}        compute & persist a risk-score snapshot
  GET    /easm/score/{asset_id}        latest score for one asset
  GET    /easm/score/vendor/{label}    aggregate score across a vendor/org label
  GET    /easm/scores/history/{asset_id} time-series of past scores
  GET    /easm/dashboard               top-level EASM summary

Start with:
  uvicorn vulnscan.api:app [--host HOST] [--port PORT]
"""
from __future__ import annotations

import importlib
import json
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from .easm import parse_file as _easm_parse_file, score_vulnerabilities as _easm_score
from .easm.scoring import score_to_grade as _score_to_grade
from .harness import run_test
from .languages.generic_backend import load_backends_from_defs, YamlBackend
from .languages.yaml_loader import load_yaml_def, YamlDefinitionError
from .recon import build_report
from .scanners import run_dynamic_scan, tool_status
from .scanners.base import DynamicFinding as _DynFinding

# ── Directories — both can be overridden by env vars for test isolation ────────
_DATA_DIR = Path(os.environ.get("VULNSCAN_DATA_DIR", "/tmp/vulnscan"))
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH = _DATA_DIR / "scans.db"

_BUILTIN_DEFS_DIR = Path(__file__).parent / "languages" / "defs"
_DEFS_DIR = Path(os.environ.get("VULNSCAN_DEFS_DIR", _BUILTIN_DEFS_DIR))

# Optional: pre-built React UI to serve as static files
_UI_DIR = Path(os.environ.get("VULNSCAN_UI_DIR", "")) if os.environ.get("VULNSCAN_UI_DIR") else None

# ── Database ───────────────────────────────────────────────────────────────────

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                path        TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                finished_at TEXT,
                source_count INTEGER DEFAULT 0,
                sink_count   INTEGER DEFAULT 0,
                pair_count   INTEGER DEFAULT 0,
                report_json  TEXT,
                error        TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id        TEXT PRIMARY KEY,
                scan_id   TEXT NOT NULL,
                kind      TEXT NOT NULL,
                category  TEXT NOT NULL,
                file      TEXT NOT NULL,
                line      INTEGER NOT NULL,
                name      TEXT NOT NULL,
                language  TEXT NOT NULL,
                severity  TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dynamic_scans (
                id          TEXT PRIMARY KEY,
                target      TEXT NOT NULL,
                target_type TEXT NOT NULL,
                tools       TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                finished_at TEXT,
                finding_count INTEGER DEFAULT 0,
                error       TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dynamic_findings (
                id          TEXT PRIMARY KEY,
                scan_id     TEXT NOT NULL,
                tool        TEXT NOT NULL,
                target      TEXT NOT NULL,
                name        TEXT NOT NULL,
                description TEXT,
                severity    TEXT NOT NULL,
                category    TEXT NOT NULL,
                evidence    TEXT,
                url         TEXT,
                port        INTEGER,
                cve         TEXT,
                remediation TEXT,
                FOREIGN KEY(scan_id) REFERENCES dynamic_scans(id)
            )
        """)
        # ── EASM tables ──────────────────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS easm_assets (
                id          TEXT PRIMARY KEY,
                identifier  TEXT NOT NULL,
                asset_type  TEXT NOT NULL,
                label       TEXT,
                tags        TEXT NOT NULL DEFAULT '[]',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(identifier)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS easm_vulnerabilities (
                id           TEXT PRIMARY KEY,
                asset_id     TEXT NOT NULL,
                source_tool  TEXT NOT NULL,
                source_file  TEXT,
                name         TEXT NOT NULL,
                description  TEXT,
                severity     TEXT NOT NULL,
                cvss_score   REAL,
                cve          TEXT,
                cwe          TEXT,
                category     TEXT NOT NULL,
                port         INTEGER,
                protocol     TEXT,
                url          TEXT,
                evidence     TEXT,
                remediation  TEXT,
                discovered_at TEXT NOT NULL,
                last_seen_at  TEXT NOT NULL,
                resolved_at   TEXT,
                status       TEXT NOT NULL DEFAULT 'open',
                FOREIGN KEY(asset_id) REFERENCES easm_assets(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS easm_scores (
                id            TEXT PRIMARY KEY,
                asset_id      TEXT,
                vendor_label  TEXT,
                score         REAL NOT NULL,
                grade         TEXT NOT NULL,
                breakdown_json TEXT NOT NULL DEFAULT '{}',
                scored_at     TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(asset_id) REFERENCES easm_assets(id)
            )
        """)


# ── Severity mapping ───────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, str] = {
    "code_exec":              "critical",
    "os_command":             "high",
    "unsafe_deser":           "high",
    "xxe_candidate":          "high",
    "sql_query":              "medium",
    "ssrf_candidate":         "medium",
    "path_traversal_candidate": "medium",
    "template_injection":     "medium",
    "file_access":            "low",
    "reflection":             "low",
    "open_redirect_candidate": "low",
}


def _severity(category: str) -> str:
    return _SEVERITY_MAP.get(category, "info")


# ── Background scan task ───────────────────────────────────────────────────────

def _run_scan(scan_id: str, path_str: str) -> None:
    conn = _db()
    try:
        conn.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
        conn.commit()

        root = Path(path_str)
        report = build_report(root)

        sources = report["sources"]
        sinks   = report["sinks"]
        pairs   = report["candidate_pairs"]

        # Persist findings
        findings: list[dict] = []
        pair_id_map: dict[tuple, str] = {}
        for pair in pairs:
            pid = str(uuid.uuid4())
            s = pair["source"]
            pair_id_map[(s["file"], s["line"], s["name"])] = pid

        for item in sources + sinks:
            fid = str(uuid.uuid4())
            cat = item["category"]
            sev = _severity(cat)
            pid = pair_id_map.get((item["file"], item["line"], item["name"]))
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                (fid, scan_id, item["kind"], cat,
                 item["file"], item["line"], item["name"],
                 item.get("language", ""), sev)
            )
            findings.append({
                "id": fid, "scan_id": scan_id,
                "kind": item["kind"], "category": cat,
                "file": item["file"], "line": item["line"],
                "name": item["name"], "language": item.get("language", ""),
                "severity": sev, "pair_id": pid,
            })

        conn.execute("""
            UPDATE scans SET
                status='done',
                finished_at=datetime('now'),
                source_count=?,
                sink_count=?,
                pair_count=?,
                report_json=?
            WHERE id=?
        """, (len(sources), len(sinks), len(pairs),
              json.dumps(report), scan_id))
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        conn.execute(
            "UPDATE scans SET status='error', error=?, finished_at=datetime('now') WHERE id=?",
            (str(exc), scan_id)
        )
        conn.commit()
        raise
    finally:
        conn.close()


# ── Language registry helpers ──────────────────────────────────────────────────

def _list_language_defs() -> list[dict]:
    results = []
    for yaml_path in sorted(_DEFS_DIR.glob("*.yaml")):
        try:
            defn = load_yaml_def(yaml_path)
        except YamlDefinitionError:
            continue
        # Check grammar availability
        try:
            importlib.import_module(defn["grammar"])
            available = True
        except Exception:  # noqa: BLE001
            available = False
        results.append({
            "name":         defn["name"],
            "extensions":   defn["extensions"],
            "grammar":      defn["grammar"],
            "source_count": len(defn.get("sources", [])),
            "sink_count":   len(defn.get("sinks", [])),
            "available":    available,
        })
    return results


def _reload_registry() -> None:
    """Reload the language registry after defs change."""
    import importlib as _imp
    import vulnscan.languages as _lang
    _imp.reload(_lang)


# ── FastAPI app ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def _lifespan(app: FastAPI):
    _init_db()
    yield


app = FastAPI(
    title="vulnscan",
    description="Forward-taint adversarial vulnerability scanner — local API.",
    version="0.1.0",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / response models ──────────────────────────────────────────────────

class StartScanRequest(BaseModel):
    path: str
    authorized: bool

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must confirm the path is authorized for scanning.")
        return v


class LanguageCreateRequest(BaseModel):
    name: str
    yaml_content: str


class LanguageUpdateRequest(BaseModel):
    yaml_content: str


class RunTestRequest(BaseModel):
    repo: str
    target: str
    framework: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

# ── Scans ──────────────────────────────────────────────────────────────────────

@app.post("/scans", status_code=201)
def start_scan(req: StartScanRequest, bg: BackgroundTasks):
    root = Path(req.path)
    if not root.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {req.path}")

    scan_id = str(uuid.uuid4())
    with _db() as conn:
        conn.execute(
            "INSERT INTO scans (id, path, status) VALUES (?, ?, 'pending')",
            (scan_id, str(root.resolve()))
        )
    bg.add_task(_run_scan, scan_id, str(root.resolve()))
    return {"id": scan_id}


@app.get("/scans")
def list_scans():
    with _db() as conn:
        rows = conn.execute(
            "SELECT id, path, status, created_at, finished_at, "
            "source_count, sink_count, pair_count, error "
            "FROM scans ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    with _db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    d = dict(row)
    if d.get("report_json"):
        d["report"] = json.loads(d.pop("report_json"))
    else:
        d.pop("report_json", None)
    return d


# ── Findings ───────────────────────────────────────────────────────────────────

@app.get("/findings")
def list_findings(
    scan_id: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    language: Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
):
    query = "SELECT * FROM findings WHERE 1=1"
    params: list[Any] = []
    if scan_id:
        query += " AND scan_id=?"
        params.append(scan_id)
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if language:
        query += " AND language=?"
        params.append(language)
    if category:
        query += " AND category=?"
        params.append(category)
    query += " ORDER BY CASE severity "
    query += " WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
    query += " WHEN 'low' THEN 3 ELSE 4 END, file, line"
    with _db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


# ── Languages ──────────────────────────────────────────────────────────────────

@app.get("/languages")
def list_languages():
    return _list_language_defs()


@app.get("/languages/{name}")
def get_language(name: str):
    yaml_path = _DEFS_DIR / f"{name}.yaml"
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail=f"Language '{name}' not found")
    try:
        defn = load_yaml_def(yaml_path)
    except YamlDefinitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        importlib.import_module(defn["grammar"])
        available = True
    except Exception:  # noqa: BLE001
        available = False
    return {
        **defn,
        "available": available,
        "yaml_content": yaml_path.read_text(encoding="utf-8"),
        "source_count": len(defn.get("sources", [])),
        "sink_count":   len(defn.get("sinks", [])),
    }


@app.post("/languages", status_code=201)
def create_language(req: LanguageCreateRequest):
    # Validate YAML content first
    try:
        raw = yaml.safe_load(req.yaml_content)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"YAML parse error: {exc}") from exc

    # Write to a temp path for validation (yaml_loader expects a Path)
    import tempfile, os
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(req.yaml_content)
        tmp_path = Path(tmp.name)

    try:
        try:
            defn = load_yaml_def(tmp_path)
        except YamlDefinitionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        target_name = defn["name"]
        if req.name and req.name != target_name:
            raise HTTPException(
                status_code=422,
                detail=f"'name' in request body ({req.name!r}) does not match "
                       f"'name' in YAML content ({target_name!r})"
            )

        dest = _DEFS_DIR / f"{target_name}.yaml"
        if dest.exists():
            raise HTTPException(
                status_code=409,
                detail=f"Language '{target_name}' already exists. Use PUT to update."
            )

        dest.write_text(req.yaml_content, encoding="utf-8")
        _reload_registry()
        return {"ok": True, "name": target_name, "errors": []}
    finally:
        os.unlink(tmp_path)


@app.put("/languages/{name}")
def update_language(name: str, req: LanguageUpdateRequest):
    dest = _DEFS_DIR / f"{name}.yaml"
    if not dest.exists():
        raise HTTPException(status_code=404, detail=f"Language '{name}' not found")

    import tempfile, os
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(req.yaml_content)
        tmp_path = Path(tmp.name)

    try:
        try:
            defn = load_yaml_def(tmp_path)
        except YamlDefinitionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        if defn["name"] != name:
            raise HTTPException(
                status_code=422,
                detail=f"Cannot rename language via PUT. "
                       f"YAML 'name' ({defn['name']!r}) must match URL ({name!r})."
            )

        dest.write_text(req.yaml_content, encoding="utf-8")
        _reload_registry()
        return {"ok": True, "name": name, "errors": []}
    finally:
        os.unlink(tmp_path)


# ── Runtest ────────────────────────────────────────────────────────────────────

@app.post("/runtest")
def runtest(req: RunTestRequest):
    repo = Path(req.repo)
    if not repo.exists():
        raise HTTPException(status_code=400, detail=f"Repo path does not exist: {req.repo}")
    result = run_test(repo, req.target, req.framework)
    return result


# ── Dynamic scanning ───────────────────────────────────────────────────────────

class DynamicScanRequest(BaseModel):
    target:      str
    target_type: str    # url | host | mcp
    tools:       list[str] | None = None
    authorized:  bool
    options:     dict | None = None

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must confirm the target is authorized for scanning.")
        return v

    @field_validator("target_type")
    @classmethod
    def valid_target_type(cls, v: str) -> str:
        if v not in ("url", "host", "mcp"):
            raise ValueError("target_type must be 'url', 'host', or 'mcp'")
        return v


def _persist_dynamic_findings(
    conn: sqlite3.Connection,
    scan_id: str,
    findings: list[_DynFinding],
) -> None:
    for f in findings:
        conn.execute(
            "INSERT INTO dynamic_findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()), scan_id,
                f.tool, f.target, f.name,
                f.description, f.severity, f.category,
                f.evidence, f.url, f.port, f.cve, f.remediation,
            ),
        )


def _run_dynamic_scan(
    scan_id: str,
    target: str,
    target_type: str,
    tools: list[str] | None,
    options: dict | None,
) -> None:
    conn = _db()
    try:
        conn.execute("UPDATE dynamic_scans SET status='running' WHERE id=?", (scan_id,))
        conn.commit()

        findings = run_dynamic_scan(
            target=target,
            target_type=target_type,  # type: ignore[arg-type]
            tools=tools,  # type: ignore[arg-type]
            options=options,
        )

        _persist_dynamic_findings(conn, scan_id, findings)
        conn.execute(
            "UPDATE dynamic_scans SET status='done', finished_at=datetime('now'), finding_count=? WHERE id=?",
            (len(findings), scan_id),
        )
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        conn.execute(
            "UPDATE dynamic_scans SET status='error', error=?, finished_at=datetime('now') WHERE id=?",
            (str(exc)[:500], scan_id),
        )
        conn.commit()
        raise
    finally:
        conn.close()


@app.post("/dynamic-scans", status_code=201)
def start_dynamic_scan(req: DynamicScanRequest, bg: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    tools_json = json.dumps(req.tools or [])
    with _db() as conn:
        conn.execute(
            "INSERT INTO dynamic_scans (id, target, target_type, tools, status) VALUES (?,?,?,?,'pending')",
            (scan_id, req.target, req.target_type, tools_json),
        )
    bg.add_task(
        _run_dynamic_scan,
        scan_id, req.target, req.target_type, req.tools, req.options,
    )
    return {"id": scan_id}


@app.get("/dynamic-scans")
def list_dynamic_scans():
    with _db() as conn:
        rows = conn.execute(
            "SELECT id, target, target_type, tools, status, created_at, finished_at, finding_count, error "
            "FROM dynamic_scans ORDER BY created_at DESC"
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["tools"] = json.loads(d["tools"]) if isinstance(d["tools"], str) else d["tools"]
        result.append(d)
    return result


@app.get("/dynamic-scans/{scan_id}")
def get_dynamic_scan(scan_id: str):
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM dynamic_scans WHERE id=?", (scan_id,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Dynamic scan not found")
    d = dict(row)
    d["tools"] = json.loads(d["tools"]) if isinstance(d["tools"], str) else d["tools"]
    return d


@app.get("/dynamic-findings")
def list_dynamic_findings(
    scan_id:  Annotated[str | None, Query()] = None,
    tool:     Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
):
    query  = "SELECT * FROM dynamic_findings WHERE 1=1"
    params: list[Any] = []
    if scan_id:
        query += " AND scan_id=?"; params.append(scan_id)
    if tool:
        query += " AND tool=?";     params.append(tool)
    if severity:
        query += " AND severity=?"; params.append(severity)
    if category:
        query += " AND category=?"; params.append(category)
    query += (" ORDER BY CASE severity "
              "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
              "WHEN 'low' THEN 3 ELSE 4 END, tool, name")
    with _db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/scanners")
def list_scanners():
    """Return availability status of each dynamic scanner tool."""
    return tool_status()


# ── Health (update to include dynamic scans) ──────────────────────────────────

@app.get("/health")
def health():
    with _db() as conn:
        scan_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        dyn_count  = conn.execute("SELECT COUNT(*) FROM dynamic_scans").fetchone()[0]
    lang_count = len(_list_language_defs())
    return {
        "status": "ok",
        "scan_count": scan_count,
        "dynamic_scan_count": dyn_count,
        "language_count": lang_count,
        "scanners": tool_status(),
    }


# ── EASM ──────────────────────────────────────────────────────────────────────
# Helper: load Vulnerability objects from DB rows

def _row_to_vuln(row: sqlite3.Row):
    """Convert a DB row from easm_vulnerabilities to a Vulnerability object."""
    from .easm.schema import Vulnerability as _V
    d = dict(row)
    return _V(
        id=d["id"], asset=d.get("identifier", ""), asset_type=d.get("asset_type", "ip"),
        source_tool=d["source_tool"],  # type: ignore[arg-type]
        source_file=d.get("source_file"),
        name=d["name"], description=d.get("description") or "",
        severity=d["severity"],  # type: ignore[arg-type]
        category=d["category"],
        cvss_score=d.get("cvss_score"), cve=d.get("cve"), cwe=d.get("cwe"),
        port=d.get("port"), protocol=d.get("protocol"),
        url=d.get("url"), evidence=d.get("evidence"), remediation=d.get("remediation"),
        discovered_at=d.get("discovered_at") or "",
        last_seen_at=d.get("last_seen_at") or "",
        resolved_at=d.get("resolved_at"),
        status=d.get("status", "open"),  # type: ignore[arg-type]
    )


# ── Request models ─────────────────────────────────────────────────────────────

class AssetCreateRequest(BaseModel):
    identifier: str     # IP, hostname, CIDR, or URL
    asset_type: str     # ip | domain | url | cidr
    label: str | None = None
    tags: list[str] = []

    @field_validator("asset_type")
    @classmethod
    def valid_asset_type(cls, v: str) -> str:
        if v not in ("ip", "domain", "url", "cidr"):
            raise ValueError("asset_type must be ip, domain, url, or cidr")
        return v


class VulnStatusUpdate(BaseModel):
    status: str   # open | resolved | accepted_risk | false_positive

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        allowed = ("open", "resolved", "accepted_risk", "false_positive")
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}")
        return v


# ── Asset endpoints ───────────────────────────────────────────────────────────

@app.post("/easm/assets", status_code=201)
def easm_create_asset(req: AssetCreateRequest):
    """Register a new attack-surface asset.  Returns the asset record."""
    asset_id = str(uuid.uuid4())
    tags_json = json.dumps(req.tags)
    try:
        with _db() as conn:
            conn.execute(
                """INSERT INTO easm_assets (id, identifier, asset_type, label, tags)
                   VALUES (?, ?, ?, ?, ?)""",
                (asset_id, req.identifier, req.asset_type, req.label, tags_json),
            )
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            raise HTTPException(status_code=409, detail=f"Asset '{req.identifier}' already exists.")
        raise
    return {
        "id": asset_id, "identifier": req.identifier,
        "asset_type": req.asset_type, "label": req.label, "tags": req.tags,
    }


@app.get("/easm/assets")
def easm_list_assets(label: Annotated[str | None, Query()] = None):
    """List all tracked assets, optionally filtered by label."""
    query = "SELECT * FROM easm_assets WHERE 1=1"
    params: list[Any] = []
    if label:
        query += " AND label=?"
        params.append(label)
    query += " ORDER BY created_at DESC"
    with _db() as conn:
        rows = conn.execute(query, params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["tags"] = json.loads(d.get("tags") or "[]")
        result.append(d)
    return result


@app.get("/easm/assets/{asset_id}")
def easm_get_asset(asset_id: str):
    """Return asset detail with its latest risk score."""
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM easm_assets WHERE id=?", (asset_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        score_row = conn.execute(
            "SELECT score, grade, breakdown_json, scored_at "
            "FROM easm_scores WHERE asset_id=? ORDER BY scored_at DESC LIMIT 1",
            (asset_id,),
        ).fetchone()
        vuln_counts = conn.execute(
            """SELECT severity, COUNT(*) as cnt FROM easm_vulnerabilities
               WHERE asset_id=? AND status='open' GROUP BY severity""",
            (asset_id,),
        ).fetchall()

    d = dict(row)
    d["tags"] = json.loads(d.get("tags") or "[]")
    d["latest_score"] = dict(score_row) if score_row else None
    if d["latest_score"]:
        d["latest_score"]["breakdown"] = json.loads(
            d["latest_score"].pop("breakdown_json", "{}")
        )
    d["open_by_severity"] = {r["severity"]: r["cnt"] for r in vuln_counts}
    return d


# ── Ingest endpoint ───────────────────────────────────────────────────────────

@app.post("/easm/ingest", status_code=201)
async def easm_ingest(
    file:       UploadFile = File(...),
    asset:      str        = Form(...),
    asset_type: str        = Form("ip"),
    label:      str        = Form(None),
    tool_hint:  str        = Form(None),
):
    """Upload a scanner output file and import its findings.

    Form fields
    -----------
    file:        The scanner output (Nmap XML, OpenVAS XML, ZAP JSON, Nuclei JSONL).
    asset:       The primary identifier of the target (IP, hostname, URL).
    asset_type:  One of ip | domain | url | cidr  (default: ip).
    label:       Optional vendor/org label for grouping assets.
    tool_hint:   Force a specific parser (nmap | openvas | zap | nuclei).
                 Auto-detected when omitted.
    """
    raw = await file.read()
    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not decode file: {exc}") from exc

    try:
        vulns = _easm_parse_file(content=content, hint=tool_hint or None)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not vulns:
        return {"imported": 0, "asset_id": None, "message": "No findings found in file."}

    # Upsert the asset
    with _db() as conn:
        existing = conn.execute(
            "SELECT id FROM easm_assets WHERE identifier=?", (asset,)
        ).fetchone()

        if existing:
            asset_id = existing["id"]
            conn.execute(
                "UPDATE easm_assets SET updated_at=datetime('now'), "
                "label=COALESCE(?, label) WHERE id=?",
                (label, asset_id),
            )
        else:
            asset_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO easm_assets (id, identifier, asset_type, label, tags) "
                "VALUES (?, ?, ?, ?, '[]')",
                (asset_id, asset, asset_type, label),
            )

        # Upsert vulnerabilities: update last_seen_at if fingerprint matches,
        # else insert.  Fingerprint = (asset_id, source_tool, name, port, cve).
        imported = 0
        for v in vulns:
            fingerprint_row = conn.execute(
                """SELECT id FROM easm_vulnerabilities
                   WHERE asset_id=? AND source_tool=? AND name=?
                     AND COALESCE(port, -1)=COALESCE(?, -1)
                     AND COALESCE(cve, '')=COALESCE(?, '')""",
                (asset_id, v.source_tool, v.name, v.port, v.cve or ""),
            ).fetchone()

            if fingerprint_row:
                conn.execute(
                    "UPDATE easm_vulnerabilities SET last_seen_at=? WHERE id=?",
                    (v.last_seen_at, fingerprint_row["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO easm_vulnerabilities
                       (id, asset_id, source_tool, source_file, name, description,
                        severity, cvss_score, cve, cwe, category, port, protocol,
                        url, evidence, remediation, discovered_at, last_seen_at,
                        resolved_at, status)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()), asset_id,
                        v.source_tool, v.source_file, v.name, v.description,
                        v.severity, v.cvss_score, v.cve, v.cwe, v.category,
                        v.port, v.protocol, v.url, v.evidence, v.remediation,
                        v.discovered_at, v.last_seen_at, v.resolved_at, v.status,
                    ),
                )
                imported += 1

    return {
        "imported":    imported,
        "total_parsed": len(vulns),
        "asset_id":    asset_id,
        "asset":       asset,
    }


# ── Vulnerability list + status update ───────────────────────────────────────

@app.get("/easm/vulnerabilities")
def easm_list_vulnerabilities(
    asset_id: Annotated[str | None, Query()] = None,
    label:    Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    status:   Annotated[str | None, Query()] = None,
    cve:      Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
    tool:     Annotated[str | None, Query()] = None,
    limit:    Annotated[int, Query(ge=1, le=1000)] = 200,
):
    """List EASM vulnerabilities with optional filters."""
    query = """
        SELECT v.*, a.identifier, a.asset_type, a.label
        FROM easm_vulnerabilities v
        JOIN easm_assets a ON a.id = v.asset_id
        WHERE 1=1
    """
    params: list[Any] = []
    if asset_id:
        query += " AND v.asset_id=?";   params.append(asset_id)
    if label:
        query += " AND a.label=?";      params.append(label)
    if severity:
        query += " AND v.severity=?";   params.append(severity)
    if status:
        query += " AND v.status=?";     params.append(status)
    if cve:
        query += " AND v.cve=?";        params.append(cve.upper())
    if category:
        query += " AND v.category=?";   params.append(category)
    if tool:
        query += " AND v.source_tool=?"; params.append(tool)
    query += (
        " ORDER BY CASE v.severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END, v.discovered_at DESC"
        f" LIMIT {limit}"
    )
    with _db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.patch("/easm/vulnerabilities/{vuln_id}")
def easm_update_vuln_status(vuln_id: str, req: VulnStatusUpdate):
    """Update the status of a specific vulnerability (resolve, accept_risk, etc.)."""
    resolved_at_sql = (
        "datetime('now')" if req.status == "resolved" else "NULL"
    )
    with _db() as conn:
        row = conn.execute(
            "SELECT id FROM easm_vulnerabilities WHERE id=?", (vuln_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        conn.execute(
            f"UPDATE easm_vulnerabilities SET status=?, resolved_at={resolved_at_sql} WHERE id=?",
            (req.status, vuln_id),
        )
    return {"id": vuln_id, "status": req.status}


# ── Scoring endpoints ─────────────────────────────────────────────────────────

def _compute_and_store_score(
    asset_id: str | None,
    vendor_label: str | None,
    conn: sqlite3.Connection,
) -> dict:
    """Fetch open vulns, compute score, persist snapshot, return dict."""
    if asset_id:
        rows = conn.execute(
            """SELECT v.*, a.identifier, a.asset_type
               FROM easm_vulnerabilities v
               JOIN easm_assets a ON a.id = v.asset_id
               WHERE v.asset_id=?""",
            (asset_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT v.*, a.identifier, a.asset_type
               FROM easm_vulnerabilities v
               JOIN easm_assets a ON a.id = v.asset_id
               WHERE a.label=?""",
            (vendor_label,),
        ).fetchall()

    vulns = [_row_to_vuln(r) for r in rows]
    rs = _easm_score(vulns, asset_id=asset_id, vendor_label=vendor_label)

    breakdown = {
        "by_severity":           rs.by_severity,
        "deduction_by_severity": rs.deduction_by_severity,
        "total_deduction":       rs.total_deduction,
        "top_issues":            rs.top_issues,
        "oldest_open_days":      rs.oldest_open_days,
        "open_count":            rs.open_count,
    }
    score_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO easm_scores
           (id, asset_id, vendor_label, score, grade, breakdown_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (score_id, asset_id, vendor_label,
         rs.score, rs.grade, json.dumps(breakdown)),
    )
    return {
        "id":        score_id,
        "score":     rs.score,
        "grade":     rs.grade,
        "scored_at": rs.scored_at,
        **breakdown,
    }


@app.post("/easm/score/{asset_id}", status_code=201)
def easm_compute_score(asset_id: str):
    """Compute a fresh risk score for an asset and persist the snapshot."""
    with _db() as conn:
        row = conn.execute(
            "SELECT id FROM easm_assets WHERE id=?", (asset_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return _compute_and_store_score(asset_id, None, conn)


@app.get("/easm/score/{asset_id}")
def easm_get_score(asset_id: str):
    """Return the most recent risk score for an asset.  404 if never scored."""
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM easm_scores WHERE asset_id=? ORDER BY scored_at DESC LIMIT 1",
            (asset_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No score found. POST /easm/score/{id} to compute one.")
    d = dict(row)
    d["breakdown"] = json.loads(d.pop("breakdown_json", "{}"))
    return d


@app.post("/easm/score/vendor/{label}", status_code=201)
def easm_compute_vendor_score(label: str):
    """Compute an aggregate risk score for all assets sharing a vendor label."""
    with _db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM easm_assets WHERE label=?", (label,)
        ).fetchone()[0]
        if count == 0:
            raise HTTPException(status_code=404, detail=f"No assets found with label '{label}'.")
        return _compute_and_store_score(None, label, conn)


@app.get("/easm/score/vendor/{label}")
def easm_get_vendor_score(label: str):
    """Latest aggregated score for a vendor/org label."""
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM easm_scores WHERE vendor_label=? ORDER BY scored_at DESC LIMIT 1",
            (label,),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No score for label '{label}'. POST /easm/score/vendor/{label} to compute."
        )
    d = dict(row)
    d["breakdown"] = json.loads(d.pop("breakdown_json", "{}"))
    return d


@app.get("/easm/scores/history/{asset_id}")
def easm_score_history(
    asset_id: str,
    limit: Annotated[int, Query(ge=1, le=500)] = 90,
):
    """Return the score time-series for an asset (most recent first)."""
    with _db() as conn:
        asset = conn.execute(
            "SELECT id FROM easm_assets WHERE id=?", (asset_id,)
        ).fetchone()
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        rows = conn.execute(
            "SELECT id, score, grade, scored_at FROM easm_scores "
            "WHERE asset_id=? ORDER BY scored_at DESC LIMIT ?",
            (asset_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/easm/dashboard")
def easm_dashboard():
    """Top-level EASM summary: asset counts, severity breakdown, grade distribution."""
    with _db() as conn:
        asset_count = conn.execute("SELECT COUNT(*) FROM easm_assets").fetchone()[0]
        vuln_count  = conn.execute("SELECT COUNT(*) FROM easm_vulnerabilities").fetchone()[0]
        open_count  = conn.execute(
            "SELECT COUNT(*) FROM easm_vulnerabilities WHERE status='open'"
        ).fetchone()[0]

        by_severity = {
            r["severity"]: r["cnt"]
            for r in conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM easm_vulnerabilities
                   WHERE status='open' GROUP BY severity"""
            ).fetchall()
        }

        latest_grades = conn.execute(
            """SELECT s.asset_id, s.grade, s.score, s.scored_at
               FROM easm_scores s
               INNER JOIN (
                 SELECT asset_id, MAX(scored_at) AS max_ts
                 FROM easm_scores WHERE asset_id IS NOT NULL
                 GROUP BY asset_id
               ) latest ON s.asset_id=latest.asset_id AND s.scored_at=latest.max_ts"""
        ).fetchall()

        grade_dist: dict[str, int] = {}
        avg_score: float | None = None
        if latest_grades:
            scores = [r["score"] for r in latest_grades]
            avg_score = round(sum(scores) / len(scores), 1)
            for r in latest_grades:
                grade_dist[r["grade"]] = grade_dist.get(r["grade"], 0) + 1

        top_critical = conn.execute(
            """SELECT v.name, v.cve, v.severity, v.category, a.identifier as asset
               FROM easm_vulnerabilities v
               JOIN easm_assets a ON a.id=v.asset_id
               WHERE v.status='open' AND v.severity='critical'
               ORDER BY v.discovered_at ASC
               LIMIT 10"""
        ).fetchall()

    return {
        "asset_count":   asset_count,
        "vuln_count":    vuln_count,
        "open_count":    open_count,
        "by_severity":   by_severity,
        "average_score": avg_score,
        "grade_distribution": grade_dist,
        "top_critical_open": [dict(r) for r in top_critical],
    }


# ── Serve pre-built React UI (must be registered AFTER all API routes) ─────────

if _UI_DIR and _UI_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_UI_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        """Return index.html for all non-API routes so React Router works."""
        index = _UI_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
        raise HTTPException(status_code=404, detail="UI not found")


# ── Entry point ────────────────────────────────────────────────────────────────

def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    import uvicorn
    uvicorn.run("vulnscan.api:app", host=host, port=port, reload=False)
