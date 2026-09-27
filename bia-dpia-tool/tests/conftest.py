"""Shared pytest fixtures. Pure stdlib -- pytest is the only test-time
dependency (never required to run the tool itself)."""

import json
import sys
import threading
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db  # noqa: E402


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """An isolated, freshly-initialized database per test."""
    db_path = str(tmp_path / "test.sqlite3")
    monkeypatch.setattr(db, "DB_PATH", db_path)
    if getattr(db._local, "conn", None):
        db._local.conn.close()
    db._local.conn = None
    db.init_db()
    yield db
    if getattr(db._local, "conn", None):
        db._local.conn.close()
        db._local.conn = None


class Client:
    """Tiny stdlib HTTP client with cookie-jar support, for hitting a live
    instance of the server in integration tests."""

    def __init__(self, base_url):
        self.base_url = base_url
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            resp = self.opener.open(req, timeout=5)
            status, raw, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            status, raw, headers = e.code, e.read(), e.headers
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = raw
        return status, payload, headers

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body)

    def put(self, path, body=None):
        return self.request("PUT", path, body)

    def delete(self, path):
        return self.request("DELETE", path)


@pytest.fixture
def live_server(test_db, monkeypatch):
    """A real instance of the app served on a free localhost port."""
    from app import http_app

    httpd = http_app.Server(("127.0.0.1", 0), http_app.Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(f"http://127.0.0.1:{port}")
    finally:
        httpd.shutdown()
        httpd.server_close()
