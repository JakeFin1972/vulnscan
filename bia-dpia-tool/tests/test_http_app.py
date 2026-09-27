"""Integration tests against a real running instance of the server."""


def test_health(live_server):
    status, body, _ = live_server.get("/api/health")
    assert status == 200
    assert body == {"ok": True}


def test_config_is_public(live_server):
    status, body, _ = live_server.get("/api/config")
    assert status == 200
    assert "tools" in body


def test_create_assessment_defaults_to_both_scope(live_server):
    status, body, _ = live_server.post("/api/assessments", {"project_name": "Test App"})
    assert status == 201
    assert body["assessment"]["scope"] == "both"
    assert body["assessment"]["bia_status"] == "draft"
    assert body["assessment"]["dpia_status"] == "draft"


def test_create_assessment_rejects_invalid_scope(live_server):
    status, body, _ = live_server.post("/api/assessments", {"project_name": "X", "scope": "nonsense"})
    assert status == 400


def test_bia_only_scope_marks_dpia_not_applicable(live_server):
    status, body, _ = live_server.post("/api/assessments", {"project_name": "X", "scope": "bia"})
    assert body["assessment"]["dpia_status"] == "not_applicable"


def test_submitting_out_of_scope_part_is_rejected(live_server):
    _, body, _ = live_server.post("/api/assessments", {"project_name": "X", "scope": "bia"})
    aid = body["assessment"]["id"]
    status, _, _ = live_server.post(f"/api/assessments/{aid}/submit/dpia")
    assert status == 400


def test_submit_and_reopen_part_round_trip(live_server):
    _, body, _ = live_server.post("/api/assessments", {"project_name": "X", "scope": "both"})
    aid = body["assessment"]["id"]
    status, body, _ = live_server.post(f"/api/assessments/{aid}/submit/bia")
    assert status == 200
    assert body["assessment"]["bia_status"] == "submitted"
    assert body["assessment"]["status"] == "draft"  # dpia part still open
    status, body, _ = live_server.post(f"/api/assessments/{aid}/reopen/bia")
    assert body["assessment"]["bia_status"] == "draft"


def test_answers_round_trip_and_affect_results(live_server):
    _, body, _ = live_server.post("/api/assessments", {"project_name": "X"})
    aid = body["assessment"]["id"]
    status, body, _ = live_server.put(
        f"/api/assessments/{aid}/answers",
        {"tool": "bia", "answers": {"bia.confidentiality.q9": {"value": 5}}},
    )
    assert status == 200
    assert body["results"]["bia_categories"]["confidentiality"]["max_label"] == "Critical"


def test_delete_assessment(live_server):
    _, body, _ = live_server.post("/api/assessments", {"project_name": "X"})
    aid = body["assessment"]["id"]
    status, _, _ = live_server.delete(f"/api/assessments/{aid}")
    assert status == 200
    status, _, _ = live_server.get(f"/api/assessments/{aid}")
    assert status == 404


def test_export_formats_have_correct_content_type(live_server):
    _, body, _ = live_server.post("/api/assessments", {"project_name": "X"})
    aid = body["assessment"]["id"]
    status, _, headers = live_server.get(f"/api/assessments/{aid}/export.csv")
    assert status == 200 and headers["Content-Type"].startswith("text/csv")
    status, _, headers = live_server.get(f"/api/assessments/{aid}/export.pdf")
    assert status == 200 and headers["Content-Type"] == "application/pdf"
    status, _, headers = live_server.get(f"/api/assessments/{aid}/export.docx")
    assert status == 200 and "wordprocessingml" in headers["Content-Type"]


def test_admin_endpoints_require_auth(live_server):
    status, _, _ = live_server.get("/api/admin/config")
    assert status == 401
    status, _, _ = live_server.get("/api/admin/users")
    assert status == 401


def test_admin_login_wrong_password_rejected(live_server):
    status, _, _ = live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "wrong"})
    assert status == 401


def test_admin_login_and_authenticated_requests(live_server):
    status, body, _ = live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "ChangeMe!123"})
    assert status == 200
    assert body["email"] == "admin@localhost"
    status, body, _ = live_server.get("/api/admin/session")
    assert body["authenticated"] is True
    status, _, _ = live_server.get("/api/admin/config")
    assert status == 200


def test_admin_login_rate_limited_after_repeated_failures(live_server):
    for _ in range(8):
        live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "wrong"})
    status, body, _ = live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "ChangeMe!123"})
    assert status == 429


def test_admin_can_create_and_deactivate_another_admin(live_server):
    live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "ChangeMe!123"})
    status, body, _ = live_server.post("/api/admin/users", {"name": "Bob", "email": "bob@company.com", "password": "BobPass123!"})
    assert status == 201
    bob_id = body["id"]
    status, body, _ = live_server.post(f"/api/admin/users/{bob_id}/deactivate")
    assert status == 200
    assert any(u["email"] == "bob@company.com" and not u["active"] for u in body["users"])


def test_cannot_deactivate_last_remaining_admin(live_server):
    live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "ChangeMe!123"})
    status, body, _ = live_server.get("/api/admin/users")
    self_id = body["users"][0]["id"]
    status, _, _ = live_server.post(f"/api/admin/users/{self_id}/deactivate")
    assert status == 400


def test_audit_log_records_login(live_server):
    live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "ChangeMe!123"})
    status, body, _ = live_server.get("/api/admin/audit-log")
    assert status == 200
    actions = [e["action"] for e in body["entries"]]
    assert "admin.login" in actions


def test_config_validation_rejects_malformed_config(live_server):
    live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "ChangeMe!123"})
    status, _, _ = live_server.put("/api/admin/config", {"org_name": "x"})  # missing required keys
    assert status == 400


def test_backup_download_is_a_valid_sqlite_file(live_server):
    live_server.post("/api/admin/login", {"email": "admin@localhost", "password": "ChangeMe!123"})
    status, body, headers = live_server.get("/api/admin/backup")
    assert status == 200
    assert headers["Content-Type"] == "application/x-sqlite3"
    assert body[:16] == b"SQLite format 3\x00"
