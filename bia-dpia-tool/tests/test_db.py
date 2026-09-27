import sqlite3
import time


def test_fresh_install_creates_default_admin(test_db):
    admins = test_db.list_admin_users()
    assert len(admins) == 1
    assert admins[0]["email"] == test_db.DEFAULT_ADMIN_EMAIL.lower()
    assert admins[0]["is_default_password"] == 1


def test_authenticate_admin_accepts_correct_password_rejects_wrong(test_db):
    ok = test_db.authenticate_admin(test_db.DEFAULT_ADMIN_EMAIL, test_db.DEFAULT_ADMIN_PASSWORD)
    assert ok is not None
    bad = test_db.authenticate_admin(test_db.DEFAULT_ADMIN_EMAIL, "wrong-password")
    assert bad is None


def test_legacy_single_admin_table_migrates_password_unchanged(tmp_path, monkeypatch):
    from app import db

    db_path = str(tmp_path / "legacy.sqlite3")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK (id=1), password_hash TEXT NOT NULL, "
        "salt TEXT NOT NULL, is_default_password INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL)"
    )
    salt = "abc123"
    pw_hash = db._hash_password("MyOldPassword!", salt)
    conn.execute(
        "INSERT INTO admin (id, password_hash, salt, is_default_password, updated_at) VALUES (1, ?, ?, 0, '2020-01-01')",
        (pw_hash, salt),
    )
    conn.execute("CREATE TABLE sessions (token TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at REAL NOT NULL)")
    conn.commit()
    conn.close()

    monkeypatch.setattr(db, "DB_PATH", db_path)
    db._local.conn = None
    db.init_db()

    admin = db.authenticate_admin("admin@localhost", "MyOldPassword!")
    assert admin is not None
    assert admin["is_default_password"] == 0


def test_create_admin_user_rejects_duplicate_email(test_db):
    test_db.create_admin_user("Alice", "alice@company.com", "AlicePass123!")
    try:
        test_db.create_admin_user("Alice2", "alice@company.com", "whatever1")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_deactivating_admin_kills_their_sessions(test_db):
    alice_id = test_db.create_admin_user("Alice", "alice@company.com", "AlicePass123!")
    token = test_db.create_session(alice_id)
    assert test_db.get_session_admin(token) is not None
    test_db.set_admin_active(alice_id, False)
    assert test_db.get_session_admin(token) is None


def test_session_valid_requires_admin_still_active(test_db):
    admin = test_db.authenticate_admin(test_db.DEFAULT_ADMIN_EMAIL, test_db.DEFAULT_ADMIN_PASSWORD)
    token = test_db.create_session(admin["id"])
    assert test_db.get_session_admin(token)["email"] == test_db.DEFAULT_ADMIN_EMAIL


def test_scope_parts():
    from app import db

    assert db.scope_parts("both") == ["bia", "dpia"]
    assert db.scope_parts("bia") == ["bia"]
    assert db.scope_parts("dpia") == ["dpia"]


def test_create_assessment_sets_not_applicable_for_out_of_scope_part(test_db):
    aid = test_db.create_assessment({"project_name": "X", "scope": "bia"})
    a = test_db.get_assessment(aid)
    assert a["bia_status"] == "draft"
    assert a["dpia_status"] == "not_applicable"


def test_set_part_status_overall_submitted_only_when_all_in_scope_parts_are(test_db):
    aid = test_db.create_assessment({"project_name": "Both", "scope": "both"})
    test_db.set_part_status(aid, "bia", "submitted")
    assert test_db.get_assessment(aid)["status"] == "draft"
    test_db.set_part_status(aid, "dpia", "submitted")
    assert test_db.get_assessment(aid)["status"] == "submitted"


def test_update_scope_expanding_resets_not_applicable_to_draft(test_db):
    aid = test_db.create_assessment({"project_name": "X", "scope": "bia"})
    test_db.set_part_status(aid, "bia", "submitted")
    test_db.update_scope(aid, "both")
    a = test_db.get_assessment(aid)
    assert a["scope"] == "both"
    assert a["bia_status"] == "submitted"  # preserved
    assert a["dpia_status"] == "draft"  # was not_applicable, now in scope
    assert a["status"] == "draft"  # overall not submitted since dpia isn't


def test_update_scope_shrinking_marks_removed_part_not_applicable(test_db):
    aid = test_db.create_assessment({"project_name": "X", "scope": "both"})
    test_db.update_scope(aid, "dpia")
    a = test_db.get_assessment(aid)
    assert a["bia_status"] == "not_applicable"
    assert a["dpia_status"] == "draft"


def test_delete_assessment_removes_answers_too(test_db):
    aid = test_db.create_assessment({"project_name": "X"})
    test_db.upsert_answers(aid, "bia", {"bia.screening.q1b_sensitive_personal_data": {"value": "Yes"}})
    assert test_db.get_answers(aid)
    test_db.delete_assessment(aid)
    assert test_db.get_assessment(aid) is None
    assert test_db.get_answers(aid) == {}


def test_audit_log_and_failed_login_rate_counter(test_db):
    test_db.log_audit("unknown", "admin.login_failed", ip="1.2.3.4")
    test_db.log_audit("unknown", "admin.login_failed", ip="1.2.3.4")
    test_db.log_audit("unknown", "admin.login_failed", ip="9.9.9.9")
    assert test_db.count_recent_failed_logins("1.2.3.4", 900) == 2
    assert test_db.count_recent_failed_logins("9.9.9.9", 900) == 1
    assert test_db.count_recent_failed_logins("1.2.3.4", 0) == 0  # window in the past


def test_config_round_trip_and_reset(test_db):
    cfg = test_db.get_config()
    cfg["org_name"] = "Changed Org"
    test_db.save_config(cfg)
    assert test_db.get_config()["org_name"] == "Changed Org"
    fresh = test_db.reset_config()
    assert fresh["org_name"] != "Changed Org"


def test_create_backup_bytes_produces_a_readable_sqlite_file(test_db, tmp_path):
    test_db.create_assessment({"project_name": "Backup Me"})
    data = test_db.create_backup_bytes()
    out = tmp_path / "backup_copy.sqlite3"
    out.write_bytes(data)
    conn = sqlite3.connect(str(out))
    rows = conn.execute("SELECT project_name FROM assessments").fetchall()
    assert rows == [("Backup Me",)]
