"""Tests for vulnscan.harness — framework detection and the RED->GREEN gate.

The pytest path is exercised for real. The dotnet path is not run here (no .NET
SDK in this environment); only its detection and command construction are tested.
"""
from pathlib import Path

from vulnscan.harness import detect_framework, _command, run_test


def test_detects_dotnet_from_csproj(tmp_path):
    (tmp_path / "App.csproj").write_text("<Project/>", encoding="utf-8")
    assert detect_framework(tmp_path) == "dotnet"


def test_detects_dotnet_from_sln(tmp_path):
    (tmp_path / "Sln.sln").write_text("", encoding="utf-8")
    assert detect_framework(tmp_path) == "dotnet"


def test_defaults_to_pytest(tmp_path):
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
    assert detect_framework(tmp_path) == "pytest"


def test_dotnet_command_shape():
    cmd = _command("dotnet", "FullyQualifiedName~Security_X")
    assert cmd[:2] == ["dotnet", "test"]
    assert "--filter" in cmd and "FullyQualifiedName~Security_X" in cmd


def test_red_then_green_cycle(tmp_path):
    """A real pytest run: the security test fails against vulnerable code (RED),
    then passes once the code is fixed (GREEN)."""
    test_file = tmp_path / "test_sec.py"
    test_file.write_text(
        "from target import lookup\n"
        "def test_no_injection():\n"
        "    # id '1 OR 1=1' must not be treated as a query fragment\n"
        "    assert lookup(\"1 OR 1=1\") == 'no-match'\n",
        encoding="utf-8")

    # Vulnerable version: naive substring check that the payload defeats.
    (tmp_path / "target.py").write_text(
        "ROWS = {'1': 'row1'}\n"
        "def lookup(id):\n"
        "    for k in ROWS:\n"
        "        if k in id:\n"          # '1' is a substring of '1 OR 1=1' -> match
        "            return ROWS[k]\n"
        "    return 'no-match'\n",
        encoding="utf-8")
    red = run_test(tmp_path, "test_sec.py::test_no_injection", "pytest")
    assert red["passed"] is False        # RED: fails because the bug exists

    # Fixed version: exact-match lookup closes the path.
    (tmp_path / "target.py").write_text(
        "ROWS = {'1': 'row1'}\n"
        "def lookup(id):\n"
        "    return ROWS.get(id, 'no-match')\n",
        encoding="utf-8")
    green = run_test(tmp_path, "test_sec.py::test_no_injection", "pytest")
    assert green["passed"] is True       # GREEN: passes after the fix


def test_missing_toolchain_is_reported_not_crashed(tmp_path):
    import shutil
    (tmp_path / "x.py").write_text("", encoding="utf-8")
    res = run_test(tmp_path, "SomeFilter", framework="dotnet")
    # Either dotnet is absent (FileNotFoundError path) or present but fails
    # (e.g. CI runners have the dotnet SDK installed).
    assert res["passed"] is False
    if shutil.which("dotnet") is None:
        # Binary not found — harness returns structured error with no returncode
        assert res["returncode"] is None
        assert "toolchain not found" in (res["error"] or "")
    else:
        # dotnet found but no project → non-zero returncode, no exception raised
        assert res["returncode"] is not None
