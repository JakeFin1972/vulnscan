"""Tests for the C#/.NET backend (tree-sitter)."""
import pytest

from vulnscan.languages import csharp_backend as cs
from vulnscan.recon import build_report


def _grammar_available() -> bool:
    try:
        cs._parser()
        return True
    except Exception:
        return False


requires_grammar = pytest.mark.skipif(
    not _grammar_available(), reason="tree-sitter-c-sharp not installed")


CONTROLLER = '''
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class OrdersController : ControllerBase
{
    [HttpGet("orders")]
    public IActionResult Get([FromQuery] string id)
    {
        var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = " + id);
        cmd.ExecuteReader();
        return Ok();
    }

    [HttpPost]
    public void Run(string cmd)
    {
        Process.Start("sh", cmd);
    }

    private void Helper() { }   // private -> not an entry point
}
'''

MINIMAL_API = '''
var app = builder.Build();
app.MapGet("/x", (string q) => Repo.FromSqlRaw("SELECT * FROM T WHERE c=" + q));
app.MapPost("/y", (string b) => { new BinaryFormatter().Deserialize(Stream(b)); });
'''


@requires_grammar
def test_controller_sources_and_sinks(tmp_path):
    (tmp_path / "OrdersController.cs").write_text(CONTROLLER, encoding="utf-8")
    r = build_report(tmp_path)
    srcs = {(s["category"], s["name"]) for s in r["sources"]}
    # Get + Run are actions; Helper is private and must not be flagged.
    assert ("http_handler", "Get") in srcs
    assert ("http_handler", "Run") in srcs
    assert all(s["name"] != "Helper" for s in r["sources"])
    sink_cats = {s["category"] for s in r["sinks"]}
    assert "sql_query" in sink_cats     # new SqlCommand + ExecuteReader
    assert "os_command" in sink_cats    # Process.Start


@requires_grammar
def test_minimal_api_and_ef_raw(tmp_path):
    (tmp_path / "Program.cs").write_text(MINIMAL_API, encoding="utf-8")
    r = build_report(tmp_path)
    src_names = {s["name"] for s in r["sources"]}
    assert any("MapGet" in n for n in src_names)
    assert any("MapPost" in n for n in src_names)
    sink_cats = {s["category"] for s in r["sinks"]}
    assert "sql_query" in sink_cats     # FromSqlRaw
    assert "unsafe_deser" in sink_cats  # BinaryFormatter().Deserialize


@requires_grammar
def test_language_tag_present(tmp_path):
    (tmp_path / "OrdersController.cs").write_text(CONTROLLER, encoding="utf-8")
    r = build_report(tmp_path)
    assert r["counts"]["by_language"].get("csharp", 0) > 0
    assert all(s["language"] == "csharp" for s in r["sources"])


@requires_grammar
def test_mixed_repo_pairs_both_languages(tmp_path):
    (tmp_path / "OrdersController.cs").write_text(CONTROLLER, encoding="utf-8")
    (tmp_path / "api.py").write_text(
        '''from flask import Flask, request
app = Flask(__name__)
@app.route("/p")
def p():
    os.system(request.args.get("c"))
''', encoding="utf-8")
    r = build_report(tmp_path)
    langs = r["counts"]["by_language"]
    assert langs.get("python", 0) > 0 and langs.get("csharp", 0) > 0
