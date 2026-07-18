"""
vulnscan.recon — Phase-1 recon for the standalone scanner.

Locates candidate sources (attacker-reachable entry points) and sinks
(dangerous operations) across supported languages, then pairs nearby source/sink
combinations as prioritized starting points for the LLM Hunt phase.

It does NOT decide exploitability — that is the model's job in phases 2-4.

Languages: Python (stdlib AST) and C#/.NET (tree-sitter). C# support degrades
gracefully to a warning if tree-sitter isn't installed.

CLI:
    vulnscan-recon /path/to/authorized/repo               # human-readable
    vulnscan-recon /path/to/repo --json out.json          # machine-readable seed
    vulnscan-recon /path/to/repo --json -                 # JSON to stdout
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .languages import (SUPPORTED_EXTENSIONS, scan_path, warn_if_degraded)
from .languages.base import SOURCE_RANK, Hit

_SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__",
              "bin", "obj", "packages"}


def scan_repo(root: Path) -> list[Hit]:
    hits: list[Hit] = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in SUPPORTED_EXTENSIONS or not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        hits.extend(scan_path(path))
    return hits


def pair_candidates(hits: list[Hit]) -> list[dict]:
    """Same-file source->sink pairs as starting hints for the Hunt phase.

    A cheap proximity heuristic only; real reachability is interprocedural and
    cross-file, which the LLM phase resolves. Same-file pairs are just the
    fastest place to start looking.
    """
    sinks_by_file: dict[str, list[Hit]] = {}
    for h in hits:
        if h.kind == "sink":
            sinks_by_file.setdefault(h.file, []).append(h)

    pairs: list[dict] = []
    for src in (h for h in hits if h.kind == "source"):
        for snk in sinks_by_file.get(src.file, []):
            pairs.append({
                "source": {"category": src.category, "file": src.file,
                           "line": src.line, "name": src.name,
                           "language": src.language},
                "sink": {"category": snk.category, "file": snk.file,
                         "line": snk.line, "name": snk.name},
                "proximity": "same_file",
                "priority": SOURCE_RANK.get(src.category, 9),
            })
    pairs.sort(key=lambda p: p["priority"])
    return pairs


def build_report(root: Path) -> dict:
    hits = scan_repo(root)
    sources = [asdict(h) for h in hits if h.kind == "source"]
    sinks = [asdict(h) for h in hits if h.kind == "sink"]
    by_lang: dict[str, int] = {}
    for h in hits:
        by_lang[h.language] = by_lang.get(h.language, 0) + 1
    return {
        "root": str(root),
        "counts": {"sources": len(sources), "sinks": len(sinks),
                   "by_language": by_lang},
        "sources": sources,
        "sinks": sinks,
        "candidate_pairs": pair_candidates(hits),
        "note": ("Candidates only. Reachability and exploitability are decided "
                 "by the LLM phases, not this script."),
    }


def _print_human(report: dict) -> None:
    print(f"# Recon seed for {report['root']}")
    c = report["counts"]
    langs = ", ".join(f"{k}:{v}" for k, v in sorted(c["by_language"].items()) if k)
    print(f"# {c['sources']} candidate sources, {c['sinks']} candidate sinks, "
          f"{len(report['candidate_pairs'])} same-file pairs" +
          (f"  ({langs})" if langs else ""))
    print("#\n# SOURCES (attacker-reachable entry points):")
    for s in report["sources"]:
        print(f"  [{s['language']}/{s['category']}] {s['file']}:{s['line']}  {s['name']}")
    print("#\n# SINKS (dangerous operations):")
    for s in report["sinks"]:
        print(f"  [{s['language']}/{s['category']}] {s['file']}:{s['line']}  {s['name']}")
    if report["candidate_pairs"]:
        print("#\n# PRIORITISED SAME-FILE PAIRS (start Hunt here):")
        for p in report["candidate_pairs"]:
            src, snk = p["source"], p["sink"]
            print(f"  {src['file']}:{src['line']} [{src['category']}] "
                  f"-> :{snk['line']} [{snk['category']}]")
    print(f"#\n# NOTE: {report['note']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vulnscan-recon",
        description="Phase-1 recon: locate candidate sources and sinks in a "
                    "codebase you are authorized to scan (Python, C#/.NET).")
    ap.add_argument("repo", type=Path, help="path to the authorized codebase")
    ap.add_argument("--json", metavar="OUT",
                    help="write JSON report to OUT (use '-' for stdout)")
    args = ap.parse_args(argv)

    if not args.repo.exists():
        print(f"no such path: {args.repo}", file=sys.stderr)
        return 2

    warn_if_degraded()
    report = build_report(args.repo)

    if args.json:
        payload = json.dumps(report, indent=2)
        if args.json == "-":
            print(payload)
        else:
            Path(args.json).write_text(payload, encoding="utf-8")
            print(f"wrote {args.json} "
                  f"({report['counts']['sources']} sources, "
                  f"{report['counts']['sinks']} sinks)", file=sys.stderr)
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
