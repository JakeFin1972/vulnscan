"""
vulnscan.harness — deterministic single-test runner for the fix/verify loop.

Runs one security test and reports structured pass/fail, so the RED (must fail
first) and GREEN (must pass after) gates aren't a judgement call for the model.

Frameworks:
  - pytest  (Python)  : runs `python -m pytest <target> -q`
  - dotnet  (.NET/C#) : runs `dotnet test --filter <target>`

The framework is taken from --framework, or inferred from the repo: a *.sln or
*.csproj present => dotnet, otherwise pytest. The runner invokes the project's
own toolchain, which must be installed on the machine (pytest / dotnet SDK).

CLI:
  vulnscan-runtest --repo . --python "tests/test_sec.py::test_no_sqli"
  vulnscan-runtest --repo . --dotnet "FullyQualifiedName~Security_NoSqli"
  vulnscan-runtest --repo . --framework pytest --target "tests/test_sec.py::test_x"
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_TAIL_LINES = 40


def detect_framework(repo: Path) -> str:
    for pattern in ("*.sln", "*.csproj"):
        if next(repo.rglob(pattern), None) is not None:
            return "dotnet"
    return "pytest"


def _command(framework: str, target: str) -> list[str]:
    if framework == "pytest":
        return [sys.executable, "-m", "pytest", target, "-q"]
    if framework == "dotnet":
        return ["dotnet", "test", "--filter", target]
    raise ValueError(f"unknown framework: {framework}")


def run_test(repo: Path, target: str, framework: str | None = None,
             timeout: int = 900) -> dict:
    fw = framework or detect_framework(repo)
    cmd = _command(fw, target)
    try:
        proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True,
                              timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        returncode = proc.returncode
        error = None
    except FileNotFoundError as exc:
        # toolchain not installed on this machine
        return {"framework": fw, "command": " ".join(cmd), "passed": False,
                "returncode": None, "error": f"toolchain not found: {exc}",
                "output_tail": ""}
    except subprocess.TimeoutExpired:
        return {"framework": fw, "command": " ".join(cmd), "passed": False,
                "returncode": None, "error": f"timed out after {timeout}s",
                "output_tail": ""}

    tail = "\n".join(out.splitlines()[-_TAIL_LINES:])
    return {
        "framework": fw,
        "command": " ".join(cmd),
        "passed": returncode == 0,
        "returncode": returncode,
        "error": error,
        "output_tail": tail,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vulnscan-runtest",
        description="Run one security test and report structured pass/fail.")
    ap.add_argument("--repo", type=Path, default=Path("."),
                    help="repo root to run in (default: cwd)")
    ap.add_argument("--framework", choices=["pytest", "dotnet"],
                    help="override framework detection")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--python", metavar="NODEID", help="pytest node id to run")
    g.add_argument("--dotnet", metavar="FILTER", help="dotnet test --filter value")
    ap.add_argument("--target", help="explicit target (with --framework)")
    ap.add_argument("--json", action="store_true", help="emit JSON result")
    args = ap.parse_args(argv)

    if args.python:
        framework, target = "pytest", args.python
    elif args.dotnet:
        framework, target = "dotnet", args.dotnet
    elif args.target:
        framework, target = args.framework or detect_framework(args.repo), args.target
    else:
        ap.error("provide one of --python, --dotnet, or --target")

    if not args.repo.exists():
        print(f"no such repo: {args.repo}", file=sys.stderr)
        return 2

    result = run_test(args.repo, target, framework)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        verdict = "PASS" if result["passed"] else "FAIL"
        print(f"[{verdict}] {result['framework']}: {result['command']}")
        if result.get("error"):
            print(f"  error: {result['error']}")
        if result["output_tail"]:
            print(result["output_tail"])
    # exit 0 if the test passed, 1 if it failed, 2 on harness/toolchain error
    if result.get("error"):
        return 2
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
