"""Tool-format auto-detection and unified dispatch for EASM parsers.

Usage::

    from vulnscan.easm.parsers import parse_file

    vulns = parse_file("/path/to/nmap-output.xml")
    vulns = parse_file("/path/to/zap-report.json")
    vulns = parse_file("/path/to/nuclei-output.jsonl")
    # Explicit hint overrides auto-detection:
    vulns = parse_file(content="<xml…>", hint="openvas")
"""
from __future__ import annotations

import json
from pathlib import Path

from ..schema import Vulnerability
from . import nmap as _nmap
from . import openvas as _openvas
from . import zap as _zap
from . import nuclei as _nuclei

# ── Format detection ──────────────────────────────────────────────────────────

def _detect_tool(content: str, filename: str) -> str:
    """Return a tool hint string based on content sniffing + filename."""
    fname = filename.lower()

    # Filename-based hints (fast path)
    if "nmap" in fname and fname.endswith(".xml"):
        return "nmap"
    if "openvas" in fname or "gvm" in fname:
        return "openvas"
    if "zap" in fname and fname.endswith(".json"):
        return "zap"
    if fname.endswith(".jsonl") or "nuclei" in fname:
        return "nuclei"

    stripped = content.lstrip()

    # XML branch
    if stripped.startswith("<"):
        if "<nmaprun" in stripped[:2000]:
            return "nmap"
        if "<get_results_response" in stripped[:2000]:
            return "openvas"
        if "<report" in stripped[:2000] and "<results" in stripped[:4000]:
            return "openvas"
        # Unknown XML — try nmap as default
        return "nmap"

    # JSON / JSONL branch
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            doc = json.loads(stripped)
            if isinstance(doc, dict):
                if "site" in doc:
                    return "zap"
                if "alerts" in doc:
                    return "zap"
                # Single Nuclei JSON object
                if "template-id" in doc or "matcher-status" in doc:
                    return "nuclei"
            elif isinstance(doc, list) and doc:
                first = doc[0] if isinstance(doc[0], dict) else {}
                if "risk" in first or "cweid" in first:
                    return "zap"
        except json.JSONDecodeError:
            pass

        # JSONL: multiple lines of JSON
        lines = [l for l in stripped.splitlines() if l.strip()]
        if len(lines) > 1:
            try:
                obj = json.loads(lines[0])
                if isinstance(obj, dict) and (
                    "template-id" in obj or "matcher-status" in obj
                ):
                    return "nuclei"
                if isinstance(obj, dict) and ("risk" in obj or "cweid" in obj):
                    return "zap"
            except json.JSONDecodeError:
                pass
        return "nuclei"  # default for unrecognised JSON

    return "nmap"  # safe default


_PARSERS = {
    "nmap":    _nmap.parse,
    "openvas": _openvas.parse,
    "zap":     _zap.parse,
    "nuclei":  _nuclei.parse,
}


def parse_file(
    path: str | Path | None = None,
    *,
    content: str | None = None,
    hint: str | None = None,
) -> list[Vulnerability]:
    """Parse a scanner output file and return normalised Vulnerability objects.

    Parameters
    ----------
    path:
        File-system path to the scanner output.  Either *path* or *content*
        must be provided.
    content:
        Raw file content as a string.  Useful for testing or when the file
        has already been read into memory.
    hint:
        Force a specific parser: ``"nmap"``, ``"openvas"``, ``"zap"``, or
        ``"nuclei"``.  When omitted the format is auto-detected.

    Returns
    -------
    list[Vulnerability]
        May be empty if the file contains no parseable findings.
    """
    if path is not None:
        p = Path(path)
        content = p.read_text(encoding="utf-8", errors="replace")
        filename = p.name
    elif content is not None:
        filename = ""
    else:
        raise ValueError("Either 'path' or 'content' must be provided.")

    tool = hint or _detect_tool(content, filename)
    parser = _PARSERS.get(tool)
    if parser is None:
        raise ValueError(
            f"Unknown tool hint {tool!r}. "
            f"Choose from: {list(_PARSERS)}"
        )

    source_file = str(path) if path else None
    return parser(content, source_file=source_file)
