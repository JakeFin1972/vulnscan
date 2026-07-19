"""Claude AI-powered vulnerability analysis.

Provides deep security analysis for both static code findings and dynamic
scan findings. Uses claude-sonnet-4-6 for cost-effective, fast analysis.

The analyzer produces:
  - Confirmed/false-positive verdict with reasoning
  - Exploit difficulty (trivial / moderate / complex / not-exploitable)
  - Step-by-step attack scenario tailored to the specific code
  - Concrete remediation code (language-aware)
  - CVSS v3.1 vector estimate
  - Confidence-adjusted severity
"""
from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path
from typing import Any

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 2048

_SYSTEM_PROMPT = textwrap.dedent("""\
You are a senior application security engineer and penetration tester.
You analyse security findings from automated scanners and produce structured,
actionable reports. You are precise: you distinguish real vulnerabilities from
false positives, assess actual exploitability, and provide concrete fixes.

Always respond in the exact JSON format requested — no markdown, no prose outside JSON.
""")


def _client():
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError("anthropic SDK not installed. Run: pip install anthropic") from exc
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")
    return anthropic.Anthropic(api_key=api_key)


def is_available() -> bool:
    """Return True if the Anthropic SDK is installed and an API key is configured."""
    try:
        import anthropic  # noqa: F401
        return bool(os.environ.get("ANTHROPIC_API_KEY", ""))
    except ImportError:
        return False


# ── Static finding analysis ───────────────────────────────────────────────────

def analyze_static_finding(
    finding: dict[str, Any],
    code_snippet: str | None = None,
    scan_root: str | None = None,
) -> dict[str, Any]:
    """Analyse a single static (code analysis) source/sink finding.

    Returns a dict with keys:
      verdict          "confirmed" | "false_positive" | "needs_review"
      severity         "critical" | "high" | "medium" | "low" | "info"
      confidence       int  0-100
      exploit_difficulty  "trivial" | "low" | "moderate" | "high" | "not_exploitable"
      exploit_scenario    str  — step-by-step attack narrative
      data_flow           str  — concise A → B → C description
      remediation_summary str  — concise fix
      remediation_code    str  — concrete code example (or "")
      cvss_vector         str  — CVSS 3.1 vector (AV:.../...)
      reasoning           str  — why this verdict
    """
    snippet_block = ""
    if code_snippet:
        snippet_block = f"\n\nCode snippet (lines around finding):\n```\n{code_snippet}\n```"

    prompt = textwrap.dedent(f"""\
    Analyse this static security finding and respond in JSON.

    Finding:
    - Kind: {finding.get('kind', 'sink')}
    - Category: {finding.get('category', 'unknown')}
    - File: {finding.get('file', '')}
    - Line: {finding.get('line', 0)}
    - Symbol: {finding.get('name', '')}
    - Language: {finding.get('language', 'unknown')}
    - Severity (scanner estimate): {finding.get('severity', 'medium')}
    - Confidence (scanner estimate): {finding.get('confidence', 75)}%
    - Scan root: {scan_root or 'unknown'}{snippet_block}

    Respond ONLY with this JSON structure (no markdown fences):
    {{
      "verdict": "confirmed|false_positive|needs_review",
      "severity": "critical|high|medium|low|info",
      "confidence": 0-100,
      "exploit_difficulty": "trivial|low|moderate|high|not_exploitable",
      "exploit_scenario": "Numbered steps: 1. ... 2. ... 3. ...",
      "data_flow": "ComponentA → function() → sink at file:line",
      "remediation_summary": "One sentence fix",
      "remediation_code": "Concrete code fix example (empty string if none)",
      "cvss_vector": "CVSS:3.1/AV:.../...",
      "reasoning": "Why this verdict — 2-3 sentences"
    }}
    """)

    client = _client()
    response = client.messages.create(
        model=_MODEL,
        max_tokens=_MAX_TOKENS,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.content[0].text.strip()
    # Strip accidental markdown fences
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)


# ── Dynamic finding analysis ──────────────────────────────────────────────────

def analyze_dynamic_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Analyse a single dynamic (network/DAST) finding.

    Returns the same structure as analyze_static_finding plus:
      attack_vector   str  — network-level attack path
      affected_system str  — what is at risk
    """
    evidence = finding.get("evidence", "")
    description = finding.get("description", "")
    cve = finding.get("cve", "")
    cwe = finding.get("cwe", "")

    prompt = textwrap.dedent(f"""\
    Analyse this dynamic security finding from an automated scanner and respond in JSON.

    Finding:
    - Name: {finding.get('name', '')}
    - Tool: {finding.get('tool', '')}
    - Target: {finding.get('target', '')}
    - Category: {finding.get('category', '')}
    - Severity (scanner): {finding.get('severity', 'medium')}
    - CVE: {cve or 'N/A'}
    - CWE: {cwe or 'N/A'}
    - Description: {description[:600] if description else 'N/A'}
    - Evidence: {evidence[:400] if evidence else 'N/A'}
    - Port: {finding.get('port', 'N/A')}
    - URL: {finding.get('url', 'N/A')}

    Respond ONLY with this JSON structure (no markdown fences):
    {{
      "verdict": "confirmed|false_positive|needs_review",
      "severity": "critical|high|medium|low|info",
      "confidence": 0-100,
      "exploit_difficulty": "trivial|low|moderate|high|not_exploitable",
      "exploit_scenario": "Numbered steps: 1. ... 2. ... 3. ...",
      "attack_vector": "How attacker reaches this from the internet",
      "affected_system": "What is compromised if exploited",
      "remediation_summary": "One sentence fix",
      "remediation_code": "Config change, command, or code fix (empty if N/A)",
      "cvss_vector": "CVSS:3.1/AV:.../...",
      "reasoning": "Why this verdict — 2-3 sentences"
    }}
    """)

    client = _client()
    response = client.messages.create(
        model=_MODEL,
        max_tokens=_MAX_TOKENS,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)


# ── Scan boost: taint analysis on source-sink pairs ──────────────────────────

def boost_scan(
    scan_report: dict[str, Any],
    max_pairs: int = 20,
) -> list[dict[str, Any]]:
    """AI taint analysis on source-sink candidate pairs from a static scan.

    Reads the candidate_pairs from the scan report, fetches code context,
    and asks Claude to determine if each pair is a confirmed data-flow path.

    Returns a list of enriched pair dicts with AI analysis fields.
    """
    pairs = scan_report.get("candidate_pairs", [])[:max_pairs]
    root  = scan_report.get("root", "")
    results = []

    for pair in pairs:
        src  = pair.get("source", {})
        sink = pair.get("sink", {})

        src_snippet  = _read_snippet(src.get("file", ""),  src.get("line",  0))
        sink_snippet = _read_snippet(sink.get("file", ""), sink.get("line", 0))

        prompt = textwrap.dedent(f"""\
        Perform taint analysis on this source-sink pair from a static scanner.

        SOURCE (attacker-controlled input enters here):
        - File: {src.get('file', '')}
        - Line: {src.get('line', 0)}
        - Symbol: {src.get('name', '')}
        - Category: {src.get('category', '')}
        Code:
        ```
        {src_snippet or '(file not readable)'}
        ```

        SINK (dangerous operation):
        - File: {sink.get('file', '')}
        - Line: {sink.get('line', 0)}
        - Symbol: {sink.get('name', '')}
        - Category: {sink.get('category', '')}
        Code:
        ```
        {sink_snippet or '(file not readable)'}
        ```

        Proximity: {pair.get('proximity', 'unknown')}
        Scan root: {root}

        Respond ONLY with JSON (no markdown):
        {{
          "verdict": "confirmed|false_positive|needs_review",
          "severity": "critical|high|medium|low|info",
          "confidence": 0-100,
          "exploit_difficulty": "trivial|low|moderate|high|not_exploitable",
          "vulnerability_title": "Short precise name (e.g. SSRF via fetch() with user-controlled URL)",
          "cwe": "CWE-NNN",
          "data_flow": "SourceSymbol (file:line) → propagation → SinkSymbol (file:line)",
          "exploit_scenario": "1. Attacker ... 2. Application ... 3. Attacker achieves ...",
          "remediation_summary": "One sentence fix",
          "remediation_code": "Concrete fixed code snippet",
          "reasoning": "2-3 sentences explaining the verdict"
        }}
        """)

        try:
            client = _client()
            response = client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            ai = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            ai = {"error": str(exc), "verdict": "needs_review"}

        results.append({
            "source": src,
            "sink": sink,
            "proximity": pair.get("proximity"),
            "ai": ai,
        })

    return results


def _read_snippet(file: str, line: int, context: int = 6) -> str:
    """Read lines around `line` from `file`."""
    try:
        lines = Path(file).read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, line - 1 - context)
        end   = min(len(lines), line - 1 + context + 1)
        return "\n".join(
            f"{i + 1:4d}  {'→' if i + 1 == line else ' '} {lines[i]}"
            for i in range(start, end)
        )
    except Exception:  # noqa: BLE001
        return ""
