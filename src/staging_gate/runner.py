"""Run H1-style prompts against Claude. The system prompts are read from the user's own prompt
files (the fenced block under '## System prompt'); nothing is embedded here."""
import json
import re

from . import layout as L
from .controls import read_controls
from .xl import cell, s

DEFAULT_MODEL = "claude-opus-5-5"


def extract_system_prompt(md: str) -> str:
    m = re.search(r"##\s*System prompt[^\n]*\n+```[^\n]*\n(.*?)\n```", md, re.DOTALL)
    if not m:
        raise ValueError("no fenced block found under a '## System prompt' heading")
    return m.group(1)


def first_json(text: str, opener: str):
    """Parse the first JSON value starting at `opener` ('[' or '{'), ignoring surrounding prose/fences."""
    i = text.find(opener)
    if i < 0:
        raise ValueError(f"no JSON {'array' if opener == '[' else 'object'} in model output")
    try:
        value, _ = json.JSONDecoder().raw_decode(text[i:])
    except json.JSONDecodeError as e:
        raise ValueError(f"model output JSON did not parse: {e}") from e
    return value


def call_model(client, system: str, user: str, model: str = DEFAULT_MODEL, fallbacks: bool = True,
               max_tokens: int = 64000) -> str:
    """Streaming call (long outputs). Adaptive thinking is the default on this model."""
    kw = {}
    if fallbacks:  # refusal fallback, per current API notes; use --no-fallbacks to disable
        kw = {"betas": ["server-side-fallback-2026-07-01"], "extra_body": {"fallbacks": "default"}}
    with client.beta.messages.stream(
        model=model, max_tokens=max_tokens, system=system,
        output_config={"effort": "high"},
        messages=[{"role": "user", "content": user}], **kw,
    ) as stream:
        msg = stream.get_final_message()
    if getattr(msg, "stop_reason", None) == "refusal":
        raise RuntimeError(f"model refused: {getattr(msg, 'stop_details', None)}")
    if getattr(msg, "stop_reason", None) == "max_tokens":
        raise RuntimeError("output hit max_tokens - JSON would be truncated")
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def h2_user_prompt(profile: str, register_text: str, controls: list[dict]) -> str:
    return ("## Approved Company Profile\n\n" + profile + "\n\n## Evidence Register\n\n" + register_text
            + "\n\n## Control rows (JSON)\n\n" + json.dumps(controls, ensure_ascii=False, indent=1))


def h3_user_prompt(profile: str, controls: list[dict], existing_risks: list[str]) -> str:
    scored = [c for c in controls if c["maturity_S"] != ""]
    return ("## Company Profile\n\n" + profile + "\n\n## Approved control rows (JSON)\n\n"
            + json.dumps(scored, ensure_ascii=False, indent=1)
            + "\n\n## Existing contents of 8. Risks (risk names)\n\n" + json.dumps(existing_risks))


def existing_risk_names(wb) -> list[str]:
    if L.RISKS_SHEET not in wb.sheetnames:
        return []
    ws = wb[L.RISKS_SHEET]
    names = [s(cell(ws, L.RISKS_NAME_COL, r).value) for r in range(L.RISK_TARGET_FIRST_ROW, L.RISK_TARGET_FIRST_ROW + 400)]
    return [n for n in names if n]
