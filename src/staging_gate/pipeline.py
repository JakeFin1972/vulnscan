"""H2 / H3 runs as plain functions (used by the CLI and the web app)."""
import json
from pathlib import Path

from .controls import read_controls
from .evidence import load_register
from .guard import guard_h2
from .h2 import write_staging
from .risks import import_risks
from .runner import (DEFAULT_MODEL, call_model, existing_risk_names, extract_system_prompt,
                     first_json, h2_user_prompt, h3_user_prompt)


def make_client():
    import anthropic  # needs ANTHROPIC_API_KEY (or an `ant auth login` profile)
    return anthropic.Anthropic()


def run_h2(wb, prompt_md, profile, evidence, sheets=None, model=DEFAULT_MODEL, fallbacks=True, client=None):
    """Returns (n_written, result_dict_with_guard_notes)."""
    profile_text = Path(profile).read_text(encoding="utf-8")
    reg_text = Path(evidence).read_text(encoding="utf-8")
    system = extract_system_prompt(Path(prompt_md).read_text(encoding="utf-8"))
    controls = read_controls(wb, sheets)
    if not controls:
        raise ValueError("no control rows found for the selected sheets")
    out = call_model(client or make_client(), system, h2_user_prompt(profile_text, reg_text, controls),
                     model, fallbacks)
    result, _ = guard_h2(first_json(out, "{"), controls, load_register(evidence))
    return write_staging(wb, result), result


def run_h3(wb, prompt_md, profile, sheets=None, model=DEFAULT_MODEL, fallbacks=True, client=None):
    """Returns (imported, rejected_list)."""
    profile_text = Path(profile).read_text(encoding="utf-8")
    system = extract_system_prompt(Path(prompt_md).read_text(encoding="utf-8"))
    out = call_model(client or make_client(), system,
                     h3_user_prompt(profile_text, read_controls(wb, sheets), existing_risk_names(wb)),
                     model, fallbacks)
    return import_risks(wb, json.dumps(first_json(out, "[")))
