# QUICKSTART — build vulnscan's professional edition with Claude Code

This folder is the starting codebase. `BUILD_BRIEF.md` is the full instruction set
for the upgrade (YAML language system, engine API, web UI). Steps below.

## 0. Authorized-use reminder
vulnscan is defensive tooling for code you own or are authorized to test. Keep the
authorization gate in the skills — do not turn it into an exploit generator.

## 1. Install Claude Code
- macOS/Linux (recommended, no Node.js):  curl -fsSL https://claude.ai/install.sh | bash
- Windows: use the installer / Desktop app from the setup page.
- npm alternative (needs Node.js 22+):    npm install -g @anthropic-ai/claude-code
Docs: https://code.claude.com/docs/en/setup   •   Verify: claude --version

## 2. Authenticate
First launch prompts you to log in. Needs a paid Claude plan (Pro/Max/Team) or an
Anthropic API key.

## 3. Project prerequisites
- Python 3.12+   (python3 --version)
- git
(Node.js only needed later, for the web UI Claude Code will build.)

## 4. Open a session in this folder
    cd <path>/vulnscan
    claude
Load the skills + CLIs, then restart the session so they register:
    ./install.sh

## 5. Kick off the build — paste this into the session:
    Read BUILD_BRIEF.md and the existing code. Show me your plan, then start with
    Deliverable 1 (the YAML language system). Keep the existing tests green and
    work through the deliverables one at a time.

## 6. Checkpoints to hold it to
- python -m pytest stays green (it starts at 15 passing)
- adding languages/defs/<lang>.yaml makes a new language scannable with NO .py edits
- uvicorn vulnscan.api:app serves; the web UI lists findings and has a Languages screen

## Tip
Go one deliverable at a time and review each diff. If a change sprawls, tell it to
stop and narrow. Small steps beat one big generation.
