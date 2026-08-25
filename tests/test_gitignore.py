"""Guard that operator secrets cannot be committed."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Paths that may contain credentials, keys, or message payloads.
MUST_IGNORE = (
    "config.ini",
    "config.local.ini",
    "config.local.mqtt.ini",
    "secrets.ini",
    "credentials.json",
    ".env",
    ".env.local",
    "mqtt.pem",
    "mqtt.key",
    "client.crt",
    "id_rsa",
    "ammb_tui_crash.log",
    "messages.jsonl",
    "messages.jsonl.1",
    "coverage.xml",
    ".vscode/settings.json",
    ".vscode/launch.json",
    ".idea/workspace.xml",
    "project.code-workspace",
    ".cursor/",
    ".claude/",
    ".grok/",
    "personal/notes.txt",
    "workspace/local.ini",
)

# Public templates that must remain shareable.
MUST_NOT_IGNORE = (
    "examples/config.ini.example",
    "examples/config.local.mqtt.ini",
    "examples/config.local.serial.ini",
)


def _check_ignore(path: str) -> int:
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "-q", path],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


def test_secret_paths_are_gitignored():
    for path in MUST_IGNORE:
        assert _check_ignore(path) == 0, f"{path} must be gitignored"


def test_example_configs_remain_tracked():
    for path in MUST_NOT_IGNORE:
        assert _check_ignore(path) == 1, f"{path} must not be gitignored"


def test_gitignore_covers_required_patterns():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        "config.ini",
        ".env",
        "*.pem",
        "*.key",
        "*.jsonl",
        "ammb_tui_crash.log",
        ".vscode/",
        "*.code-workspace",
        "/personal/",
        "/workspace/",
    ):
        assert pattern in text
