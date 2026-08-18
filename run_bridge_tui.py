#!/usr/bin/env python3
# run_bridge_tui.py
"""
Full-screen terminal dashboard entry point for the Akita Meshtastic
Meshcore Bridge.
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from argparse import ArgumentParser
from datetime import datetime
from importlib import import_module
from pathlib import Path

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from ammb.config_handler import resolve_config_path
from ammb.preflight import (
    RUNTIME_DEPENDENCIES,
    TUI_DEPENDENCIES,
    build_config_summary,
    check_missing_dependencies,
    format_preflight_report,
    run_preflight,
)

CRASH_LOG_FILE = "ammb_tui_crash.log"


def install_command(root_path: str) -> str:
    """Build the recommended pip install command."""
    return f"pip install -r {os.path.join(root_path, 'requirements.txt')}"


def default_config_path() -> str:
    """Return the default config path for repo and installed usage."""
    return resolve_config_path(
        fallback=os.path.join(project_root, "config.ini")
    )


def check_runtime_dependencies(importer=import_module) -> list[str]:
    """Return a sorted list of missing runtime packages."""
    return check_missing_dependencies(
        RUNTIME_DEPENDENCIES + TUI_DEPENDENCIES,
        importer=importer,
    )


def build_parser() -> ArgumentParser:
    """Build command-line options for the command center."""
    parser = ArgumentParser(
        description="Run or inspect the AMMB terminal command center."
    )
    parser.add_argument(
        "--config",
        default=default_config_path(),
        help=(
            "Path to the bridge config file. Defaults to AMMB_CONFIG, "
            "./config.ini, then the project-root config.ini."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run preflight diagnostics and exit without starting the TUI.",
    )
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="Print a redacted config summary and exit.",
    )
    return parser


def print_config_summary(config) -> None:
    """Print the effective configuration without secrets."""
    rows = build_config_summary(config)
    label_width = max(len(label) for label, _ in rows)
    print("AMMB Effective Configuration")
    for label, value in rows:
        print(f"  {label:<{label_width}}  {value}")


def write_crash_report(exc: Exception, root_path: str) -> str:
    """Persist an unhandled TUI exception for post-mortem debugging."""
    crash_path = Path(root_path) / CRASH_LOG_FILE
    trace_text = "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    )
    timestamp = datetime.now().isoformat(timespec="seconds")
    with crash_path.open("a", encoding="utf-8") as handle:
        handle.write(f"[{timestamp}] AMMB TUI crash\n")
        handle.write(trace_text)
        handle.write("\n")
    return str(crash_path)


def main(argv: list[str] | None = None) -> int:
    """Run the AMMB Textual dashboard entry point."""
    args = build_parser().parse_args(argv)

    if args.check:
        report = run_preflight(args.config, include_tui=True)
        print(format_preflight_report(report))
        return 0 if report.ready else 1

    if args.print_config:
        from ammb.config_handler import load_config

        config = load_config(os.path.abspath(args.config))
        if not config:
            print(
                "ERROR: Failed to load configuration.",
                file=sys.stderr,
            )
            return 1
        print_config_summary(config)
        return 0

    missing = check_runtime_dependencies()
    if missing:
        print(
            "ERROR: Missing required libraries - %s"
            % ", ".join(missing),
            file=sys.stderr,
        )
        print("Please install required libraries by running:", file=sys.stderr)
        print(f"  {install_command(project_root)}", file=sys.stderr)
        return 1

    try:
        from ammb.config_handler import load_config
        from ammb.tui import run_tui
    except ImportError as e:
        print(f"ERROR: Failed to import AMMB modules: {e}", file=sys.stderr)
        print(
            "Ensure the script is run from the project root directory",
            file=sys.stderr,
        )
        print(f"  {install_command(project_root)}", file=sys.stderr)
        return 1

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.info("--- Akita Mesh Bridge Command Center Starting ---")

    config_path = os.path.abspath(args.config)
    logging.info("Loading configuration from: %s", config_path)
    config = load_config(config_path)
    if not config:
        logging.critical(
            "Failed to load configuration. Command center cannot start."
        )
        return 1

    try:
        run_tui(config)
    except Exception as exc:
        crash_report_path = None
        try:
            crash_report_path = write_crash_report(exc, project_root)
        except OSError as log_error:
            print(
                f"ERROR: Failed to write TUI crash report: {log_error}",
                file=sys.stderr,
            )
        print(f"ERROR: Command center crashed: {exc}", file=sys.stderr)
        if crash_report_path:
            print(
                f"Crash report written to: {crash_report_path}",
                file=sys.stderr,
            )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
