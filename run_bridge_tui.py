#!/usr/bin/env python3
# run_bridge_tui.py
"""
Full-screen terminal dashboard entry point for the Akita Meshtastic
Meshcore Bridge.
"""

import logging
import os
import sys
import traceback
from datetime import datetime
from importlib import import_module
from pathlib import Path

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

RUNTIME_DEPENDENCIES = (
    ("meshtastic", "meshtastic"),
    ("meshtastic.serial_interface", "meshtastic"),
    ("paho.mqtt.client", "paho-mqtt"),
    ("pubsub", "pypubsub"),
    ("serial", "pyserial"),
    ("textual", "textual"),
)
CRASH_LOG_FILE = "ammb_tui_crash.log"


def install_command(root_path: str) -> str:
    """Build the recommended pip install command."""
    return f"pip install -r {os.path.join(root_path, 'requirements.txt')}"


def check_runtime_dependencies(importer=import_module) -> list[str]:
    """Return a sorted list of missing runtime packages."""
    missing: set[str] = set()
    for module_name, package_name in RUNTIME_DEPENDENCIES:
        try:
            importer(module_name)
        except ImportError:
            missing.add(package_name)
    return sorted(missing)


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


def main() -> int:
    """Run the AMMB Textual dashboard entry point."""
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
        from ammb.config_handler import CONFIG_FILE, load_config
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

    config_path = os.path.join(project_root, CONFIG_FILE)
    logging.info(f"Loading configuration from: {config_path}")
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