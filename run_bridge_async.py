#!/usr/bin/env python3
# run_bridge_async.py
"""
Async entry point for Akita Meshtastic Meshcore Bridge.

This launches the same production Bridge as run_bridge.py, plus an
optional in-process FastAPI server when API_ENABLED is true.
"""
import argparse
import asyncio
import logging
import os
import signal
import sys

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    from ammb.bridge_async import AsyncBridge
    from ammb.config_handler import resolve_config_path
    from ammb.preflight import run_preflight
    from ammb.utils import setup_logging
except ImportError as e:
    print(f"ERROR: Failed to import AMMB modules: {e}", file=sys.stderr)
    sys.exit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the AMMB production bridge under asyncio."
    )
    parser.add_argument(
        "--config",
        default=None,
        help=(
            "Path to config.ini. Defaults to AMMB_CONFIG, ./config.ini, "
            "then the project-root config.ini."
        ),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.info("--- Akita Meshtastic Meshcore Bridge (Async) Starting ---")

    config_path = resolve_config_path(
        args.config, fallback=os.path.join(project_root, "config.ini")
    )
    logging.info("Loading configuration from: %s", config_path)
    report = run_preflight(config_path)
    config = report.config
    if not report.ready or config is None:
        for diagnostic in report.diagnostics:
            log = (
                logging.error
                if diagnostic.is_error
                else logging.warning
            )
            log("Preflight %s: %s", diagnostic.title, diagnostic.detail)
        logging.critical("Failed to load configuration. Bridge cannot start.")
        sys.exit(1)
    for diagnostic in report.diagnostics:
        if diagnostic.severity.lower() == "warning":
            logging.warning(
                "Preflight warning: %s: %s",
                diagnostic.title,
                diagnostic.detail,
            )
    logging.info("Configuration loaded successfully.")
    logging.info("Selected external transport: %s", config.external_transport)

    setup_logging(config.log_level)
    logging.debug("Logging level set to %s", config.log_level)

    bridge = AsyncBridge(config)
    if not bridge.bridge.external_handler:
        logging.critical(
            "Bridge initialization failed (likely handler issue). Exiting."
        )
        sys.exit(1)

    def _handle_sigterm(signum, _frame):
        logging.info(
            "Signal %s received. Initiating graceful shutdown...", signum
        )
        bridge.request_shutdown()

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        asyncio.run(bridge.start())
    except KeyboardInterrupt:
        logging.info(
            "KeyboardInterrupt received. Initiating graceful shutdown..."
        )
    except Exception as e:
        logging.critical(
            "Unhandled critical exception in async bridge execution: %s",
            e,
            exc_info=True,
        )
        sys.exit(1)
    logging.info("--- Akita Meshtastic Meshcore Bridge (Async) Stopped ---")
    sys.exit(0)


if __name__ == "__main__":
    main()
