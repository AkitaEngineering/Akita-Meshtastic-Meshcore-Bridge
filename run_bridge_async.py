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
import sys

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    from ammb.bridge_async import AsyncBridge
    from ammb.config_handler import load_config, resolve_config_path
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
    config = load_config(config_path)
    if not config:
        logging.critical("Failed to load configuration. Bridge cannot start.")
        sys.exit(1)
    logging.info("Configuration loaded successfully.")
    logging.info("Selected external transport: %s", config.external_transport)

    setup_logging(config.log_level)
    logging.debug("Logging level set to %s", config.log_level)

    bridge = AsyncBridge(config)

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
