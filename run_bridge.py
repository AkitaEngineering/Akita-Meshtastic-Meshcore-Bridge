#!/usr/bin/env python3
# run_bridge.py
"""
Executable script to initialize and run the Akita Meshtastic Meshcore
Bridge (AMMB).

This script handles:
- Checking for essential dependencies.
- Loading configuration from 'config.ini'.
- Setting up application-wide logging.
- Creating and running the main Bridge instance.
- Handling graceful shutdown on KeyboardInterrupt (Ctrl+C).
"""

import logging
import os
import sys

# Ensure the script can find the 'ammb' package
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# --- Dependency Check ---
try:
    import configparser  # noqa: F401
    import json  # noqa: F401
    import queue  # noqa: F401
    import threading  # noqa: F401
    import time  # noqa: F401

    import meshtastic  # noqa: F401
    import meshtastic.serial_interface  # noqa: F401
    import paho.mqtt.client as paho_mqtt  # noqa: F401
    import serial  # noqa: F401
    from pubsub import pub  # noqa: F401
except ImportError as e:
    print("ERROR: Missing required library - %s" % e.name, file=sys.stderr)
    print("Please install required libraries by running:", file=sys.stderr)
    print(
        "  pip install -r %s" % os.path.join(project_root, 'requirements.txt'),
        file=sys.stderr,
    )
    sys.exit(1)

# --- Imports ---
try:
    from ammb import Bridge
    from ammb.config_handler import CONFIG_FILE, load_config
    from ammb.utils import setup_logging
except ImportError as e:
    print(f"ERROR: Failed to import AMMB modules: {e}", file=sys.stderr)
    print(
        "Ensure the script is run from the project root directory",
        file=sys.stderr,
    )
    sys.exit(1)


# --- Main Execution ---
if __name__ == "__main__":
    # Basic logging setup until config is loaded
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.info("--- Akita Meshtastic Meshcore Bridge Starting ---")

    # --- Configuration Loading ---
    config_path = os.path.join(project_root, CONFIG_FILE)
    logging.info(f"Loading configuration from: {config_path}")
    config = load_config(config_path)
    if not config:
        logging.critical("Failed to load configuration. Bridge cannot start.")
        sys.exit(1)
    logging.info("Configuration loaded successfully.")
    logging.info(f"Selected external transport: {config.external_transport}")

    # --- Logging Setup ---
    setup_logging(config.log_level)
    logging.debug(f"Logging level set to {config.log_level}")

    # --- Bridge Initialization and Execution ---
    logging.info("Initializing bridge instance...")
    bridge = Bridge(config)

    # Check if external handler was successfully created
    if not bridge.external_handler:
        logging.critical(
            "Bridge initialization failed (likely handler issue). Exiting."
        )
        sys.exit(1)

    try:
        logging.info("Starting bridge run loop...")
        bridge.run()
    except KeyboardInterrupt:
        logging.info(
            "KeyboardInterrupt received. Initiating graceful shutdown..."
        )
    except Exception as e:
        logging.critical(
            f"Unhandled critical exception in bridge execution: {e}",
            exc_info=True,
        )
        logging.info("Attempting emergency shutdown...")
        bridge.stop()
        sys.exit(1)

    logging.info("--- Akita Meshtastic Meshcore Bridge Stopped ---")
    sys.exit(0)
