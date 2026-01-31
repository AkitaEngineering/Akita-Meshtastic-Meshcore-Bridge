#!/usr/bin/env python3
# run_bridge_async.py
"""
Async entry point for Akita Meshtastic Meshcore Bridge using meshcore_py.
"""
import logging
import os
import sys
import asyncio

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    from ammb.config_handler import CONFIG_FILE, load_config
    from ammb.utils import setup_logging
    from ammb.bridge_async import AsyncBridge
except ImportError as e:
    print(f"ERROR: Failed to import AMMB modules: {e}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logging.info("--- Akita Meshtastic Meshcore Bridge (Async) Starting ---")

    config_path = os.path.join(project_root, CONFIG_FILE)
    logging.info(f"Loading configuration from: {config_path}")
    config = load_config(config_path)
    if not config:
        logging.critical("Failed to load configuration. Bridge cannot start.")
        sys.exit(1)
    logging.info("Configuration loaded successfully.")
    logging.info(f"Selected external transport: {config.external_transport}")

    setup_logging(config.log_level)
    logging.debug(f"Logging level set to {config.log_level}")

    bridge = AsyncBridge(config)

    async def main():
        import uvicorn
        from multiprocessing import Process
        def run_api():
            uvicorn.run("ammb.api_async:app", host=config.api_host or "127.0.0.1", port=int(config.api_port or 8080), log_level="info")

        api_proc = None
        if getattr(config, "api_enabled", False):
            api_proc = Process(target=run_api)
            api_proc.start()
            logging.info(f"Async API server started on http://{config.api_host or '127.0.0.1'}:{config.api_port or 8080}")
        try:
            await bridge.start()
        finally:
            if api_proc:
                api_proc.terminate()
                api_proc.join()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received. Initiating graceful shutdown...")
    except Exception as e:
        logging.critical(f"Unhandled critical exception in async bridge execution: {e}", exc_info=True)
        sys.exit(1)
    logging.info("--- Akita Meshtastic Meshcore Bridge (Async) Stopped ---")
    sys.exit(0)
