# ammb/bridge_async.py
"""
Async entry-point wrapper around the production Bridge.

The production forwarding path is the same thread-based Bridge used by
run_bridge.py. This wrapper adds an in-process FastAPI server so health
and metrics share process state with the running bridge.
"""

import asyncio
import logging
import threading
from typing import Optional

from ammb.bridge import Bridge
from ammb.config_handler import BridgeConfig


class AsyncBridge:
    """Run the production bridge under asyncio, with an optional API."""

    def __init__(self, config: BridgeConfig):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.bridge = Bridge(config)
        self._running = False
        self._bridge_thread: Optional[threading.Thread] = None

    async def start(self):
        """Start the production bridge and optional in-process API."""
        self._running = True
        api_task: Optional[asyncio.Task] = None
        server = None

        if self.config.api_enabled:
            try:
                import uvicorn

                from ammb.api_async import app, configure_async_api

                configure_async_api(
                    self.bridge,
                    getattr(self.config, "api_token", None),
                )
                server_config = uvicorn.Config(
                    app,
                    host=self.config.api_host or "127.0.0.1",
                    port=int(self.config.api_port or 8080),
                    log_level="info",
                )
                server = uvicorn.Server(server_config)
                api_task = asyncio.create_task(server.serve())
                self.logger.info(
                    "Async API server starting on http://%s:%s",
                    self.config.api_host or "127.0.0.1",
                    self.config.api_port or 8080,
                )
            except Exception as e:
                self.logger.error(
                    "Failed to start async API server: %s", e, exc_info=True
                )

        self._bridge_thread = threading.Thread(
            target=self.bridge.run,
            name="AMMB-Bridge",
            daemon=True,
        )
        self._bridge_thread.start()
        self.logger.info("Production bridge thread started.")

        try:
            while self._bridge_thread.is_alive() and self._running:
                await asyncio.sleep(0.25)
        except asyncio.CancelledError:
            self.logger.info("AsyncBridge received cancellation signal.")
            raise
        except Exception as e:
            self.logger.critical(
                "Unhandled exception in AsyncBridge: %s", e, exc_info=True
            )
        finally:
            if server is not None:
                server.should_exit = True
            if api_task is not None:
                api_task.cancel()
                try:
                    await api_task
                except (asyncio.CancelledError, Exception):
                    pass
            await self.shutdown()

    async def shutdown(self):
        self.logger.info("Shutting down AsyncBridge...")
        self._running = False
        self.bridge.stop()
        if self._bridge_thread and self._bridge_thread.is_alive():
            self._bridge_thread.join(timeout=10)
        self.logger.info("AsyncBridge shutdown complete.")
