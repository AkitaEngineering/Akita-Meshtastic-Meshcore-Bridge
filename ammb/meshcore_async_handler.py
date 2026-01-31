# ammb/meshcore_async_handler.py
"""
Async Meshcore handler using meshcore_py for serial communication.
"""

import asyncio
import logging
from typing import Any, Dict, Optional, Callable
from meshcore import MeshCore, EventType

class MeshcoreAsyncHandler:
    """
    Async handler for Meshcore devices using meshcore_py.
    """
    def __init__(self, serial_port: str, baud: int = 115200, debug: bool = False):
        self.logger = logging.getLogger(__name__)
        self.serial_port = serial_port
        self.baud = baud
        self.debug = debug
        self.meshcore: Optional[MeshCore] = None
        self._event_handlers: Dict[EventType, Callable] = {}
        self._connected = asyncio.Event()
        self._disconnect_requested = False

    async def connect(self):
        self.logger.info(f"Connecting to Meshcore device on {self.serial_port}...")
        self.meshcore = await MeshCore.create_serial(self.serial_port, self.baud, debug=self.debug)
        self.meshcore.subscribe(EventType.CONNECTED, self._on_connected)
        self.meshcore.subscribe(EventType.DISCONNECTED, self._on_disconnected)
        self._connected.set()
        self.logger.info("Meshcore device connected.")

    async def disconnect(self):
        self._disconnect_requested = True
        if self.meshcore:
            await self.meshcore.disconnect()
        self._connected.clear()
        self.logger.info("Meshcore device disconnected.")

    async def send_message(self, contact_or_key: Any, message: str):
        if not self.meshcore:
            raise RuntimeError("Meshcore not connected.")
        result = await self.meshcore.commands.send_msg(contact_or_key, message)
        if result is None:
            self.logger.error("send_msg returned None (no response from Meshcore).")
            return False
        if result.type == EventType.ERROR:
            self.logger.error(f"Error sending message: {result.payload}")
            return False
        self.logger.info("Message sent successfully!")
        return True

    def subscribe(self, event_type: EventType, handler: Callable):
        if not self.meshcore:
            raise RuntimeError("Meshcore not connected.")
        # Wrap handler for centralized error logging
        def safe_handler(event):
            try:
                if asyncio.iscoroutinefunction(handler):
                    asyncio.create_task(handler(event))
                else:
                    handler(event)
            except Exception as e:
                self.logger.error(f"Error in event handler for {event_type}: {e}", exc_info=True)
        self.meshcore.subscribe(event_type, safe_handler)
        self.logger.info(f"Subscribed to event: {event_type}")

    async def get_contacts(self):
        if not self.meshcore:
            raise RuntimeError("Meshcore not connected.")
        result = await self.meshcore.commands.get_contacts()
        if result is None:
            self.logger.error("get_contacts returned None (no response from Meshcore).")
            return None
        if result.type == EventType.ERROR:
            self.logger.error(f"Error getting contacts: {result.payload}")
            return None
        return result.payload

    async def run(self):
        # Only connect once per run, and wait for disconnect request
        try:
            await self.connect()
            while not self._disconnect_requested:
                await asyncio.sleep(1)
        except Exception as e:
            self.logger.error(f"Unhandled exception in MeshcoreAsyncHandler.run: {e}", exc_info=True)
            raise
        finally:
            # Ensure disconnect is called only once per run
            await self.disconnect()

    def _on_connected(self, event):
        self.logger.info(f"Connected: {event.payload}")

    def _on_disconnected(self, event):
        self.logger.warning(f"Disconnected: {event.payload}")
        self._connected.clear()
