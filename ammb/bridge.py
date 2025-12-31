# ammb/bridge.py
"""
Main Bridge orchestrator class.
"""

import logging
import threading
from queue import Queue
import time
from typing import Union, Optional

from .config_handler import BridgeConfig
from .meshtastic_handler import MeshtasticHandler
from .meshcore_handler import MeshcoreHandler 
from .mqtt_handler import MQTTHandler 
from .metrics import get_metrics
from .health import get_health_monitor, HealthStatus
from .api import BridgeAPIServer

ExternalHandler = Union[MeshcoreHandler, MQTTHandler]

class Bridge:
    """Orchestrates the Meshtastic-External Network bridge operation."""

    def __init__(self, config: BridgeConfig):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.shutdown_event = threading.Event() 

        self.to_meshtastic_queue = Queue(maxsize=config.queue_size)
        self.to_external_queue = Queue(maxsize=config.queue_size)
        self.logger.info(f"Message queues initialized with max size: {config.queue_size}")

        # Initialize metrics and health monitoring
        self.metrics = get_metrics()
        self.health_monitor = get_health_monitor()
        self.health_monitor.register_component("meshtastic", HealthStatus.UNKNOWN)
        self.health_monitor.register_component("external", HealthStatus.UNKNOWN)
        self.health_monitor.start_monitoring()

        # Initialize API server if enabled
        self.api_server: Optional[BridgeAPIServer] = None
        if config.api_enabled:
            self.api_server = BridgeAPIServer(self, host=config.api_host, port=config.api_port)

        self.logger.info("Initializing network handlers...")
        self.meshtastic_handler: Optional[MeshtasticHandler] = None
        self.external_handler: Optional[ExternalHandler] = None
        self.handlers = []

        try:
            self.meshtastic_handler = MeshtasticHandler(
                config=config,
                to_external_queue=self.to_external_queue,
                from_external_queue=self.to_meshtastic_queue,
                shutdown_event=self.shutdown_event
            )
            self.handlers.append(self.meshtastic_handler)

            if config.external_transport == 'serial':
                self.logger.info("Selected external transport: Serial")
                self.external_handler = MeshcoreHandler(
                    config=config,
                    to_meshtastic_queue=self.to_meshtastic_queue,
                    from_meshtastic_queue=self.to_external_queue,
                    shutdown_event=self.shutdown_event
                )
                self.handlers.append(self.external_handler)
            elif config.external_transport == 'mqtt':
                self.logger.info("Selected external transport: MQTT")
                self.external_handler = MQTTHandler(
                    config=config,
                    to_meshtastic_queue=self.to_meshtastic_queue,
                    from_meshtastic_queue=self.to_external_queue,
                    shutdown_event=self.shutdown_event
                )
                self.handlers.append(self.external_handler)
            else:
                raise ValueError(f"Invalid external_transport configured: {config.external_transport}")

            self.logger.info(f"All required handlers initialized successfully.")

        except (ValueError, Exception) as e:
             self.logger.critical(f"Failed to initialize handlers: {e}. Bridge cannot start.", exc_info=True)
             self.stop()
             self.external_handler = None


    def run(self):
        self.logger.info("Starting AMMB run sequence...")

        if not self.meshtastic_handler or not self.external_handler:
             self.logger.error("One or more handlers failed to initialize. Bridge cannot run.")
             self.stop()
             return

        self.logger.info("Attempting initial network connections...")
        if not self.meshtastic_handler.connect():
            self.logger.critical("Failed to connect to Meshtastic device on startup. Bridge cannot start.")
            self.stop()
            return

        if not self.external_handler.connect():
            handler_type = type(self.external_handler).__name__
            self.logger.warning(f"Failed to initiate connection for {handler_type} initially. Handler will keep trying in background.")

        self.logger.info("Starting handler background tasks/threads...")
        try:
            self.meshtastic_handler.start_sender()
            if isinstance(self.external_handler, MeshcoreHandler):
                self.external_handler.start_threads()
            elif isinstance(self.external_handler, MQTTHandler):
                self.external_handler.start_publisher()

        except Exception as e:
             self.logger.critical(f"Failed to start handler background tasks: {e}", exc_info=True)
             self.stop()
             return

        # Start API server if enabled
        if self.api_server:
            self.api_server.start()

        self.logger.info("Bridge background tasks started. Running... (Press Ctrl+C to stop)")

        try:
            while not self.shutdown_event.is_set():
                time.sleep(1) 

        except Exception as e:
             self.logger.critical(f"Unexpected error in main bridge loop: {e}", exc_info=True)
        finally:
             self.logger.info("Main loop exiting. Initiating shutdown sequence...")
             self.stop()

    def stop(self):
        if self.shutdown_event.is_set():
             return

        self.logger.info("Signaling shutdown to all components...")
        self.shutdown_event.set()

        # Stop API server
        if self.api_server:
            self.api_server.stop()

        # Stop health monitoring
        self.health_monitor.stop_monitoring()

        self.logger.info(f"Stopping {len(self.handlers)} handlers...")
        for handler in reversed(self.handlers):
             try:
                  handler.stop()
             except Exception as e:
                  self.logger.error(f"Error stopping handler: {e}", exc_info=True)

        self.logger.info("Bridge shutdown sequence complete.")
