# ammb/bridge.py
"""
Main Bridge orchestrator class.
"""

import logging
import threading
import time
from queue import Queue
from typing import Any, Optional, Union

from .api import BridgeAPIServer
from .config_handler import BridgeConfig
from .health import HealthStatus, get_health_monitor
from .meshcore_handler import MeshcoreHandler
from .meshtastic_handler import MeshtasticHandler
from .message_logger import configure_message_logger, get_message_logger
from .metrics import get_metrics
from .mqtt_handler import MQTTHandler

ExternalHandler = Union[MeshcoreHandler, MQTTHandler]


class Bridge:
    """Orchestrates the Meshtastic-External Network bridge operation."""

    # Attribute annotations for mypy
    to_meshtastic_queue: Queue
    to_external_queue: Queue
    meshtastic_handler: Optional[MeshtasticHandler]
    external_handler: Optional[ExternalHandler]
    handlers: list[Any]
    api_server: Optional[BridgeAPIServer]

    def __init__(self, config: BridgeConfig):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.shutdown_event = threading.Event()
        self._stopped = False

        self.to_meshtastic_queue = Queue(maxsize=config.queue_size)
        self.to_external_queue = Queue(maxsize=config.queue_size)
        self.logger.info(
            "Message queues initialized with max size: %s",
            config.queue_size,
        )

        # Initialize metrics, health, and optional message persistence
        self.metrics = get_metrics()
        self.health_monitor = get_health_monitor()
        self.message_logger = configure_message_logger(
            log_file=config.message_log_file,
            max_file_size_mb=int(config.message_log_max_mb or 10),
            max_backups=int(config.message_log_max_backups or 5),
        )
        self.health_monitor.register_component(
            "meshtastic", HealthStatus.UNKNOWN
        )
        self.health_monitor.register_component(
            "external", HealthStatus.UNKNOWN
        )
        self.health_monitor.start_monitoring()

        # Initialize API server if enabled
        self.api_server: Optional[BridgeAPIServer] = None
        if config.api_enabled:
            api_host = config.api_host or "127.0.0.1"
            api_port = int(config.api_port or 8080)
            self.api_server = BridgeAPIServer(
                self, host=api_host, port=api_port
            )

        self.logger.info("Initializing network handlers...")
        self.meshtastic_handler: Optional[MeshtasticHandler] = None
        self.external_handler: Optional[ExternalHandler] = None
        self.handlers: list[object] = []

        try:
            # Only initialize Meshtastic handler if MESHTASTIC_SERIAL_PORT is set
            if config.meshtastic_port and config.meshtastic_port.strip():
                self.meshtastic_handler = MeshtasticHandler(
                    config=config,
                    to_external_queue=self.to_external_queue,
                    from_external_queue=self.to_meshtastic_queue,
                    shutdown_event=self.shutdown_event,
                )
                self.handlers.append(self.meshtastic_handler)
            else:
                self.meshtastic_handler = None
                self.logger.info("MESHTASTIC_SERIAL_PORT not set; skipping Meshtastic handler initialization.")

            if config.external_transport == "serial":
                self.logger.info("Selected external transport: Serial")
                self.external_handler = MeshcoreHandler(
                    config=config,
                    to_meshtastic_queue=self.to_meshtastic_queue,
                    from_meshtastic_queue=self.to_external_queue,
                    shutdown_event=self.shutdown_event,
                )
                self.handlers.append(self.external_handler)
            elif config.external_transport == "mqtt":
                self.logger.info("Selected external transport: MQTT")
                self.external_handler = MQTTHandler(
                    config=config,
                    to_meshtastic_queue=self.to_meshtastic_queue,
                    from_meshtastic_queue=self.to_external_queue,
                    shutdown_event=self.shutdown_event,
                )
                self.handlers.append(self.external_handler)
            else:
                raise ValueError(
                    "Invalid external_transport configured: "
                    f"{config.external_transport}"
                )

            self.logger.info(
                "All required handlers initialized successfully."
            )

        except (ValueError, Exception) as e:
            self.logger.critical(
                "Failed to initialize handlers: %s. Bridge cannot start.",
                e,
                exc_info=True,
            )
            self.stop()
            self.external_handler = None

    def run(self):
        self.logger.info("Starting AMMB run sequence...")

        if not self.external_handler:
            self.logger.error(
                "One or more handlers failed to initialize. Bridge cannot run."
            )
            self.stop()
            return

        self.logger.info("Attempting initial network connections...")
        if self.meshtastic_handler:
            if not self.meshtastic_handler.connect():
                if self.config.meshtastic_retry_on_boot:
                    self.logger.warning(
                        "Failed to connect to Meshtastic on startup. "
                        "Sender thread will keep retrying."
                    )
                else:
                    self.logger.critical(
                        "Failed to connect to Meshtastic device on "
                        "startup. Bridge cannot start."
                    )
                    self.stop()
                    return

        if not self.external_handler.connect():
            handler_type = type(self.external_handler).__name__
            self.logger.warning(
                "Failed to initiate connection for %s initially. "
                "Handler will keep trying in background.",
                handler_type,
            )
        self.logger.info("Starting handler background tasks/threads...")
        try:
            if self.meshtastic_handler:
                self.meshtastic_handler.start_sender()
            if hasattr(self.external_handler, "start_threads"):
                self.external_handler.start_threads()
            elif hasattr(self.external_handler, "start_publisher"):
                self.external_handler.start_publisher()

        except Exception as e:
            self.logger.critical(
                "Failed to start handler background tasks: %s",
                e,
                exc_info=True,
            )
            self.stop()
            return

        # Start API server if enabled
        if self.api_server:
            self.api_server.start()

        self.logger.info(
            "Bridge background tasks started. Running... "
            "(Press Ctrl+C to stop)"
        )

        try:
            while not self.shutdown_event.is_set():
                time.sleep(1)

        except Exception as e:
            self.logger.critical(
                f"Unexpected error in main bridge loop: {e}", exc_info=True
            )
        finally:
            self.logger.info(
                "Main loop exiting. Initiating shutdown sequence..."
            )
            self.stop()

    def stop(self):
        if self._stopped:
            return
        self._stopped = True

        self.logger.info("Signaling shutdown to all components...")
        self.shutdown_event.set()

        # Stop API server
        if self.api_server:
            self.api_server.stop()

        # Stop health monitoring
        self.health_monitor.stop_monitoring()
        get_message_logger().stop()

        self.logger.info("Stopping %s handlers...", len(self.handlers))
        for handler in reversed(self.handlers):
            try:
                handler.stop()
            except Exception as e:
                self.logger.error(
                    f"Error stopping handler: {e}", exc_info=True
                )

        self.logger.info("Bridge shutdown sequence complete.")
