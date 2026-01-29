# ammb/mqtt_handler.py
"""
Handles interactions with an MQTT broker as the external network interface.
"""

import json
import logging
import threading
import time
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional

# External dependencies
import paho.mqtt.client as paho_mqtt
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import paho.mqtt.enums as paho_enums  # type: ignore[import-not-found]
else:
    paho_enums: Any = None

# Project dependencies
from .config_handler import BridgeConfig
from .health import HealthStatus, get_health_monitor
from .metrics import get_metrics
from .rate_limiter import RateLimiter
from .validator import MessageValidator


class MQTTHandler:
    """Manages connection and communication with an MQTT broker."""

    RECONNECT_DELAY_S = 10

    def __init__(
        self,
        config: BridgeConfig,
        to_meshtastic_queue: Queue,
        from_meshtastic_queue: Queue,
        shutdown_event: threading.Event,
    ):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.to_meshtastic_queue = to_meshtastic_queue
        self.to_mqtt_queue = from_meshtastic_queue
        self.shutdown_event = shutdown_event

        self.client: Optional[paho_mqtt.Client] = None
        self.publisher_thread: Optional[threading.Thread] = None
        self._mqtt_connected = threading.Event()
        self._lock = threading.Lock()

        # Initialize metrics, health, validator, and rate limiter
        self.metrics = get_metrics()
        self.health_monitor = get_health_monitor()
        self.validator = MessageValidator()
        self.rate_limiter = RateLimiter(max_messages=60, time_window=60.0)

        if not all(
            [
                config.mqtt_broker,
                config.mqtt_port is not None,
                config.mqtt_topic_in,
                config.mqtt_topic_out,
                config.mqtt_client_id,
                config.mqtt_qos is not None,
                config.mqtt_retain_out is not None,
            ]
        ):
            raise ValueError(
                "MQTT transport selected, but required MQTT "
                "configuration options seem missing."
            )

        self.logger.info("MQTT Handler Initialized.")

    def connect(self) -> bool:
        with self._lock:
            if self.client and self.client.is_connected():
                self._mqtt_connected.set()
                return True

            if self.client:
                try:
                    self.client.reconnect()
                    return True
                except Exception:
                    try:
                        self.client.loop_stop(force=True)
                    except Exception:
                        pass
                    self.client = None
                    self._mqtt_connected.clear()

            try:
                self.client = paho_mqtt.Client(
                    client_id=self.config.mqtt_client_id,
                    protocol=paho_mqtt.MQTTv311,
                    clean_session=True,
                )
                self.logger.info(
                    "Attempting connection to MQTT broker %s:%s...",
                    self.config.mqtt_broker,
                    self.config.mqtt_port,
                )

                self.client.on_connect = self._on_connect
                self.client.on_disconnect = self._on_disconnect
                self.client.on_message = self._on_message
                self.client.on_log = self._on_log

                # TLS/SSL support
                if (
                    hasattr(self.config, "mqtt_tls_enabled")
                    and self.config.mqtt_tls_enabled
                ):
                    import ssl

                    context = ssl.create_default_context()
                    if (
                        hasattr(self.config, "mqtt_tls_ca_certs")
                        and self.config.mqtt_tls_ca_certs
                    ):
                        context.load_verify_locations(
                            self.config.mqtt_tls_ca_certs
                        )
                    if (
                        hasattr(self.config, "mqtt_tls_insecure")
                        and self.config.mqtt_tls_insecure
                    ):
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    self.client.tls_set_context(context)
                    self.logger.info("MQTT TLS/SSL enabled")

                if self.config.mqtt_username:
                    self.client.username_pw_set(
                        self.config.mqtt_username, self.config.mqtt_password
                    )

                # Ensure configuration values present for mypy
                assert (
                    self.config.mqtt_broker is not None
                    and self.config.mqtt_port is not None
                )
                self.client.connect_async(
                    self.config.mqtt_broker,
                    self.config.mqtt_port,
                    keepalive=60,
                )
                self.client.loop_start()
                self.logger.info("MQTT client network loop started.")
                return True

            except Exception as e:
                self.logger.error(
                    "Error initiating MQTT connection or starting loop: %s",
                    e,
                    exc_info=True,
                )
                if self.client:
                    try:
                        self.client.loop_stop(force=True)
                    except Exception:
                        pass
                self.client = None
                self._mqtt_connected.clear()
                return False

    def start_publisher(self):
        if self.publisher_thread and self.publisher_thread.is_alive():
            return
        self.logger.info("Starting MQTT publisher thread...")
        self.publisher_thread = threading.Thread(
            target=self._mqtt_publisher_loop, daemon=True, name="MQTTPublisher"
        )
        self.publisher_thread.start()

    def stop(self):
        self.logger.info("Stopping MQTT handler...")
        if self.publisher_thread and self.publisher_thread.is_alive():
            self.publisher_thread.join(timeout=5)

        with self._lock:
            if self.client:
                try:
                    self.client.loop_stop(force=True)
                except Exception:
                    pass
                try:
                    self.client.disconnect()
                except Exception:
                    pass
                self.client = None
            self._mqtt_connected.clear()
            self.metrics.record_external_disconnection()
            self.health_monitor.update_component(
                "external", HealthStatus.UNHEALTHY, "Stopped"
            )
        self.logger.info("MQTT handler stopped.")

    # --- MQTT Callbacks (Executed by Paho's Network Thread) ---

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        connack_str = paho_mqtt.connack_string(rc)
        if rc == 0:
            self.logger.info(
                "Successfully connected to MQTT broker: %s (%s)",
                self.config.mqtt_broker,
                connack_str,
            )
            self._mqtt_connected.set()
            self.metrics.record_external_connection()
            self.health_monitor.update_component(
                "external", HealthStatus.HEALTHY, "MQTT connected"
            )
            try:
                client.subscribe(
                    self.config.mqtt_topic_in, qos=self.config.mqtt_qos
                )
            except Exception as e:
                self.logger.error("Error during MQTT subscription: %s", e)
        else:
            self.logger.error(
                "MQTT connection failed. Result code: %s - %s",
                rc,
                connack_str,
            )
            self._mqtt_connected.clear()
            self.metrics.record_external_disconnection()
            self.health_monitor.update_component(
                "external",
                HealthStatus.UNHEALTHY,
                "Connection failed: %s" % connack_str,
            )

    def _on_disconnect(self, client, userdata, rc, properties=None):
        self._mqtt_connected.clear()
        self.metrics.record_external_disconnection()
        if rc != 0:
            self.logger.warning(f"Unexpected MQTT disconnection. RC: {rc}")
            self.health_monitor.update_component(
                "external",
                HealthStatus.UNHEALTHY,
                f"Unexpected disconnect: RC {rc}",
            )
        else:
            self.health_monitor.update_component(
                "external", HealthStatus.UNHEALTHY, "Disconnected"
            )

    def _on_log(self, client, userdata, level, buf):
        """MQTT client logging callback."""
        # Only log at DEBUG level to avoid noise
        if level <= paho_mqtt.MQTT_LOG_DEBUG:
            self.logger.debug("MQTT: %s", buf)

    def _on_message(self, client, userdata, msg: paho_mqtt.MQTTMessage):
        try:
            payload_bytes = msg.payload
            if not payload_bytes:
                return

            try:
                payload_str = payload_bytes.decode("utf-8", errors="replace")
                mqtt_data = json.loads(payload_str)

                # Validate message
                is_valid, error_msg = self.validator.validate_external_message(
                    mqtt_data
                )
                if not is_valid:
                    self.logger.warning(
                        "Invalid MQTT message rejected: %s",
                        error_msg,
                    )
                    self.metrics.record_error("external")
                    return

                # Check rate limit
                if not self.rate_limiter.check_rate_limit("mqtt_receiver"):
                    self.logger.warning(
                        "Rate limit exceeded for MQTT receiver"
                    )
                    self.metrics.record_rate_limit_violation("mqtt_receiver")
                    return

                # Sanitize message
                mqtt_data = self.validator.sanitize_external_message(mqtt_data)

                dest_meshtastic_id = mqtt_data.get("destination_meshtastic_id")
                payload = mqtt_data.get("payload")
                payload_json = mqtt_data.get("payload_json")
                channel_index = mqtt_data.get("channel_index", 0)
                want_ack = mqtt_data.get("want_ack", False)

                text_payload_str = None
                if isinstance(payload, str):
                    text_payload_str = payload
                elif payload_json is not None:
                    try:
                        text_payload_str = json.dumps(payload_json)
                    except Exception:
                        pass
                elif payload is not None:
                    text_payload_str = str(payload)

                if dest_meshtastic_id and text_payload_str is not None:
                    meshtastic_msg = {
                        "destination": dest_meshtastic_id,
                        "text": text_payload_str,
                        "channel_index": (
                            int(channel_index)
                            if str(channel_index).isdigit()
                            else 0
                        ),
                        "want_ack": bool(want_ack),
                    }
                    try:
                        self.to_meshtastic_queue.put_nowait(meshtastic_msg)
                        payload_size = (
                            len(text_payload_str.encode("utf-8"))
                            if text_payload_str
                            else 0
                        )
                        self.metrics.record_external_received(payload_size)
                        self.logger.info(
                            "Queued MQTT message for %s",
                            dest_meshtastic_id,
                        )
                    except Full:
                        self.logger.warning("Meshtastic send queue full.")
                        self.metrics.record_dropped("external")
            except Exception as e:
                self.logger.error(f"Error processing MQTT message: {e}")

        except Exception as e:
            self.logger.error(f"Critical error in _on_message: {e}")

    def _mqtt_publisher_loop(self):
        self.logger.info("MQTT publisher loop started.")
        while not self.shutdown_event.is_set():
            if not self._mqtt_connected.is_set():
                self._mqtt_connected.wait(timeout=self.RECONNECT_DELAY_S / 2)
                continue

            try:
                item: Optional[Dict[str, Any]] = self.to_mqtt_queue.get(
                    timeout=1
                )
                if not item:
                    continue

                try:
                    payload_str = json.dumps(item)
                    topic = self.config.mqtt_topic_out

                    if not topic:
                        self.logger.error(
                            "MQTT_TOPIC_OUT is not configured. Cannot publish."
                        )
                        self.to_mqtt_queue.task_done()
                        continue

                    qos = self.config.mqtt_qos
                    if qos not in [0, 1, 2]:
                        self.logger.error(
                            "Invalid MQTT_QOS (%s); using QoS 0.",
                            qos,
                        )
                        qos = 0

                    with self._lock:
                        if self.client and self.client.is_connected():
                            self.client.publish(
                                topic,
                                payload=payload_str,
                                qos=qos,
                                retain=self.config.mqtt_retain_out,
                            )
                            self.metrics.record_external_sent(
                                len(payload_str.encode("utf-8"))
                            )
                        else:
                            self._mqtt_connected.clear()

                    self.to_mqtt_queue.task_done()
                except Exception as e:
                    self.logger.error(f"Error during MQTT publish: {e}")
                    self.to_mqtt_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(
                    f"Critical error in mqtt_publisher_loop: {e}",
                    exc_info=True,
                )
                time.sleep(5)

        self.logger.info("MQTT publisher loop stopped.")
