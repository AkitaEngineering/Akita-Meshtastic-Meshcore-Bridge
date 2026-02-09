# ammb/meshcore_handler.py
"""
Handles interactions with an external device via a **Serial** port.
"""

import json
import logging
import threading
import time
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional

import serial

from .config_handler import BridgeConfig
from .health import HealthStatus, get_health_monitor
from .metrics import get_metrics
from .protocol import MeshcoreProtocolHandler, get_serial_protocol_handler
from .rate_limiter import RateLimiter
from .validator import MessageValidator



class MeshcoreHandler:
    """Manages Serial connection and communication with an external device."""

    RECONNECT_DELAY_S = 10
    AUTO_DETECT_FAILURE_THRESHOLD = 5

    def start_threads(self):
        """Start the receiver and sender threads for MeshcoreHandler."""
        if self.receiver_thread and self.receiver_thread.is_alive():
            self.logger.warning("Serial receiver thread already started.")
        else:
            self.logger.info("Starting Serial receiver thread...")
            self.receiver_thread = threading.Thread(
                target=self._serial_receiver_loop,
                daemon=True,
                name="SerialReceiver",
            )
            self.receiver_thread.start()

        if self.sender_thread and self.sender_thread.is_alive():
            self.logger.warning("Serial sender thread already started.")
        else:
            self.logger.info("Starting Serial sender thread...")
            self.sender_thread = threading.Thread(
                target=self._serial_sender_loop,
                daemon=True,
                name="SerialSender",
            )
            self.sender_thread.start()

        if (
            self._protocol_name == "companion_radio"
            and self._companion_contacts_poll_s > 0
        ):
            if self._contacts_poll_thread and self._contacts_poll_thread.is_alive():
                self.logger.warning("Companion contacts poll thread already started.")
            else:
                self.logger.info("Starting Companion contacts poll thread...")
                self._contacts_poll_thread = threading.Thread(
                    target=self._contacts_poll_loop,
                    daemon=True,
                    name="CompanionContactsPoll",
                )
                self._contacts_poll_thread.start()

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
        self.to_serial_queue = from_meshtastic_queue
        self.shutdown_event = shutdown_event

        self.serial_port: Optional[serial.Serial] = None
        self.receiver_thread: Optional[threading.Thread] = None
        self.sender_thread: Optional[threading.Thread] = None
        self._contacts_poll_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._is_connected = threading.Event()

        # Initialize metrics, health, validator, and rate limiter
        self.metrics = get_metrics()
        self.health_monitor = get_health_monitor()
        self.validator = MessageValidator()
        self.rate_limiter = RateLimiter(max_messages=60, time_window=60.0)

        if (
            not config.serial_port
            or not config.serial_baud
            or not config.serial_protocol
        ):
            raise ValueError(
                "Serial transport selected, but required SERIAL "
                "configuration options are missing."
            )

        self._protocol_name = config.serial_protocol.lower()
        self.logger.info(f"Selected serial protocol: {self._protocol_name}")
        self._companion_handshake_enabled = getattr(
            config, "companion_handshake_enabled", True
        )
        self._companion_contacts_poll_s = int(
            getattr(config, "companion_contacts_poll_s", 0) or 0
        )
        self._companion_debug = bool(
            getattr(config, "companion_debug", False)
        )
        self._companion_msg_polling = False
        self._failure_count = 0
        self._auto_switched = False
        self._auto_switch_enabled = config.serial_auto_switch if config.serial_auto_switch is not None else True
        self._protocols_tried = set([self._protocol_name])
        try:
            self.protocol_handler: MeshcoreProtocolHandler = (
                get_serial_protocol_handler(self._protocol_name)
            )
            self.logger.info(f"Initialized protocol handler: {type(self.protocol_handler).__name__}")
            if self._protocol_name == "companion_radio" and not self._companion_debug:
                self.protocol_handler.logger.setLevel(logging.INFO)
        except ValueError as e:
            self.logger.critical(
                "Failed to initialize serial protocol handler '%s': %s.",
                config.serial_protocol,
                e,
            )
            class DummyHandler(MeshcoreProtocolHandler):
                def read(self, port):
                    return None
                def encode(self, data):
                    return None
                def decode(self, line):
                    return None
            self.protocol_handler = DummyHandler()
            self.logger.warning("Using DummyHandler for protocol; no serial communication will occur.")
        self.logger.info("Serial Handler (MeshcoreHandler) Initialized.")

    def _switch_protocol(self):
        # Switch between json_newline and raw_serial
        if not self._auto_switch_enabled:
            self.logger.info("Protocol auto-switching is disabled by config.")
            return
        new_protocol = "raw_serial" if self._protocol_name == "json_newline" else "json_newline"
        if new_protocol in self._protocols_tried:
            self.logger.error(
                f"Both serial protocols failed to decode any valid messages. "
                f"Check your device firmware, serial settings, and protocol config. "
                f"Auto-detection is now disabled for this session."
            )
            self._auto_switch_enabled = False
            return
        self.logger.warning(
            f"Auto-switching serial protocol from {self._protocol_name} to {new_protocol} after repeated decode failures. "
            f"Check your device firmware and config."
        )
        try:
            self.protocol_handler = get_serial_protocol_handler(new_protocol)
            self._protocol_name = new_protocol
            self._failure_count = 0
            self._auto_switched = True
            self._protocols_tried.add(new_protocol)
        except Exception as e:
            self.logger.error(f"Failed to auto-switch protocol: {e}")
            # Do not switch if handler fails
            pass

    def connect(self) -> bool:
        with self._lock:
            if self.serial_port and self.serial_port.is_open:
                self.logger.info(
                    "Serial port %s already connected.",
                    self.config.serial_port,
                )
                self._is_connected.set()
                return True
            # Try to open the serial port
            try:
                self.serial_port = serial.Serial(
                    port=self.config.serial_port,
                    baudrate=self.config.serial_baud,
                    timeout=1,
                    write_timeout=1
                )
                if self.serial_port.is_open:
                    self.logger.info(
                        "Serial port %s opened successfully.",
                        self.config.serial_port,
                    )
                    if (
                        self._protocol_name == "companion_radio"
                        and self._companion_handshake_enabled
                    ):
                        self._send_companion_handshake()
                    self._is_connected.set()
                    return True
                else:
                    self.logger.error(
                        "Failed to open serial port %s.",
                        self.config.serial_port,
                    )
                    self._is_connected.clear()
                    return False
            except serial.SerialException as e:
                self.logger.error(
                    "SerialException opening port %s: %s",
                    self.config.serial_port,
                    e,
                )
                self._is_connected.clear()
                return False
            except Exception as e:
                self.logger.error(
                    "Unexpected error opening serial port %s: %s",
                    self.config.serial_port,
                    e,
                    exc_info=True,
                )
                self._is_connected.clear()
                return False

    def _send_companion_handshake(self) -> None:
        """Send basic companion protocol handshake commands to elicit responses."""
        try:
            # CMD_DEVICE_QUERY (22) + app_target_ver (3)
            self._send_companion_command(bytes([22, 3]), "CMD_DEVICE_QUERY")
            # CMD_APP_START (1) + app_ver (3) + reserved(6) + app_name
            app_name = b"AMMB"
            payload = bytes([1, 3]) + (b"\x00" * 6) + app_name
            self._send_companion_command(payload, "CMD_APP_START")
            # Initial poll for any pending messages
            self._companion_msg_polling = True
            self._send_companion_command(bytes([10]), "CMD_SYNC_NEXT_MESSAGE")
        except Exception as e:
            self.logger.warning("Failed to send companion handshake: %s", e)

    def _send_companion_command(self, payload: bytes, label: str) -> None:
        if not self.serial_port or not self.serial_port.is_open:
            return
        try:
            encoded_message = self.protocol_handler.encode({"payload": payload})
            if not encoded_message:
                self.logger.warning("Failed to encode companion command: %s", label)
                return
            self.serial_port.write(encoded_message)
            self.serial_port.flush()
            self.logger.info("Sent companion command: %s", label)
        except Exception as e:
            self.logger.warning("Error sending companion command %s: %s", label, e)

    def _send_sync_next_message(self):
        """Send CMD_SYNC_NEXT_MESSAGE to poll queued messages from MeshCore."""
        try:
            payload = bytes([10])  # CMD_SYNC_NEXT_MESSAGE
            encoded = self.protocol_handler.encode({"payload": payload})
            if not encoded:
                return
            with self._lock:
                if self.serial_port and self.serial_port.is_open:
                    self.serial_port.write(encoded)
                    self.serial_port.flush()
                    self.logger.debug("Sent CMD_SYNC_NEXT_MESSAGE")
        except Exception as e:
            self.logger.warning("Failed to send CMD_SYNC_NEXT_MESSAGE: %s", e)

    def _contacts_poll_loop(self) -> None:
        """Periodically request contacts from MeshCore to surface adverts."""
        self.logger.info(
            "Companion contacts poll loop started (interval=%ss).",
            self._companion_contacts_poll_s,
        )
        while not self.shutdown_event.is_set():
            if not self._is_connected.is_set():
                self.shutdown_event.wait(self.RECONNECT_DELAY_S)
                continue
            try:
                # CMD_GET_CONTACTS (4) with no 'since' param
                self._send_companion_command(bytes([4]), "CMD_GET_CONTACTS")
            except Exception as e:
                self.logger.warning("Contacts poll failed: %s", e)
            self.shutdown_event.wait(self._companion_contacts_poll_s)
        self.logger.info("Companion contacts poll loop stopped.")

    def stop(self):
        self.logger.info("Stopping Serial handler...")
        if self.receiver_thread and self.receiver_thread.is_alive():
            self.receiver_thread.join(timeout=2)
        if self.sender_thread and self.sender_thread.is_alive():
            self.sender_thread.join(timeout=5)
        if self._contacts_poll_thread and self._contacts_poll_thread.is_alive():
            self._contacts_poll_thread.join(timeout=2)
        self._close_serial()
        self.logger.info("Serial handler stopped.")

    def _close_serial(self):
        self._companion_msg_polling = False
        with self._lock:
            if self.serial_port and self.serial_port.is_open:
                port_name = self.config.serial_port
                try:
                    self.serial_port.close()
                    self.logger.info("Serial port %s closed.", port_name)
                except Exception as e:
                    self.logger.error(
                        "Error closing serial port %s: %s",
                        port_name,
                        e,
                        exc_info=True,
                    )
                finally:
                    self.serial_port = None
                    self._is_connected.clear()
                    self.metrics.record_external_disconnection()
                    self.health_monitor.update_component(
                        "external", HealthStatus.UNHEALTHY, "Disconnected"
                    )

    def _serial_receiver_loop(self):
        """Continuously reads from serial using Protocol Handler, translates,
        and queues."""
        self.logger.info("Serial receiver loop started.")
        while not self.shutdown_event.is_set():
            # Placeholder: ACK/event handling logic could be added here
            # --- Connection Check ---
            if not self._is_connected.is_set():
                self.logger.warning(
                    "Serial port %s not connected. "
                    "Attempting reconnect...",
                    self.config.serial_port,
                )
                if self.connect():
                    self.logger.info(
                        "Serial device reconnected on %s",
                        self.config.serial_port,
                    )
                else:
                    self.shutdown_event.wait(self.RECONNECT_DELAY_S)
                    continue

            # --- Read and Process Data ---
            try:
                raw_data: Optional[bytes] = None
                decoded_msg: Optional[Dict[str, Any]] = None
                with self._lock:
                    if self.serial_port and self.serial_port.is_open:
                        # Delegate reading to protocol handler
                        raw_data = self.protocol_handler.read(self.serial_port)
                    else:
                        self._is_connected.clear()
                        continue

                if raw_data:
                    if self._protocol_name != "companion_radio" or self._companion_debug:
                        self.logger.debug(f"Serial RAW RX: {raw_data!r}")
                    self.health_monitor.update_component(
                        "external", HealthStatus.HEALTHY, "Serial RX received"
                    )
                    decoded_msg = (
                        self.protocol_handler.decode(raw_data)
                    )
                    self.logger.debug(f"Decoded serial message: {decoded_msg}")

                    if decoded_msg:
                        # Reset failure count on successful decode
                        self._failure_count = 0
                        if decoded_msg.get("internal_only"):
                            kind = decoded_msg.get("companion_kind")
                            self.logger.info(
                                "Companion event: %s", kind
                            )
                            # Handle message polling
                            if kind == "msg_waiting":
                                if not self._companion_msg_polling:
                                    self._companion_msg_polling = True
                                    self._send_sync_next_message()
                            elif kind == "no_more_messages":
                                self._companion_msg_polling = False
                            continue
                        if self._protocol_name == "companion_radio" and "payload" not in decoded_msg:
                            self.logger.debug("Skipping non-message companion frame.")
                            continue
                        is_valid, error_msg = (
                            self.validator.validate_external_message(
                                decoded_msg
                            )
                        )
                        if not is_valid:
                            self.logger.warning(
                                f"Invalid external message rejected: {error_msg}"
                            )
                            self.metrics.record_error("external")
                            continue

                        if not self.rate_limiter.check_rate_limit(
                            "serial_receiver"
                        ):
                            self.logger.warning(
                                "Rate limit exceeded for Serial receiver"
                            )
                            self.metrics.record_rate_limit_violation(
                                "serial_receiver"
                            )
                            continue

                        decoded_msg = self.validator.sanitize_external_message(
                            decoded_msg
                        )

                        dest_meshtastic_id = decoded_msg.get(
                            "destination_meshtastic_id"
                        )
                        payload = decoded_msg.get("payload")
                        payload_json = decoded_msg.get("payload_json")
                        channel_index = decoded_msg.get("channel_index", 0)
                        want_ack = decoded_msg.get("want_ack", False)

                        text_payload_str: Optional[str] = None
                        if isinstance(payload, str):
                            text_payload_str = payload
                        elif payload_json is not None:
                            try:
                                text_payload_str = json.dumps(payload_json)
                            except (TypeError, ValueError) as e:
                                self.logger.error(
                                    f"Failed to serialize payload_json: {e}"
                                )
                        elif payload is not None:
                            text_payload_str = str(payload)

                        self.logger.debug(f"Translation: dest={dest_meshtastic_id}, text={text_payload_str}, channel={channel_index}, want_ack={want_ack}")

                        if dest_meshtastic_id and text_payload_str is not None:
                            meshtastic_msg = {
                                "destination": dest_meshtastic_id,
                                "text": text_payload_str,
                                "channel_index": channel_index,
                                "want_ack": want_ack,
                            }
                            try:
                                self.to_meshtastic_queue.put_nowait(
                                    meshtastic_msg
                                )
                                payload_size = (
                                    len(text_payload_str.encode("utf-8"))
                                    if text_payload_str
                                    else 0
                                )
                                self.metrics.record_external_received(
                                    payload_size
                                )
                                self.logger.info(
                                    f"Queued message for Meshtastic {dest_meshtastic_id}"
                                )
                                # Continue polling if active
                                if (
                                    self._protocol_name == "companion_radio"
                                    and self._companion_msg_polling
                                ):
                                    self._send_sync_next_message()
                            except Full:
                                self.logger.warning(
                                    "Meshtastic queue full; dropping message."
                                )
                                self.metrics.record_dropped("external")
                        else:
                            self.logger.warning(
                                "Decoded serial message missing fields."
                            )
                            self.logger.debug(f"Decoded: {decoded_msg}")
                else:
                    # No data available - sleep briefly to avoid CPU spin
                    time.sleep(0.1)

                # Track decode failures for protocol auto-switching
                if raw_data and not decoded_msg:
                    self._failure_count += 1
                    if self._failure_count >= self.AUTO_DETECT_FAILURE_THRESHOLD:
                        self._switch_protocol()
                        self._failure_count = 0

            except serial.SerialException as e:
                self.logger.error(
                    "Serial error in receiver loop (%s): %s",
                    self.config.serial_port,
                    e,
                )
                self.logger.info("Attempting to reconnect...")
                self._close_serial()
                time.sleep(1)
            except Exception as e:
                self.logger.error(
                    "Unexpected error in serial_receiver_loop: %s",
                    e,
                    exc_info=True,
                )
                self._close_serial()
                time.sleep(self.RECONNECT_DELAY_S / 2)

        self.logger.info("Serial receiver loop stopped.")

    def _serial_sender_loop(self):
        """Continuously reads from the queue, encodes, and sends
        messages via Serial."""
        self.logger.info("Serial sender loop started.")
        while not self.shutdown_event.is_set():
            if not self._is_connected.is_set():
                time.sleep(self.RECONNECT_DELAY_S / 2)
                continue

            try:
                item: Optional[Dict[str, Any]] = self.to_serial_queue.get(
                    timeout=1
                )
                if not item:
                    self.to_serial_queue.task_done()
                    continue
                encoded_message: Optional[bytes] = None
                if self._protocol_name == "companion_radio":
                    encoded_message = self._encode_companion_from_meshtastic(item)
                    if encoded_message is None:
                        self.to_serial_queue.task_done()
                        continue
                else:
                    encoded_message = self.protocol_handler.encode(item)

                if encoded_message:
                    # Truncate log for binary safety
                    log_preview = repr(encoded_message[:50])
                    self.logger.info(
                        "Serial TX port %s payload %s",
                        self.config.serial_port,
                        log_preview,
                    )

                    send_success = False
                    with self._lock:
                        if self.serial_port and self.serial_port.is_open:
                            try:
                                self.serial_port.write(encoded_message)
                                self.serial_port.flush()
                                send_success = True
                                self.metrics.record_external_sent(
                                    len(encoded_message)
                                )
                            except serial.SerialException as e:
                                self.logger.error(
                                    "Serial error during send (%s): %s.",
                                    self.config.serial_port,
                                    e
                                )
                                self._close_serial()
                            except Exception as e:
                                self.logger.error(
                                    "Unexpected error sending Serial "
                                    "message: %s",
                                    e,
                                    exc_info=True,
                                )
                        else:
                            self.logger.warning(
                                "Serial port disconnected before send."
                            )
                            self._is_connected.clear()

                    if send_success:
                        # Update health on every successful send
                        self.health_monitor.update_component(
                            "external", HealthStatus.HEALTHY, "Serial TX sent"
                        )
                        self.to_serial_queue.task_done()
                    else:
                        self.logger.error(
                            "Failed to send Serial message. Discarding."
                        )
                        self.to_serial_queue.task_done()
                else:
                    self.logger.error(
                        "Failed to encode message for Serial: %s",
                        item
                    )
                    self.to_serial_queue.task_done()

            except Empty:
                continue
            except Exception as e:
                self.logger.error(
                    "Critical error in serial_sender_loop: %s",
                    e,
                    exc_info=True,
                )
                self._is_connected.clear()
                time.sleep(5)

        self.logger.info("Serial sender loop stopped.")

    def _encode_companion_from_meshtastic(self, item: Dict[str, Any]) -> Optional[bytes]:
        """Encode Meshtastic-originated messages into MeshCore companion commands."""
        msg_type = item.get("type")
        if msg_type != "meshtastic_message":
            self.logger.debug(
                "Skipping non-text Meshtastic message for companion: %s",
                msg_type,
            )
            return None

        payload = item.get("payload")
        if not isinstance(payload, str):
            self.logger.warning(
                "Unsupported Meshtastic payload type for companion: %s",
                type(payload),
            )
            return None

        # CMD_SEND_CHANNEL_TXT_MSG (3)
        txt_type = 0
        channel_idx = int(item.get("channel_index", 0))
        sender_ts = int(time.time())
        text_bytes = payload.encode("utf-8")
        cmd_payload = bytes([3, txt_type, channel_idx]) + sender_ts.to_bytes(4, "little") + text_bytes

        encoded = self.protocol_handler.encode({"payload": cmd_payload})
        if not encoded:
            self.logger.warning("Failed to encode companion text message.")
        return encoded
