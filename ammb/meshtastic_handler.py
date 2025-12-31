# ammb/meshtastic_handler.py
"""
Handles all interactions with the Meshtastic device and network.
"""

import logging
import threading
import time
from queue import Queue, Empty, Full
from typing import Optional, Dict, Any
import meshtastic
import meshtastic.serial_interface
from pubsub import pub
import serial

from .config_handler import BridgeConfig
from .metrics import get_metrics
from .health import get_health_monitor, HealthStatus
from .validator import MessageValidator
from .rate_limiter import RateLimiter

class MeshtasticHandler:
    """Manages connection and communication with the Meshtastic network."""
    RECONNECT_DELAY_S = 10

    def __init__(self, config: BridgeConfig, to_external_queue: Queue, from_external_queue: Queue, shutdown_event: threading.Event):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.to_external_queue = to_external_queue
        self.to_meshtastic_queue = from_external_queue
        self.shutdown_event = shutdown_event

        self.interface: Optional[meshtastic.serial_interface.SerialInterface] = None
        self.my_node_id: Optional[str] = None
        self.sender_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._is_connected = threading.Event()
        
        # Initialize metrics, health, validator, and rate limiter
        self.metrics = get_metrics()
        self.health_monitor = get_health_monitor()
        self.validator = MessageValidator()
        self.rate_limiter = RateLimiter(max_messages=60, time_window=60.0)  # 60 messages per minute

    def connect(self) -> bool:
        with self._lock:
            if self.interface and self._is_connected.is_set():
                return True

            try:
                self.logger.info(f"Attempting connection to Meshtastic on {self.config.meshtastic_port}...")
                self._is_connected.clear()
                self.my_node_id = None
                if self.interface:
                    try: self.interface.close()
                    except Exception: pass

                self.interface = meshtastic.serial_interface.SerialInterface(
                    self.config.meshtastic_port
                )

                my_info = self.interface.getMyNodeInfo()
                retry_count = 0
                while (not my_info or 'num' not in my_info) and retry_count < 3:
                     time.sleep(2)
                     my_info = self.interface.getMyNodeInfo()
                     retry_count += 1

                if my_info and 'num' in my_info:
                    self.my_node_id = f"!{my_info['num']:x}"
                    user_id = my_info.get('user', {}).get('id', 'N/A')
                    self.logger.info(f"Connected to Meshtastic device. Node ID: {self.my_node_id} ('{user_id}')")
                    self._is_connected.set()
                    self.metrics.record_meshtastic_connection()
                    self.health_monitor.update_component("meshtastic", HealthStatus.HEALTHY, "Connected")
                else:
                     self.logger.warning("Connected to Meshtastic, but failed to retrieve node info. Loopback detection unreliable.")
                     self._is_connected.set()
                     self.metrics.record_meshtastic_connection()
                     self.health_monitor.update_component("meshtastic", HealthStatus.DEGRADED, "Connected but node info unavailable")

                pub.subscribe(self._on_meshtastic_receive, "meshtastic.receive", weak=False)
                self.logger.info("Meshtastic receive callback registered.")
                return True

            except Exception as e:
                self.logger.error(f"Error connecting to Meshtastic device {self.config.meshtastic_port}: {e}", exc_info=False)
                if self.interface:
                     try: self.interface.close()
                     except Exception: pass
                self.interface = None
                self.my_node_id = None
                self._is_connected.clear()
                self.metrics.record_meshtastic_disconnection()
                self.health_monitor.update_component("meshtastic", HealthStatus.UNHEALTHY, f"Connection failed: {e}")
                return False

    def start_sender(self):
        if self.sender_thread and self.sender_thread.is_alive():
            return
        self.logger.info("Starting Meshtastic sender thread...")
        self.sender_thread = threading.Thread(target=self._meshtastic_sender_loop, daemon=True, name="MeshtasticSender")
        self.sender_thread.start()

    def stop(self):
        self.logger.info("Stopping Meshtastic handler...")
        try:
            pub.unsubscribe(self._on_meshtastic_receive, "meshtastic.receive")
        except Exception: pass

        with self._lock:
            if self.interface:
                try:
                    self.interface.close()
                except Exception as e:
                    self.logger.error(f"Error closing Meshtastic interface: {e}")
                finally:
                    self.interface = None
                    self.my_node_id = None
                    self._is_connected.clear()
                    self.metrics.record_meshtastic_disconnection()
                    self.health_monitor.update_component("meshtastic", HealthStatus.UNHEALTHY, "Disconnected")

        if self.sender_thread and self.sender_thread.is_alive():
             self.sender_thread.join(timeout=5)

        self.logger.info("Meshtastic handler stopped.")

    def _on_meshtastic_receive(self, packet: Dict[str, Any], interface: Any):
        try:
            if not packet or 'from' not in packet:
                return

            sender_id_num = packet.get('from')
            sender_id_hex = f"!{sender_id_num:x}" if isinstance(sender_id_num, int) else "UNKNOWN"
            portnum = packet.get('decoded', {}).get('portnum', 'UNKNOWN')
            payload_bytes = packet.get('decoded', {}).get('payload')
            
            # Loopback Prevention
            bridge_id_lower = self.config.bridge_node_id.lower() if self.config.bridge_node_id else None
            my_node_id_lower = self.my_node_id.lower() if self.my_node_id else None
            sender_id_lower = sender_id_hex.lower()

            if (bridge_id_lower and sender_id_lower == bridge_id_lower) or \
               (my_node_id_lower and sender_id_lower == my_node_id_lower):
                 return

            portnum_str = str(portnum) if portnum else 'UNKNOWN'
            translated_payload = None
            message_type = "meshtastic_message"

            if portnum_str == 'TEXT_MESSAGE_APP' and payload_bytes:
                try:
                    text_payload = payload_bytes.decode('utf-8', errors='replace')
                    self.logger.info(f"Meshtastic RX <{portnum_str}> From {sender_id_hex}: '{text_payload}'")
                    translated_payload = text_payload
                except UnicodeDecodeError:
                    translated_payload = repr(payload_bytes)

            elif portnum_str == 'POSITION_APP':
                 pos_data = packet.get('decoded', {}).get('position', {})
                 translated_payload = {
                      "latitude": pos_data.get('latitude'),
                      "longitude": pos_data.get('longitude'),
                      "altitude": pos_data.get('altitude'),
                      "timestamp_gps": pos_data.get('time')
                 }
                 message_type = "meshtastic_position"

            else:
                return

            if translated_payload is not None:
                external_message = {
                    "type": message_type,
                    "sender_meshtastic_id": sender_id_hex,
                    "portnum": portnum_str,
                    "payload": translated_payload,
                    "timestamp_rx": time.time(),
                    "rx_rssi": packet.get('rxRssi'),
                    "rx_snr": packet.get('rxSnr'),
                }

                try:
                    self.to_external_queue.put_nowait(external_message)
                    payload_size = len(str(translated_payload).encode('utf-8')) if translated_payload else 0
                    self.metrics.record_meshtastic_received(payload_size)
                    self.logger.debug(f"Queued message from {sender_id_hex} for external handler.")
                except Full:
                    self.logger.warning("External handler send queue is full.")
                    self.metrics.record_dropped("meshtastic")

        except Exception as e:
            self.logger.error(f"Error in _on_meshtastic_receive callback: {e}", exc_info=True)

    def _meshtastic_sender_loop(self):
        self.logger.info("Meshtastic sender loop started.")
        while not self.shutdown_event.is_set():
            try:
                item: Optional[Dict[str, Any]] = self.to_meshtastic_queue.get(timeout=1)
                if not item: continue

                if not self._is_connected.is_set():
                     self.to_meshtastic_queue.task_done()
                     time.sleep(self.RECONNECT_DELAY_S / 2)
                     continue

                # Validate and sanitize message
                is_valid, error_msg = self.validator.validate_meshtastic_message(item)
                if not is_valid:
                    self.logger.warning(f"Invalid message rejected: {error_msg}")
                    self.metrics.record_error("meshtastic")
                    self.to_meshtastic_queue.task_done()
                    continue

                # Check rate limit
                if not self.rate_limiter.check_rate_limit("meshtastic_sender"):
                    self.logger.warning("Rate limit exceeded for Meshtastic sender")
                    self.metrics.record_rate_limit_violation("meshtastic_sender")
                    self.to_meshtastic_queue.task_done()
                    continue

                # Sanitize message
                item = self.validator.sanitize_meshtastic_message(item)

                destination = item.get('destination')
                text_to_send = item.get('text')
                channel_index = item.get('channel_index', 0)
                want_ack = item.get('want_ack', False)

                if destination and isinstance(text_to_send, str):
                    log_payload = (text_to_send[:100] + '...') if len(text_to_send) > 100 else text_to_send
                    self.logger.info(f"Meshtastic TX -> Dest: {destination}, Payload: '{log_payload}'")

                    send_success = False
                    with self._lock:
                        if self.interface and self._is_connected.is_set():
                            try:
                                self.interface.sendText(
                                    text=text_to_send,
                                    destinationId=destination,
                                    channelIndex=channel_index,
                                    wantAck=want_ack
                                )
                                send_success = True
                                payload_size = len(text_to_send.encode('utf-8'))
                                self.metrics.record_meshtastic_sent(payload_size)
                            except Exception as e:
                                 self.logger.error(f"Error sending Meshtastic message: {e}")
                                 if "Not connected" in str(e): self._is_connected.clear()
                        else:
                             self._is_connected.clear()

                    self.to_meshtastic_queue.task_done()
                else:
                    self.to_meshtastic_queue.task_done()

            except Empty:
                if not self._is_connected.is_set(): time.sleep(self.RECONNECT_DELAY_S)
                continue
            except Exception as e:
                self.logger.error(f"Critical error in meshtastic_sender_loop: {e}", exc_info=True)
                self._is_connected.clear()
                time.sleep(5)

        self.logger.info("Meshtastic sender loop stopped.")
