# ammb/meshcore_handler.py
"""
Handles interactions with an external device via a **Serial** port.
"""

import logging
import threading
import time
import json 
from queue import Queue, Empty, Full
from typing import Optional, Dict, Any
import serial

from .config_handler import BridgeConfig
from .protocol import MeshcoreProtocolHandler, get_serial_protocol_handler

class MeshcoreHandler:
    """Manages Serial connection and communication with an external device."""
    RECONNECT_DELAY_S = 10 

    def __init__(self, config: BridgeConfig, to_meshtastic_queue: Queue, from_meshtastic_queue: Queue, shutdown_event: threading.Event):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.to_meshtastic_queue = to_meshtastic_queue
        self.to_serial_queue = from_meshtastic_queue 
        self.shutdown_event = shutdown_event

        self.serial_port: Optional[serial.Serial] = None
        self.receiver_thread: Optional[threading.Thread] = None
        self.sender_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock() 
        self._is_connected = threading.Event() 

        if not config.serial_port or not config.serial_baud or not config.serial_protocol:
            raise ValueError("Serial transport selected, but required SERIAL configuration options are missing.")

        try:
            self.protocol_handler: MeshcoreProtocolHandler = get_serial_protocol_handler(config.serial_protocol)
        except ValueError as e:
            self.logger.critical(f"Failed to initialize serial protocol handler '{config.serial_protocol}': {e}.")
            class DummyHandler(MeshcoreProtocolHandler):
                def read(self, port): return None
                def encode(self, data): return None
                def decode(self, line): return None
            self.protocol_handler = DummyHandler()

        self.logger.info("Serial Handler (MeshcoreHandler) Initialized.")


    def connect(self) -> bool:
        with self._lock: 
            if self.serial_port and self.serial_port.is_open:
                self.logger.info(f"Serial port {self.config.serial_port} already connected.")
                self._is_connected.set() 
                return True

            try:
                self.logger.info(f"Attempting connection to Serial device on {self.config.serial_port} at {self.config.serial_baud} baud...")
                self._is_connected.clear()
                if self.serial_port: 
                     try:
                          self.serial_port.close()
                     except Exception: pass

                self.serial_port = serial.Serial(
                    port=self.config.serial_port,
                    baudrate=self.config.serial_baud,
                    timeout=1, 
                )
                if self.serial_port.is_open:
                    self.logger.info(f"Connected to Serial device on {self.config.serial_port}")
                    self._is_connected.set() 
                    return True
                else:
                    self.logger.error(f"Failed to open serial port {self.config.serial_port}, but no exception was raised.")
                    self.serial_port = None
                    self._is_connected.clear()
                    return False

            except serial.SerialException as e:
                self.logger.error(f"Serial error connecting to device {self.config.serial_port}: {e}")
                self.serial_port = None
                self._is_connected.clear()
                return False
            except Exception as e:
                self.logger.error(f"Unexpected error connecting to serial device: {e}", exc_info=True)
                self.serial_port = None
                self._is_connected.clear()
                return False

    def start_threads(self):
        if self.receiver_thread and self.receiver_thread.is_alive():
            self.logger.warning("Serial receiver thread already started.")
        else:
            self.logger.info("Starting Serial receiver thread...")
            self.receiver_thread = threading.Thread(target=self._serial_receiver_loop, daemon=True, name="SerialReceiver")
            self.receiver_thread.start()

        if self.sender_thread and self.sender_thread.is_alive():
            self.logger.warning("Serial sender thread already started.")
        else:
            self.logger.info("Starting Serial sender thread...")
            self.sender_thread = threading.Thread(target=self._serial_sender_loop, daemon=True, name="SerialSender")
            self.sender_thread.start()

    def stop(self):
        self.logger.info("Stopping Serial handler...")
        if self.receiver_thread and self.receiver_thread.is_alive():
             self.receiver_thread.join(timeout=2) 
        if self.sender_thread and self.sender_thread.is_alive():
             self.sender_thread.join(timeout=5)
        self._close_serial()
        self.logger.info("Serial handler stopped.")

    def _close_serial(self):
        with self._lock:
            if self.serial_port and self.serial_port.is_open:
                port_name = self.config.serial_port
                try:
                    self.serial_port.close()
                    self.logger.info(f"Serial port {port_name} closed.")
                except Exception as e:
                    self.logger.error(f"Error closing serial port {port_name}: {e}", exc_info=True)
                finally:
                    self.serial_port = None
                    self._is_connected.clear() 

    def _serial_receiver_loop(self):
        """Continuously reads from serial using Protocol Handler, translates, and queues."""
        self.logger.info("Serial receiver loop started.")
        while not self.shutdown_event.is_set():
            # --- Connection Check ---
            if not self._is_connected.is_set():
                self.logger.warning(f"Serial port {self.config.serial_port} not connected. Attempting reconnect...")
                if self.connect(): 
                    self.logger.info(f"Serial device reconnected successfully on {self.config.serial_port}.")
                else:
                    self.shutdown_event.wait(self.RECONNECT_DELAY_S)
                    continue 

            # --- Read and Process Data ---
            try:
                raw_data: Optional[bytes] = None
                with self._lock:
                     if self.serial_port and self.serial_port.is_open:
                          # Delegate reading to protocol handler
                          raw_data = self.protocol_handler.read(self.serial_port)
                     else:
                          self._is_connected.clear()
                          continue

                if raw_data:
                    self.logger.debug(f"Serial RAW RX: {raw_data!r}")
                    
                    # Decode using the selected protocol handler
                    decoded_msg: Optional[Dict[str, Any]] = self.protocol_handler.decode(raw_data)

                    if decoded_msg:
                        # Basic Translation Logic (Serial -> Meshtastic)
                        dest_meshtastic_id = decoded_msg.get("destination_meshtastic_id")
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
                                self.logger.error(f"Failed to serialize payload_json: {e}")
                        elif payload is not None: 
                             text_payload_str = str(payload) 

                        if dest_meshtastic_id and text_payload_str is not None:
                            meshtastic_msg = {
                                "destination": dest_meshtastic_id,
                                "text": text_payload_str,
                                "channel_index": channel_index,
                                "want_ack": want_ack,
                            }

                            try:
                                self.to_meshtastic_queue.put_nowait(meshtastic_msg)
                                self.logger.info(f"Queued message from Serial for Meshtastic node {dest_meshtastic_id}")
                            except Full:
                                self.logger.warning("Meshtastic send queue is full. Dropping incoming message from Serial.")
                        else:
                            self.logger.warning(f"Serial RX: Decoded message lacks required fields: {decoded_msg}")
                else:
                    # No data available from serial, sleep briefly to prevent CPU spin
                    time.sleep(0.1)

            except serial.SerialException as e:
                self.logger.error(f"Serial error in receiver loop ({self.config.serial_port}): {e}. Attempting to reconnect...")
                self._close_serial() 
                time.sleep(1) 
            except Exception as e:
                self.logger.error(f"Unexpected error in serial_receiver_loop: {e}", exc_info=True)
                self._close_serial()
                time.sleep(self.RECONNECT_DELAY_S / 2) 

        self.logger.info("Serial receiver loop stopped.")


    def _serial_sender_loop(self):
        """Continuously reads from the queue, encodes, and sends messages via Serial."""
        self.logger.info("Serial sender loop started.")
        while not self.shutdown_event.is_set():
            if not self._is_connected.is_set():
                 time.sleep(self.RECONNECT_DELAY_S / 2)
                 continue

            try:
                item: Optional[Dict[str, Any]] = self.to_serial_queue.get(timeout=1)
                if not item:
                    continue

                encoded_message: Optional[bytes] = self.protocol_handler.encode(item)

                if encoded_message:
                    # Truncate log for binary safety
                    log_preview = repr(encoded_message[:50])
                    self.logger.info(f"Serial TX -> Port: {self.config.serial_port}, Payload: {log_preview}")

                    send_success = False
                    with self._lock:
                        if self.serial_port and self.serial_port.is_open:
                            try:
                                self.serial_port.write(encoded_message)
                                self.serial_port.flush() 
                                send_success = True
                            except serial.SerialException as e:
                                self.logger.error(f"Serial error during send ({self.config.serial_port}): {e}.")
                                self._close_serial() 
                            except Exception as e:
                                self.logger.error(f"Unexpected error sending Serial message: {e}", exc_info=True)
                        else:
                             self.logger.warning(f"Serial port disconnected just before send attempt.")
                             self._is_connected.clear()

                    if send_success:
                         self.to_serial_queue.task_done() 
                    else:
                         self.logger.error("Failed to send Serial message. Discarding.")
                         self.to_serial_queue.task_done()
                else:
                    self.logger.error(f"Failed to encode message for Serial: {item}")
                    self.to_serial_queue.task_done() 

            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"Critical error in serial_sender_loop: {e}", exc_info=True)
                self._is_connected.clear() 
                time.sleep(5) 

        self.logger.info("Serial sender loop stopped.")
