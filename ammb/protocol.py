# ammb/protocol.py
"""
Defines handlers for different **Serial** communication
protocols.

Allows the bridge (specifically the MeshcoreHandler) to
encode/decode messages based on the serial protocol specified
in the configuration.

Includes:
- JsonNewlineProtocol: For text-based JSON (default).
- RawSerialProtocol: For binary/companion modes (fallback).
"""

import binascii
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


# --- Base Class ---
class MeshcoreProtocolHandler(ABC):
    """
    Abstract base class for **Serial** protocol handling.

    Subclasses implement read, encode, and decode methods.
    """

    def __init__(self):
        # Logger named after the subclass
        name = __name__ + "." + self.__class__.__name__
        self.logger = logging.getLogger(name)
        self.logger.debug("Serial protocol handler initialized.")

    @abstractmethod
    def read(self, serial_port) -> Optional[bytes]:
        """
        Reads data from the serial port.

        Implementations should return bytes read, or None.
        """
        pass

    @abstractmethod
    def encode(self, data: Dict[str, Any]) -> Optional[bytes]:
        """
        Encodes a dictionary payload into bytes for sending over serial.
        """
        pass

    @abstractmethod
    def decode(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Decodes bytes received from serial into a dictionary.
        """
        pass


# --- Concrete Implementations ---


class JsonNewlineProtocol(MeshcoreProtocolHandler):
    """
    Handles newline-terminated JSON strings encoded in UTF-8 over **Serial**.
    """

    def read(self, serial_port) -> Optional[bytes]:
        """Reads a single line ending in \\n."""
        if serial_port.in_waiting > 0:
            return serial_port.readline()
        return None

    def encode(self, data: Dict[str, Any]) -> Optional[bytes]:
        try:
            encoded_message = json.dumps(data).encode("utf-8") + b"\n"
            self.logger.debug("Encoded: %r", encoded_message)
            return encoded_message
        except (TypeError, ValueError) as e:
            self.logger.error(
                "JSON Encode Error: %s - Data: %s",
                e,
                data,
                exc_info=True,
            )
            return None
        except Exception as e:
            self.logger.error(
                "Unexpected serial encoding error: %s",
                e,
                exc_info=True,
            )
            return None

    def decode(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        try:
            decoded_str = raw_data.decode("utf-8", errors="replace").strip()
            if not decoded_str:
                return None

            decoded_data = json.loads(decoded_str)
            if not isinstance(decoded_data, dict):
                self.logger.warning(
                    "Decoded JSON is not a dictionary: %r",
                    decoded_str,
                )
                return None
            return decoded_data
        except json.JSONDecodeError:
            self.logger.warning(
                "Received non-JSON or incomplete JSON line: %r",
                raw_data,
            )
            return None
        except Exception as e:
            self.logger.error(
                "Error decoding serial data: %s - Raw: %r",
                e,
                raw_data,
            )
            return None


class RawSerialProtocol(MeshcoreProtocolHandler):
    """
    Handles RAW Binary data from the serial port. Use for 'Companion USB Mode'.
    """

    def read(self, serial_port) -> Optional[bytes]:
        """Reads all currently available bytes from the buffer."""
        if serial_port.in_waiting > 0:
            return serial_port.read(serial_port.in_waiting)
        return None

    def encode(self, data: Dict[str, Any]) -> Optional[bytes]:
        """Encodes outgoing data."""
        try:
            payload = data.get("payload", "")
            if isinstance(payload, str):
                return payload.encode("utf-8")
            elif isinstance(payload, (bytes, bytearray)):
                return payload
            return None
        except Exception as e:
            self.logger.error("Error encoding raw data: %s", e)
            return None

    def decode(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        """Wraps received raw bytes into a bridge-compatible dictionary."""
        if not raw_data:
            return None

        try:
            hex_str = binascii.hexlify(raw_data).decode("ascii")
            return {
                "destination_meshtastic_id": "^all",
                "payload": "MC_BIN: " + hex_str,
                "raw_binary": True,
            }
        except Exception as e:
            self.logger.error("Error processing raw binary: %s", e)
            return None


# --- Factory Function ---


# --- Meshcore Companion Radio Protocol Handler ---
import struct

class MeshcoreCompanionProtocol(MeshcoreProtocolHandler):
    """
    Handles the Meshcore Companion Radio Protocol (USB framing).
    Outbound (radio -> app): [0x3E][len_le][payload...]
    Inbound  (app -> radio): [0x3C][len_le][payload...]
    """

    OUTBOUND_START = 0x3E  # '>'
    INBOUND_START = 0x3C   # '<'

    def __init__(self):
        super().__init__()
        self._rx_buffer = bytearray()

    def read(self, serial_port) -> Optional[bytes]:
        """Reads and returns a single outbound payload frame (without framing)."""
        if serial_port.in_waiting > 0:
            chunk = serial_port.read(serial_port.in_waiting)
            if chunk:
                self.logger.debug("Companion RAW bytes: %s", chunk.hex())
                self._rx_buffer.extend(chunk)

        while True:
            if len(self._rx_buffer) < 3:
                return None

            if self._rx_buffer[0] != self.OUTBOUND_START:
                # Resync to next '>'
                try:
                    next_idx = self._rx_buffer.index(self.OUTBOUND_START)
                    del self._rx_buffer[:next_idx]
                except ValueError:
                    self._rx_buffer.clear()
                    return None

            if len(self._rx_buffer) < 3:
                return None

            length = self._rx_buffer[1] | (self._rx_buffer[2] << 8)
            frame_len = 3 + length
            if len(self._rx_buffer) < frame_len:
                return None

            payload = bytes(self._rx_buffer[3:frame_len])
            del self._rx_buffer[:frame_len]
            return payload

    def encode(self, data: Dict[str, Any]) -> Optional[bytes]:
        """Encodes a payload dict into an inbound frame."""
        try:
            payload = data.get("payload", b"")
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            elif not isinstance(payload, (bytes, bytearray)):
                return None
            length = len(payload)
            frame = bytearray()
            frame.append(self.INBOUND_START)
            frame.append(length & 0xFF)
            frame.append((length >> 8) & 0xFF)
            frame.extend(payload)
            return bytes(frame)
        except Exception as e:
            self.logger.error("Error encoding companion frame: %s", e)
            return None

    def decode(self, raw_data: bytes) -> Optional[Dict[str, Any]]:
        """Decode companion payload bytes into a dict.

        Handles RESP codes (from CMD_SYNC_NEXT_MESSAGE) and PUSH codes
        (unsolicited events from the radio).  PUSH codes (>=0x80) have
        their own meanings and must NOT be mapped via base_code masking.
        """
        if not raw_data:
            return None

        code = raw_data[0]

        # --- RESP codes (responses to CMD_SYNC_NEXT_MESSAGE) ---

        # V3 contact message (code 16 / 0x10)
        if code == 16:  # RESP_CODE_CONTACT_MSG_RECV_V3
            if len(raw_data) < 1 + 1 + 2 + 6 + 1 + 1 + 4:
                return None
            snr = raw_data[1]
            pubkey_prefix = raw_data[4:10]
            path_len = raw_data[10]
            txt_type = raw_data[11]
            sender_ts = int.from_bytes(
                raw_data[12:16], "little", signed=False
            )
            text_bytes = raw_data[16:]
            text = text_bytes.decode("utf-8", errors="replace")
            return {
                "destination_meshtastic_id": "^all",
                "payload": text,
                "channel_index": 0,
                "companion_kind": "contact_msg",
                "sender_pubkey_prefix": pubkey_prefix.hex(),
                "path_len": path_len,
                "txt_type": txt_type,
                "snr": snr,
                "sender_timestamp": sender_ts,
                "protocol": "companion_radio",
            }

        # Legacy contact message (code 7)
        if code == 7:  # RESP_CODE_CONTACT_MSG_RECV
            if len(raw_data) < 1 + 6 + 1 + 1 + 4:
                return None
            pubkey_prefix = raw_data[1:7]
            path_len = raw_data[7]
            txt_type = raw_data[8]
            sender_ts = int.from_bytes(raw_data[9:13], "little", signed=False)
            text_bytes = raw_data[13:]
            text = text_bytes.decode("utf-8", errors="replace")
            return {
                "destination_meshtastic_id": "^all",
                "payload": text,
                "channel_index": 0,
                "companion_kind": "contact_msg",
                "sender_pubkey_prefix": pubkey_prefix.hex(),
                "path_len": path_len,
                "txt_type": txt_type,
                "sender_timestamp": sender_ts,
                "protocol": "companion_radio",
            }

        # V3 channel message (code 17 / 0x11)
        if code == 17:  # RESP_CODE_CHANNEL_MSG_RECV_V3
            if len(raw_data) < 1 + 1 + 2 + 1 + 1 + 1 + 4:
                return None
            snr = raw_data[1]
            channel_idx = raw_data[4]
            path_len = raw_data[5]
            txt_type = raw_data[6]
            sender_ts = int.from_bytes(
                raw_data[7:11], "little", signed=False
            )
            text_bytes = raw_data[11:]
            text = text_bytes.decode("utf-8", errors="replace")
            return {
                "destination_meshtastic_id": "^all",
                "payload": text,
                "channel_index": channel_idx,
                "companion_kind": "channel_msg",
                "path_len": path_len,
                "txt_type": txt_type,
                "snr": snr,
                "sender_timestamp": sender_ts,
                "protocol": "companion_radio",
            }

        # Legacy channel message (code 8)
        if code == 8:  # RESP_CODE_CHANNEL_MSG_RECV
            if len(raw_data) < 1 + 1 + 1 + 1 + 4:
                return None
            channel_idx = raw_data[1]
            path_len = raw_data[2]
            txt_type = raw_data[3]
            sender_ts = int.from_bytes(raw_data[4:8], "little", signed=False)
            text_bytes = raw_data[8:]
            text = text_bytes.decode("utf-8", errors="replace")
            return {
                "destination_meshtastic_id": "^all",
                "payload": text,
                "channel_index": channel_idx,
                "companion_kind": "channel_msg",
                "path_len": path_len,
                "txt_type": txt_type,
                "sender_timestamp": sender_ts,
                "protocol": "companion_radio",
            }

        if code == 0:  # RESP_CODE_OK
            return {
                "companion_kind": "ok",
                "internal_only": True,
                "protocol": "companion_radio",
            }

        if code == 1:  # RESP_CODE_ERR
            err_code = raw_data[1] if len(raw_data) > 1 else None
            return {
                "companion_kind": "err",
                "error_code": err_code,
                "internal_only": True,
                "protocol": "companion_radio",
            }

        if code == 6:  # RESP_CODE_SENT
            if len(raw_data) < 1 + 1 + 4 + 4:
                return None
            send_type = raw_data[1]
            ack_tag = raw_data[2:6]
            timeout_ms = int.from_bytes(raw_data[6:10], "little", signed=False)
            return {
                "companion_kind": "sent",
                "send_type": send_type,
                "ack_tag": ack_tag.hex(),
                "timeout_ms": timeout_ms,
                "internal_only": True,
                "protocol": "companion_radio",
            }

        if code == 10:  # RESP_CODE_NO_MORE_MESSAGES
            return {
                "companion_kind": "no_more_messages",
                "internal_only": True,
                "protocol": "companion_radio",
            }

        # --- PUSH codes (unsolicited events from the radio) ---

        if code == 0x82:  # PUSH_CODE_SEND_CONFIRMED
            if len(raw_data) < 1 + 4 + 4:
                return None
            ack_code = raw_data[1:5]
            round_trip = int.from_bytes(raw_data[5:9], "little", signed=False)
            return {
                "companion_kind": "send_confirmed",
                "ack_code": ack_code.hex(),
                "round_trip_ms": round_trip,
                "internal_only": True,
                "protocol": "companion_radio",
            }

        if code == 0x83:  # PUSH_CODE_MSG_WAITING
            return {
                "companion_kind": "msg_waiting",
                "internal_only": True,
                "protocol": "companion_radio",
            }

        if code == 0x80:  # PUSH_CODE_ADVERT
            if len(raw_data) < 1 + 32:
                return None
            pubkey = raw_data[1:33]
            self.logger.info("MeshCore advert from: %s", pubkey[:4].hex())
            return {
                "companion_kind": "advert",
                "pubkey": pubkey.hex(),
                "internal_only": True,
                "protocol": "companion_radio",
            }

        if code == 0x8A:  # PUSH_CODE_NEW_ADVERT
            if len(raw_data) < 1 + 32:
                return None
            pubkey = raw_data[1:33]
            self.logger.info("MeshCore new advert from: %s", pubkey[:4].hex())
            return {
                "companion_kind": "new_advert",
                "pubkey": pubkey.hex(),
                "internal_only": True,
                "protocol": "companion_radio",
            }

        # Ignore non-message frames (device info, log data, etc.)
        self.logger.debug("Ignoring companion frame code: 0x%02x", code)
        return None

_serial_protocol_handlers = {
    "json_newline": JsonNewlineProtocol,
    "raw_serial": RawSerialProtocol,
    "companion_radio": MeshcoreCompanionProtocol,
}


def get_serial_protocol_handler(protocol_name: str) -> MeshcoreProtocolHandler:
    """Factory function to get an instance of the appropriate
    **Serial** protocol handler."""
    logger = logging.getLogger(__name__)
    protocol_name_lower = protocol_name.lower()
    handler_class = _serial_protocol_handlers.get(protocol_name_lower)

    if handler_class:
        logger.info(
            "Using Serial protocol handler: %s",
            handler_class.__name__,
        )
        return handler_class()
    else:
        logger.error(
            "Unsupported Serial protocol: %s. "
            "Available: %s",
            protocol_name,
            list(_serial_protocol_handlers.keys()),
        )
        raise ValueError(f"Unsupported Serial protocol: {protocol_name}")
