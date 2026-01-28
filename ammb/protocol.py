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

_serial_protocol_handlers = {
    "json_newline": JsonNewlineProtocol,
    "raw_serial": RawSerialProtocol,
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
