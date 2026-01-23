# ammb/validator.py
"""
Message validation and sanitization utilities.
"""

import logging
import re
from typing import Any, Dict, Optional, Tuple


class MessageValidator:
    """Validates and sanitizes messages."""

    def __init__(
        self,
        max_message_length: int = 240,
        max_payload_length: int = 1000,
    ):
        self.logger = logging.getLogger(__name__)
        self.max_message_length = max_message_length
        self.max_payload_length = max_payload_length

        # Patterns for validation
        self.meshtastic_id_pattern = re.compile(
            (
                r"^!?[0-9a-fA-F]{8}$|"
                r"^\^all$|"
                r"^\^broadcast$"
            )
        )
        self.safe_string_pattern = re.compile(
            r"^[\x20-\x7E\n\r\t]*$"
        )  # Printable ASCII + newlines/tabs

    def validate_meshtastic_id(self, node_id: str) -> bool:
        """Validate a Meshtastic node ID format."""
        if not isinstance(node_id, str):
            return False
        return bool(self.meshtastic_id_pattern.match(node_id))

    def sanitize_string(
        self, text: str, max_length: Optional[int] = None
    ) -> str:
        """Sanitize a string for safe transmission."""
        if not isinstance(text, str):
            text = str(text)

        # Remove nulls and control chars except newline/tab/CR
        sanitized = "".join(c for c in text if ord(c) >= 32 or c in "\n\r\t")

        # Truncate if needed
        max_len = max_length or self.max_message_length
        if len(sanitized) > max_len:
            sanitized = sanitized[:max_len]
            self.logger.warning("String truncated to %s characters", max_len)

        return sanitized

    def validate_meshtastic_message(
        self, message: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Validate a message destined for Meshtastic."""
        if not isinstance(message, dict):
            return False, "Message must be a dictionary"

        destination = message.get("destination")
        if not destination:
            return False, "Missing 'destination' field"

        if not self.validate_meshtastic_id(destination):
            return False, f"Invalid destination format: {destination}"

        text = message.get("text")
        if not isinstance(text, str):
            return False, "Missing or invalid 'text' field"

        if len(text) > self.max_message_length:
            msg = "Message too long: %s > %s" % (
                len(text), self.max_message_length
            )
            return False, msg

        channel_index = message.get("channel_index", 0)
        if not isinstance(channel_index, (int, str)):
            return False, "Invalid 'channel_index' type"

        try:
            channel_index = int(channel_index)
            if channel_index < 0 or channel_index > 7:
                return False, f"Channel index out of range: {channel_index}"
        except (ValueError, TypeError):
            return False, "Invalid 'channel_index' value"

        return True, None

    def validate_external_message(
        self, message: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Validate a message from external system."""
        if not isinstance(message, dict):
            return False, "Message must be a dictionary"

        # Check for required fields based on message type
        payload = message.get("payload")
        payload_json = message.get("payload_json")

        if payload is None and payload_json is None:
            return False, "Missing 'payload' or 'payload_json' field"

        destination = message.get("destination_meshtastic_id")
        if destination and not self.validate_meshtastic_id(destination):
            msg = (
                "Invalid destination_meshtastic_id format: %s" % (destination,)
            )
            return False, msg

        # Validate payload length
        if (
            payload
            and isinstance(payload, str)
            and len(payload) > self.max_payload_length
        ):
            msg = "Payload too long: %s > %s" % (
                len(payload), self.max_payload_length
            )
            return False, msg

        return True, None

    def sanitize_meshtastic_message(
        self, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Sanitize a message for Meshtastic."""
        sanitized = message.copy()

        # Sanitize destination
        if "destination" in sanitized:
            dest = str(sanitized["destination"]).strip()
            if not self.validate_meshtastic_id(dest):
                self.logger.warning(
                    "Invalid destination, using broadcast: %s",
                    dest,
                )
                dest = "^all"
            sanitized["destination"] = dest

        # Sanitize text
        if "text" in sanitized:
            sanitized["text"] = self.sanitize_string(
                sanitized["text"], self.max_message_length
            )

        # Ensure channel_index is valid
        if "channel_index" in sanitized:
            try:
                sanitized["channel_index"] = max(
                    0, min(7, int(sanitized["channel_index"]))
                )
            except (ValueError, TypeError):
                sanitized["channel_index"] = 0

        # Ensure want_ack is boolean
        if "want_ack" in sanitized:
            sanitized["want_ack"] = bool(sanitized["want_ack"])

        return sanitized

    def sanitize_external_message(
        self, message: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Sanitize a message from external system."""
        sanitized = message.copy()

        # Sanitize destination if present
        if "destination_meshtastic_id" in sanitized:
            dest = str(sanitized["destination_meshtastic_id"]).strip()
            if not self.validate_meshtastic_id(dest):
                self.logger.warning(
                    "Invalid destination, using broadcast: %s",
                    dest,
                )
                dest = "^all"
            sanitized["destination_meshtastic_id"] = dest

        # Sanitize payload if it's a string
        if "payload" in sanitized and isinstance(sanitized["payload"], str):
            sanitized["payload"] = self.sanitize_string(
                sanitized["payload"], self.max_payload_length
            )

        return sanitized
