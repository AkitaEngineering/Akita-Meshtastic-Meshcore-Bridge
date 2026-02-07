# tests/test_meshcore.py
"""
Comprehensive tests for all meshcore-related code:
- protocol.py (RawSerialProtocol, MeshcoreCompanionProtocol)
- meshcore_handler.py (MeshcoreHandler)
- meshcore_async_handler.py (MeshcoreAsyncHandler)
- validator.py (MessageValidator)
"""

import json
import struct
import threading
import time
from queue import Queue
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from ammb.protocol import (
    JsonNewlineProtocol,
    MeshcoreCompanionProtocol,
    MeshcoreProtocolHandler,
    RawSerialProtocol,
    get_serial_protocol_handler,
)
from ammb.validator import MessageValidator


# =========================================================================
# Protocol Tests: RawSerialProtocol
# =========================================================================


class TestRawSerialProtocol:
    @pytest.fixture
    def handler(self):
        return RawSerialProtocol()

    # --- read ---
    def test_read_data_available(self, handler):
        port = MagicMock()
        port.in_waiting = 5
        port.read.return_value = b"\x01\x02\x03\x04\x05"
        result = handler.read(port)
        assert result == b"\x01\x02\x03\x04\x05"
        port.read.assert_called_once_with(5)

    def test_read_no_data(self, handler):
        port = MagicMock()
        port.in_waiting = 0
        result = handler.read(port)
        assert result is None

    # --- encode ---
    def test_encode_string_payload(self, handler):
        result = handler.encode({"payload": "hello"})
        assert result == b"hello"

    def test_encode_bytes_payload(self, handler):
        result = handler.encode({"payload": b"\x01\x02"})
        assert result == b"\x01\x02"

    def test_encode_bytearray_payload(self, handler):
        result = handler.encode({"payload": bytearray(b"\x03\x04")})
        assert result == bytearray(b"\x03\x04")

    def test_encode_empty_payload(self, handler):
        result = handler.encode({"payload": ""})
        assert result == b""

    def test_encode_missing_payload(self, handler):
        result = handler.encode({})
        assert result == b""

    def test_encode_numeric_payload_returns_none(self, handler):
        result = handler.encode({"payload": 12345})
        assert result is None

    # --- decode ---
    def test_decode_binary_data(self, handler):
        result = handler.decode(b"\x01\x02\x03")
        assert result == {
            "destination_meshtastic_id": "^all",
            "payload": "MC_BIN: 010203",
            "raw_binary": True,
        }

    def test_decode_empty_bytes_returns_none(self, handler):
        assert handler.decode(b"") is None
        assert handler.decode(None) is None


# =========================================================================
# Protocol Tests: MeshcoreCompanionProtocol
# =========================================================================


class TestMeshcoreCompanionProtocol:
    @pytest.fixture
    def handler(self):
        return MeshcoreCompanionProtocol()

    # --- read / framing ---
    def test_read_complete_frame(self, handler):
        """A full outbound frame: [0x3E][len_lo][len_hi][payload]"""
        payload = b"Hello"
        frame = bytes([0x3E, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF]) + payload
        port = MagicMock()
        port.in_waiting = len(frame)
        port.read.return_value = frame
        result = handler.read(port)
        assert result == payload

    def test_read_incomplete_frame_returns_none(self, handler):
        """If the buffer doesn't have enough bytes for the frame, return None."""
        # Frame header says 10 bytes payload, but we only provide 3 bytes total
        port = MagicMock()
        port.in_waiting = 3
        port.read.return_value = bytes([0x3E, 10, 0])
        result = handler.read(port)
        assert result is None

    def test_read_no_data(self, handler):
        port = MagicMock()
        port.in_waiting = 0
        result = handler.read(port)
        assert result is None

    def test_read_resync_on_bad_start_byte(self, handler):
        """If buffer starts with garbage, resync to next 0x3E."""
        payload = b"Hi"
        frame = b"\xFF\xFF" + bytes([0x3E, len(payload) & 0xFF, 0]) + payload
        port = MagicMock()
        port.in_waiting = len(frame)
        port.read.return_value = frame
        result = handler.read(port)
        assert result == payload

    def test_read_resync_no_start_byte_clears_buffer(self, handler):
        """If no start byte found in buffer, clear buffer."""
        port = MagicMock()
        port.in_waiting = 5
        port.read.return_value = b"\xFF\xFF\xFF\xFF\xFF"
        result = handler.read(port)
        assert result is None
        # Buffer should be empty now
        assert len(handler._rx_buffer) == 0

    def test_read_multiple_frames(self, handler):
        """Two frames in one read should return the first, then the second."""
        payload1 = b"AAA"
        payload2 = b"BB"
        frame1 = bytes([0x3E, 3, 0]) + payload1
        frame2 = bytes([0x3E, 2, 0]) + payload2
        port = MagicMock()
        port.in_waiting = len(frame1) + len(frame2)
        port.read.return_value = frame1 + frame2

        result1 = handler.read(port)
        assert result1 == payload1

        # Second call - no new data, but buffer has frame2
        port.in_waiting = 0
        result2 = handler.read(port)
        assert result2 == payload2

    def test_read_large_payload(self, handler):
        """Payload > 255 bytes uses 2-byte little-endian length."""
        payload = b"X" * 300
        length = len(payload)
        frame = bytes([0x3E, length & 0xFF, (length >> 8) & 0xFF]) + payload
        port = MagicMock()
        port.in_waiting = len(frame)
        port.read.return_value = frame
        result = handler.read(port)
        assert result == payload

    # --- encode ---
    def test_encode_bytes_payload(self, handler):
        payload = b"\x01\x02\x03"
        result = handler.encode({"payload": payload})
        expected = bytes([0x3C, 3, 0]) + payload
        assert result == expected

    def test_encode_string_payload(self, handler):
        result = handler.encode({"payload": "ABC"})
        expected = bytes([0x3C, 3, 0]) + b"ABC"
        assert result == expected

    def test_encode_empty_payload(self, handler):
        result = handler.encode({"payload": b""})
        expected = bytes([0x3C, 0, 0])
        assert result == expected

    def test_encode_missing_payload(self, handler):
        result = handler.encode({})
        expected = bytes([0x3C, 0, 0])
        assert result == expected

    def test_encode_invalid_payload_type(self, handler):
        result = handler.encode({"payload": 12345})
        assert result is None

    def test_encode_large_payload(self, handler):
        payload = b"X" * 300
        result = handler.encode({"payload": payload})
        assert result[0] == 0x3C
        assert result[1] == 300 & 0xFF  # 44
        assert result[2] == (300 >> 8) & 0xFF  # 1
        assert result[3:] == payload

    # --- decode: text message frames ---
    def test_decode_channel_msg_legacy(self, handler):
        """Legacy channel message (code 8): [code][ch][path_len][txt_type][ts_4bytes][text]"""
        ts = int(time.time())
        ts_bytes = ts.to_bytes(4, "little")
        raw = bytes([8, 0, 1, 0]) + ts_bytes + b"Hello channel"
        result = handler.decode(raw)
        assert result is not None
        assert result["payload"] == "Hello channel"
        assert result["channel_index"] == 0
        assert result["companion_kind"] == "channel_msg"
        assert result["sender_timestamp"] == ts
        assert result["destination_meshtastic_id"] == "^all"

    def test_decode_contact_msg_legacy(self, handler):
        """Legacy contact message (code 7): [code][pubkey_6][path_len][txt_type][ts_4bytes][text]"""
        pubkey = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        ts = 1000
        ts_bytes = ts.to_bytes(4, "little")
        raw = bytes([7]) + pubkey + bytes([2, 0]) + ts_bytes + b"Hello contact"
        result = handler.decode(raw)
        assert result is not None
        assert result["payload"] == "Hello contact"
        assert result["companion_kind"] == "contact_msg"
        assert result["sender_pubkey_prefix"] == pubkey.hex()

    def test_decode_channel_msg_v3(self, handler):
        """V3 channel message (code 17): [code][snr][2bytes][ch][path_len][txt_type][ts_4bytes][text]"""
        ts = 2000
        ts_bytes = ts.to_bytes(4, "little")
        # code=17, snr=10, 2 reserved bytes, channel_idx=2, path_len=0, txt_type=0, ts, text
        raw = bytes([17, 10, 0, 0, 2, 0, 0]) + ts_bytes + b"V3 channel msg"
        result = handler.decode(raw)
        assert result is not None
        assert result["payload"] == "V3 channel msg"
        assert result["channel_index"] == 2
        assert result["snr"] == 10
        assert result["companion_kind"] == "channel_msg"

    def test_decode_contact_msg_v3(self, handler):
        """V3 contact message (code 16): [code][snr][2bytes][pubkey_6][path_len][txt_type][ts_4bytes][text]"""
        pubkey = b"\x11\x22\x33\x44\x55\x66"
        ts = 3000
        ts_bytes = ts.to_bytes(4, "little")
        raw = bytes([16, 5, 0, 0]) + pubkey + bytes([1, 0]) + ts_bytes + b"V3 contact msg"
        result = handler.decode(raw)
        assert result is not None
        assert result["payload"] == "V3 contact msg"
        assert result["sender_pubkey_prefix"] == pubkey.hex()
        assert result["snr"] == 5

    def test_decode_push_channel_msg(self, handler):
        """PUSH variant (high bit set): code 0x88 = 8 | 0x80, base_code=8"""
        ts = 4000
        ts_bytes = ts.to_bytes(4, "little")
        raw = bytes([0x88, 1, 0, 0]) + ts_bytes + b"push channel"
        result = handler.decode(raw)
        assert result is not None
        assert result["payload"] == "push channel"
        assert result["channel_index"] == 1

    def test_decode_push_contact_msg(self, handler):
        """PUSH variant (high bit set): code 0x87 = 7 | 0x80, base_code=7"""
        pubkey = b"\x01\x02\x03\x04\x05\x06"
        ts = 5000
        ts_bytes = ts.to_bytes(4, "little")
        raw = bytes([0x87]) + pubkey + bytes([0, 0]) + ts_bytes + b"push contact"
        result = handler.decode(raw)
        assert result is not None
        assert result["payload"] == "push contact"

    # --- decode: control frames ---
    def test_decode_ok_response(self, handler):
        result = handler.decode(bytes([0]))
        assert result is not None
        assert result["companion_kind"] == "ok"
        assert result["internal_only"] is True

    def test_decode_error_response(self, handler):
        result = handler.decode(bytes([1, 42]))
        assert result is not None
        assert result["companion_kind"] == "err"
        assert result["error_code"] == 42
        assert result["internal_only"] is True

    def test_decode_error_response_no_code(self, handler):
        result = handler.decode(bytes([1]))
        assert result is not None
        assert result["error_code"] is None

    def test_decode_sent_response(self, handler):
        ack_tag = b"\x01\x02\x03\x04"
        timeout = 5000
        raw = bytes([6, 1]) + ack_tag + timeout.to_bytes(4, "little")
        result = handler.decode(raw)
        assert result is not None
        assert result["companion_kind"] == "sent"
        assert result["send_type"] == 1
        assert result["timeout_ms"] == 5000
        assert result["internal_only"] is True

    def test_decode_sent_too_short(self, handler):
        result = handler.decode(bytes([6, 1, 2]))
        assert result is None

    def test_decode_send_confirmed(self, handler):
        ack = b"\xAA\xBB\xCC\xDD"
        rt = 150
        raw = bytes([0x82]) + ack + rt.to_bytes(4, "little")
        result = handler.decode(raw)
        assert result is not None
        assert result["companion_kind"] == "send_confirmed"
        assert result["round_trip_ms"] == 150

    def test_decode_send_confirmed_too_short(self, handler):
        result = handler.decode(bytes([0x82, 1, 2]))
        assert result is None

    def test_decode_advert(self, handler):
        pubkey = bytes(range(32))
        raw = bytes([0x80]) + pubkey
        result = handler.decode(raw)
        assert result is not None
        assert result["companion_kind"] == "advert"
        assert "MC_ADVERT:" in result["payload"]

    def test_decode_advert_too_short(self, handler):
        result = handler.decode(bytes([0x80]) + b"\x00" * 10)
        assert result is None

    def test_decode_new_advert(self, handler):
        pubkey = bytes(range(32))
        raw = bytes([0x8A]) + pubkey
        result = handler.decode(raw)
        assert result is not None
        assert result["companion_kind"] == "new_advert"
        assert "MC_NEW_ADVERT:" in result["payload"]

    def test_decode_unknown_frame_returns_none(self, handler):
        """Unknown/unhandled frame codes should return None."""
        result = handler.decode(bytes([0x99, 0, 0, 0]))
        assert result is None

    def test_decode_empty_returns_none(self, handler):
        assert handler.decode(b"") is None
        assert handler.decode(None) is None

    def test_decode_channel_msg_too_short(self, handler):
        """Channel message too short should return None."""
        result = handler.decode(bytes([8, 0, 1]))
        assert result is None


# =========================================================================
# Protocol Tests: Factory
# =========================================================================


class TestProtocolFactory:
    def test_get_companion_radio_handler(self):
        handler = get_serial_protocol_handler("companion_radio")
        assert isinstance(handler, MeshcoreCompanionProtocol)

    def test_get_raw_serial_handler(self):
        handler = get_serial_protocol_handler("raw_serial")
        assert isinstance(handler, RawSerialProtocol)

    def test_get_json_newline_handler(self):
        handler = get_serial_protocol_handler("json_newline")
        assert isinstance(handler, JsonNewlineProtocol)

    def test_get_handler_case_insensitive(self):
        handler = get_serial_protocol_handler("COMPANION_RADIO")
        assert isinstance(handler, MeshcoreCompanionProtocol)

    def test_unsupported_protocol_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            get_serial_protocol_handler("nonexistent")


# =========================================================================
# Validator Tests
# =========================================================================


class TestMessageValidator:
    @pytest.fixture
    def validator(self):
        return MessageValidator()

    # --- Meshtastic ID validation ---
    def test_valid_meshtastic_hex_id(self, validator):
        assert validator.validate_meshtastic_id("!aabbccdd") is True
        assert validator.validate_meshtastic_id("aabbccdd") is True

    def test_valid_broadcast_ids(self, validator):
        assert validator.validate_meshtastic_id("^all") is True
        assert validator.validate_meshtastic_id("^broadcast") is True

    def test_invalid_meshtastic_ids(self, validator):
        assert validator.validate_meshtastic_id("") is False
        assert validator.validate_meshtastic_id("!short") is False
        assert validator.validate_meshtastic_id("!gggggggg") is False
        assert validator.validate_meshtastic_id(12345) is False
        assert validator.validate_meshtastic_id(None) is False

    # --- String sanitization ---
    def test_sanitize_string_removes_control_chars(self, validator):
        result = validator.sanitize_string("hello\x00world\x01!")
        assert "\x00" not in result
        assert "\x01" not in result
        assert "helloworld!" in result

    def test_sanitize_preserves_allowed_chars(self, validator):
        result = validator.sanitize_string("line1\nline2\ttab\rcarriage")
        assert "\n" in result
        assert "\t" in result

    def test_sanitize_truncates(self, validator):
        long_str = "A" * 500
        result = validator.sanitize_string(long_str)
        assert len(result) == 240  # default max

    def test_sanitize_custom_max_length(self, validator):
        result = validator.sanitize_string("A" * 50, max_length=10)
        assert len(result) == 10

    def test_sanitize_non_string_input(self, validator):
        result = validator.sanitize_string(12345)
        assert result == "12345"

    # --- Meshtastic message validation ---
    def test_validate_meshtastic_msg_valid(self, validator):
        msg = {"destination": "^all", "text": "hello", "channel_index": 0}
        is_valid, err = validator.validate_meshtastic_message(msg)
        assert is_valid is True
        assert err is None

    def test_validate_meshtastic_msg_missing_destination(self, validator):
        msg = {"text": "hello"}
        is_valid, err = validator.validate_meshtastic_message(msg)
        assert is_valid is False
        assert "destination" in err.lower()

    def test_validate_meshtastic_msg_invalid_destination(self, validator):
        msg = {"destination": "invalid", "text": "hello"}
        is_valid, err = validator.validate_meshtastic_message(msg)
        assert is_valid is False

    def test_validate_meshtastic_msg_missing_text(self, validator):
        msg = {"destination": "^all"}
        is_valid, err = validator.validate_meshtastic_message(msg)
        assert is_valid is False
        assert "text" in err.lower()

    def test_validate_meshtastic_msg_text_too_long(self, validator):
        msg = {"destination": "^all", "text": "A" * 500}
        is_valid, err = validator.validate_meshtastic_message(msg)
        assert is_valid is False
        assert "long" in err.lower()

    def test_validate_meshtastic_msg_channel_index_out_of_range(self, validator):
        msg = {"destination": "^all", "text": "hi", "channel_index": 8}
        is_valid, err = validator.validate_meshtastic_message(msg)
        assert is_valid is False
        assert "channel" in err.lower()

    def test_validate_meshtastic_msg_not_dict(self, validator):
        is_valid, err = validator.validate_meshtastic_message("not a dict")
        assert is_valid is False

    # --- External message validation ---
    def test_validate_external_msg_valid(self, validator):
        msg = {"destination_meshtastic_id": "^all", "payload": "data"}
        is_valid, err = validator.validate_external_message(msg)
        assert is_valid is True

    def test_validate_external_msg_payload_json(self, validator):
        msg = {"destination_meshtastic_id": "^all", "payload_json": {"key": "val"}}
        is_valid, err = validator.validate_external_message(msg)
        assert is_valid is True

    def test_validate_external_msg_no_payload(self, validator):
        msg = {"destination_meshtastic_id": "^all"}
        is_valid, err = validator.validate_external_message(msg)
        assert is_valid is False
        assert "payload" in err.lower()

    def test_validate_external_msg_invalid_dest(self, validator):
        msg = {"destination_meshtastic_id": "bad_id", "payload": "data"}
        is_valid, err = validator.validate_external_message(msg)
        assert is_valid is False

    def test_validate_external_msg_payload_too_long(self, validator):
        msg = {"payload": "X" * 1001, "destination_meshtastic_id": "^all"}
        is_valid, err = validator.validate_external_message(msg)
        assert is_valid is False
        assert "long" in err.lower()

    def test_validate_external_msg_not_dict(self, validator):
        is_valid, err = validator.validate_external_message([1, 2, 3])
        assert is_valid is False

    # --- Sanitization ---
    def test_sanitize_meshtastic_message(self, validator):
        msg = {
            "destination": "  ^all  ",
            "text": "hello\x00world",
            "channel_index": "3",
            "want_ack": 1,
        }
        result = validator.sanitize_meshtastic_message(msg)
        assert result["destination"] == "^all"
        assert "\x00" not in result["text"]
        assert result["channel_index"] == 3
        assert result["want_ack"] is True

    def test_sanitize_meshtastic_invalid_dest_becomes_broadcast(self, validator):
        msg = {"destination": "invalid_dest", "text": "hello"}
        result = validator.sanitize_meshtastic_message(msg)
        assert result["destination"] == "^all"

    def test_sanitize_meshtastic_channel_clamped(self, validator):
        msg = {"channel_index": 99}
        result = validator.sanitize_meshtastic_message(msg)
        assert result["channel_index"] == 7

    def test_sanitize_meshtastic_channel_negative(self, validator):
        msg = {"channel_index": -5}
        result = validator.sanitize_meshtastic_message(msg)
        assert result["channel_index"] == 0

    def test_sanitize_external_message(self, validator):
        msg = {
            "destination_meshtastic_id": "  ^all  ",
            "payload": "test\x00data",
        }
        result = validator.sanitize_external_message(msg)
        assert result["destination_meshtastic_id"] == "^all"
        assert "\x00" not in result["payload"]

    def test_sanitize_external_invalid_dest(self, validator):
        msg = {"destination_meshtastic_id": "bad", "payload": "data"}
        result = validator.sanitize_external_message(msg)
        assert result["destination_meshtastic_id"] == "^all"


# =========================================================================
# MeshcoreHandler Tests (sync, with mocked serial)
# =========================================================================


def _make_bridge_config(**overrides):
    """Helper to create a BridgeConfig with serial defaults."""
    from ammb.config_handler import BridgeConfig

    defaults = {
        "meshtastic_port": "/dev/ttyUSB0",
        "external_transport": "serial",
        "serial_port": "/dev/ttyS0",
        "serial_baud": 115200,
        "serial_protocol": "json_newline",
        "mqtt_broker": None,
        "mqtt_port": None,
        "mqtt_topic_in": None,
        "mqtt_topic_out": None,
        "mqtt_username": None,
        "mqtt_password": None,
        "mqtt_client_id": None,
        "mqtt_qos": None,
        "mqtt_retain_out": None,
        "external_network_id": "test_net",
        "bridge_node_id": "!testnode",
        "queue_size": 100,
        "log_level": "DEBUG",
        "api_enabled": False,
        "api_host": "127.0.0.1",
        "api_port": 8080,
        "mqtt_tls_enabled": False,
        "mqtt_tls_ca_certs": None,
        "mqtt_tls_insecure": False,
        "companion_handshake_enabled": True,
        "companion_contacts_poll_s": 0,
        "companion_debug": False,
        "serial_auto_switch": True,
    }
    defaults.update(overrides)
    return BridgeConfig(**defaults)


class TestMeshcoreHandler:
    """Tests for MeshcoreHandler using mocked serial port."""

    @pytest.fixture
    def handler_parts(self):
        """Create handler dependencies."""
        to_mesh_q = Queue(maxsize=10)
        from_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()
        return config, to_mesh_q, from_mesh_q, shutdown

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_connect_success(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        result = handler.connect()
        assert result is True
        assert handler._is_connected.is_set()

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_connect_failure(self, mock_serial_cls, handler_parts):
        import serial as ser

        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        mock_serial_cls.side_effect = ser.SerialException("Port not found")

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        result = handler.connect()
        assert result is False
        assert not handler._is_connected.is_set()

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_connect_already_open(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.serial_port = MagicMock()
        handler.serial_port.is_open = True

        result = handler.connect()
        assert result is True
        mock_serial_cls.assert_not_called()

    def test_init_missing_serial_port_raises(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_port=None)
        with pytest.raises(ValueError, match="SERIAL"):
            MeshcoreHandler(config, Queue(), Queue(), threading.Event())

    def test_init_missing_serial_baud_raises(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_baud=None)
        with pytest.raises(ValueError, match="SERIAL"):
            MeshcoreHandler(config, Queue(), Queue(), threading.Event())

    def test_init_missing_serial_protocol_raises(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol=None)
        with pytest.raises(ValueError, match="SERIAL"):
            MeshcoreHandler(config, Queue(), Queue(), threading.Event())

    def test_init_invalid_protocol_uses_dummy(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol="totally_bogus")
        handler = MeshcoreHandler(config, Queue(), Queue(), threading.Event())
        # DummyHandler should be used
        assert handler.protocol_handler.read(None) is None
        assert handler.protocol_handler.encode({}) is None
        assert handler.protocol_handler.decode(b"") is None

    def test_protocol_auto_switch_disabled_by_config(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_auto_switch=False)
        handler = MeshcoreHandler(config, Queue(), Queue(), threading.Event())
        assert handler._auto_switch_enabled is False

    def test_switch_protocol(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol="json_newline")
        handler = MeshcoreHandler(config, Queue(), Queue(), threading.Event())
        assert handler._protocol_name == "json_newline"

        handler._switch_protocol()
        assert handler._protocol_name == "raw_serial"
        assert isinstance(handler.protocol_handler, RawSerialProtocol)

    def test_switch_protocol_both_tried_disables(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol="json_newline")
        handler = MeshcoreHandler(config, Queue(), Queue(), threading.Event())

        handler._switch_protocol()  # switches to raw_serial
        assert handler._protocol_name == "raw_serial"

        handler._switch_protocol()  # both tried, should disable
        assert handler._auto_switch_enabled is False

    def test_switch_protocol_disabled(self):
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_auto_switch=False)
        handler = MeshcoreHandler(config, Queue(), Queue(), threading.Event())
        original_protocol = handler._protocol_name

        handler._switch_protocol()
        assert handler._protocol_name == original_protocol  # unchanged

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_close_serial(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()
        handler._close_serial()

        mock_port.close.assert_called_once()
        assert handler.serial_port is None
        assert not handler._is_connected.is_set()

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_sender_loop_encodes_and_writes(self, mock_serial_cls, handler_parts):
        """Test that sender loop reads from queue, encodes, and writes to serial."""
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()

        # Put a message in the queue
        msg = {"destination_meshtastic_id": "^all", "payload": "test"}
        from_mesh_q.put(msg)

        # Run one iteration of sender loop then shutdown
        def run_sender():
            handler._serial_sender_loop()

        shutdown_timer = threading.Timer(0.5, shutdown.set)
        shutdown_timer.start()
        run_sender()

        # Verify serial.write was called
        assert mock_port.write.called

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_sender_loop_falsy_item_calls_task_done(self, mock_serial_cls, handler_parts):
        """Ensure task_done() is called even when item is falsy."""
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()

        # Put a falsy item (empty dict)
        from_mesh_q.put({})

        # Queue should not block on join after processing
        shutdown_timer = threading.Timer(0.5, shutdown.set)
        shutdown_timer.start()
        handler._serial_sender_loop()

        # If task_done wasn't called, this would hang
        from_mesh_q.join()

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_companion_handshake_sent(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol="companion_radio")
        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()

        # The handshake should have written to the serial port
        assert mock_port.write.called
        assert mock_port.flush.called

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_companion_handshake_disabled(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(
            serial_protocol="companion_radio",
            companion_handshake_enabled=False,
        )
        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()

        # Handshake should NOT have been sent
        assert not mock_port.write.called

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_encode_companion_from_meshtastic(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol="companion_radio")
        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)

        item = {
            "type": "meshtastic_message",
            "payload": "Hello from Meshtastic",
            "channel_index": 0,
        }
        encoded = handler._encode_companion_from_meshtastic(item)
        assert encoded is not None
        # Should be a companion inbound frame: [0x3C][len_lo][len_hi][payload]
        assert encoded[0] == 0x3C

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_encode_companion_skips_non_text(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol="companion_radio")
        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)

        item = {"type": "position_update", "payload": "data"}
        result = handler._encode_companion_from_meshtastic(item)
        assert result is None

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_encode_companion_skips_non_string_payload(self, mock_serial_cls, handler_parts):
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config(serial_protocol="companion_radio")
        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)

        item = {"type": "meshtastic_message", "payload": 12345}
        result = handler._encode_companion_from_meshtastic(item)
        assert result is None

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_receiver_loop_processes_json_message(self, mock_serial_cls, handler_parts):
        """Test receiver loop reads a JSON message and queues it for Meshtastic."""
        config, to_mesh_q, from_mesh_q, shutdown = handler_parts
        from ammb.meshcore_handler import MeshcoreHandler

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()

        # Simulate serial data: one valid message, then shutdown
        json_msg = json.dumps({
            "destination_meshtastic_id": "^all",
            "payload": "test from meshcore",
        }).encode("utf-8") + b"\n"

        call_count = [0]
        original_in_waiting = PropertyMock(side_effect=lambda: len(json_msg) if call_count[0] == 0 else 0)
        type(mock_port).in_waiting = original_in_waiting

        def mock_readline():
            if call_count[0] == 0:
                call_count[0] += 1
                return json_msg
            shutdown.set()
            return b""

        mock_port.readline.side_effect = mock_readline

        # Run receiver in a thread
        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        # Check that message was queued
        assert not to_mesh_q.empty()
        queued_msg = to_mesh_q.get_nowait()
        assert queued_msg["destination"] == "^all"
        assert queued_msg["text"] == "test from meshcore"

    def test_stop_cleans_up(self):
        """Test that stop() joins threads and closes serial."""
        from ammb.meshcore_handler import MeshcoreHandler

        config = _make_bridge_config()
        handler = MeshcoreHandler(config, Queue(), Queue(), threading.Event())
        handler.shutdown_event.set()

        # Create mock threads
        handler.receiver_thread = MagicMock()
        handler.receiver_thread.is_alive.return_value = True
        handler.sender_thread = MagicMock()
        handler.sender_thread.is_alive.return_value = True

        handler.stop()

        handler.receiver_thread.join.assert_called_once()
        handler.sender_thread.join.assert_called_once()


# =========================================================================
# MeshcoreAsyncHandler Tests
# =========================================================================


class TestMeshcoreAsyncHandler:
    def test_subscribe_before_connect_queues(self):
        """Subscribing before connect should queue the subscription."""
        from ammb.meshcore_async_handler import MeshcoreAsyncHandler
        from unittest.mock import MagicMock

        handler = MeshcoreAsyncHandler("/dev/test", 115200)
        mock_callback = MagicMock()

        # This should not raise, even though meshcore is None
        from meshcore import EventType
        handler.subscribe(EventType.CONTACT_MSG_RECV, mock_callback)

        assert len(handler._pending_subscriptions) == 1
        assert handler._pending_subscriptions[0] == (EventType.CONTACT_MSG_RECV, mock_callback)

    @pytest.mark.asyncio
    async def test_send_message_not_connected(self):
        """send_message should raise when not connected."""
        from ammb.meshcore_async_handler import MeshcoreAsyncHandler

        handler = MeshcoreAsyncHandler("/dev/test", 115200)
        with pytest.raises(RuntimeError, match="not connected"):
            await handler.send_message("key", "hello")

    @pytest.mark.asyncio
    async def test_get_contacts_not_connected(self):
        """get_contacts should raise when not connected."""
        from ammb.meshcore_async_handler import MeshcoreAsyncHandler

        handler = MeshcoreAsyncHandler("/dev/test", 115200)
        with pytest.raises(RuntimeError, match="not connected"):
            await handler.get_contacts()

    @pytest.mark.asyncio
    async def test_disconnect_clears_connected(self):
        """disconnect should clear the connected event."""
        import asyncio
        from ammb.meshcore_async_handler import MeshcoreAsyncHandler

        handler = MeshcoreAsyncHandler("/dev/test", 115200)
        handler._connected.set()
        handler.meshcore = MagicMock()

        async def noop():
            pass

        handler.meshcore.disconnect = MagicMock(return_value=noop())

        await handler.disconnect()
        assert not handler._connected.is_set()
        assert handler._disconnect_requested is True


# =========================================================================
# Config handler tests for meshcore-related fields
# =========================================================================


class TestConfigMeshcoreFields:
    def test_config_loads_companion_settings(self, temp_config_file, tmp_path):
        """Test that companion/meshcore config fields load correctly."""
        import configparser

        # Write a config with companion settings
        config_path = tmp_path / "companion_config.ini"
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {
            "MESHTASTIC_SERIAL_PORT": "/dev/ttyUSB0",
            "EXTERNAL_TRANSPORT": "serial",
            "SERIAL_PORT": "/dev/ttyS0",
            "SERIAL_BAUD_RATE": "115200",
            "SERIAL_PROTOCOL": "companion_radio",
            "MESSAGE_QUEUE_SIZE": "100",
            "LOG_LEVEL": "DEBUG",
            "COMPANION_HANDSHAKE_ENABLED": "True",
            "COMPANION_CONTACTS_POLL_S": "30",
            "COMPANION_DEBUG": "True",
            "SERIAL_AUTO_SWITCH": "False",
        }
        with open(config_path, "w") as f:
            parser.write(f)

        from ammb.config_handler import load_config

        cfg = load_config(str(config_path))
        assert cfg is not None
        assert cfg.serial_protocol == "companion_radio"
        assert cfg.companion_handshake_enabled is True
        assert cfg.companion_contacts_poll_s == 30
        assert cfg.companion_debug is True
        assert cfg.serial_auto_switch is False

    def test_config_defaults_serial_auto_switch(self, tmp_path):
        """serial_auto_switch should default to True."""
        import configparser

        config_path = tmp_path / "default_config.ini"
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {
            "MESHTASTIC_SERIAL_PORT": "/dev/ttyUSB0",
            "EXTERNAL_TRANSPORT": "serial",
            "SERIAL_PORT": "/dev/ttyS0",
            "SERIAL_BAUD_RATE": "9600",
            "SERIAL_PROTOCOL": "json_newline",
            "MESSAGE_QUEUE_SIZE": "50",
            "LOG_LEVEL": "INFO",
        }
        with open(config_path, "w") as f:
            parser.write(f)

        from ammb.config_handler import load_config

        cfg = load_config(str(config_path))
        assert cfg is not None
        assert cfg.serial_auto_switch is True


# =========================================================================
# Integration-style test: companion encode/decode round-trip
# =========================================================================


class TestCompanionRoundTrip:
    def test_encode_then_decode_text_message(self):
        """Encode a companion text command, then frame-read + decode it."""
        protocol = MeshcoreCompanionProtocol()

        # Encode a text payload (simulating CMD_SEND_CHANNEL_TXT_MSG)
        text = "Round trip test"
        text_bytes = text.encode("utf-8")
        ts = 12345
        cmd_payload = bytes([3, 0, 0]) + ts.to_bytes(4, "little") + text_bytes
        encoded = protocol.encode({"payload": cmd_payload})

        assert encoded is not None
        assert encoded[0] == 0x3C  # inbound frame

        # Verify frame structure
        length = encoded[1] | (encoded[2] << 8)
        assert length == len(cmd_payload)
        assert encoded[3:] == cmd_payload

    def test_framing_read_write_symmetry(self):
        """Write an inbound frame, read it as outbound (simulating loopback)."""
        protocol = MeshcoreCompanionProtocol()

        payload = b"symmetric test"
        encoded = protocol.encode({"payload": payload})

        # Modify the frame to be outbound (change 0x3C to 0x3E for reading)
        outbound_frame = bytes([0x3E]) + encoded[1:]

        port = MagicMock()
        port.in_waiting = len(outbound_frame)
        port.read.return_value = outbound_frame

        result = protocol.read(port)
        assert result == payload
