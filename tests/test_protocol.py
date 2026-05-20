# tests/test_protocol.py
"""
Tests for the ammb.protocol module, focusing on protocol handlers.
"""

import pytest

# Module to test
from ammb.protocol import (
    JsonNewlineProtocol,
    MeshcoreCompanionProtocol,
    get_serial_protocol_handler,
)

# --- Test JsonNewlineProtocol ---


@pytest.fixture
def json_handler() -> JsonNewlineProtocol:
    """Provides an instance of the JsonNewlineProtocol handler."""
    return JsonNewlineProtocol()


@pytest.fixture
def companion_handler() -> MeshcoreCompanionProtocol:
    """Provides an instance of the MeshcoreCompanionProtocol handler."""
    return MeshcoreCompanionProtocol()


# Parameterize test data for encoding
encode_test_data = [
    ({"key": "value", "num": 123}, b'{"key": "value", "num": 123}\n'),
    ({"list": [1, 2, None]}, b'{"list": [1, 2, null]}\n'),
    ({}, b"{}\n"),
]


@pytest.mark.parametrize("input_dict, expected_bytes", encode_test_data)
def test_json_newline_encode_success(
    json_handler: JsonNewlineProtocol, input_dict: dict, expected_bytes: bytes
):
    """Test successful encoding with JsonNewlineProtocol."""
    result = json_handler.encode(input_dict)
    assert result == expected_bytes


def test_json_newline_encode_error(json_handler: JsonNewlineProtocol):
    """Test encoding data that cannot be JSON serialized."""
    # Sets cannot be directly JSON serialized
    result = json_handler.encode({"data": {1, 2, 3}})
    assert result is None


# Parameterize test data for decoding
decode_test_data = [
    (b'{"key": "value", "num": 123}\n', {"key": "value", "num": 123}),
    (
        b'{"list": [1, 2, null]} \r\n',
        {"list": [1, 2, None]},
    ),  # Handle trailing whitespace/CR
    (b"{}", {}),
]


@pytest.mark.parametrize("input_bytes, expected_dict", decode_test_data)
def test_json_newline_decode_success(
    json_handler: JsonNewlineProtocol, input_bytes: bytes, expected_dict: dict
):
    """Test successful decoding with JsonNewlineProtocol."""
    result = json_handler.decode(input_bytes)
    assert result == expected_dict


# Parameterize invalid data for decoding
decode_error_data = [
    b"this is not json\n",  # Invalid JSON
    b'{"key": "value",\n',  # Incomplete JSON
    b'{"key": value_without_quotes}\n',  # Invalid JSON syntax
    b"\x80\x81\x82\n",  # Invalid UTF-8 start bytes
    b"",  # Empty bytes
    b"   \n",  # Whitespace only line
    b'["list", "not_dict"]\n',  # Valid JSON, but not a dictionary
]


@pytest.mark.parametrize("invalid_bytes", decode_error_data)
def test_json_newline_decode_errors(
    json_handler: JsonNewlineProtocol, invalid_bytes: bytes
):
    """Test decoding various forms of invalid input."""
    result = json_handler.decode(invalid_bytes)
    assert result is None


# --- Test Factory Function ---


def test_get_protocol_handler_success():
    """Test getting a known protocol handler."""
    handler = get_serial_protocol_handler("json_newline")
    assert isinstance(handler, JsonNewlineProtocol)
    # Test case insensitivity
    handler_upper = get_serial_protocol_handler("JSON_NEWLINE")
    assert isinstance(handler_upper, JsonNewlineProtocol)


def test_get_protocol_handler_unsupported():
    """Test getting an unknown protocol handler raises ValueError."""
    with pytest.raises(ValueError):
        get_serial_protocol_handler("unknown_protocol")


def test_companion_decode_contact_book_frames(
    companion_handler: MeshcoreCompanionProtocol,
):
    pubkey = bytes(range(32))
    out_path = bytes.fromhex("010203") + (b"\x00" * 61)
    adv_name = b"Desk Node" + (b"\x00" * 23)
    contact_info = (
        bytes([0x03])
        + pubkey
        + bytes([2, 7, 3])
        + out_path
        + adv_name
        + (123456).to_bytes(4, "little")
        + int(51.501234 * 1_000_000).to_bytes(4, "little", signed=True)
        + int(-0.141234 * 1_000_000).to_bytes(4, "little", signed=True)
        + (654321).to_bytes(4, "little")
    )

    assert companion_handler.decode(bytes([0x02]) + (4).to_bytes(4, "little")) == {
        "companion_kind": "contact_start",
        "contact_count": 4,
        "internal_only": True,
        "protocol": "companion_radio",
    }

    assert companion_handler.decode(contact_info) == {
        "companion_kind": "contact_info",
        "contact": {
            "public_key": pubkey.hex(),
            "type": 2,
            "flags": 7,
            "out_path_len": 3,
            "out_path": "010203",
            "adv_name": "Desk Node",
            "last_advert": 123456,
            "adv_lat": pytest.approx(51.501234),
            "adv_lon": pytest.approx(-0.141234),
            "lastmod": 654321,
        },
        "internal_only": True,
        "protocol": "companion_radio",
    }

    assert companion_handler.decode(bytes([0x04]) + (99).to_bytes(4, "little")) == {
        "companion_kind": "contact_end",
        "lastmod": 99,
        "internal_only": True,
        "protocol": "companion_radio",
    }


def test_companion_decode_self_info(companion_handler: MeshcoreCompanionProtocol):
    public_key = bytes(range(31, -1, -1))
    payload = (
        bytes([0x05, 3, 10, 20])
        + public_key
        + int(40.7128 * 1_000_000).to_bytes(4, "little", signed=True)
        + int(-74.0060 * 1_000_000).to_bytes(4, "little", signed=True)
        + bytes([1, 2, 0b011001, 1])
        + (915_000).to_bytes(4, "little")
        + (250_000).to_bytes(4, "little")
        + bytes([11, 5])
        + b"Bridge Node"
    )

    assert companion_handler.decode(payload) == {
        "companion_kind": "self_info",
        "self_info": {
            "adv_type": 3,
            "tx_power": 10,
            "max_tx_power": 20,
            "public_key": public_key.hex(),
            "adv_lat": pytest.approx(40.7128),
            "adv_lon": pytest.approx(-74.006),
            "multi_acks": 1,
            "adv_loc_policy": 2,
            "telemetry_mode_env": 1,
            "telemetry_mode_loc": 2,
            "telemetry_mode_base": 1,
            "manual_add_contacts": True,
            "radio_freq": 915.0,
            "radio_bw": 250.0,
            "radio_sf": 11,
            "radio_cr": 5,
            "name": "Bridge Node",
        },
        "internal_only": True,
        "protocol": "companion_radio",
    }


def test_companion_decode_device_info_and_new_advert(
    companion_handler: MeshcoreCompanionProtocol,
):
    advert_pubkey = bytes.fromhex("aa" * 32)
    advert_path = bytes.fromhex("beef") + (b"\x00" * 62)
    advert_name = b"Field Unit" + (b"\x00" * 22)
    advert_payload = (
        bytes([0x8A])
        + advert_pubkey
        + bytes([1, 0, 2])
        + advert_path
        + advert_name
        + (77).to_bytes(4, "little")
        + int(34.123456 * 1_000_000).to_bytes(4, "little", signed=True)
        + int(-117.123456 * 1_000_000).to_bytes(4, "little", signed=True)
        + (78).to_bytes(4, "little")
    )
    device_payload = (
        bytes([0x0D, 3, 16, 8])
        + (123456).to_bytes(4, "little")
        + b"20260519abcd"
        + b"Akita MeshCore Board".ljust(40, b"\x00")
        + b"2.1.1".ljust(20, b"\x00")
    )

    assert companion_handler.decode(advert_payload) == {
        "companion_kind": "new_advert",
        "advert": {
            "public_key": advert_pubkey.hex(),
            "type": 1,
            "flags": 0,
            "out_path_len": 2,
            "out_path": "beef",
            "adv_name": "Field Unit",
            "last_advert": 77,
            "adv_lat": pytest.approx(34.123456),
            "adv_lon": pytest.approx(-117.123456),
            "lastmod": 78,
        },
        "internal_only": True,
        "protocol": "companion_radio",
    }

    assert companion_handler.decode(device_payload) == {
        "companion_kind": "device_info",
        "device_info": {
            "fw_ver": 3,
            "max_contacts": 32,
            "max_channels": 8,
            "ble_pin": 123456,
            "fw_build": "20260519abcd",
            "model": "Akita MeshCore Board",
            "ver": "2.1.1",
        },
        "internal_only": True,
        "protocol": "companion_radio",
    }


# Add tests for other protocol handlers (e.g., PlainTextProtocol)
# when implemented.
