# tests/test_protocol.py
"""
Tests for the ammb.protocol module, focusing on protocol handlers.
"""

import pytest
import json

# Module to test
from ammb.protocol import get_serial_protocol_handler, JsonNewlineProtocol, MeshcoreProtocolHandler

# --- Test JsonNewlineProtocol ---

@pytest.fixture
def json_handler() -> JsonNewlineProtocol:
    """Provides an instance of the JsonNewlineProtocol handler."""
    return JsonNewlineProtocol()

# Parameterize test data for encoding
encode_test_data = [
    ({"key": "value", "num": 123}, b'{"key": "value", "num": 123}\n'),
    ({"list": [1, 2, None]}, b'{"list": [1, 2, null]}\n'),
    ({}, b'{}\n'),
]

@pytest.mark.parametrize("input_dict, expected_bytes", encode_test_data)
def test_json_newline_encode_success(json_handler: JsonNewlineProtocol, input_dict: dict, expected_bytes: bytes):
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
    (b'{"list": [1, 2, null]} \r\n', {"list": [1, 2, None]}), # Handle trailing whitespace/CR
    (b'{}', {}),
]

@pytest.mark.parametrize("input_bytes, expected_dict", decode_test_data)
def test_json_newline_decode_success(json_handler: JsonNewlineProtocol, input_bytes: bytes, expected_dict: dict):
    """Test successful decoding with JsonNewlineProtocol."""
    result = json_handler.decode(input_bytes)
    assert result == expected_dict

# Parameterize invalid data for decoding
decode_error_data = [
    b'this is not json\n',         # Invalid JSON
    b'{"key": "value",\n',        # Incomplete JSON
    b'{"key": value_without_quotes}\n', # Invalid JSON syntax
    b'\x80\x81\x82\n',             # Invalid UTF-8 start bytes
    b'',                           # Empty bytes
    b'   \n',                      # Whitespace only line
    b'["list", "not_dict"]\n',     # Valid JSON, but not a dictionary
]

@pytest.mark.parametrize("invalid_bytes", decode_error_data)
def test_json_newline_decode_errors(json_handler: JsonNewlineProtocol, invalid_bytes: bytes):
    """Test decoding various forms of invalid input."""
    result = json_handler.decode(invalid_bytes)
    assert result is None

# --- Test Factory Function ---

def test_get_protocol_handler_success():
    """Test getting a known protocol handler."""
    handler = get_serial_protocol_handler('json_newline')
    assert isinstance(handler, JsonNewlineProtocol)
    # Test case insensitivity
    handler_upper = get_serial_protocol_handler('JSON_NEWLINE')
    assert isinstance(handler_upper, JsonNewlineProtocol)

def test_get_protocol_handler_unsupported():
    """Test getting an unknown protocol handler raises ValueError."""
    with pytest.raises(ValueError):
        get_serial_protocol_handler('unknown_protocol')

# Add tests for other protocol handlers (e.g., PlainTextProtocol) when implemented.

