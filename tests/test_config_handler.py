from ammb.protocol import JsonNewlineProtocol, get_serial_protocol_handler


def test_json_newline_encode():
    handler = JsonNewlineProtocol()
    data = {"key": "value"}
    encoded = handler.encode(data)
    assert encoded == b'{"key": "value"}\n'


def test_factory_function():
    handler = get_serial_protocol_handler("json_newline")
    assert isinstance(handler, JsonNewlineProtocol)


def test_raw_serial_handler():
    handler = get_serial_protocol_handler("raw_serial")
    raw_data = b"\x01\x02\x03"
    decoded = handler.decode(raw_data)
    assert decoded["payload"] == "MC_BIN: 010203"
