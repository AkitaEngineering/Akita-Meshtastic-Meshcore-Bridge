"""
Integration tests that simulate the full MeshCore ↔ Meshtastic bridge flow
*without* any physical devices.

Each scenario builds companion-radio binary frames, feeds them through a
mocked serial port, and asserts the correct messages reach the Meshtastic
queue (or are correctly suppressed).

The reverse direction (MT → MC) is also tested: a Meshtastic message is
placed in the from_meshtastic queue and the companion-encoded bytes
written to the mock serial port are verified.
"""

import json
import struct
import threading
import time
from queue import Queue
from unittest.mock import MagicMock, PropertyMock, patch, call

import pytest

from ammb.protocol import MeshcoreCompanionProtocol

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bridge_config(**overrides):
    """Create a BridgeConfig wired for companion_radio protocol."""
    from ammb.config_handler import BridgeConfig

    defaults = {
        "meshtastic_port": "/dev/ttyUSB0",
        "external_transport": "serial",
        "serial_port": "/dev/ttyS0",
        "serial_baud": 115200,
        "serial_protocol": "companion_radio",
        "mqtt_broker": None,
        "mqtt_port": None,
        "mqtt_topic_in": None,
        "mqtt_topic_out": None,
        "mqtt_username": None,
        "mqtt_password": None,
        "mqtt_client_id": None,
        "mqtt_qos": None,
        "mqtt_retain_out": None,
        "mqtt_tls_enabled": False,
        "mqtt_tls_ca_certs": None,
        "mqtt_tls_insecure": False,
        "external_network_id": "test_net",
        "bridge_node_id": "!testnode",
        "queue_size": 100,
        "log_level": "DEBUG",
        "api_enabled": False,
        "api_host": "127.0.0.1",
        "api_port": 8080,
        "companion_handshake_enabled": False,   # disable for cleaner tests
        "companion_contacts_poll_s": 0,
        "companion_debug": True,
        "serial_auto_switch": False,
    }
    defaults.update(overrides)
    return BridgeConfig(**defaults)


def _outbound_frame(payload: bytes) -> bytes:
    """Build a companion outbound frame (radio → app): [0x3E][len_le16][payload]."""
    length = len(payload)
    return bytes([0x3E, length & 0xFF, (length >> 8) & 0xFF]) + payload


def _inbound_frame(payload: bytes) -> bytes:
    """Build a companion inbound frame (app → radio): [0x3C][len_le16][payload]."""
    length = len(payload)
    return bytes([0x3C, length & 0xFF, (length >> 8) & 0xFF]) + payload


def _v3_channel_msg_payload(
    text: str,
    channel_idx: int = 0,
    snr: int = 10,
    path_len: int = 0,
    txt_type: int = 0,
    sender_ts: int = 1700000000,
) -> bytes:
    """Build the raw payload for RESP_CODE_CHANNEL_MSG_RECV_V3 (code 17 / 0x11).

    Layout: [17][snr][reserved_2bytes][channel_idx][path_len][txt_type][ts_le32][text...]
    """
    ts_bytes = sender_ts.to_bytes(4, "little")
    return (
        bytes([17, snr, 0, 0, channel_idx, path_len, txt_type])
        + ts_bytes
        + text.encode("utf-8")
    )


def _legacy_channel_msg_payload(
    text: str,
    channel_idx: int = 0,
    path_len: int = 0,
    txt_type: int = 0,
    sender_ts: int = 1700000000,
) -> bytes:
    """Build the raw payload for RESP_CODE_CHANNEL_MSG_RECV (code 8).

    Layout: [8][channel_idx][path_len][txt_type][ts_le32][text...]
    """
    ts_bytes = sender_ts.to_bytes(4, "little")
    return (
        bytes([8, channel_idx, path_len, txt_type])
        + ts_bytes
        + text.encode("utf-8")
    )


def _contact_msg_payload(
    text: str,
    pubkey_prefix: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    path_len: int = 0,
    txt_type: int = 0,
    sender_ts: int = 1700000000,
) -> bytes:
    """Build the raw payload for RESP_CODE_CONTACT_MSG_RECV (code 7).

    Layout: [7][pubkey_prefix_6bytes][path_len][txt_type][ts_le32][text...]
    """
    ts_bytes = sender_ts.to_bytes(4, "little")
    return (
        bytes([7])
        + pubkey_prefix[:6]
        + bytes([path_len, txt_type])
        + ts_bytes
        + text.encode("utf-8")
    )


def _msg_waiting_payload() -> bytes:
    """PUSH_CODE_MSG_WAITING (0x83) — 1-byte payload."""
    return bytes([0x83])


def _no_more_messages_payload() -> bytes:
    """RESP_CODE_NO_MORE_MESSAGES (10) — 1-byte payload."""
    return bytes([10])


def _advert_payload(pubkey: bytes = b"\x00" * 32) -> bytes:
    """PUSH_CODE_ADVERT (0x80) — [0x80][32-byte pubkey]."""
    return bytes([0x80]) + pubkey[:32].ljust(32, b"\x00")


def _new_advert_payload(pubkey: bytes = b"\x00" * 32) -> bytes:
    """PUSH_CODE_NEW_ADVERT (0x8A) — [0x8A][32-byte pubkey]."""
    return bytes([0x8A]) + pubkey[:32].ljust(32, b"\x00")


def _log_rx_data_payload() -> bytes:
    """PUSH_CODE_LOG_RX_DATA (0x88) — the frame that used to be misidentified.

    Payload is [0x88][variable_data].  We use 20 bytes of junk, similar
    to what the user's radio actually sends.
    """
    return bytes([0x88]) + bytes(range(20))


# ---------------------------------------------------------------------------
# Fixture: create MeshcoreHandler wired with companion_radio protocol
# ---------------------------------------------------------------------------

@pytest.fixture
def companion_handler():
    """Return (handler, to_meshtastic_queue, from_meshtastic_queue, shutdown, mock_port)."""
    from ammb.meshcore_handler import MeshcoreHandler

    to_mesh_q = Queue(maxsize=50)
    from_mesh_q = Queue(maxsize=50)
    shutdown = threading.Event()
    config = _make_bridge_config()

    with patch("ammb.meshcore_handler.serial.Serial") as mock_serial_cls:
        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()

        yield handler, to_mesh_q, from_mesh_q, shutdown, mock_port


# ===========================================================================
# Scenario 1 — MC → MT channel message via the polling flow
# ===========================================================================


class TestMCtoMT_ChannelMessage:
    """Simulate a channel message arriving from MeshCore and reaching the
    Meshtastic queue."""

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_v3_channel_message_queued_for_meshtastic(self, mock_serial_cls):
        """A V3 channel message (code 17) should be decoded and queued."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        from_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()

        # Build a V3 channel message frame
        text = "Hello from MeshCore"
        payload = _v3_channel_msg_payload(text, channel_idx=0)
        frame = _outbound_frame(payload)

        # Feed the frame to the serial port mock
        read_count = [0]

        def mock_in_waiting():
            if read_count[0] == 0:
                return len(frame)
            return 0

        type(mock_port).in_waiting = PropertyMock(side_effect=mock_in_waiting)

        def mock_read(n):
            if read_count[0] == 0:
                read_count[0] += 1
                return frame
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        # Run receiver loop in a thread
        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert not to_mesh_q.empty(), "Channel message should have been queued"
        msg = to_mesh_q.get_nowait()
        assert msg["destination"] == "^all"
        assert msg["text"] == "Hello from MeshCore"
        assert msg["channel_index"] == 0

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_legacy_channel_message_queued(self, mock_serial_cls):
        """A legacy channel message (code 8) should also work."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        text = "Legacy channel msg"
        payload = _legacy_channel_msg_payload(text, channel_idx=2)
        frame = _outbound_frame(payload)

        read_count = [0]
        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(frame) if read_count[0] == 0 else 0
        )

        def mock_read(n):
            if read_count[0] == 0:
                read_count[0] += 1
                return frame
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert not to_mesh_q.empty()
        msg = to_mesh_q.get_nowait()
        assert msg["text"] == "Legacy channel msg"
        assert msg["channel_index"] == 2

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_contact_message_queued(self, mock_serial_cls):
        """A contact/DM message (code 7) should be queued."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        text = "Private DM"
        payload = _contact_msg_payload(text)
        frame = _outbound_frame(payload)

        read_count = [0]
        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(frame) if read_count[0] == 0 else 0
        )

        def mock_read(n):
            if read_count[0] == 0:
                read_count[0] += 1
                return frame
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert not to_mesh_q.empty()
        msg = to_mesh_q.get_nowait()
        assert msg["text"] == "Private DM"


# ===========================================================================
# Scenario 2 — Full polling cycle: MSG_WAITING → SYNC → msg → NO_MORE
# ===========================================================================


class TestCompanionPollingCycle:
    """Simulate the complete message polling flow:

    1. Radio sends PUSH_CODE_MSG_WAITING (0x83)
    2. Bridge sends CMD_SYNC_NEXT_MESSAGE (10)
    3. Radio replies with a channel message
    4. Bridge sends another CMD_SYNC_NEXT_MESSAGE
    5. Radio replies with RESP_CODE_NO_MORE_MESSAGES (10)
    6. Polling stops
    """

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_full_polling_flow(self, mock_serial_cls):
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        # Build the frame sequence the radio would send
        frames = [
            _outbound_frame(_msg_waiting_payload()),          # step 1
            _outbound_frame(                                   # step 3
                _v3_channel_msg_payload("Polled message", channel_idx=0)
            ),
            _outbound_frame(_no_more_messages_payload()),     # step 5
        ]
        all_data = b"".join(frames)

        read_idx = [0]
        chunks = list(frames)  # feed one frame at a time

        def mock_in_waiting():
            if read_idx[0] < len(chunks):
                return len(chunks[read_idx[0]])
            return 0

        type(mock_port).in_waiting = PropertyMock(side_effect=mock_in_waiting)

        def mock_read(n):
            idx = read_idx[0]
            if idx < len(chunks):
                read_idx[0] += 1
                return chunks[idx]
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=5)

        # The channel message should be queued
        assert not to_mesh_q.empty()
        msg = to_mesh_q.get_nowait()
        assert msg["text"] == "Polled message"

        # Bridge should have sent CMD_SYNC_NEXT_MESSAGE at least once
        # (written to serial as companion inbound frame for cmd byte 10)
        expected_sync_frame = _inbound_frame(bytes([10]))
        write_calls = [c for c in mock_port.write.call_args_list
                       if c.args and c.args[0] == expected_sync_frame]
        assert len(write_calls) >= 1, (
            f"Expected CMD_SYNC_NEXT_MESSAGE writes, got: {mock_port.write.call_args_list}"
        )

        # Polling should have stopped
        assert handler._companion_msg_polling is False

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_multiple_messages_then_stop(self, mock_serial_cls):
        """Radio has 2 queued messages, then signals no more."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        frames = [
            _outbound_frame(_msg_waiting_payload()),
            _outbound_frame(_v3_channel_msg_payload("First message")),
            _outbound_frame(_v3_channel_msg_payload("Second message")),
            _outbound_frame(_no_more_messages_payload()),
        ]

        read_idx = [0]
        chunks = list(frames)

        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(chunks[read_idx[0]]) if read_idx[0] < len(chunks) else 0
        )

        def mock_read(n):
            idx = read_idx[0]
            if idx < len(chunks):
                read_idx[0] += 1
                return chunks[idx]
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=5)

        messages = []
        while not to_mesh_q.empty():
            messages.append(to_mesh_q.get_nowait())
        assert len(messages) == 2
        assert messages[0]["text"] == "First message"
        assert messages[1]["text"] == "Second message"
        assert handler._companion_msg_polling is False


# ===========================================================================
# Scenario 3 — Adverts are NOT forwarded to Meshtastic
# ===========================================================================


class TestAdvertsNotForwarded:
    """Adverts (0x80, 0x8A) must be consumed internally and never reach
    the Meshtastic queue."""

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_advert_not_queued(self, mock_serial_cls):
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        pubkey = bytes(range(32))
        frame = _outbound_frame(_advert_payload(pubkey))

        read_count = [0]
        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(frame) if read_count[0] == 0 else 0
        )

        def mock_read(n):
            if read_count[0] == 0:
                read_count[0] += 1
                return frame
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert to_mesh_q.empty(), "Advert must NOT be queued to Meshtastic"

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_new_advert_not_queued(self, mock_serial_cls):
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        frame = _outbound_frame(_new_advert_payload(b"\xde\xad" * 16))

        read_count = [0]
        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(frame) if read_count[0] == 0 else 0
        )

        def mock_read(n):
            if read_count[0] == 0:
                read_count[0] += 1
                return frame
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert to_mesh_q.empty(), "New advert must NOT be queued to Meshtastic"


# ===========================================================================
# Scenario 4 — PUSH_CODE_LOG_RX_DATA (0x88) is safely ignored
# ===========================================================================


class TestLogRxDataIgnored:
    """0x88 (PUSH_CODE_LOG_RX_DATA) was previously misidentified as
    a channel message (old bug: base_code = 0x88 & 0x7F == 8).
    Verify it now produces *nothing* on the Meshtastic queue."""

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_push_log_rx_data_not_forwarded(self, mock_serial_cls):
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        frame = _outbound_frame(_log_rx_data_payload())

        read_count = [0]
        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(frame) if read_count[0] == 0 else 0
        )

        def mock_read(n):
            if read_count[0] == 0:
                read_count[0] += 1
                return frame
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert to_mesh_q.empty(), (
            "PUSH_CODE_LOG_RX_DATA (0x88) must NOT produce a Meshtastic message"
        )

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_0x88_followed_by_real_message_still_works(self, mock_serial_cls):
        """0x88 junk should not prevent a subsequent real message from being
        decoded and queued."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        frames = [
            _outbound_frame(_log_rx_data_payload()),
            _outbound_frame(_v3_channel_msg_payload("After log_rx")),
        ]

        read_idx = [0]
        chunks = list(frames)
        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(chunks[read_idx[0]]) if read_idx[0] < len(chunks) else 0
        )

        def mock_read(n):
            idx = read_idx[0]
            if idx < len(chunks):
                read_idx[0] += 1
                return chunks[idx]
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert not to_mesh_q.empty(), "Real message after 0x88 should be queued"
        msg = to_mesh_q.get_nowait()
        assert msg["text"] == "After log_rx"


# ===========================================================================
# Scenario 5 — MT → MC: Meshtastic message encoded as companion command
# ===========================================================================


class TestMTtoMC_Encoding:
    """Simulate a Meshtastic text message being encoded and written to
    the MeshCore serial port."""

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_meshtastic_message_written_as_companion_frame(self, mock_serial_cls):
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        from_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()
        # Clear handshake writes (should be none since handshake is disabled)
        mock_port.write.reset_mock()

        # Put a Meshtastic-originated message in the from_mesh queue
        mt_msg = {
            "type": "meshtastic_message",
            "payload": "Hello MeshCore!",
            "channel_index": 0,
        }
        from_mesh_q.put(mt_msg)

        # Run sender loop briefly
        shutdown_timer = threading.Timer(0.6, shutdown.set)
        shutdown_timer.start()
        handler._serial_sender_loop()

        # Verify that serial.write was called with a companion inbound frame
        assert mock_port.write.called, "Sender should write to serial"
        written = mock_port.write.call_args_list[-1].args[0]

        # Must be an inbound frame (0x3C header)
        assert written[0] == 0x3C, "Frame must have inbound header 0x3C"

        # Decode the written frame to verify content
        length = written[1] | (written[2] << 8)
        cmd_payload = written[3 : 3 + length]

        # First byte = CMD_SEND_CHANNEL_TXT_MSG (3)
        assert cmd_payload[0] == 3, "Command must be CMD_SEND_CHANNEL_TXT_MSG (3)"
        # txt_type, channel_idx
        assert cmd_payload[1] == 0   # txt_type
        assert cmd_payload[2] == 0   # channel_index

        # Bytes 3-6 = timestamp (4 bytes LE)
        # Bytes 7+ = text
        text = cmd_payload[7:].decode("utf-8")
        assert text == "Hello MeshCore!"

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_non_text_meshtastic_msg_skipped(self, mock_serial_cls):
        """Non-text Meshtastic messages should not be encoded."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        from_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, from_mesh_q, shutdown)
        handler.connect()
        mock_port.write.reset_mock()

        from_mesh_q.put({"type": "position_update", "payload": "data"})

        shutdown_timer = threading.Timer(0.6, shutdown.set)
        shutdown_timer.start()
        handler._serial_sender_loop()

        # No companion frame should have been written
        assert not mock_port.write.called, (
            "Non-text messages should not be sent to MeshCore"
        )


# ===========================================================================
# Scenario 6 — Mixed traffic: messages + adverts + junk in one stream
# ===========================================================================


class TestMixedTrafficStream:
    """Simulate a realistic radio stream with interleaved message types."""

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_mixed_stream_only_messages_forwarded(self, mock_serial_cls):
        """Only genuine channel/contact messages reach the Meshtastic queue;
        adverts, log data, and internal events are suppressed."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=50)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        frames = [
            _outbound_frame(_advert_payload()),                              # suppressed
            _outbound_frame(_log_rx_data_payload()),                         # suppressed
            _outbound_frame(_msg_waiting_payload()),                         # internal
            _outbound_frame(_v3_channel_msg_payload("Msg 1", channel_idx=0)),# forwarded
            _outbound_frame(_new_advert_payload()),                          # suppressed
            _outbound_frame(_v3_channel_msg_payload("Msg 2", channel_idx=1)),# forwarded
            _outbound_frame(_no_more_messages_payload()),                    # internal
            _outbound_frame(_contact_msg_payload("DM msg")),                 # forwarded
        ]

        read_idx = [0]
        chunks = list(frames)

        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(chunks[read_idx[0]]) if read_idx[0] < len(chunks) else 0
        )

        def mock_read(n):
            idx = read_idx[0]
            if idx < len(chunks):
                read_idx[0] += 1
                return chunks[idx]
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=5)

        messages = []
        while not to_mesh_q.empty():
            messages.append(to_mesh_q.get_nowait())

        texts = [m["text"] for m in messages]
        assert "Msg 1" in texts
        assert "Msg 2" in texts
        assert "DM msg" in texts
        assert len(messages) == 3, f"Expected 3 forwarded messages, got {len(messages)}: {texts}"


# ===========================================================================
# Scenario 7 — Protocol-only round-trip (no handler, pure encode/decode)
# ===========================================================================


class TestProtocolRoundTrips:
    """Verify that encoding and decoding are symmetric for all message types."""

    def test_v3_channel_msg_round_trip(self):
        proto = MeshcoreCompanionProtocol()
        text = "Round trip V3 channel"
        payload = _v3_channel_msg_payload(text, channel_idx=3, snr=15)
        decoded = proto.decode(payload)

        assert decoded is not None
        assert decoded["payload"] == text
        assert decoded["channel_index"] == 3
        assert decoded["companion_kind"] == "channel_msg"
        assert decoded["snr"] == 15

    def test_legacy_channel_msg_round_trip(self):
        proto = MeshcoreCompanionProtocol()
        text = "Legacy RT"
        payload = _legacy_channel_msg_payload(text, channel_idx=5)
        decoded = proto.decode(payload)

        assert decoded is not None
        assert decoded["payload"] == text
        assert decoded["channel_index"] == 5

    def test_contact_msg_round_trip(self):
        proto = MeshcoreCompanionProtocol()
        text = "Contact RT"
        payload = _contact_msg_payload(text)
        decoded = proto.decode(payload)

        assert decoded is not None
        assert decoded["payload"] == text
        assert decoded["companion_kind"] == "contact_msg"

    def test_msg_waiting_decoded(self):
        proto = MeshcoreCompanionProtocol()
        decoded = proto.decode(_msg_waiting_payload())
        assert decoded is not None
        assert decoded["companion_kind"] == "msg_waiting"
        assert decoded["internal_only"] is True

    def test_no_more_messages_decoded(self):
        proto = MeshcoreCompanionProtocol()
        decoded = proto.decode(_no_more_messages_payload())
        assert decoded is not None
        assert decoded["companion_kind"] == "no_more_messages"
        assert decoded["internal_only"] is True

    def test_advert_decoded_as_internal(self):
        proto = MeshcoreCompanionProtocol()
        decoded = proto.decode(_advert_payload(b"\xab" * 32))
        assert decoded is not None
        assert decoded["internal_only"] is True
        assert decoded["companion_kind"] == "advert"
        assert decoded["pubkey"].startswith("abab")

    def test_log_rx_data_returns_none(self):
        proto = MeshcoreCompanionProtocol()
        decoded = proto.decode(_log_rx_data_payload())
        assert decoded is None, "0x88 LOG_RX_DATA should return None"

    def test_framing_write_read_symmetry(self):
        """Write an inbound frame, flip to outbound header, read it back."""
        proto = MeshcoreCompanionProtocol()
        original = _v3_channel_msg_payload("Symmetry test")
        encoded = proto.encode({"payload": original})
        assert encoded is not None

        # Simulate the radio echoing it back as outbound
        outbound = bytes([0x3E]) + encoded[1:]
        mock_port = MagicMock()
        mock_port.in_waiting = len(outbound)
        mock_port.read.return_value = outbound

        read_back = proto.read(mock_port)
        assert read_back == original

        decoded = proto.decode(read_back)
        assert decoded is not None
        assert decoded["payload"] == "Symmetry test"


# ===========================================================================
# Scenario 8 — Reproduce the exact bug from the user's original log
# ===========================================================================


class TestReproduceOriginalBugs:
    """Reproduce the exact bytes from the user's debug log that exposed
    the three bugs, and verify they are now handled correctly."""

    def test_0x88_no_longer_misidentified_as_channel_msg(self):
        """The user's log showed 0x88 (PUSH_CODE_LOG_RX_DATA) being decoded
        as channel_index=49 (the SNR byte), which the validator rejected.
        Verify it is now safely ignored."""
        proto = MeshcoreCompanionProtocol()

        # Simulate the kind of payload the radio sends for LOG_RX_DATA
        # [0x88][SNR=0x31][...data...]
        raw = bytes([0x88, 0x31, 0x00, 0x00, 0x01, 0x00, 0x00]) + b"Test log data"
        decoded = proto.decode(raw)
        assert decoded is None

    def test_advert_no_longer_forwarded_as_text(self):
        """The user saw 'MC_ADVERT:db46 --------' on Meshtastic chat.
        Verify adverts are now internal-only."""
        proto = MeshcoreCompanionProtocol()

        pubkey = bytes.fromhex(
            "db46" + "00" * 30  # 32-byte pubkey with db46 prefix
        )
        raw = bytes([0x80]) + pubkey
        decoded = proto.decode(raw)

        assert decoded is not None
        assert decoded["internal_only"] is True
        assert decoded["companion_kind"] == "advert"
        assert "payload" not in decoded, "Advert must not have a 'payload' field"
        assert decoded["pubkey"].startswith("db46")

    @patch("ammb.meshcore_handler.serial.Serial")
    def test_end_to_end_0x88_does_not_reach_meshtastic(self, mock_serial_cls):
        """Full handler-level test: a 0x88 frame does not produce any
        message in the Meshtastic queue."""
        from ammb.meshcore_handler import MeshcoreHandler

        to_mesh_q = Queue(maxsize=10)
        shutdown = threading.Event()
        config = _make_bridge_config()

        mock_port = MagicMock()
        mock_port.is_open = True
        mock_serial_cls.return_value = mock_port

        handler = MeshcoreHandler(config, to_mesh_q, Queue(), shutdown)
        handler.connect()

        # Exactly the kind of frame the radio sends
        raw_payload = bytes([0x88, 0x31, 0x00, 0x00, 0x01, 0x00, 0x00]) + b"rssi data"
        frame = _outbound_frame(raw_payload)

        read_count = [0]
        type(mock_port).in_waiting = PropertyMock(
            side_effect=lambda: len(frame) if read_count[0] == 0 else 0
        )

        def mock_read(n):
            if read_count[0] == 0:
                read_count[0] += 1
                return frame
            shutdown.set()
            return b""

        mock_port.read.side_effect = mock_read

        t = threading.Thread(target=handler._serial_receiver_loop, daemon=True)
        t.start()
        t.join(timeout=3)

        assert to_mesh_q.empty(), "0x88 LOG_RX_DATA must NOT reach Meshtastic queue"
