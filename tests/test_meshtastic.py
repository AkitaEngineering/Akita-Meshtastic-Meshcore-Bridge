import threading
from queue import Queue
from unittest.mock import MagicMock, patch

import pytest
from pubsub import pub

from ammb.meshcore_handler import MeshcoreHandler
from ammb.meshtastic_handler import MeshtasticHandler
from tests.conftest import make_bridge_config


def _handler():
    return MeshtasticHandler(
        make_bridge_config(bridge_node_id="!000000ab"),
        Queue(), Queue(), threading.Event(),
    )


def _packet(sender=0x1234):
    return {
        "from": sender,
        "decoded": {"portnum": "TEXT_MESSAGE_APP", "payload": b"hello"},
    }


@pytest.mark.parametrize("channel", [None, 0])
def test_primary_channel_packet_forwards_to_companion(channel):
    handler = _handler()
    packet = _packet()
    if channel is not None:
        packet["channel"] = channel
    handler._on_meshtastic_receive(packet, MagicMock())
    message = handler.to_external_queue.get_nowait()
    assert message["sender_meshtastic_id"] == "!00001234"
    assert message["channel_index"] == 0
    external = MeshcoreHandler(
        make_bridge_config(), Queue(), Queue(), threading.Event()
    )
    encoded = external._encode_companion_from_meshtastic(message)
    assert encoded is not None
    assert b"hello" in encoded


def test_loopback_node_id_with_leading_zeroes_is_ignored():
    handler = _handler()
    handler._on_meshtastic_receive(_packet(sender=0xAB), MagicMock())
    assert handler.to_external_queue.empty()


def test_meshtastic_disconnect_subscription_tracks_current_interface():
    handler = _handler()
    interface = MagicMock()
    interface.getMyNodeInfo.return_value = {"num": 0xAB}
    with patch(
        "ammb.meshtastic_handler.meshtastic.serial_interface.SerialInterface",
        return_value=interface,
    ):
        try:
            assert handler.connect()
            assert handler.my_node_id == "!000000ab"
            pub.sendMessage("meshtastic.connection.lost", interface=MagicMock())
            assert handler._is_connected.is_set()
            pub.sendMessage("meshtastic.connection.lost", interface=interface)
            assert not handler._is_connected.is_set()
            assert handler.connect()
            assert handler._is_connected.is_set()
        finally:
            handler.stop()
    assert not pub.isSubscribed(handler._on_meshtastic_disconnect, "meshtastic.connection.lost")
    assert not pub.isSubscribed(handler._on_meshtastic_receive, "meshtastic.receive")


def test_packets_from_another_interface_are_ignored():
    handler = _handler()
    handler.interface = MagicMock()
    handler._on_meshtastic_receive(_packet(), MagicMock())
    assert handler.to_external_queue.empty()
