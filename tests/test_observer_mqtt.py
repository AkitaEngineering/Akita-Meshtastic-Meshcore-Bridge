import json
import threading
from queue import Queue
from types import SimpleNamespace

from ammb.observer_mqtt import (
    PUBLIC_CHANNEL_KEY,
    ChannelKey,
    SeenHashCache,
    calculate_packet_hash,
    decrypt_group_text,
    encode_group_text_packet,
    hashtag_channel_key,
    is_observer_packet,
    is_observer_status,
    meshtastic_item_to_observer_packet,
    observer_packet_to_bridge_message,
    parse_channel_keys,
    parse_raw_packet,
    topic_is_observer_control,
)
from tests.test_mqtt import _mqtt_config
from ammb.mqtt_handler import MQTTHandler


ISSUE_16_PACKET = {
    "timestamp": "2026-09-13T04:29:52.407921+00:00",
    "hash": "1D342605534E2CB3",
    "origin": "Meshcore Repeater obs",
    "type": "PACKET",
    "direction": "rx",
    "time": "04:29:52",
    "date": "13/09/2026",
    "len": "39",
    "packet_type": "5",
    "route": "F",
    "payload_len": "35",
    "raw": (
        "1502DCD189D184C69F37468FB3E0474C81B3D966D7116D1DFC472C43DB1084FED4CD7732D750AD"
    ),
    "origin_id": "4FEF19D131C41F5C936B7E59D93A8D4DA061B1DA2B413D381FC84A20FBCB8E62",
    "SNR": "1.8",
    "RSSI": "-112",
    "score": "784",
}


def test_public_channel_hash_is_stable():
    key = ChannelKey("Public", PUBLIC_CHANNEL_KEY)
    assert key.channel_hash == 0x11


def test_group_text_roundtrip():
    key = ChannelKey("Public", PUBLIC_CHANNEL_KEY)
    encoded = encode_group_text_packet(
        "hello mesh",
        "Alice",
        key,
        timestamp=1700000000,
        origin="bridge",
        origin_id="ABCD",
    )
    assert encoded["type"] == "PACKET"
    assert encoded["packet_type"] == "5"
    assert encoded["route"] == "F"
    assert len(encoded["hash"]) == 16

    parsed = parse_raw_packet(encoded["raw"])
    assert parsed is not None
    assert parsed.payload_type == 5
    assert parsed.route_type == 1
    assert parsed.hop_count == 0
    assert parsed.packet_hash == encoded["hash"]
    assert calculate_packet_hash(parsed.payload_type, parsed.payload) == encoded["hash"]

    group = decrypt_group_text(parsed.payload, [key])
    assert group is not None
    assert group.sender == "Alice"
    assert group.text == "hello mesh"
    assert group.timestamp == 1700000000


def test_observer_packet_converts_to_bridge_message():
    key = ChannelKey("Public", PUBLIC_CHANNEL_KEY)
    encoded = encode_group_text_packet("Test 123", "Repeater", key)
    converted = observer_packet_to_bridge_message(encoded, [key])
    assert converted is not None
    assert converted["destination_meshtastic_id"] == "^all"
    assert converted["payload"] == "Repeater: Test 123"


def test_issue_16_packet_is_detected_and_not_ammb_json():
    assert is_observer_packet(ISSUE_16_PACKET)
    assert not is_observer_status(ISSUE_16_PACKET)
    parsed = parse_raw_packet(ISSUE_16_PACKET["raw"])
    assert parsed is not None
    assert parsed.payload_type == 5
    assert parsed.route_type == 1
    assert parsed.hop_count == 2
    # Encrypted against a non-public channel in the report, so decrypt fails
    # and the converter skips rather than inventing a payload.
    converted = observer_packet_to_bridge_message(
        ISSUE_16_PACKET, parse_channel_keys(include_public=True)
    )
    assert converted is None


def test_predecoded_group_text_is_used():
    packet = dict(ISSUE_16_PACKET)
    packet["decoded"] = {
        "kind": "GRP_TXT",
        "sender": "Alice",
        "text": "hello mesh",
        "decrypted": True,
    }
    converted = observer_packet_to_bridge_message(
        packet, parse_channel_keys(include_public=True)
    )
    assert converted is not None
    assert converted["payload"] == "Alice: hello mesh"


def test_status_and_control_topics_are_ignored():
    assert is_observer_status({"status": "online", "origin": "obs"})
    assert topic_is_observer_control("meshcore/IATA/ABC/status")
    assert topic_is_observer_control("meshcore/IATA/ABC/neighbors")
    assert not topic_is_observer_control("meshcore/IATA/ABC/packets")


def test_hashtag_and_extra_keys_parse():
    keys = parse_channel_keys(
        extra="#bot,custom=ff2b7d74e8d20f71505bda9ea8d59a1c",
        include_public=True,
    )
    names = [key.name for key in keys]
    assert "Public" in names
    assert "#bot" in names
    assert "custom" in names
    bot = next(key for key in keys if key.name == "#bot")
    assert bot.secret == hashtag_channel_key("#bot")


def test_seen_hash_cache_dedups():
    cache = SeenHashCache(max_size=2)
    assert cache.seen("AAAA") is False
    assert cache.seen("AAAA") is True
    assert cache.seen("BBBB") is False
    assert cache.seen("CCCC") is False
    # AAAA was evicted
    assert cache.seen("AAAA") is False


def test_mqtt_handler_accepts_observer_group_text():
    key = ChannelKey("Public", PUBLIC_CHANNEL_KEY)
    encoded = encode_group_text_packet("ping", "MC", key)
    to_mesh = Queue()
    handler = MQTTHandler(
        _mqtt_config(), to_mesh, Queue(), threading.Event()
    )
    msg = SimpleNamespace(
        topic="meshcore/IATA/DEVICE/packets",
        payload=json.dumps(encoded).encode("utf-8"),
    )
    handler._on_message(None, None, msg)
    queued = to_mesh.get_nowait()
    assert queued["destination"] == "^all"
    assert queued["text"] == "MC: ping"


def test_mqtt_handler_skips_issue_16_packet_without_warning_error(caplog):
    to_mesh = Queue()
    handler = MQTTHandler(
        _mqtt_config(), to_mesh, Queue(), threading.Event()
    )
    msg = SimpleNamespace(
        topic="meshcore/IATA/DEVICE/packets",
        payload=json.dumps(ISSUE_16_PACKET).encode("utf-8"),
    )
    handler._on_message(None, None, msg)
    assert to_mesh.empty()
    assert "Missing 'payload'" not in caplog.text


def test_mqtt_handler_still_accepts_ammb_json():
    to_mesh = Queue()
    handler = MQTTHandler(
        _mqtt_config(), to_mesh, Queue(), threading.Event()
    )
    msg = SimpleNamespace(
        topic="ammb/in",
        payload=json.dumps(
            {
                "destination_meshtastic_id": "!abcd1234",
                "payload": "hello mesh",
                "channel_index": 1,
            }
        ).encode("utf-8"),
    )
    handler._on_message(None, None, msg)
    queued = to_mesh.get_nowait()
    assert queued["destination"] == "!abcd1234"
    assert queued["text"] == "hello mesh"
    assert queued["channel_index"] == 1


def test_mqtt_handler_ignores_status_messages(caplog):
    to_mesh = Queue()
    handler = MQTTHandler(
        _mqtt_config(), to_mesh, Queue(), threading.Event()
    )
    msg = SimpleNamespace(
        topic="meshcore/IATA/DEVICE/status",
        payload=json.dumps(
            {"status": "online", "origin": "obs", "origin_id": "ABC"}
        ).encode("utf-8"),
    )
    handler._on_message(None, None, msg)
    assert to_mesh.empty()
    assert "Missing 'payload'" not in caplog.text


def test_mqtt_publisher_emits_observer_packets():
    config = _mqtt_config(mqtt_payload_format="observer")
    to_mesh = Queue()
    from_mesh = Queue()
    shutdown = threading.Event()
    handler = MQTTHandler(config, to_mesh, from_mesh, shutdown)
    client = SimpleNamespace()
    published = {}

    def publish(topic, payload=None, qos=0, retain=False):
        published["topic"] = topic
        published["payload"] = payload
        shutdown.set()
        return SimpleNamespace(rc=0)

    client.is_connected = lambda: True
    client.publish = publish
    handler.client = client
    handler._mqtt_connected.set()
    from_mesh.put(
        {
            "type": "meshtastic_message",
            "sender_meshtastic_id": "!a2eb419c",
            "sender_display_name": "Meshtastic Repeater Ownername",
            "portnum": "TEXT_MESSAGE_APP",
            "payload": "Test 123",
            "channel_index": 1,
        }
    )
    handler._mqtt_publisher_loop()
    decoded = json.loads(published["payload"])
    assert decoded["type"] == "PACKET"
    assert decoded["packet_type"] == "5"
    converted = observer_packet_to_bridge_message(
        decoded, handler._channel_keys
    )
    assert converted is not None
    assert "Test 123" in converted["payload"]


def test_meshtastic_item_helper_skips_position():
    key = ChannelKey("Public", PUBLIC_CHANNEL_KEY)
    encoded = meshtastic_item_to_observer_packet(
        {"type": "meshtastic_position", "payload": {"latitude": 1}},
        key,
        origin="ammb",
        origin_id="",
    )
    assert encoded is None
