import json
import threading
from queue import Queue
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from ammb.mqtt_handler import MQTTHandler
from tests.conftest import make_bridge_config


def _mqtt_config(**overrides):
    values = {
        "external_transport": "mqtt",
        "serial_port": None,
        "serial_baud": None,
        "serial_protocol": None,
        "mqtt_broker": "localhost",
        "mqtt_port": 1883,
        "mqtt_topic_in": "ammb/in",
        "mqtt_topic_out": "ammb/out",
        "mqtt_client_id": "ammb-test",
        "mqtt_qos": 0,
        "mqtt_retain_out": False,
        "mqtt_username": None,
        "mqtt_password": None,
    }
    values.update(overrides)
    return make_bridge_config(**values)


@pytest.fixture
def mqtt_handler():
    to_mesh = Queue()
    from_mesh = Queue()
    shutdown = threading.Event()
    handler = MQTTHandler(
        _mqtt_config(), to_mesh, from_mesh, shutdown
    )
    return handler, to_mesh, from_mesh, shutdown


def test_mqtt_message_is_queued_for_meshtastic(mqtt_handler):
    handler, to_mesh, _from_mesh, _shutdown = mqtt_handler
    msg = SimpleNamespace(
        payload=json.dumps(
            {
                "destination_meshtastic_id": "!abcd1234",
                "payload": "hello mesh",
                "channel_index": 1,
            }
        ).encode("utf-8")
    )

    handler._on_message(None, None, msg)

    queued = to_mesh.get_nowait()
    assert queued["destination"] == "!abcd1234"
    assert queued["text"] == "hello mesh"
    assert queued["channel_index"] == 1


def test_mqtt_invalid_payload_is_rejected(mqtt_handler):
    handler, to_mesh, _from_mesh, _shutdown = mqtt_handler
    msg = SimpleNamespace(payload=b"not-json")

    handler._on_message(None, None, msg)

    assert to_mesh.empty()


def test_mqtt_rate_limit_drops_excess_messages():
    config = _mqtt_config(
        rate_limit_max_messages=1,
        rate_limit_window_s=60.0,
    )
    to_mesh = Queue()
    handler = MQTTHandler(
        config, to_mesh, Queue(), threading.Event()
    )
    msg = SimpleNamespace(
        payload=json.dumps(
            {
                "destination_meshtastic_id": "!abcd1234",
                "payload": "one",
            }
        ).encode("utf-8")
    )

    handler._on_message(None, None, msg)
    handler._on_message(None, None, msg)

    assert to_mesh.qsize() == 1


def test_mqtt_publisher_sends_json_payload(mqtt_handler):
    handler, _to_mesh, from_mesh, shutdown = mqtt_handler
    client = MagicMock()
    client.is_connected.return_value = True
    handler.client = client
    handler._mqtt_connected.set()
    from_mesh.put(
        {
            "type": "meshtastic_message",
            "payload": "ping",
        }
    )

    def _stop_after_first(*_args, **_kwargs):
        shutdown.set()

    client.publish.side_effect = _stop_after_first
    handler._mqtt_publisher_loop()

    client.publish.assert_called_once()
    topic, kwargs = client.publish.call_args[0][0], client.publish.call_args[1]
    if not kwargs:
        kwargs = {
            "payload": client.publish.call_args[0][1],
        }
    assert topic == "ammb/out"
    payload = kwargs.get("payload")
    if payload is None:
        payload = client.publish.call_args[0][1]
    decoded = json.loads(payload)
    assert decoded["payload"] == "ping"


def test_mqtt_connect_configures_tls():
    config = _mqtt_config(mqtt_tls_enabled=True, mqtt_tls_insecure=True)
    handler = MQTTHandler(
        config, Queue(), Queue(), threading.Event()
    )
    fake_client = MagicMock()
    fake_client.is_connected.return_value = False

    with patch("ammb.mqtt_handler.paho_mqtt.Client", return_value=fake_client):
        assert handler.connect() is True

    fake_client.tls_set_context.assert_called_once()
    fake_client.connect_async.assert_called_once()
    fake_client.loop_start.assert_called_once()
    handler.stop()
