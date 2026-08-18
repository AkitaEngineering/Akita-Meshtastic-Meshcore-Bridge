import threading
import time
from queue import Queue

import pytest

from ammb.config_handler import BridgeConfig
from ammb.tui import (
    BridgeController,
    BridgeDashboardApp,
    DashboardStore,
    build_config_rows,
)


def make_config(**overrides):
    values = {
        "meshtastic_port": "/dev/ttyUSB0",
        "external_transport": "serial",
        "serial_port": "/dev/ttyS0",
        "serial_baud": 9600,
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
        "external_network_id": "meshcore-net",
        "bridge_node_id": "!bridge",
        "queue_size": 100,
        "log_level": "INFO",
        "api_enabled": True,
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
    values.update(overrides)
    return BridgeConfig(**values)


class FakeBridge:
    def __init__(self, config):
        self.config = config
        self.external_handler = object()
        self.shutdown_event = threading.Event()
        self.to_meshtastic_queue = Queue()
        self.to_external_queue = Queue()

    def run(self):
        self.shutdown_event.wait(timeout=2)

    def stop(self):
        self.shutdown_event.set()


class BrokenBridge(FakeBridge):
    def __init__(self, config):
        super().__init__(config)
        self.external_handler = None

    def run(self):
        raise AssertionError("run() should not be called")


def test_build_config_rows_redacts_mqtt_password():
    config = make_config(
        external_transport="mqtt",
        serial_port=None,
        serial_baud=None,
        serial_protocol=None,
        mqtt_broker="broker.example",
        mqtt_port=1883,
        mqtt_topic_in="mesh/in",
        mqtt_topic_out="mesh/out",
        mqtt_username="operator",
        mqtt_password="super-secret",
        mqtt_client_id="bridge-client",
    )

    rows = dict(build_config_rows(config))

    assert rows["MQTT Password"] == "configured (hidden)"
    assert rows["MQTT Broker"] == "broker.example:1883"


def test_build_config_rows_redacts_api_token():
    rows = dict(build_config_rows(make_config(api_token="super-secret")))
    assert rows["API Token"] == "configured (hidden)"
    assert "super-secret" not in rows["API Token"]


def test_build_config_rows_only_show_companion_fields_for_companion_protocol():
    standard_rows = dict(build_config_rows(make_config(serial_protocol="json_newline")))
    companion_rows = dict(
        build_config_rows(
            make_config(
                serial_protocol="companion_radio",
                companion_contacts_poll_s=30,
                companion_debug=True,
            )
        )
    )

    assert "Companion Handshake" not in standard_rows
    assert "Companion Poll" not in standard_rows
    assert "Companion Debug" not in standard_rows
    assert companion_rows["Companion Handshake"] == "enabled"
    assert companion_rows["Companion Poll"] == "30s"
    assert companion_rows["Companion Debug"] == "enabled"


def test_bridge_controller_start_and_stop():
    controller = BridgeController(make_config(), bridge_factory=FakeBridge)

    started, _ = controller.start()

    assert started is True
    for _ in range(20):
        if controller.snapshot().thread_alive:
            break
        time.sleep(0.05)

    snapshot = controller.snapshot()
    assert snapshot.thread_alive is True
    assert snapshot.state == "running"

    stopped, _ = controller.stop(wait=True)

    assert stopped is True
    final_snapshot = controller.snapshot()
    assert final_snapshot.thread_alive is False
    assert final_snapshot.state == "stopped"


def test_bridge_controller_reports_init_failure():
    controller = BridgeController(make_config(), bridge_factory=BrokenBridge)

    started, message = controller.start()

    assert started is False
    assert "initialization failed" in message.lower()
    assert controller.snapshot().state == "error"


def test_bridge_dashboard_app_mounts(monkeypatch):
    config = make_config()
    store = DashboardStore()
    controller = BridgeController(
        config,
        bridge_factory=FakeBridge,
        event_sink=store.add_event,
    )
    app = BridgeDashboardApp(
        config=config,
        controller=controller,
        store=store,
    )

    refresh_calls = []
    interval_calls = []

    monkeypatch.setattr(
        app,
        "refresh_dashboard",
        lambda: refresh_calls.append("refresh"),
    )
    monkeypatch.setattr(
        app,
        "set_interval",
        lambda interval, callback: interval_calls.append((interval, callback)),
    )

    app.on_mount()

    assert app.title == "Akita Mesh Bridge Command Center"
    assert app.sub_title == config.external_transport.upper()
    assert refresh_calls == ["refresh"]
    assert interval_calls == [(1.0, app.refresh_dashboard)]
    assert controller.snapshot().state == "running"

    controller.stop(wait=True)