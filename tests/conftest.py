import configparser

import pytest

from ammb.config_handler import BridgeConfig
from ammb.message_logger import reset_message_logger


@pytest.fixture(autouse=True)
def _reset_message_logger():
    reset_message_logger()
    yield
    reset_message_logger()


def make_bridge_config(**overrides):
    """Build a BridgeConfig with serial defaults for unit tests."""
    values = {
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
        "external_network_id": "test_net",
        "bridge_node_id": "!testnode",
        "queue_size": 100,
        "log_level": "DEBUG",
        "api_enabled": False,
        "api_host": "127.0.0.1",
        "api_port": 8080,
    }
    values.update(overrides)
    return BridgeConfig(**values)


@pytest.fixture(scope="function")
def temp_config_file(tmp_path):
    config_path = tmp_path / "config.ini"
    parser = configparser.ConfigParser()
    parser["DEFAULT"] = {
        "MESHTASTIC_SERIAL_PORT": "/dev/test_meshtastic",
        "EXTERNAL_TRANSPORT": "serial",
        "SERIAL_PORT": "/dev/test_meshcore",
        "SERIAL_BAUD_RATE": "19200",
        "SERIAL_PROTOCOL": "json_newline",
        "MESSAGE_QUEUE_SIZE": "50",
        "LOG_LEVEL": "DEBUG",
        "SERIAL_AUTO_SWITCH": "True",
    }
    with open(config_path, "w") as f:
        parser.write(f)
    yield str(config_path)
