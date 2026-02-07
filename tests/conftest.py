import configparser

import pytest


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
