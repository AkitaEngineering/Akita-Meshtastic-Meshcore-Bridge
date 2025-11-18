import pytest
from ammb.config_handler import load_config, BridgeConfig

def test_load_config_success(temp_config_file):
    config = load_config(temp_config_file)
    assert config is not None
    assert isinstance(config, BridgeConfig)
    assert config.meshtastic_port == '/dev/test_meshtastic'
    assert config.serial_port == '/dev/test_meshcore'

def test_load_config_file_not_found():
    config = load_config("non_existent_file.ini")
    assert config is None
