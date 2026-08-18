from ammb.config_handler import load_config, resolve_config_path
from ammb.version import __version__


def _write_config(path, extra=""):
    path.write_text(
        "[DEFAULT]\n"
        "MESHTASTIC_SERIAL_PORT = /dev/ttyUSB0\n"
        "EXTERNAL_TRANSPORT = serial\n"
        "SERIAL_PORT = /dev/ttyS0\n"
        "SERIAL_BAUD_RATE = 115200\n"
        "SERIAL_PROTOCOL = companion_radio\n"
        f"{extra}"
    )
    return path


def test_package_version_is_canonical():
    assert __version__ == "2.2.0"


def test_load_config_reads_production_settings(tmp_path):
    path = _write_config(
        tmp_path / "config.ini",
        extra=(
            "RATE_LIMIT_MAX_MESSAGES = 12\n"
            "RATE_LIMIT_WINDOW_S = 15\n"
            "MESSAGE_LOG_FILE = /tmp/ammb.jsonl\n"
            "MESSAGE_LOG_MAX_MB = 3\n"
            "MESSAGE_LOG_MAX_BACKUPS = 2\n"
            "API_ENABLED = True\n"
            "API_TOKEN = hidden-token\n"
            "MESHTASTIC_RETRY_ON_BOOT = False\n"
            "MESHTASTIC_RETRY_DELAY_S = 7\n"
        ),
    )
    config = load_config(str(path))
    assert config is not None
    assert config.rate_limit_max_messages == 12
    assert config.rate_limit_window_s == 15.0
    assert config.message_log_file == "/tmp/ammb.jsonl"
    assert config.message_log_max_mb == 3
    assert config.message_log_max_backups == 2
    assert config.api_token == "hidden-token"
    assert config.meshtastic_retry_on_boot is False
    assert config.meshtastic_retry_delay_s == 7


def test_resolve_config_path_prefers_explicit_then_env(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit.ini"
    env_file = tmp_path / "env.ini"
    explicit.write_text("")
    env_file.write_text("")
    monkeypatch.setenv("AMMB_CONFIG", str(env_file))
    assert resolve_config_path(str(explicit)).endswith("explicit.ini")
    assert resolve_config_path().endswith("env.ini")
