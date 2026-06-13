from pathlib import Path

from ammb.preflight import (
    build_config_summary,
    format_preflight_report,
    run_preflight,
)


def _write_config(path: Path, body: str) -> Path:
    path.write_text("[DEFAULT]\n" + body, encoding="utf-8")
    return path


def _fake_importer(_module_name):
    return object()


def test_preflight_redacts_mqtt_password(tmp_path):
    config_path = _write_config(
        tmp_path / "mqtt.ini",
        """
EXTERNAL_TRANSPORT = mqtt
MQTT_BROKER = broker.example
MQTT_PORT = 1883
MQTT_TOPIC_IN = ammb/in
MQTT_TOPIC_OUT = ammb/out
MQTT_USERNAME = operator
MQTT_PASSWORD = super-secret
MQTT_CLIENT_ID = bridge-client
MQTT_QOS = 1
MQTT_RETAIN_OUT = False
MQTT_TLS_ENABLED = True
LOG_LEVEL = INFO
""",
    )

    report = run_preflight(str(config_path), importer=_fake_importer)
    summary = dict(build_config_summary(report.config))
    rendered = format_preflight_report(report)

    assert summary["MQTT password"] == "configured (hidden)"
    assert "super-secret" not in rendered


def test_preflight_flags_missing_mqtt_ca_cert_as_error(tmp_path):
    config_path = _write_config(
        tmp_path / "mqtt.ini",
        """
EXTERNAL_TRANSPORT = mqtt
MQTT_BROKER = broker.example
MQTT_PORT = 8883
MQTT_TOPIC_IN = ammb/in
MQTT_TOPIC_OUT = ammb/out
MQTT_CLIENT_ID = bridge-client
MQTT_QOS = 1
MQTT_RETAIN_OUT = False
MQTT_TLS_ENABLED = True
MQTT_TLS_CA_CERTS = /definitely/missing/ca.pem
LOG_LEVEL = INFO
""",
    )

    report = run_preflight(str(config_path), importer=_fake_importer)

    assert report.ready is False
    assert report.error_count == 1
    assert report.diagnostics[0].title == "MQTT CA certificate missing"


def test_preflight_allows_warnings_without_blocking_start(tmp_path):
    config_path = _write_config(
        tmp_path / "serial.ini",
        """
MESHTASTIC_SERIAL_PORT = /dev/definitely-missing-meshtastic
EXTERNAL_TRANSPORT = serial
SERIAL_PORT = /dev/definitely-missing-meshcore
SERIAL_BAUD_RATE = 9600
SERIAL_PROTOCOL = companion_radio
MESSAGE_QUEUE_SIZE = 5
LOG_LEVEL = DEBUG
""",
    )

    report = run_preflight(str(config_path), importer=_fake_importer)
    titles = {item.title for item in report.diagnostics}

    assert report.ready is True
    assert report.warning_count >= 4
    assert "Small message queue" in titles
    assert "Verbose logging enabled" in titles
    assert "Meshtastic serial port" in titles
    assert "External serial port" in titles


def test_preflight_reports_missing_config(tmp_path):
    report = run_preflight(str(tmp_path / "missing.ini"), importer=_fake_importer)

    assert report.ready is False
    assert report.config is None
    assert report.diagnostics[0].title == "Configuration file missing"
