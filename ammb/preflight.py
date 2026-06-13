"""
Preflight diagnostics and redacted configuration summaries for AMMB.
"""

from __future__ import annotations

import importlib
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .config_handler import BridgeConfig, load_config


DependencySpec = tuple[str, str]
Importer = Callable[[str], object]


RUNTIME_DEPENDENCIES: tuple[DependencySpec, ...] = (
    ("meshtastic", "meshtastic"),
    ("meshtastic.serial_interface", "meshtastic"),
    ("paho.mqtt.client", "paho-mqtt"),
    ("pubsub", "pypubsub"),
    ("serial", "pyserial"),
)

TUI_DEPENDENCIES: tuple[DependencySpec, ...] = (
    ("textual", "textual"),
    ("rich", "rich"),
)


@dataclass(frozen=True)
class Diagnostic:
    """Single preflight finding."""

    severity: str
    title: str
    detail: str
    action: str = ""

    @property
    def is_error(self) -> bool:
        return self.severity.lower() == "error"


@dataclass(frozen=True)
class PreflightReport:
    """Operator-friendly startup readiness report."""

    config_path: str
    config: BridgeConfig | None
    diagnostics: tuple[Diagnostic, ...]

    @property
    def ready(self) -> bool:
        return self.config is not None and not any(
            item.is_error for item in self.diagnostics
        )

    @property
    def error_count(self) -> int:
        return sum(1 for item in self.diagnostics if item.is_error)

    @property
    def warning_count(self) -> int:
        return sum(
            1 for item in self.diagnostics
            if item.severity.lower() == "warning"
        )


def check_missing_dependencies(
    dependencies: Iterable[DependencySpec],
    *,
    importer: Importer = importlib.import_module,
) -> list[str]:
    """Return a sorted, de-duplicated list of missing package names."""
    missing: set[str] = set()
    for module_name, package_name in dependencies:
        try:
            importer(module_name)
        except ImportError:
            missing.add(package_name)
    return sorted(missing)


def build_config_summary(config: BridgeConfig) -> list[tuple[str, str]]:
    """Build a redacted summary suitable for CLI output and support bundles."""
    rows = [
        ("Meshtastic port", config.meshtastic_port or "disabled"),
        ("External transport", config.external_transport),
        ("External network", config.external_network_id),
        ("Bridge node", config.bridge_node_id),
        ("Queue size", str(config.queue_size)),
        ("Log level", config.log_level),
        ("API", _api_value(config)),
    ]

    if config.external_transport == "serial":
        rows.extend(
            [
                ("Serial port", config.serial_port or "not configured"),
                ("Serial baud", str(config.serial_baud or "--")),
                ("Serial protocol", config.serial_protocol or "--"),
                (
                    "Meshtastic channel",
                    _channel_value(config.meshtastic_channel_index),
                ),
                (
                    "MeshCore channel",
                    _channel_value(config.meshcore_channel_index),
                ),
            ]
        )
    else:
        rows.extend(
            [
                (
                    "MQTT broker",
                    f"{config.mqtt_broker or '--'}:{config.mqtt_port or '--'}",
                ),
                ("MQTT topic in", config.mqtt_topic_in or "--"),
                ("MQTT topic out", config.mqtt_topic_out or "--"),
                ("MQTT client ID", config.mqtt_client_id or "--"),
                ("MQTT username", config.mqtt_username or "anonymous"),
                (
                    "MQTT password",
                    "configured (hidden)" if config.mqtt_password else "not set",
                ),
                (
                    "MQTT QoS",
                    str(config.mqtt_qos if config.mqtt_qos is not None else "--"),
                ),
                ("MQTT retain out", _bool_value(config.mqtt_retain_out)),
                ("MQTT TLS", _bool_value(config.mqtt_tls_enabled)),
                (
                    "MQTT CA certs",
                    config.mqtt_tls_ca_certs or "system/default",
                ),
            ]
        )

    return rows


def run_preflight(
    config_path: str,
    *,
    include_tui: bool = False,
    importer: Importer = importlib.import_module,
) -> PreflightReport:
    """Load config and return diagnostics without opening hardware devices."""
    diagnostics: list[Diagnostic] = []
    normalized_path = os.path.abspath(config_path)

    if not os.path.exists(normalized_path):
        return PreflightReport(
            config_path=normalized_path,
            config=None,
            diagnostics=(
                Diagnostic(
                    "error",
                    "Configuration file missing",
                    f"No config file found at {normalized_path}.",
                    "Copy examples/config.ini.example to config.ini or pass --config.",
                ),
            ),
        )

    config = load_config(normalized_path)
    if config is None:
        return PreflightReport(
            config_path=normalized_path,
            config=None,
            diagnostics=(
                Diagnostic(
                    "error",
                    "Configuration did not validate",
                    "The configuration loader rejected one or more values.",
                    "Review the log output above and update the config file.",
                ),
            ),
        )

    dependencies: Sequence[DependencySpec]
    if include_tui:
        dependencies = RUNTIME_DEPENDENCIES + TUI_DEPENDENCIES
    else:
        dependencies = RUNTIME_DEPENDENCIES
    missing = check_missing_dependencies(dependencies, importer=importer)
    if missing:
        diagnostics.append(
            Diagnostic(
                "error",
                "Missing Python packages",
                ", ".join(missing),
                "Run pip install -r requirements.txt in the project environment.",
            )
        )

    diagnostics.extend(_config_diagnostics(config))

    if not diagnostics:
        diagnostics.append(
            Diagnostic(
                "info",
                "Ready to start",
                "Configuration and runtime package checks passed.",
            )
        )

    return PreflightReport(
        config_path=normalized_path,
        config=config,
        diagnostics=tuple(diagnostics),
    )


def format_preflight_report(report: PreflightReport) -> str:
    """Render a compact terminal report."""
    lines = [
        "AMMB Preflight Report",
        f"Config: {report.config_path}",
        f"Status: {'READY' if report.ready else 'ACTION REQUIRED'}",
    ]

    if report.config is not None:
        lines.append("")
        lines.append("Configuration")
        summary = build_config_summary(report.config)
        label_width = max(len(label) for label, _ in summary)
        for label, value in summary:
            lines.append(f"  {label:<{label_width}}  {value}")

    lines.append("")
    lines.append("Diagnostics")
    for item in report.diagnostics:
        prefix = item.severity.upper()
        lines.append(f"  [{prefix}] {item.title}: {item.detail}")
        if item.action:
            lines.append(f"          Action: {item.action}")

    return "\n".join(lines)


def _config_diagnostics(config: BridgeConfig) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []

    if config.queue_size < 10:
        diagnostics.append(
            Diagnostic(
                "warning",
                "Small message queue",
                f"MESSAGE_QUEUE_SIZE is {config.queue_size}. Bursty links may drop messages.",
                "Use 50 or higher for routine operation.",
            )
        )

    if config.log_level == "DEBUG":
        diagnostics.append(
            Diagnostic(
                "warning",
                "Verbose logging enabled",
                "DEBUG logging can expose payloads and grow logs quickly.",
                "Use INFO or WARNING outside troubleshooting sessions.",
            )
        )

    if not str(config.bridge_node_id).startswith("!"):
        diagnostics.append(
            Diagnostic(
                "warning",
                "Bridge node ID format",
                "BRIDGE_NODE_ID does not look like a Meshtastic node ID.",
                "Use the !aabbccdd style value from meshtastic --info when possible.",
            )
        )

    if config.api_enabled and config.api_host in {"0.0.0.0", "::"}:
        diagnostics.append(
            Diagnostic(
                "warning",
                "API listens on all interfaces",
                f"The REST API is exposed on {config.api_host}:{config.api_port}.",
                "Bind to 127.0.0.1 unless remote monitoring is intentional.",
            )
        )

    if config.external_transport == "serial":
        diagnostics.extend(_serial_diagnostics(config))
    else:
        diagnostics.extend(_mqtt_diagnostics(config))

    return diagnostics


def _serial_diagnostics(config: BridgeConfig) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    ports = [
        ("Meshtastic serial port", config.meshtastic_port),
        ("External serial port", config.serial_port),
    ]
    for label, port in ports:
        if not port:
            continue
        if _should_check_local_device_path(port) and not Path(port).exists():
            diagnostics.append(
                Diagnostic(
                    "warning",
                    label,
                    f"{port} does not exist on this machine right now.",
                    "Connect the device, update the port, or start after udev creates it.",
                )
            )

    if config.serial_protocol == "companion_radio" and config.serial_baud not in {
        115200,
        57600,
    }:
        diagnostics.append(
            Diagnostic(
                "warning",
                "Companion baud rate",
                f"SERIAL_BAUD_RATE is {config.serial_baud}.",
                "Confirm this matches the MeshCore radio's companion USB setting.",
            )
        )

    return diagnostics


def _mqtt_diagnostics(config: BridgeConfig) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []

    if config.mqtt_topic_in == config.mqtt_topic_out:
        diagnostics.append(
            Diagnostic(
                "warning",
                "MQTT topics are identical",
                "MQTT_TOPIC_IN and MQTT_TOPIC_OUT use the same topic.",
                "Use separate topics to reduce loop and replay risk.",
            )
        )

    if config.mqtt_tls_enabled:
        if config.mqtt_port == 1883:
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "MQTT TLS port",
                    "TLS is enabled while MQTT_PORT is 1883.",
                    "Confirm the broker expects TLS on this port, or use 8883.",
                )
            )
        if config.mqtt_tls_ca_certs and not Path(config.mqtt_tls_ca_certs).exists():
            diagnostics.append(
                Diagnostic(
                    "error",
                    "MQTT CA certificate missing",
                    f"{config.mqtt_tls_ca_certs} does not exist.",
                    "Fix MQTT_TLS_CA_CERTS or leave it blank for system trust.",
                )
            )
    elif config.mqtt_password:
        diagnostics.append(
            Diagnostic(
                "warning",
                "MQTT credentials without TLS",
                "A password is configured while MQTT TLS is disabled.",
                "Enable MQTT_TLS_ENABLED when credentials cross an untrusted network.",
            )
        )

    return diagnostics


def _should_check_local_device_path(port: str) -> bool:
    if platform.system().lower().startswith("win"):
        return False
    return port.startswith("/dev/")


def _api_value(config: BridgeConfig) -> str:
    if not config.api_enabled:
        return "disabled"
    return f"http://{config.api_host or '127.0.0.1'}:{config.api_port or 8080}"


def _bool_value(value: bool | None) -> str:
    return "enabled" if value else "disabled"


def _channel_value(value: int | None) -> str:
    return str(value) if value is not None else "all"
