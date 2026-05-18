"""
Full-screen terminal command center for the bridge.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from queue import Queue
from typing import Callable, Deque, Optional, Protocol

from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Footer, Header, RichLog, Static

from . import Bridge
from .config_handler import BridgeConfig
from .health import get_health_monitor
from .metrics import get_metrics
from .utils import setup_logging

PALETTE = {
    "black": "#0b0b0b",
    "surface": "#151515",
    "gray": "#5f5f5f",
    "silver": "#c0c0c0",
    "white": "#f5f3ef",
    "copper": "#b87333",
}

IGNORED_LOGGER_PREFIXES = ("textual", "rich", "asyncio")
VISIBLE_LOG_LINES = 200


class BridgeRuntime(Protocol):
    """Runtime surface required by the dashboard controller."""

    external_handler: object | None
    shutdown_event: threading.Event
    to_meshtastic_queue: Queue
    to_external_queue: Queue

    def run(self) -> None:
        """Run the bridge loop."""

    def stop(self) -> None:
        """Stop the bridge loop."""


BridgeFactory = Callable[[BridgeConfig], BridgeRuntime]


@dataclass(frozen=True)
class LogEntry:
    """Single log line rendered into the live tail."""

    timestamp: datetime
    level: str
    logger_name: str
    message: str


@dataclass(frozen=True)
class DashboardEvent:
    """Recent operational event shown in the side panel."""

    timestamp: datetime
    level: str
    message: str


@dataclass(frozen=True)
class BridgeSnapshot:
    """Current controller state consumed by the dashboard."""

    state: str
    status_message: str
    last_error: Optional[str]
    thread_alive: bool
    thread_name: str
    started_at: Optional[datetime]
    uptime_seconds: float
    to_meshtastic_depth: int
    to_external_depth: int


class DashboardStore:
    """Thread-safe store for dashboard logs and events."""

    def __init__(self, max_logs: int = 400, max_events: int = 16):
        self._lock = threading.Lock()
        self._logs: Deque[LogEntry] = deque(maxlen=max_logs)
        self._events: Deque[DashboardEvent] = deque(maxlen=max_events)

    def add_log(self, entry: LogEntry) -> None:
        with self._lock:
            self._logs.append(entry)

    def add_event(self, message: str, level: str = "info") -> None:
        with self._lock:
            self._events.append(
                DashboardEvent(
                    timestamp=datetime.now(),
                    level=level.lower(),
                    message=message,
                )
            )

    def snapshot_logs(self) -> list[LogEntry]:
        with self._lock:
            return list(self._logs)

    def snapshot_events(self) -> list[DashboardEvent]:
        with self._lock:
            return list(self._events)

    def clear_logs(self) -> None:
        with self._lock:
            self._logs.clear()


class BridgeLogHandler(logging.Handler):
    """Routes application logs into the terminal dashboard."""

    def __init__(self, store: DashboardStore):
        super().__init__()
        self.store = store

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith(IGNORED_LOGGER_PREFIXES):
            return

        message = record.getMessage()
        self.store.add_log(
            LogEntry(
                timestamp=datetime.fromtimestamp(record.created),
                level=record.levelname,
                logger_name=record.name,
                message=message,
            )
        )

        if record.levelno >= logging.WARNING:
            event_level = "error" if record.levelno >= logging.ERROR else "warning"
            self.store.add_event(
                f"{record.levelname}: {message}",
                event_level,
            )


class BridgeController:
    """Starts, stops, and snapshots the synchronous bridge runtime."""

    def __init__(
        self,
        config: BridgeConfig,
        *,
        bridge_factory: BridgeFactory = Bridge,
        event_sink: Optional[Callable[[str, str], None]] = None,
    ):
        self.config = config
        self.bridge_factory = bridge_factory
        self._event_sink = event_sink
        self._lock = threading.Lock()
        self._bridge: Optional[BridgeRuntime] = None
        self._thread: Optional[threading.Thread] = None
        self._state = "stopped"
        self._status_message = "Bridge idle."
        self._started_at: Optional[datetime] = None
        self._last_error: Optional[str] = None

    def _emit_event(self, message: str, level: str = "info") -> None:
        if self._event_sink is not None:
            self._event_sink(message, level)

    def start(self) -> tuple[bool, str]:
        """Start the bridge in a background thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False, "Bridge is already running."

            self._state = "starting"
            self._status_message = "Initializing bridge handlers."
            self._last_error = None

        try:
            bridge = self.bridge_factory(self.config)
        except Exception as exc:
            message = f"Bridge initialization failed: {exc}"
            with self._lock:
                self._bridge = None
                self._thread = None
                self._state = "error"
                self._status_message = message
                self._last_error = f"{type(exc).__name__}: {exc}"
            self._emit_event(message, "error")
            return False, message

        if not getattr(bridge, "external_handler", None):
            message = (
                "Bridge initialization failed. Check the live logs for "
                "handler errors."
            )
            with self._lock:
                self._bridge = bridge
                self._thread = None
                self._state = "error"
                self._status_message = message
            self._emit_event(message, "error")
            return False, message

        thread = threading.Thread(
            target=self._run_bridge,
            args=(bridge,),
            daemon=True,
            name="AMMB-Bridge",
        )
        with self._lock:
            self._bridge = bridge
            self._thread = thread
            self._started_at = datetime.now()
            self._state = "running"
            self._status_message = "Bridge is running."

        thread.start()
        self._emit_event("Bridge started.", "info")
        return True, "Bridge started."

    def _run_bridge(self, bridge: BridgeRuntime) -> None:
        try:
            bridge.run()
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            with self._lock:
                self._state = "error"
                self._status_message = "Bridge stopped unexpectedly."
                self._last_error = message
            self._emit_event(f"Bridge crashed: {message}", "error")
            return

        with self._lock:
            if self._state != "error":
                self._state = "stopped"
                self._status_message = "Bridge stopped."

        self._emit_event("Bridge stopped.", "info")

    def stop(self, wait: bool = False) -> tuple[bool, str]:
        """Signal the bridge to stop."""
        with self._lock:
            bridge = self._bridge
            thread = self._thread
            if bridge is None or thread is None or not thread.is_alive():
                self._state = "stopped"
                self._status_message = "Bridge is not running."
                return False, "Bridge is not running."

            self._state = "stopping"
            self._status_message = "Stop requested."

        self._emit_event("Stopping bridge.", "warning")

        if wait:
            self._stop_bridge(bridge, thread)
        else:
            threading.Thread(
                target=self._stop_bridge,
                args=(bridge, thread),
                daemon=True,
                name="AMMB-BridgeStop",
            ).start()

        return True, "Stopping bridge."

    def _stop_bridge(
        self,
        bridge: BridgeRuntime,
        thread: threading.Thread,
    ) -> None:
        try:
            bridge.stop()
        except Exception as exc:
            message = f"Stop failed: {type(exc).__name__}: {exc}"
            with self._lock:
                self._state = "error"
                self._status_message = message
                self._last_error = message
            self._emit_event(message, "error")
            return

        if thread.is_alive():
            thread.join(timeout=5)

        if not thread.is_alive():
            with self._lock:
                if self._state != "error":
                    self._state = "stopped"
                    self._status_message = "Bridge stopped."

    def restart(self) -> tuple[bool, str]:
        """Restart the bridge without blocking the UI thread."""
        with self._lock:
            self._state = "stopping"
            self._status_message = "Restarting bridge."

        self._emit_event("Restart requested.", "warning")
        threading.Thread(
            target=self._restart_worker,
            daemon=True,
            name="AMMB-BridgeRestart",
        ).start()
        return True, "Restarting bridge."

    def _restart_worker(self) -> None:
        self.stop(wait=True)
        snapshot = self.snapshot()
        if snapshot.thread_alive:
            message = "Restart failed: bridge did not stop cleanly."
            with self._lock:
                self._state = "error"
                self._status_message = message
                self._last_error = message
            self._emit_event(message, "error")
            return

        self.start()

    def reset_metrics(self) -> tuple[bool, str]:
        """Reset the global metrics collector."""
        get_metrics().reset()
        self._emit_event("Metrics reset.", "info")
        return True, "Metrics reset."

    def snapshot(self) -> BridgeSnapshot:
        """Return the current controller state for rendering."""
        with self._lock:
            bridge = self._bridge
            thread = self._thread
            state = self._state
            status_message = self._status_message
            last_error = self._last_error
            started_at = self._started_at

        thread_alive = bool(thread and thread.is_alive())
        if not thread_alive and state in {"running", "starting", "stopping"}:
            state = "error" if last_error else "stopped"
            if not last_error:
                status_message = "Bridge stopped."

        uptime_seconds = 0.0
        if started_at and thread_alive:
            uptime_seconds = (datetime.now() - started_at).total_seconds()

        return BridgeSnapshot(
            state=state,
            status_message=status_message,
            last_error=last_error,
            thread_alive=thread_alive,
            thread_name=thread.name if thread else "idle",
            started_at=started_at,
            uptime_seconds=uptime_seconds,
            to_meshtastic_depth=_safe_qsize(
                getattr(bridge, "to_meshtastic_queue", None)
            ),
            to_external_depth=_safe_qsize(
                getattr(bridge, "to_external_queue", None)
            ),
        )


def _safe_qsize(queue_obj: object) -> int:
    if queue_obj is None or not hasattr(queue_obj, "qsize"):
        return 0

    try:
        return int(queue_obj.qsize())
    except (AttributeError, NotImplementedError, TypeError, ValueError):
        return 0


def _bool_label(value: Optional[bool]) -> str:
    return "enabled" if value else "disabled"


def _api_label(config: BridgeConfig) -> str:
    if not config.api_enabled:
        return "disabled"
    return f"http://{config.api_host or '127.0.0.1'}:{config.api_port or 8080}"


def format_duration(total_seconds: float | int | None) -> str:
    """Return a compact uptime string."""
    total = max(int(total_seconds or 0), 0)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def format_bytes(byte_count: int | None) -> str:
    """Return a human-friendly byte size."""
    amount = float(byte_count or 0)
    units = ["B", "KB", "MB", "GB"]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "0 B"


def format_timestamp(value: object) -> str:
    """Format datetimes or ISO-8601 strings for display."""
    if value is None:
        return "--"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return value
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def build_config_rows(config: BridgeConfig) -> list[tuple[str, str]]:
    """Build the configuration summary shown in the side panel."""
    rows = [
        ("Meshtastic Port", config.meshtastic_port or "disabled"),
        ("External Transport", config.external_transport.upper()),
        ("External Network", config.external_network_id),
        ("Bridge Node", config.bridge_node_id),
        ("Queue Size", str(config.queue_size)),
        ("Log Level", config.log_level.upper()),
        ("API", _api_label(config)),
    ]

    if config.external_transport == "serial":
        rows.extend(
            [
                ("Serial Port", config.serial_port or "not configured"),
                ("Serial Baud", str(config.serial_baud or "--")),
                (
                    "Serial Protocol",
                    (config.serial_protocol or "not configured").upper(),
                ),
                (
                    "Companion Handshake",
                    _bool_label(config.companion_handshake_enabled),
                ),
                (
                    "Companion Poll",
                    f"{config.companion_contacts_poll_s or 0}s",
                ),
                ("Auto Switch", _bool_label(config.serial_auto_switch)),
            ]
        )
    else:
        rows.extend(
            [
                (
                    "MQTT Broker",
                    f"{config.mqtt_broker or '--'}:{config.mqtt_port or '--'}",
                ),
                ("MQTT Topic In", config.mqtt_topic_in or "--"),
                ("MQTT Topic Out", config.mqtt_topic_out or "--"),
                ("MQTT Client ID", config.mqtt_client_id or "--"),
                ("MQTT Username", config.mqtt_username or "anonymous"),
                (
                    "MQTT Password",
                    "configured (hidden)"
                    if config.mqtt_password
                    else "not set",
                ),
                ("MQTT TLS", _bool_label(config.mqtt_tls_enabled)),
            ]
        )

    return rows


def _status_style(status: str) -> str:
    normalized = status.lower()
    if normalized == "healthy":
        return f"bold {PALETTE['white']}"
    if normalized == "degraded":
        return f"bold {PALETTE['silver']}"
    if normalized == "unhealthy":
        return f"bold {PALETTE['copper']}"
    return PALETTE["gray"]


def _level_style(level: str) -> str:
    normalized = level.upper()
    if normalized in {"CRITICAL", "ERROR"}:
        return f"bold {PALETTE['copper']}"
    if normalized == "WARNING":
        return f"bold {PALETTE['silver']}"
    if normalized == "DEBUG":
        return PALETTE["gray"]
    return PALETTE["white"]


def _section_title(title: str) -> Text:
    return Text(title, style=f"bold {PALETTE['copper']}")


def _meta_block(label: str, value: str) -> RenderableType:
    return Group(
        Text(label, style=f"bold {PALETTE['gray']}"),
        Text(value, style=f"bold {PALETTE['white']}"),
    )


def _metric_card(
    title: str,
    value: str,
    detail: str,
    *,
    border_style: str,
) -> Panel:
    body = Group(
        Text(value, style=f"bold {PALETTE['white']}"),
        Text(detail, style=PALETTE["silver"]),
    )
    return Panel(
        body,
        title=title,
        border_style=border_style,
        padding=(1, 2),
        expand=True,
    )


def build_banner(config: BridgeConfig, snapshot: BridgeSnapshot) -> RenderableType:
    transport_label = "Meshcore" if config.external_transport == "serial" else "MQTT"
    title = Text.assemble(
        ("AKITA ", f"bold {PALETTE['copper']}"),
        ("MESH BRIDGE ", f"bold {PALETTE['white']}"),
        ("COMMAND CENTER", f"bold {PALETTE['silver']}"),
    )
    subtitle = Text(
        f"Full-screen terminal cockpit for Meshtastic and {transport_label}.",
        style=PALETTE["silver"],
    )
    metadata = Table.grid(expand=True)
    metadata.add_column(ratio=1)
    metadata.add_column(ratio=1)
    metadata.add_column(ratio=1)
    metadata.add_column(ratio=1)
    metadata.add_row(
        _meta_block("TRANSPORT", config.external_transport.upper()),
        _meta_block("BRIDGE NODE", config.bridge_node_id),
        _meta_block("EXTERNAL NET", config.external_network_id),
        _meta_block("API", _api_label(config)),
    )

    status = Text(snapshot.status_message, style=PALETTE["white"])
    if snapshot.last_error:
        status.append("  Last error: ", style=PALETTE["gray"])
        status.append(snapshot.last_error, style=f"bold {PALETTE['copper']}")

    return Group(title, subtitle, Text(""), metadata, Text(""), status)


def build_overview(
    snapshot: BridgeSnapshot,
    health: dict,
) -> RenderableType:
    overall_status = str(health.get("status", "unknown"))
    cards = Columns(
        [
            _metric_card(
                "Bridge",
                snapshot.state.upper(),
                snapshot.status_message,
                border_style=(
                    PALETTE["copper"]
                    if snapshot.thread_alive
                    else PALETTE["gray"]
                ),
            ),
            _metric_card(
                "Health",
                overall_status.upper(),
                f"{len(health.get('components', {}))} components reporting",
                border_style=(
                    PALETTE["white"]
                    if overall_status == "healthy"
                    else PALETTE["copper"]
                    if overall_status == "unhealthy"
                    else PALETTE["silver"]
                ),
            ),
            _metric_card(
                "Uptime",
                format_duration(snapshot.uptime_seconds),
                (
                    format_timestamp(snapshot.started_at)
                    if snapshot.started_at
                    else "Not started"
                ),
                border_style=PALETTE["silver"],
            ),
            _metric_card(
                "Queues",
                f"{snapshot.to_meshtastic_depth}/{snapshot.to_external_depth}",
                "to mesh / to external",
                border_style=PALETTE["gray"],
            ),
        ],
        expand=True,
        equal=True,
    )

    return Group(_section_title("LIVE OVERVIEW"), Text(""), cards)


def build_health_panel(health: dict) -> RenderableType:
    table = Table(expand=True, box=box.SIMPLE_HEAVY)
    table.add_column("Component", style=f"bold {PALETTE['white']}")
    table.add_column("Status")
    table.add_column("Last Check", style=PALETTE["silver"])
    table.add_column("Message", style=PALETTE["silver"])

    components = health.get("components", {})
    if not components:
        table.add_row("Bridge", "UNKNOWN", "--", "No health data yet.")
    else:
        for name, component in components.items():
            status = str(component.get("status", "unknown"))
            table.add_row(
                name.replace("_", " ").title(),
                Text(status.upper(), style=_status_style(status)),
                format_timestamp(component.get("last_check")),
                str(component.get("message") or "Awaiting activity."),
            )

    return Group(_section_title("COMPONENT HEALTH"), Text(""), table)


def build_traffic_panel(metrics: dict) -> RenderableType:
    table = Table(expand=True, box=box.SIMPLE_HEAVY)
    table.add_column("Link", style=f"bold {PALETTE['white']}")
    table.add_column("Rx", justify="right")
    table.add_column("Tx", justify="right")
    table.add_column("Drop", justify="right")
    table.add_column("Err", justify="right")
    table.add_column("Bytes In", justify="right")
    table.add_column("Bytes Out", justify="right")
    table.add_column("Conn", justify="right")
    table.add_column("Live Uptime", justify="right")

    for label in ("meshtastic", "external"):
        branch = metrics.get(label, {})
        message_stats = branch.get("messages", {})
        connection = branch.get("connection", {})
        table.add_row(
            label.title(),
            str(message_stats.get("total_received", 0)),
            str(message_stats.get("total_sent", 0)),
            str(message_stats.get("total_dropped", 0)),
            str(message_stats.get("total_errors", 0)),
            format_bytes(message_stats.get("bytes_received", 0)),
            format_bytes(message_stats.get("bytes_sent", 0)),
            (
                f"{connection.get('connection_count', 0)}/"
                f"{connection.get('disconnection_count', 0)}"
            ),
            format_duration(connection.get("current_uptime_seconds", 0)),
        )

    rate_limits = metrics.get("rate_limits", {})
    if rate_limits:
        summary = ", ".join(
            f"{name}: {count}" for name, count in rate_limits.items()
        )
    else:
        summary = "none"

    rate_text = Text()
    rate_text.append("Rate limit violations: ", style=PALETTE["gray"])
    rate_text.append(summary, style=PALETTE["white"])

    return Group(_section_title("MESSAGE FLOW"), Text(""), table, Text(""), rate_text)


def build_controls_panel(
    snapshot: BridgeSnapshot,
    logs_paused: bool,
) -> RenderableType:
    table = Table.grid(expand=True)
    table.add_column(style=f"bold {PALETTE['silver']}", width=14)
    table.add_column(style=PALETTE["white"])
    table.add_row("Bridge", snapshot.state.upper())
    table.add_row("Thread", snapshot.thread_name if snapshot.thread_alive else "idle")
    table.add_row("Logs", "PAUSED" if logs_paused else "LIVE")
    table.add_row(
        "Queues",
        f"{snapshot.to_meshtastic_depth} mesh / {snapshot.to_external_depth} external",
    )
    table.add_row(
        "Uptime",
        format_duration(snapshot.uptime_seconds),
    )
    if snapshot.started_at:
        table.add_row("Started", format_timestamp(snapshot.started_at))
    if snapshot.last_error:
        table.add_row("Last Error", snapshot.last_error)

    hints = Text(
        "S start/stop  R restart  M reset metrics  P pause logs  C clear logs  Q quit",
        style=PALETTE["gray"],
    )
    return Group(_section_title("CONTROL SURFACE"), Text(""), table, Text(""), hints)


def build_config_panel(config: BridgeConfig) -> RenderableType:
    table = Table.grid(expand=True)
    table.add_column(style=f"bold {PALETTE['silver']}", width=18)
    table.add_column(style=PALETTE["white"])

    for label, value in build_config_rows(config):
        table.add_row(label, value)

    return Group(_section_title("CONFIGURATION"), Text(""), table)


def build_events_panel(events: list[DashboardEvent]) -> RenderableType:
    table = Table.grid(expand=True)
    table.add_column(width=9, style=PALETTE["gray"])
    table.add_column(width=8)
    table.add_column(ratio=1, style=PALETTE["white"])

    if not events:
        table.add_row("--:--:--", "INFO", "No events yet.")
    else:
        for event in reversed(events[-8:]):
            table.add_row(
                event.timestamp.strftime("%H:%M:%S"),
                Text(event.level.upper(), style=_level_style(event.level)),
                event.message,
            )

    return Group(_section_title("EVENT FEED"), Text(""), table)


def build_logs_heading(log_count: int, logs_paused: bool) -> Text:
    heading = Text()
    heading.append("LIVE LOG TAIL", style=f"bold {PALETTE['copper']}")
    heading.append("  ")
    heading.append(
        "PAUSED" if logs_paused else "LIVE",
        style=(
            f"bold {PALETTE['silver']}"
            if logs_paused
            else f"bold {PALETTE['white']}"
        ),
    )
    heading.append(
        f"  {log_count} buffered lines",
        style=PALETTE["gray"],
    )
    return heading


def render_log_entry(entry: LogEntry) -> Text:
    text = Text()
    text.append(entry.timestamp.strftime("%H:%M:%S "), style=PALETTE["gray"])
    text.append(f"{entry.level:<8}", style=_level_style(entry.level))
    text.append(" ")
    text.append(f"{entry.logger_name:<24}", style=PALETTE["silver"])
    text.append(" ")
    text.append(entry.message, style=PALETTE["white"])
    return text


class BridgeDashboardApp(App[None]):
    """Textual app presenting the bridge control surface."""

    CSS = """
    Screen {
        background: #0b0b0b;
        color: #f5f3ef;
    }

    #shell {
        height: 1fr;
    }

    #hero {
        height: 10;
        margin: 1 2 0 2;
    }

    #dashboard-body {
        height: 1fr;
        margin: 1 2 1 2;
    }

    #main-column {
        width: 2fr;
        height: 1fr;
    }

    #side-column {
        width: 1fr;
        height: 1fr;
        margin: 0 0 0 1;
    }

    .panel {
        border: round #5f5f5f;
        background: #151515;
        color: #f5f3ef;
        padding: 1 1;
        margin: 0 0 1 0;
    }

    .accent {
        border: heavy #b87333;
    }

    #overview {
        height: 13;
    }

    #health {
        height: 13;
    }

    #traffic {
        height: 15;
    }

    #logs-card {
        height: 1fr;
    }

    #logs-heading {
        height: 2;
        color: #b87333;
    }

    #logs {
        height: 1fr;
        background: #0e0e0e;
        border: none;
        color: #c0c0c0;
    }

    #controls-card {
        height: 16;
    }

    .button-row {
        height: 3;
        margin: 1 0 0 0;
    }

    Button {
        width: 1fr;
        margin: 0 1 0 0;
        color: #f5f3ef;
        background: #5f5f5f;
        border: round #c0c0c0;
    }

    #restart-button {
        background: #b87333;
        border: round #b87333;
    }

    #reset-button {
        background: #c0c0c0;
        color: #0b0b0b;
        border: round #c0c0c0;
    }

    Button:disabled {
        background: #2b2b2b;
        color: #7a7a7a;
        border: round #3d3d3d;
    }

    #config {
        height: 1fr;
        min-height: 16;
    }

    #events {
        height: 14;
    }

    Header {
        background: #151515;
        color: #f5f3ef;
    }

    Footer {
        background: #b87333;
        color: #f5f3ef;
    }
    """

    BINDINGS = [
        Binding("q", "quit_application", "Quit"),
        Binding("s", "toggle_bridge", "Start/Stop"),
        Binding("r", "restart_bridge", "Restart"),
        Binding("m", "reset_metrics", "Reset Metrics"),
        Binding("p", "toggle_logs", "Pause Logs"),
        Binding("c", "clear_logs", "Clear Logs"),
    ]

    def __init__(
        self,
        *,
        config: BridgeConfig,
        controller: BridgeController,
        store: DashboardStore,
    ):
        super().__init__()
        self.config = config
        self.controller = controller
        self.store = store
        self.logs_paused = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="shell"):
            yield Static(id="hero", classes="panel accent")
            with Horizontal(id="dashboard-body"):
                with Vertical(id="main-column"):
                    yield Static(id="overview", classes="panel accent")
                    yield Static(id="health", classes="panel")
                    yield Static(id="traffic", classes="panel")
                    with Vertical(id="logs-card", classes="panel accent"):
                        yield Static(id="logs-heading")
                        yield RichLog(
                            id="logs",
                            wrap=True,
                            highlight=False,
                            markup=False,
                        )
                with Vertical(id="side-column"):
                    with Vertical(id="controls-card", classes="panel accent"):
                        yield Static(id="controls-summary")
                        with Horizontal(classes="button-row"):
                            yield Button("Start", id="start-button")
                            yield Button("Stop", id="stop-button")
                        with Horizontal(classes="button-row"):
                            yield Button("Restart", id="restart-button")
                            yield Button("Reset Metrics", id="reset-button")
                    yield Static(id="config", classes="panel")
                    yield Static(id="events", classes="panel")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Akita Mesh Bridge Command Center"
        self.sub_title = self.config.external_transport.upper()
        self.controller.start()
        self.refresh_dashboard()
        self.set_interval(1.0, self.refresh_dashboard)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "start-button":
            self.controller.start()
        elif button_id == "stop-button":
            self.controller.stop()
        elif button_id == "restart-button":
            self.controller.restart()
        elif button_id == "reset-button":
            self.controller.reset_metrics()
        self.refresh_dashboard()

    def action_toggle_bridge(self) -> None:
        snapshot = self.controller.snapshot()
        if snapshot.thread_alive:
            self.controller.stop()
        else:
            self.controller.start()
        self.refresh_dashboard()

    def action_restart_bridge(self) -> None:
        self.controller.restart()
        self.refresh_dashboard()

    def action_reset_metrics(self) -> None:
        self.controller.reset_metrics()
        self.refresh_dashboard()

    def action_toggle_logs(self) -> None:
        self.logs_paused = not self.logs_paused
        self.store.add_event(
            "Live log tail paused."
            if self.logs_paused
            else "Live log tail resumed.",
            "info",
        )
        self.refresh_dashboard()

    def action_clear_logs(self) -> None:
        self.store.clear_logs()
        self.query_one("#logs", RichLog).clear()
        self.store.add_event("Log buffer cleared.", "info")
        self.refresh_dashboard()

    def action_quit_application(self) -> None:
        self.exit()

    def refresh_dashboard(self) -> None:
        snapshot = self.controller.snapshot()
        health = get_health_monitor().get_overall_health()
        metrics = get_metrics().get_all_stats()
        logs = self.store.snapshot_logs()

        self.query_one("#hero", Static).update(build_banner(self.config, snapshot))
        self.query_one("#overview", Static).update(build_overview(snapshot, health))
        self.query_one("#health", Static).update(build_health_panel(health))
        self.query_one("#traffic", Static).update(build_traffic_panel(metrics))
        self.query_one("#controls-summary", Static).update(
            build_controls_panel(snapshot, self.logs_paused)
        )
        self.query_one("#config", Static).update(build_config_panel(self.config))
        self.query_one("#events", Static).update(
            build_events_panel(self.store.snapshot_events())
        )
        self.query_one("#logs-heading", Static).update(
            build_logs_heading(len(logs), self.logs_paused)
        )

        self._sync_buttons(snapshot)
        self._sync_logs(logs)

    def _sync_buttons(self, snapshot: BridgeSnapshot) -> None:
        busy = snapshot.state in {"starting", "stopping"}
        self.query_one("#start-button", Button).disabled = (
            busy or snapshot.thread_alive
        )
        self.query_one("#stop-button", Button).disabled = (
            busy or not snapshot.thread_alive
        )
        self.query_one("#restart-button", Button).disabled = busy

    def _sync_logs(self, logs: list[LogEntry]) -> None:
        if self.logs_paused:
            return

        log_widget = self.query_one("#logs", RichLog)
        log_widget.clear()
        for entry in logs[-VISIBLE_LOG_LINES:]:
            log_widget.write(render_log_entry(entry))


def run_tui(config: BridgeConfig) -> None:
    """Launch the full-screen terminal dashboard."""
    store = DashboardStore()
    handler = BridgeLogHandler(store)
    controller = BridgeController(config, event_sink=store.add_event)

    setup_logging(
        config.log_level,
        console=False,
        extra_handlers=[handler],
    )
    store.add_event("Command center ready.", "info")

    app = BridgeDashboardApp(
        config=config,
        controller=controller,
        store=store,
    )

    try:
        app.run()
    finally:
        controller.stop(wait=True)
        root_logger = logging.getLogger()
        if handler in root_logger.handlers:
            root_logger.removeHandler(handler)
        handler.close()