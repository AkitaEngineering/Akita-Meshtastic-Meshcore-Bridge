# ammb/metrics.py
"""
Metrics and statistics collection for the bridge.
"""

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional


@dataclass
class MessageStats:
    """Statistics for message processing."""

    total_received: int = 0
    total_sent: int = 0
    total_dropped: int = 0
    total_errors: int = 0
    last_received: Optional[datetime] = None
    last_sent: Optional[datetime] = None
    bytes_received: int = 0
    bytes_sent: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment_received(self, bytes_count: int = 0):
        """Increment received message counter."""
        with self._lock:
            self.total_received += 1
            self.bytes_received += bytes_count
            self.last_received = datetime.now()

    def increment_sent(self, bytes_count: int = 0):
        """Increment sent message counter."""
        with self._lock:
            self.total_sent += 1
            self.bytes_sent += bytes_count
            self.last_sent = datetime.now()

    def increment_dropped(self):
        """Increment dropped message counter."""
        with self._lock:
            self.total_dropped += 1

    def increment_errors(self):
        """Increment error counter."""
        with self._lock:
            self.total_errors += 1

    def to_dict(self) -> Dict:
        """Convert stats to dictionary."""
        with self._lock:
            return {
                "total_received": self.total_received,
                "total_sent": self.total_sent,
                "total_dropped": self.total_dropped,
                "total_errors": self.total_errors,
                "last_received": (
                    self.last_received.isoformat()
                    if self.last_received
                    else None
                ),
                "last_sent": (
                    self.last_sent.isoformat() if self.last_sent else None
                ),
                "bytes_received": self.bytes_received,
                "bytes_sent": self.bytes_sent,
            }


@dataclass
class ConnectionStats:
    """Statistics for connection health."""

    connection_count: int = 0
    disconnection_count: int = 0
    last_connected: Optional[datetime] = None
    last_disconnected: Optional[datetime] = None
    total_uptime_seconds: float = 0.0
    current_uptime_start: Optional[datetime] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_connection(self):
        """Record a connection event."""
        with self._lock:
            self.connection_count += 1
            self.last_connected = datetime.now()
            if self.current_uptime_start is None:
                self.current_uptime_start = datetime.now()

    def record_disconnection(self):
        """Record a disconnection event."""
        with self._lock:
            self.disconnection_count += 1
            self.last_disconnected = datetime.now()
            if self.current_uptime_start:
                uptime = (
                    datetime.now() - self.current_uptime_start
                ).total_seconds()
                self.total_uptime_seconds += uptime
                self.current_uptime_start = None

    def get_current_uptime(self) -> float:
        """Get current uptime in seconds."""
        with self._lock:
            if self.current_uptime_start:
                return (
                    datetime.now() - self.current_uptime_start
                ).total_seconds()
            return 0.0

    def to_dict(self) -> Dict:
        """Convert stats to dictionary."""
        with self._lock:
            return {
                "connection_count": self.connection_count,
                "disconnection_count": self.disconnection_count,
                "last_connected": (
                    self.last_connected.isoformat()
                    if self.last_connected
                    else None
                ),
                "last_disconnected": (
                    self.last_disconnected.isoformat()
                    if self.last_disconnected
                    else None
                ),
                "total_uptime_seconds": self.total_uptime_seconds
                + self.get_current_uptime(),
                "current_uptime_seconds": self.get_current_uptime(),
            }


class MetricsCollector:
    """Central metrics collector for the bridge."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.start_time = datetime.now()
        self._lock = threading.Lock()

        # Per-handler statistics
        self.meshtastic_stats = MessageStats()
        self.external_stats = MessageStats()
        self.meshtastic_connection = ConnectionStats()
        self.external_connection = ConnectionStats()

        # Rate limiting stats (messages per minute)
        self.rate_limit_violations = defaultdict(int)
        self._rate_limit_lock = threading.Lock()

    def record_meshtastic_received(self, bytes_count: int = 0):
        """Record a message received from Meshtastic."""
        self.meshtastic_stats.increment_received(bytes_count)

    def record_meshtastic_sent(self, bytes_count: int = 0):
        """Record a message sent to Meshtastic."""
        self.meshtastic_stats.increment_sent(bytes_count)

    def record_external_received(self, bytes_count: int = 0):
        """Record a message received from external system."""
        self.external_stats.increment_received(bytes_count)

    def record_external_sent(self, bytes_count: int = 0):
        """Record a message sent to external system."""
        self.external_stats.increment_sent(bytes_count)

    def record_dropped(self, source: str = "unknown"):
        """Record a dropped message."""
        if source == "meshtastic":
            self.meshtastic_stats.increment_dropped()
        else:
            self.external_stats.increment_dropped()

    def record_error(self, source: str = "unknown"):
        """Record an error."""
        if source == "meshtastic":
            self.meshtastic_stats.increment_errors()
        else:
            self.external_stats.increment_errors()

    def record_meshtastic_connection(self):
        """Record Meshtastic connection."""
        self.meshtastic_connection.record_connection()

    def record_meshtastic_disconnection(self):
        """Record Meshtastic disconnection."""
        self.meshtastic_connection.record_disconnection()

    def record_external_connection(self):
        """Record external system connection."""
        self.external_connection.record_connection()

    def record_external_disconnection(self):
        """Record external system disconnection."""
        self.external_connection.record_disconnection()

    def record_rate_limit_violation(self, source: str):
        """Record a rate limit violation."""
        with self._rate_limit_lock:
            self.rate_limit_violations[source] += 1

    def get_all_stats(self) -> Dict:
        """Get all statistics as a dictionary."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        return {
            "bridge": {
                "uptime_seconds": uptime,
                "start_time": self.start_time.isoformat(),
            },
            "meshtastic": {
                "messages": self.meshtastic_stats.to_dict(),
                "connection": self.meshtastic_connection.to_dict(),
            },
            "external": {
                "messages": self.external_stats.to_dict(),
                "connection": self.external_connection.to_dict(),
            },
            "rate_limits": dict(self.rate_limit_violations),
        }

    def reset(self):
        """Reset all statistics."""
        with self._lock:
            self.meshtastic_stats = MessageStats()
            self.external_stats = MessageStats()
            self.meshtastic_connection = ConnectionStats()
            self.external_connection = ConnectionStats()
            self.rate_limit_violations.clear()
            self.start_time = datetime.now()


# Global metrics instance
_metrics: Optional[MetricsCollector] = None
_metrics_lock = threading.Lock()


def get_metrics() -> MetricsCollector:
    """Get or create the global metrics instance."""
    global _metrics
    with _metrics_lock:
        if _metrics is None:
            _metrics = MetricsCollector()
        return _metrics
