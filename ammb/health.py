# ammb/health.py
"""
Health monitoring and status checking for the bridge.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Optional


class HealthStatus(Enum):
    """Health status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status for a component."""

    name: str
    status: HealthStatus
    last_check: datetime
    message: str = ""
    details: Dict = field(default_factory=dict)

    def __post_init__(self):
        if self.details is None:
            self.details = {}

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "last_check": self.last_check.isoformat(),
            "message": self.message,
            "details": self.details,
        }


class HealthMonitor:
    """Monitors the health of bridge components."""

    def __init__(self, check_interval: float = 30.0):
        self.logger = logging.getLogger(__name__)
        self.check_interval = check_interval
        self.components: Dict[str, ComponentHealth] = {}
        self._lock = threading.Lock()
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None

    def register_component(
        self, name: str, initial_status: HealthStatus = HealthStatus.UNKNOWN
    ):
        """Register a component for health monitoring."""
        with self._lock:
            self.components[name] = ComponentHealth(
                name=name,
                status=initial_status,
                last_check=datetime.now(),
            )

    def update_component(
        self,
        name: str,
        status: HealthStatus,
        message: str = "",
        details: Optional[Dict] = None,
    ):
        """Update the health status of a component."""
        with self._lock:
            if name in self.components:
                self.components[name].status = status
                self.components[name].last_check = datetime.now()
                self.components[name].message = message
                if details:
                    # Ensure details is a dict.
                    # Dataclass __post_init__ should set it.
                    # Be defensive if None.
                    if self.components[name].details is None:
                        self.components[name].details = {}
                    self.components[name].details.update(details)
            else:
                self.logger.warning(
                    "Component %s not registered for health "
                    "monitoring",
                    name,
                )

    def get_component_health(self, name: str) -> Optional[ComponentHealth]:
        """Get health status for a specific component."""
        with self._lock:
            return self.components.get(name)

    def get_overall_health(self) -> Dict:
        """Get overall health status."""
        with self._lock:
            if not self.components:
                return {
                    "status": HealthStatus.UNKNOWN.value,
                    "message": "No components registered",
                    "components": {},
                }

            statuses = [comp.status for comp in self.components.values()]

            # Determine overall status from component states
            if HealthStatus.UNHEALTHY in statuses:
                overall = HealthStatus.UNHEALTHY
            elif HealthStatus.DEGRADED in statuses:
                overall = HealthStatus.DEGRADED
            elif all(s == HealthStatus.HEALTHY for s in statuses):
                overall = HealthStatus.HEALTHY
            else:
                overall = HealthStatus.UNKNOWN

            components = {
                name: comp.to_dict()
                for name, comp in self.components.items()
            }
            return {
                "status": overall.value,
                "timestamp": datetime.now().isoformat(),
                "components": components,
            }

    def start_monitoring(self):
        """Start background health monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="HealthMonitor"
        )
        self._monitor_thread.start()
        self.logger.info("Health monitoring started")

    def stop_monitoring(self):
        """Stop background health monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        self.logger.info("Health monitoring stopped")

    def _monitor_loop(self):
        """Background monitoring loop."""
        while self._monitoring:
            try:
                # Check for stale components (no update in 2x check interval)
                stale_threshold = timedelta(seconds=self.check_interval * 2)
                now = datetime.now()

                with self._lock:
                    for name, comp in list(self.components.items()):
                        if (now - comp.last_check) > stale_threshold:
                            if comp.status != HealthStatus.UNHEALTHY:
                                self.logger.warning(
                                    "Component %s health check is stale",
                                    name,
                                )
                                comp.status = HealthStatus.DEGRADED
                                comp.message = (
                                    "Health check stale; no recent updates"
                                )

                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(
                    "Error in health monitor loop: %s", e, exc_info=True
                )
                time.sleep(self.check_interval)


# Global health monitor instance
_health_monitor: Optional[HealthMonitor] = None
_health_lock = threading.Lock()


def get_health_monitor() -> HealthMonitor:
    """Get or create the global health monitor instance."""
    global _health_monitor
    with _health_lock:
        if _health_monitor is None:
            _health_monitor = HealthMonitor()
        return _health_monitor
