# ammb/rate_limiter.py
"""
Rate limiting for message processing.
"""

import logging
import time
from collections import deque
from threading import Lock
from typing import Optional


class RateLimiter:
    """Simple token bucket rate limiter."""

    def __init__(self, max_messages: int, time_window: float = 60.0):
        """
        Initialize rate limiter.

        Args:
            max_messages: Maximum number of messages allowed
            time_window: Time window in seconds (default: 60 seconds)
                # (1 minute)
        """
        self.logger = logging.getLogger(__name__)
        self.max_messages = max_messages
        self.time_window = time_window
        self.message_times: deque = deque()
        self._lock = Lock()
        self.violations = 0

    def check_rate_limit(self, source: str = "unknown") -> bool:
        """
        Check if a message should be allowed based on rate limits.

        Returns:
            True if message should be allowed, False if rate limit exceeded
        """
        now = time.time()

        with self._lock:
            # Remove old message timestamps outside the time window
            while (
                self.message_times
                and (now - self.message_times[0]) > self.time_window
            ):
                self.message_times.popleft()

            # Check if we're at the limit
            if len(self.message_times) >= self.max_messages:
                self.violations += 1
                self.logger.warning(
                    "Rate limit exceeded for %s: %s/%s messages in %ss",
                    source,
                    len(self.message_times),
                    self.max_messages,
                    self.time_window,
                )
                return False

            # Add current message timestamp
            self.message_times.append(now)
            return True

    def get_current_rate(self) -> float:
        """Get current message rate (messages per minute)."""
        with self._lock:
            if not self.message_times:
                return 0.0

            now = time.time()
            # Count messages in the last minute
            recent_count = sum(
                1 for t in self.message_times if (now - t) <= 60.0
            )
            return recent_count

    def reset(self):
        """Reset the rate limiter."""
        with self._lock:
            self.message_times.clear()
            self.violations = 0

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        with self._lock:
            return {
                "max_messages": self.max_messages,
                "time_window": self.time_window,
                "current_count": len(self.message_times),
                "violations": self.violations,
                "current_rate_per_minute": self.get_current_rate(),
            }


class MultiSourceRateLimiter:
    """Rate limiter that tracks multiple sources separately."""

    def __init__(self, max_messages: int, time_window: float = 60.0):
        self.max_messages = max_messages
        self.time_window = time_window
        self.limiters: dict[str, RateLimiter] = {}
        self._lock = Lock()

    def check_rate_limit(self, source: str) -> bool:
        """Check rate limit for a specific source."""
        with self._lock:
            if source not in self.limiters:
                self.limiters[source] = RateLimiter(
                    self.max_messages, self.time_window
                )
            return self.limiters[source].check_rate_limit(source)

    def get_stats(self) -> dict:
        """Get statistics for all sources."""
        with self._lock:
            return {
                source: limiter.get_stats()
                for source, limiter in self.limiters.items()
            }

    def reset(self, source: Optional[str] = None):
        """Reset rate limiter(s)."""
        with self._lock:
            if source:
                if source in self.limiters:
                    self.limiters[source].reset()
            else:
                for limiter in self.limiters.values():
                    limiter.reset()
