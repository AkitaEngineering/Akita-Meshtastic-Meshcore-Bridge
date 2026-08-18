# ammb/message_logger.py
"""
Message persistence and logging for the bridge.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional


_instance: Optional["MessageLogger"] = None
_instance_lock = threading.Lock()


def configure_message_logger(
    log_file: Optional[str] = None,
    max_file_size_mb: int = 10,
    max_backups: int = 5,
) -> "MessageLogger":
    """Replace the process-wide message logger."""
    global _instance
    with _instance_lock:
        if _instance is not None:
            _instance.stop()
        _instance = MessageLogger(
            log_file=log_file,
            max_file_size_mb=max_file_size_mb,
            max_backups=max_backups,
        )
        return _instance


def get_message_logger() -> "MessageLogger":
    """Return the process-wide message logger, creating a disabled one."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = MessageLogger(log_file=None)
        return _instance


def reset_message_logger() -> None:
    """Stop and clear the process-wide message logger."""
    global _instance
    with _instance_lock:
        if _instance is not None:
            _instance.stop()
        _instance = None


class MessageLogger:
    """Logs messages to file for persistence and analysis."""

    def __init__(
        self,
        log_file: Optional[str] = None,
        max_file_size_mb: int = 10,
        max_backups: int = 5,
    ):
        self.logger = logging.getLogger(__name__)
        self.log_file = log_file
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.max_backups = max_backups
        self._lock = threading.Lock()
        self._enabled = bool(log_file)
        self._message_queue: Queue = Queue(maxsize=1000)
        self._worker_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        self._log_path: Optional[Path] = None

        if self._enabled:
            assert self.log_file is not None
            self._log_path = Path(self.log_file)
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            self._start_worker()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _start_worker(self):
        """Start background worker thread for logging."""
        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._worker_thread = threading.Thread(
            target=self._worker_loop, daemon=True, name="MessageLogger"
        )
        self._worker_thread.start()
        self.logger.info("Message logger started, logging to: %s", self.log_file)

    def _worker_loop(self):
        """Background loop for writing messages."""
        while not self._shutdown_event.is_set():
            try:
                message = self._message_queue.get(timeout=1)
                if message:
                    self._write_message(message)
                    self._message_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                self.logger.error(
                    "Error in message logger worker: %s", e, exc_info=True
                )

    def _write_message(self, message: Dict[str, Any]):
        """Write a message to the log file."""
        if not self._enabled or self._log_path is None:
            return

        try:
            entry = dict(message)
            if "timestamp" not in entry:
                entry["timestamp"] = datetime.now().isoformat()

            self._rotate_if_needed()

            with self._lock:
                with open(self._log_path, "a", encoding="utf-8") as f:
                    json.dump(entry, f, ensure_ascii=False, default=str)
                    f.write("\n")

        except Exception as e:
            self.logger.error(
                "Error writing message to log file: %s", e, exc_info=True
            )

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds max size."""
        if self._log_path is None or not self._log_path.exists():
            return

        if self._log_path.stat().st_size < self.max_file_size:
            return

        try:
            for i in range(self.max_backups - 1, 0, -1):
                old_file = Path(f"{self._log_path}.{i}")
                new_file = Path(f"{self._log_path}.{i + 1}")
                if old_file.exists():
                    if new_file.exists():
                        new_file.unlink()
                    old_file.rename(new_file)

            backup_file = Path(f"{self._log_path}.1")
            if backup_file.exists():
                backup_file.unlink()
            self._log_path.rename(backup_file)

            self.logger.info(
                "Rotated log file: %s -> %s", self._log_path, backup_file
            )

        except Exception as e:
            self.logger.error("Error rotating log file: %s", e, exc_info=True)

    def log_message(self, message: Dict[str, Any], direction: str = "unknown"):
        """Queue a message for logging."""
        if not self._enabled:
            return

        log_entry = {
            **message,
            "direction": direction,
            "logged_at": datetime.now().isoformat(),
        }

        try:
            self._message_queue.put_nowait(log_entry)
        except Full:
            self.logger.warning("Message log queue is full; dropping entry")
        except Exception as e:
            self.logger.warning("Failed to queue message for logging: %s", e)

    def stop(self):
        """Stop the message logger."""
        if not self._enabled:
            return

        self._shutdown_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5)

        while not self._message_queue.empty():
            try:
                message = self._message_queue.get_nowait()
                self._write_message(message)
            except Empty:
                break

        self.logger.info("Message logger stopped")
