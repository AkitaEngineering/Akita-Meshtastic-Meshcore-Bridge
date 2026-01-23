# ammb/message_logger.py
"""
Message persistence and logging for the bridge.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Dict, Optional


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
        self.max_file_size = max_file_size_mb * 1024 * 1024  # Convert to bytes
        self.max_backups = max_backups
        self._lock = threading.Lock()
        self._enabled = log_file is not None
        self._message_queue: Queue = Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()

        if self._enabled:
            assert self.log_file is not None
            self._log_path = Path(self.log_file)
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            self._start_worker()

    def _start_worker(self):
        """Start background worker thread for logging."""
        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._worker_thread = threading.Thread(
            target=self._worker_loop, daemon=True, name="MessageLogger"
        )
        self._worker_thread.start()
        self.logger.info(
            f"Message logger started, logging to: {self.log_file}"
        )

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
                    f"Error in message logger worker: {e}", exc_info=True
                )

    def _write_message(self, message: Dict[str, Any]):
        """Write a message to the log file."""
        if not self._enabled:
            return

        try:
            # Add timestamp if not present
            if "timestamp" not in message:
                message["timestamp"] = datetime.now().isoformat()

            # Rotate log file if needed
            self._rotate_if_needed()

            # Write message as JSON line
            with self._lock:
                with open(self._log_path, "a", encoding="utf-8") as f:
                    json.dump(message, f, ensure_ascii=False)
                    f.write("\n")

        except Exception as e:
            self.logger.error(
                f"Error writing message to log file: {e}", exc_info=True
            )

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds max size."""
        if not self._log_path.exists():
            return

        if self._log_path.stat().st_size < self.max_file_size:
            return

        try:
            # Rotate existing backups
            for i in range(self.max_backups - 1, 0, -1):
                old_file = self._log_path.with_suffix(f".{i}.log")
                new_file = self._log_path.with_suffix(f".{i + 1}.log")
                if old_file.exists():
                    old_file.rename(new_file)

            # Move current log to .1.log
            backup_file = self._log_path.with_suffix(".1.log")
            self._log_path.rename(backup_file)

            self.logger.info(
                f"Rotated log file: {self._log_path} -> {backup_file}"
            )

        except Exception as e:
            self.logger.error(f"Error rotating log file: {e}", exc_info=True)

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
        except Exception as e:
            self.logger.warning(f"Failed to queue message for logging: {e}")

    def stop(self):
        """Stop the message logger."""
        if not self._enabled:
            return

        self._shutdown_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5)

        # Process remaining messages
        while not self._message_queue.empty():
            try:
                message = self._message_queue.get_nowait()
                self._write_message(message)
            except Empty:
                break

        self.logger.info("Message logger stopped")
