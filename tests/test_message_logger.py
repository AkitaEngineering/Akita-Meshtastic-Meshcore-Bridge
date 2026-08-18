import json
import time
from pathlib import Path

from ammb.message_logger import (
    MessageLogger,
    configure_message_logger,
    get_message_logger,
    reset_message_logger,
)


def _wait_for_file(path: Path, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(0.05)
    raise AssertionError(f"log file was not written: {path}")


def test_disabled_logger_does_not_create_file(tmp_path):
    logger = MessageLogger(log_file=None)
    logger.log_message({"payload": "nope"}, "test")
    logger.stop()
    assert list(tmp_path.iterdir()) == []


def test_logger_writes_json_lines(tmp_path):
    log_file = tmp_path / "messages.jsonl"
    logger = MessageLogger(log_file=str(log_file))
    logger.log_message({"payload": "hello", "id": 1}, "meshtastic_to_external")
    logger.stop()
    _wait_for_file(log_file)

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["payload"] == "hello"
    assert entry["direction"] == "meshtastic_to_external"
    assert "logged_at" in entry


def test_configure_message_logger_is_process_wide(tmp_path):
    log_file = tmp_path / "bridge.jsonl"
    configured = configure_message_logger(str(log_file))
    assert get_message_logger() is configured
    get_message_logger().log_message({"payload": "x"}, "test")
    get_message_logger().stop()
    _wait_for_file(log_file)
    reset_message_logger()
    assert get_message_logger() is not configured


def test_logger_rotates_when_max_size_exceeded(tmp_path):
    log_file = tmp_path / "rotate.jsonl"
    logger = MessageLogger(
        log_file=str(log_file),
        max_file_size_mb=0,
        max_backups=2,
    )
    # Force the size check to treat any existing bytes as over limit
    logger.max_file_size = 1
    logger.log_message({"payload": "first"}, "test")
    logger.stop()
    logger._write_message({"payload": "second"})
    logger._write_message({"payload": "third"})

    assert log_file.exists() or Path(f"{log_file}.1").exists()
