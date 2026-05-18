# ammb/utils.py
"""
Shared utilities for the AMMB application, primarily logging setup.
"""

import logging
from typing import Iterable, Optional

LOG_FORMAT = (
    "%(asctime)s - %(threadName)s - %(levelname)s - %(name)s - %(message)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    log_level_str: str,
    *,
    console: bool = True,
    extra_handlers: Optional[Iterable[logging.Handler]] = None,
):
    """
    Configures application-wide logging.
    """
    if not isinstance(log_level_str, str):
        log_level_str = "INFO"
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        logging.warning(
            "Invalid log level specified: '%s'. Defaulting to INFO.",
            log_level_str,
        )
        numeric_level = logging.INFO

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # Reconfigure the root logger without forcing output to the terminal.
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(numeric_level)

    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    for handler in extra_handlers or []:
        handler.setLevel(numeric_level)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    # Adjust logging levels for noisy libraries
    logging.getLogger("pypubsub").setLevel(logging.WARNING)
    logging.getLogger("pubsub").setLevel(logging.WARNING)
    logging.getLogger("meshtastic").setLevel(logging.INFO)
    logging.getLogger("paho").setLevel(logging.WARNING)

    logging.info(
        "Logging configured to level %s (%s)",
        logging.getLevelName(numeric_level),
        numeric_level,
    )
