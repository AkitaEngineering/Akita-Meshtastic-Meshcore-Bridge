# ammb/utils.py
"""
Shared utilities for the AMMB application, primarily logging setup.
"""

import logging

LOG_FORMAT = (
    "%(asctime)s - %(threadName)s - %(levelname)s - %(name)s - %(message)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_level_str: str):
    """
    Configures application-wide logging.
    """
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        logging.warning(
            "Invalid log level specified: '%s'. Defaulting to INFO.",
            log_level_str,
        )
        numeric_level = logging.INFO

    # Reconfigure the root logger
    logging.basicConfig(
        level=numeric_level, format=LOG_FORMAT, datefmt=DATE_FORMAT, force=True
    )

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
