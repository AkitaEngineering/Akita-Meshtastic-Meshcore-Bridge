# ammb/config_handler.py
"""
Handles loading, validation, and access for the bridge configuration.
"""

import configparser
import logging
import os
from typing import Literal, NamedTuple, Optional, cast


class BridgeConfig(NamedTuple):
    """Stores all configuration settings for the bridge."""

    # Meshtastic Settings
    meshtastic_port: str

    # External Network Interface Settings
    external_transport: Literal["serial", "mqtt"]

    # Serial Specific (Optional)
    serial_port: Optional[str]
    serial_baud: Optional[int]
    serial_protocol: Optional[str]

    # MQTT Specific (Optional)
    mqtt_broker: Optional[str]
    mqtt_port: Optional[int]
    mqtt_topic_in: Optional[str]
    mqtt_topic_out: Optional[str]
    mqtt_username: Optional[str]
    mqtt_password: Optional[str]
    mqtt_client_id: Optional[str]
    mqtt_qos: Optional[int]
    mqtt_retain_out: Optional[bool]

    # Common Settings
    external_network_id: str
    bridge_node_id: str
    queue_size: int
    log_level: str

    # API Settings (Optional)
    api_enabled: Optional[bool] = False
    api_host: Optional[str] = "127.0.0.1"
    api_port: Optional[int] = 8080

    # MQTT TLS Settings (Optional)
    mqtt_tls_enabled: Optional[bool] = False
    mqtt_tls_ca_certs: Optional[str] = None
    mqtt_tls_insecure: Optional[bool] = False


CONFIG_FILE = "config.ini"

DEFAULT_CONFIG = {
    "MESHTASTIC_SERIAL_PORT": "/dev/ttyUSB0",
    "EXTERNAL_TRANSPORT": "serial",
    "SERIAL_PORT": "/dev/ttyS0",
    "SERIAL_BAUD_RATE": "9600",
    "SERIAL_PROTOCOL": "json_newline",
    "MQTT_BROKER": "localhost",
    "MQTT_PORT": "1883",
    "MQTT_TOPIC_IN": "ammb/to_meshtastic",
    "MQTT_TOPIC_OUT": "ammb/from_meshtastic",
    "MQTT_USERNAME": "",
    "MQTT_PASSWORD": "",
    "MQTT_CLIENT_ID": "ammb_bridge_client",
    "MQTT_QOS": "0",
    "MQTT_RETAIN_OUT": "False",
    "EXTERNAL_NETWORK_ID": "default_external_net",
    "BRIDGE_NODE_ID": "!ammb_bridge",
    "MESSAGE_QUEUE_SIZE": "100",
    "LOG_LEVEL": "INFO",
    "API_ENABLED": "False",
    "API_HOST": "127.0.0.1",
    "API_PORT": "8080",
    "MQTT_TLS_ENABLED": "False",
    "MQTT_TLS_CA_CERTS": "",
    "MQTT_TLS_INSECURE": "False",
}

VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
VALID_SERIAL_PROTOCOLS = {"json_newline", "raw_serial"}
VALID_TRANSPORTS = {"serial", "mqtt"}
VALID_MQTT_QOS = {0, 1, 2}


def load_config(config_path: str = CONFIG_FILE) -> Optional[BridgeConfig]:
    """
    Loads and validates configuration from the specified INI file.
    """
    logger = logging.getLogger(__name__)
    config = configparser.ConfigParser(
        defaults=DEFAULT_CONFIG, interpolation=None
    )

    if not os.path.exists(config_path):
        logger.error("Configuration file not found: %s", config_path)
        logger.error(
            "Please copy 'examples/config.ini.example' to 'config.ini' "
            "and configure it."
        )
        return None

    try:
        logger.info("Reading configuration from: %s", config_path)
        config.read(config_path)

        if "DEFAULT" not in config.sections():
            logger.warning(
                "Configuration file '%s' lacks the [DEFAULT] section.",
                config_path,
            )
            logger.warning("Using only defaults.")
        cfg_section = config["DEFAULT"] if "DEFAULT" in config else DEFAULT_CONFIG

        meshtastic_port = cfg_section.get(
            "MESHTASTIC_SERIAL_PORT",
            fallback=DEFAULT_CONFIG["MESHTASTIC_SERIAL_PORT"],
        )
        external_network_id = cfg_section.get(
            "EXTERNAL_NETWORK_ID",
            fallback=DEFAULT_CONFIG["EXTERNAL_NETWORK_ID"],
        )
        bridge_node_id = cfg_section.get(
            "BRIDGE_NODE_ID", fallback=DEFAULT_CONFIG["BRIDGE_NODE_ID"]
        )
        log_level_raw = cfg_section.get(
            "LOG_LEVEL", DEFAULT_CONFIG["LOG_LEVEL"]
        )
        log_level = log_level_raw.upper() if isinstance(log_level_raw, str) else DEFAULT_CONFIG["LOG_LEVEL"].upper()

        if log_level not in VALID_LOG_LEVELS:
            logger.error(
                "Invalid LOG_LEVEL '%s'. Must be one of: %s",
                log_level,
                VALID_LOG_LEVELS,
            )
            return None

        try:
            queue_size = cfg_section.getint("MESSAGE_QUEUE_SIZE")
            if queue_size is None or queue_size <= 0:
                raise ValueError("Queue size must be positive.")
        except ValueError as e:
            logger.error("Invalid integer value for MESSAGE_QUEUE_SIZE: %s", e)
            return None

        external_transport = cfg_section.get(
            "EXTERNAL_TRANSPORT", fallback=DEFAULT_CONFIG["EXTERNAL_TRANSPORT"]
        ).lower()
        if external_transport not in VALID_TRANSPORTS:
            logger.error(
                "Invalid EXTERNAL_TRANSPORT '%s'. Must be one of: %s",
                external_transport,
                VALID_TRANSPORTS,
            )
            return None

        serial_port = None
        serial_baud = None
        serial_protocol = None
        mqtt_broker = None
        mqtt_port = None
        mqtt_topic_in = None
        mqtt_topic_out = None
        mqtt_username = None
        mqtt_password = None
        mqtt_client_id = None
        mqtt_qos = None
        mqtt_retain_out = None

        if external_transport == "serial":
            serial_port = cfg_section.get(
                "SERIAL_PORT", fallback=DEFAULT_CONFIG["SERIAL_PORT"]
            )
            serial_protocol = cfg_section.get(
                "SERIAL_PROTOCOL", fallback=DEFAULT_CONFIG["SERIAL_PROTOCOL"]
            ).lower()
            if not serial_port:
                logger.error(
                    "SERIAL_PORT must be set when EXTERNAL_TRANSPORT "
                    "is 'serial'."
                )
                return None
            if serial_protocol not in VALID_SERIAL_PROTOCOLS:
                logger.warning(
                    "Unrecognized SERIAL_PROTOCOL '%s'."
                    " Valid options: %s.",
                    serial_protocol,
                    VALID_SERIAL_PROTOCOLS,
                )
                logger.warning(
                    "Attempting to use '%s' - ensure a corresponding "
                    "handler exists.",
                    serial_protocol,
                )
            try:
                serial_baud = cfg_section.getint("SERIAL_BAUD_RATE")
                if serial_baud is None or serial_baud <= 0:
                    raise ValueError("Serial baud rate must be positive.")
            except ValueError as e:
                logger.error(
                    "Invalid integer value for SERIAL_BAUD_RATE: %s",
                    e,
                )
                return None

        elif external_transport == "mqtt":
            mqtt_broker = cfg_section.get("MQTT_BROKER")
            mqtt_topic_in = cfg_section.get("MQTT_TOPIC_IN")
            mqtt_topic_out = cfg_section.get("MQTT_TOPIC_OUT")
            mqtt_username = cfg_section.get("MQTT_USERNAME")
            mqtt_password = cfg_section.get("MQTT_PASSWORD")
            mqtt_client_id = cfg_section.get("MQTT_CLIENT_ID")

            if not mqtt_broker or not mqtt_topic_in or not mqtt_topic_out:
                logger.error(
                    "MQTT_BROKER, MQTT_TOPIC_IN and "
                    "MQTT_TOPIC_OUT must be set."
                )
                return None
            if not mqtt_client_id:
                logger.warning(
                    "MQTT_CLIENT_ID empty. Using default."
                )
                mqtt_client_id = DEFAULT_CONFIG["MQTT_CLIENT_ID"]

            try:
                mqtt_port = cfg_section.getint("MQTT_PORT")
                mqtt_qos = cfg_section.getint("MQTT_QOS")
                mqtt_retain_out = cfg_section.getboolean("MQTT_RETAIN_OUT")
                if mqtt_port is None or mqtt_port <= 0 or mqtt_port > 65535:
                    raise ValueError("MQTT port must be between 1 and 65535.")
                if mqtt_qos is None or mqtt_qos not in VALID_MQTT_QOS:
                    msg = "MQTT_QOS must be one of %s" % (VALID_MQTT_QOS,)
                    raise ValueError(msg)
            except ValueError as e:
                logger.error(
                    "Invalid integer/boolean value in MQTT configuration: %s",
                    e,
                )
                return None

        # Parse API settings
        api_enabled = cfg_section.getboolean("API_ENABLED", fallback=False)
        api_host = cfg_section.get("API_HOST", fallback="127.0.0.1")
        try:
            api_port = cfg_section.getint("API_PORT", fallback=8080)
            if api_port <= 0 or api_port > 65535:
                logger.warning(
                    "Invalid API_PORT %s, using default 8080",
                    api_port,
                )
                api_port = 8080
        except ValueError:
            logger.warning("Invalid API_PORT, using default 8080")
            api_port = 8080

        # Parse MQTT TLS settings
        mqtt_tls_enabled = cfg_section.getboolean(
            "MQTT_TLS_ENABLED", fallback=False
        )
        mqtt_tls_ca_certs = (
            cfg_section.get("MQTT_TLS_CA_CERTS", fallback="").strip() or None
        )
        mqtt_tls_insecure = cfg_section.getboolean(
            "MQTT_TLS_INSECURE", fallback=False
        )

        bridge_config = BridgeConfig(
            meshtastic_port=meshtastic_port,
            external_transport=cast(
                Literal["serial", "mqtt"], external_transport
            ),
            serial_port=serial_port,
            serial_baud=serial_baud,
            serial_protocol=serial_protocol,
            mqtt_broker=mqtt_broker,
            mqtt_port=mqtt_port,
            mqtt_topic_in=mqtt_topic_in,
            mqtt_topic_out=mqtt_topic_out,
            mqtt_username=mqtt_username,
            mqtt_password=mqtt_password,
            mqtt_client_id=mqtt_client_id,
            mqtt_qos=mqtt_qos,
            mqtt_retain_out=mqtt_retain_out,
            external_network_id=external_network_id,
            bridge_node_id=bridge_node_id,
            queue_size=int(queue_size),
            log_level=log_level,
            api_enabled=api_enabled,
            api_host=api_host,
            api_port=api_port,
            mqtt_tls_enabled=mqtt_tls_enabled,
            mqtt_tls_ca_certs=mqtt_tls_ca_certs,
            mqtt_tls_insecure=mqtt_tls_insecure,
        )
        logger.debug("Configuration loaded: %s", bridge_config)
        return bridge_config

    except Exception as e:
        logger.error(
            "Unexpected error loading configuration: %s",
            e,
            exc_info=True,
        )
        return None
