# Configuration Guide

**Last Updated: December 31, 2025**

The Akita Meshtastic Meshcore Bridge (AMMB) uses a configuration file named `config.ini` located in the project's root directory. Copy `examples/config.ini.example` to `config.ini` and modify it according to your setup.

All settings are placed under the `[DEFAULT]` section.

## Configuration Sections

### Meshtastic Settings

* **`MESHTASTIC_SERIAL_PORT`**
    * **Description:** The serial port where your Meshtastic device is connected.
    * **Example Linux:** `/dev/ttyUSB0`, `/dev/ttyACM0`
    * **Example Windows:** `COM3`, `COM4`
    * **Finding the port:**
        * Use the command `meshtastic --port list`.
        * Check your operating system's device manager or `/dev` directory.
    * **Required:** Yes
    * **Default:** `/dev/ttyUSB0`

### External Transport Selection

* **`EXTERNAL_TRANSPORT`**
    * **Description:** Selects the transport method for the external system connection.
    * **Supported Values:**
        * `serial`: Connect via serial port (for devices like MeshCore)
        * `mqtt`: Connect via MQTT broker
    * **Required:** Yes
    * **Default:** `serial`

### Serial Transport Settings

These settings are only used when `EXTERNAL_TRANSPORT = serial`.

* **`SERIAL_PORT`**
    * **Description:** The serial port where your external device (e.g., MeshCore) is connected.
    * **Example Linux:** `/dev/ttyS0`, `/dev/ttyAMA0` (Raspberry Pi)
    * **Example Windows:** `COM1`, `COM5`
    * **Required:** Yes (when using serial transport)
    * **Default:** `/dev/ttyS0`

* **`SERIAL_BAUD_RATE`**
    * **Description:** The baud rate (speed) for serial communication. This must exactly match the device's baud rate setting.
    * **Common Values:** `9600`, `19200`, `38400`, `57600`, `115200`
    * **Required:** Yes (when using serial transport)
    * **Default:** `9600`

* **`SERIAL_PROTOCOL`**
    * **Description:** Specifies how messages are formatted over the serial connection.
    * **Supported Values:**
        * `json_newline`: Messages are newline-terminated UTF-8 JSON strings (default for structured data)
        * `raw_serial`: Raw binary/text bytes forwarded as hex (for MeshCore Companion Mode)
    * **Required:** Yes (when using serial transport)
    * **Default:** `json_newline`

### MQTT Transport Settings

These settings are only used when `EXTERNAL_TRANSPORT = mqtt`.

* **`MQTT_BROKER`**
    * **Description:** Address (hostname or IP) of the MQTT broker.
    * **Example:** `localhost`, `192.168.1.100`, `mqtt.example.com`
    * **Required:** Yes (when using MQTT transport)
    * **Default:** `localhost`

* **`MQTT_PORT`**
    * **Description:** Port number for the MQTT broker.
    * **Common Values:** `1883` (unencrypted), `8883` (TLS/SSL)
    * **Required:** Yes (when using MQTT transport)
    * **Default:** `1883`

* **`MQTT_TOPIC_IN`**
    * **Description:** MQTT topic the bridge subscribes to, receiving messages destined for Meshtastic.
    * **Example:** `ammb/to_meshtastic`
    * **Required:** Yes (when using MQTT transport)
    * **Default:** `ammb/to_meshtastic`

* **`MQTT_TOPIC_OUT`**
    * **Description:** MQTT topic the bridge publishes messages to, originating from Meshtastic.
    * **Example:** `ammb/from_meshtastic`
    * **Required:** Yes (when using MQTT transport)
    * **Default:** `ammb/from_meshtastic`

* **`MQTT_USERNAME`**
    * **Description:** Username for MQTT broker authentication. Leave blank for no authentication.
    * **Required:** No
    * **Default:** (empty)

* **`MQTT_PASSWORD`**
    * **Description:** Password for MQTT broker authentication. Leave blank if no authentication.
    * **Required:** No
    * **Default:** (empty)

* **`MQTT_CLIENT_ID`**
    * **Description:** Client ID for this bridge instance. Should be unique if multiple bridges connect to the same broker.
    * **Required:** No
    * **Default:** `ammb_bridge_client`

* **`MQTT_QOS`**
    * **Description:** MQTT Quality of Service level for publishing and subscribing.
    * **Supported Values:**
        * `0`: At most once (fire and forget)
        * `1`: At least once (acknowledgement required)
        * `2`: Exactly once (more complex handshake)
    * **Required:** No
    * **Default:** `0`

* **`MQTT_RETAIN_OUT`**
    * **Description:** MQTT retain flag for outgoing messages.
    * **Values:**
        * `True`: Broker keeps last message for new subscribers
        * `False`: Messages are transient
    * **Required:** No
    * **Default:** `False`

* **`MQTT_TLS_ENABLED`**
    * **Description:** Enable TLS/SSL for MQTT connections.
    * **Values:** `True`, `False`
    * **Required:** No
    * **Default:** `False`

* **`MQTT_TLS_CA_CERTS`**
    * **Description:** Path to CA certificate file for TLS verification. Leave blank to use system default.
    * **Example:** `/path/to/ca-cert.pem`
    * **Required:** No
    * **Default:** (empty)

* **`MQTT_TLS_INSECURE`**
    * **Description:** Allow insecure TLS connections (disables certificate verification). Not recommended for production.
    * **Values:** `True`, `False`
    * **Required:** No
    * **Default:** `False`

### API Settings

* **`API_ENABLED`**
    * **Description:** Enable the REST API server for monitoring and control.
    * **Values:** `True`, `False`
    * **Required:** No
    * **Default:** `False`

* **`API_HOST`**
    * **Description:** Host address for the API server.
    * **Example:** `127.0.0.1` (localhost only), `0.0.0.0` (all interfaces)
    * **Required:** No
    * **Default:** `127.0.0.1`

* **`API_PORT`**
    * **Description:** Port number for the API server.
    * **Range:** 1-65535
    * **Required:** No
    * **Default:** `8080`

### Bridge Settings

* **`EXTERNAL_NETWORK_ID`**
    * **Description:** Conceptual identifier for the external network. Used primarily for logging.
    * **Required:** No
    * **Default:** `default_external_net`

* **`BRIDGE_NODE_ID`**
    * **Description:** Identifier for the bridge node on the Meshtastic network. Used to prevent message loops.
    * **Format:** Recommended to use Meshtastic node ID format (e.g., `!a1b2c3d4`)
    * **Finding your ID:** Use `meshtastic --info` when connected to your device.
    * **Required:** No
    * **Default:** `!ammb_bridge`

* **`MESSAGE_QUEUE_SIZE`**
    * **Description:** Maximum number of messages in each internal queue. Messages are dropped if queue is full.
    * **Range:** 1 and above
    * **Required:** No
    * **Default:** `100`

### Logging Settings

* **`LOG_LEVEL`**
    * **Description:** Minimum severity level for console logging.
    * **Supported Values (least to most verbose):**
        * `CRITICAL`: Only critical errors
        * `ERROR`: Errors and above
        * `WARNING`: Warnings and above
        * `INFO`: General information and above (recommended)
        * `DEBUG`: All messages including detailed debugging
    * **Required:** No
    * **Default:** `INFO`

## Configuration File Format

The configuration file uses INI format:

```ini
[DEFAULT]
MESHTASTIC_SERIAL_PORT = /dev/ttyUSB0
EXTERNAL_TRANSPORT = serial
SERIAL_PORT = /dev/ttyS0
SERIAL_BAUD_RATE = 9600
SERIAL_PROTOCOL = json_newline
LOG_LEVEL = INFO
```

## Configuration Validation

The configuration handler validates all settings at startup:

- Required fields are checked
- Numeric values are validated (ranges, types)
- Enum values are checked against allowed options
- Port numbers are validated (1-65535)
- Boolean values are parsed correctly

If validation fails, the bridge will not start and will log the specific error.

## Environment-Specific Configuration

For different environments (development, production), you can:

1. Use different `config.ini` files
2. Use environment variables (requires code modification)
3. Use configuration management tools

## Security Considerations

- **MQTT Passwords**: Store securely, consider using environment variables for sensitive data
- **TLS Certificates**: Use proper certificate paths and avoid insecure mode in production
- **API Access**: Restrict API host to localhost (127.0.0.1) unless firewall protection is in place
- **Serial Ports**: Ensure proper permissions are set on serial devices

## Troubleshooting Configuration

Common configuration issues:

1. **Invalid port names**: Verify port exists and is accessible
2. **Wrong baud rate**: Must match device setting exactly
3. **Missing required fields**: Check error messages for specific missing fields
4. **Invalid enum values**: Check allowed values in this documentation
5. **Port conflicts**: Ensure API port is not already in use

See `docs/usage.md` for more troubleshooting guidance.
