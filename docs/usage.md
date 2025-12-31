# Usage Guide

**Last Updated: December 31, 2025**

This guide explains how to run and interact with the Akita Meshtastic Meshcore Bridge (AMMB).

## Prerequisites

Ensure you have completed the steps in the [Installation](README.md#installation) section of the main README, including:

1. Cloning the repository
2. Setting up a Python virtual environment (recommended)
3. Installing dependencies (`pip install -r requirements.txt`)
4. Creating and configuring your `config.ini` file

## Running the Bridge

1. **Navigate to the project root directory** in your terminal or command prompt (the directory containing `run_bridge.py`).

2. **Activate your virtual environment** (if you created one):
   * Linux/macOS: `source venv/bin/activate`
   * Windows: `.\venv\Scripts\activate`

3. **Run the bridge script:**
   ```bash
   python run_bridge.py
   ```

## Expected Output

Upon successful startup, you should see log messages similar to this in your console:

```
2025-12-31 10:00:00 - MainThread - INFO - config_handler - Configuration loaded successfully from config.ini
2025-12-31 10:00:00 - MainThread - INFO - utils - Logging level set to INFO
2025-12-31 10:00:00 - MainThread - INFO - bridge - Initializing network handlers...
2025-12-31 10:00:00 - MainThread - INFO - meshtastic_handler - Attempting connection to Meshtastic on /dev/ttyUSB0...
2025-12-31 10:00:01 - MainThread - INFO - meshtastic_handler - Connected to Meshtastic device. Node ID: !deadbeef
2025-12-31 10:00:01 - MainThread - INFO - meshtastic_handler - Meshtastic receive callback registered.
2025-12-31 10:00:01 - MainThread - INFO - meshcore_handler - Attempting connection to Serial device on /dev/ttyS0 at 9600 baud...
2025-12-31 10:00:01 - MainThread - INFO - meshcore_handler - Connected to Serial device on /dev/ttyS0
2025-12-31 10:00:01 - MainThread - INFO - bridge - Starting handler background tasks/threads...
2025-12-31 10:00:01 - MainThread - INFO - bridge - Bridge background tasks started. Running... (Press Ctrl+C to stop)
```

Notes:
* The bridge will attempt to connect to both the Meshtastic and external devices based on your `config.ini`
* If a connection fails initially (e.g., device not plugged in), it will log a warning or error and periodically retry in the background
* Once running, it will log messages received and sent on both networks (depending on your `LOG_LEVEL`)

## Monitoring

### Console Logs

Keep an eye on the terminal where you ran `python run_bridge.py`. This is the primary way to see what the bridge is doing, including:
* Received messages
* Sent messages
* Connection attempts
* Errors and warnings
* Metrics and statistics

### Log Level

If you need more detailed information for troubleshooting:
1. Stop the bridge (`Ctrl+C`)
2. Edit `config.ini`
3. Set `LOG_LEVEL = DEBUG`
4. Restart the bridge
5. Remember to set it back to `INFO` or `WARNING` for normal operation to avoid excessive output

### REST API Monitoring

If the REST API is enabled (`API_ENABLED = True` in `config.ini`), you can monitor the bridge programmatically:

**Health Status:**
```bash
curl http://localhost:8080/api/health
```

**Metrics:**
```bash
curl http://localhost:8080/api/metrics
```

**Combined Status:**
```bash
curl http://localhost:8080/api/status
```

**Bridge Information:**
```bash
curl http://localhost:8080/api/info
```

**Reset Metrics:**
```bash
curl -X POST http://localhost:8080/api/control \
  -H "Content-Type: application/json" \
  -d '{"action": "reset_metrics"}'
```

The API returns JSON data that can be parsed by monitoring tools, scripts, or dashboards.

## Stopping the Bridge

Press `Ctrl+C` in the terminal where the bridge is running. The bridge will:
1. Detect the shutdown signal
2. Stop all handler threads
3. Close all connections
4. Stop the API server (if enabled)
5. Stop health monitoring
6. Log shutdown messages

The shutdown sequence is designed to be graceful, ensuring all resources are properly cleaned up.

## Message Format

### Meshtastic to External

Messages from Meshtastic are translated to the following format:

```json
{
  "type": "meshtastic_message",
  "sender_meshtastic_id": "!deadbeef",
  "portnum": "TEXT_MESSAGE_APP",
  "payload": "Hello from Meshtastic",
  "timestamp_rx": 1704067200.0,
  "rx_rssi": -85,
  "rx_snr": 5.2
}
```

For position messages:
```json
{
  "type": "meshtastic_position",
  "sender_meshtastic_id": "!deadbeef",
  "portnum": "POSITION_APP",
  "payload": {
    "latitude": 37.7749,
    "longitude": -122.4194,
    "altitude": 100,
    "timestamp_gps": 1704067200
  },
  "timestamp_rx": 1704067200.0
}
```

### External to Meshtastic

Messages from external systems should be in the following format:

**For Serial (JSON protocol):**
```json
{
  "destination_meshtastic_id": "^all",
  "payload": "Hello from external system",
  "channel_index": 0,
  "want_ack": false
}
```

**For MQTT:**
```json
{
  "destination_meshtastic_id": "^all",
  "payload": "Hello from MQTT",
  "channel_index": 0,
  "want_ack": false
}
```

**Destination Options:**
* `^all` or `^broadcast`: Broadcast to all nodes
* `!aabbccdd`: Send to specific node ID (hexadecimal)

## Troubleshooting Common Issues

### Connection Issues

**Error: `Error connecting to Meshtastic device: [Errno 2] No such file or directory: '/dev/ttyUSB0'`**

* **Cause:** The specified `MESHTASTIC_SERIAL_PORT` in `config.ini` is incorrect, or the device is not connected/detected by the OS.
* **Solution:**
  * Verify the port name using `meshtastic --port list` or OS tools
  * Ensure the device is plugged in and drivers are installed
  * Check permissions (Linux users might need to be in the `dialout` group: `sudo usermod -a -G dialout $USER`)

**Error: `Error connecting to Serial device: [Errno 2] No such file or directory: '/dev/ttyS0'`**

* **Cause:** The specified `SERIAL_PORT` in `config.ini` is incorrect, or the device is not connected/detected.
* **Solution:**
  * Verify the port name using OS tools
  * Ensure the device is plugged in and drivers are installed
  * Check permissions

**Error: `serial.SerialException: Could not configure port: (5, 'Input/output error')`**

* **Cause:** The user running the script doesn't have permission to access the serial port.
* **Solution (Linux):** Add your user to the `dialout` group: `sudo usermod -a -G dialout $USER`. You may need to log out and log back in for the change to take effect.

### Message Issues

**No messages received from external device / Gibberish received**

* **Cause 1:** Incorrect `SERIAL_BAUD_RATE` in `config.ini`. It must match the device's setting exactly.
* **Cause 2:** Incorrect `SERIAL_PROTOCOL` selected, or the device is not sending data in the expected format.
* **Cause 3:** Wiring issue between the computer and the device.
* **Solution:**
  * Verify baud rate matches device setting
  * Verify the protocol setting matches the actual data format
  * Check physical connections
  * Use a serial terminal program to test communication directly

**Messages dropped (`Queue is full` warnings)**

* **Cause:** Messages are arriving faster than they can be sent out on the other network, or the destination network/device is unresponsive.
* **Solution:**
  * Investigate potential bottlenecks on the destination network
  * Consider increasing `MESSAGE_QUEUE_SIZE` in `config.ini` if temporary bursts are expected
  * Check if rate limiting is too restrictive
  * Note: This won't solve underlying rate issues, only provides temporary buffering

**JSONDecodeError / UnicodeDecodeError**

* **Cause:** The bridge received data that was not valid JSON (when using `json_newline` protocol) or not valid UTF-8 text.
* **Solution:**
  * Ensure the device is sending correctly formatted, UTF-8 encoded JSON strings, terminated by a newline
  * Check the log messages for clues about the invalid data
  * Verify the protocol setting matches the actual data format

**Rate limit exceeded warnings**

* **Cause:** Too many messages are being sent in a short time period.
* **Solution:**
  * This is a protective feature to prevent message flooding
  * Review your message sending rate
  * The default limit is 60 messages per minute per source
  * Rate limit violations are tracked in metrics

### Validation Errors

**Invalid message rejected warnings**

* **Cause:** A message failed validation (invalid format, missing fields, etc.)
* **Solution:**
  * Check the error message in the logs for specific validation failures
  * Ensure messages match the expected format (see Message Format section)
  * Verify node IDs are in the correct format (`!aabbccdd` or `^all`)

### API Issues

**API server not starting**

* **Cause:** Port may be in use, or configuration error.
* **Solution:**
  * Check if another process is using the API port
  * Verify `API_ENABLED = True` in `config.ini`
  * Check `API_HOST` and `API_PORT` settings
  * Review error messages in logs

**Cannot connect to API**

* **Cause:** Firewall blocking, wrong host/port, or API not enabled.
* **Solution:**
  * Verify API is enabled in configuration
  * Check firewall settings
  * Verify host and port settings
  * Try connecting from localhost first

### MQTT Issues

**MQTT connection failed**

* **Cause:** Broker unreachable, wrong credentials, or network issues.
* **Solution:**
  * Verify broker address and port
  * Check username and password (if required)
  * Test broker connectivity with another MQTT client
  * Check firewall settings

**MQTT TLS errors**

* **Cause:** Certificate issues or TLS configuration problems.
* **Solution:**
  * Verify certificate file path (if using custom CA)
  * Check TLS settings in configuration
  * Review TLS error messages in logs
  * Consider using `MQTT_TLS_INSECURE = True` for testing only (not recommended for production)

## Performance Tips

1. **Queue Size:** Increase `MESSAGE_QUEUE_SIZE` if you experience frequent message drops during bursts
2. **Log Level:** Use `INFO` or `WARNING` in production to reduce logging overhead
3. **API:** Disable API if not needed to reduce resource usage
4. **Rate Limiting:** Adjust rate limits based on your actual message volume
5. **Serial Baud Rate:** Use higher baud rates (115200) if your device supports it for better throughput

## Getting Help

If you encounter issues not covered in this guide:

1. Check the logs with `LOG_LEVEL = DEBUG` for detailed information
2. Review the API metrics and health status
3. Consult the architecture documentation (`docs/architecture.md`)
4. Check the configuration documentation (`docs/configuration.md`)
5. Review the development guide (`docs/development.md`)
