# Architecture Documentation

**Last Updated: May 19, 2026**

This document describes the architecture and design of the Akita Meshtastic Meshcore Bridge (AMMB).

## Overview

AMMB is a bidirectional bridge that connects Meshtastic LoRa mesh networks with external systems via Serial or MQTT. The bridge operates as a message relay, translating and forwarding messages between the two networks while maintaining connection health and providing monitoring capabilities.

The project currently exposes three operator-facing runtime modes:

* `run_bridge.py`: legacy synchronous runtime with plain terminal logging
* `run_bridge_async.py`: async runtime for `meshcore_py`, async MQTT, and the async API surface
* `run_bridge_tui.py`: full-screen Textual command center that wraps the synchronous bridge and surfaces live status, metrics, health, and logs

## Runtime Modes

### Synchronous Runtime

The synchronous runtime is built around `ammb/bridge.py`. It uses thread-based handlers, bounded queues, and shared singleton metrics and health collectors.

### Async Runtime

The async runtime is built around `ammb/bridge_async.py`. It uses async handlers for MeshCore and MQTT, runs on an asyncio event loop, and can launch the async FastAPI server when enabled.

### Terminal Command Center

The command center is implemented in `ammb/tui.py`. It launches the synchronous bridge in a background thread and renders live bridge state, connection health, metrics, queue depth, events, and logs inside a full-screen Textual interface.

## System Architecture

### Core Components

1. **Bridge Orchestrators** (`ammb/bridge.py`, `ammb/bridge_async.py`)
   - `Bridge` manages the synchronous thread-based runtime
   - `AsyncBridge` manages the asyncio-based runtime
   - Both coordinate handlers, startup, shutdown, and runtime state

2. **Terminal Command Center** (`ammb/tui.py`)
   - Textual-based full-screen dashboard
   - Starts and stops the synchronous bridge runtime
   - Renders health, metrics, events, queue depth, and log tail
   - Writes launcher crash reports through `run_bridge_tui.py` if the UI fails unexpectedly

3. **Meshtastic Handler** (`ammb/meshtastic_handler.py`)
   - Manages connection to Meshtastic device
   - Receives messages from Meshtastic network
   - Sends messages to Meshtastic network
   - Implements loopback prevention
   - Integrates with metrics, health monitoring, validation, and rate limiting

4. **External Handlers**
   - **Sync Serial Handler** (`ammb/meshcore_handler.py`): Manages serial port communication
   - **Sync MQTT Handler** (`ammb/mqtt_handler.py`): Manages MQTT broker communication
   - **Async Serial Handler** (`ammb/meshcore_async_handler.py`): Async MeshCore integration
   - **Async MQTT Handler** (`ammb/mqtt_async_handler.py`): Async MQTT integration
   - All handlers support bidirectional message flow in their respective runtimes
   - All handlers integrate with metrics, health monitoring, validation, and rate limiting where applicable

5. **Protocol Handlers** (`ammb/protocol.py`)
   - Abstract base class for serial protocols
   - Implementations: `JsonNewlineProtocol`, `RawSerialProtocol`, `MeshcoreCompanionProtocol`
   - `MeshcoreCompanionProtocol` decodes both user messages and MeshCore management frames such as contact sync records, self info, device info, and adverts into structured bridge events
   - Extensible for custom protocols

6. **Configuration Handler** (`ammb/config_handler.py`)
   - Loads and validates configuration from `config.ini`
   - Provides type-safe configuration access
   - Validates all settings

7. **Metrics Collector** (`ammb/metrics.py`)
   - Thread-safe metrics collection
   - Tracks message statistics (received, sent, dropped, errors)
   - Tracks connection statistics (uptime, connection counts)
   - Rate limit violation tracking
   - Global singleton instance

8. **Health Monitor** (`ammb/health.py`)
   - Real-time component health tracking
   - Health status levels: HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
   - Automatic stale component detection
   - Background monitoring thread
   - Global singleton instance

9. **REST API Servers** (`ammb/api.py`, `ammb/api_async.py`)
   - HTTP servers for monitoring and control
   - Provide endpoints for health, metrics, status, and info
   - Sync and async implementations are available
   - Optional components (enabled via configuration)

10. **Message Validator** (`ammb/validator.py`)
   - Validates message format and content
   - Sanitizes input to prevent injection attacks
   - Validates Meshtastic node IDs
   - Validates message length and structure

11. **Rate Limiter** (`ammb/rate_limiter.py`)
    - Token bucket rate limiting algorithm
    - Prevents message flooding
    - Per-source rate limiting
    - Configurable limits

12. **Message Logger** (`ammb/message_logger.py`)
    - Optional message persistence to file
    - JSON line format
    - Automatic log rotation
    - Background worker thread

## Message Flow

### Meshtastic to External

1. Meshtastic device receives message on mesh network
2. Meshtastic Handler receives message via pubsub callback
3. Message is validated and sanitized
4. Rate limiting is checked
5. Message is translated to bridge format
6. Metrics are recorded
7. Message is queued to external handler
8. External handler (Serial or MQTT) sends message

### External to Meshtastic

1. External system sends message (via Serial or MQTT)
2. External Handler receives message
3. Message is validated and sanitized
4. Rate limiting is checked
5. Message is translated to Meshtastic format
6. Metrics are recorded
7. Message is queued to Meshtastic handler
8. Meshtastic Handler sends message to mesh network

## Concurrency Model

### Synchronous Runtime

The synchronous bridge uses multiple threads for concurrent operation:

- **Main Thread**: Bridge orchestration and main loop
- **Meshtastic Sender Thread**: Sends messages to Meshtastic network
- **Serial Receiver Thread**: Reads from serial port
- **Serial Sender Thread**: Writes to serial port
- **MQTT Publisher Thread**: Publishes messages to MQTT broker
- **MQTT Network Thread**: Handles MQTT client network operations (managed by paho-mqtt)
- **Health Monitor Thread**: Background health checking
- **API Server Thread**: HTTP request handling
- **Message Logger Thread**: Background message logging (if enabled)

All threads are daemon threads except the main thread, ensuring clean shutdown.

### Terminal Command Center

The command center keeps the Textual app on the main thread and launches the synchronous bridge runtime in a background `AMMB-Bridge` thread. This preserves the same queue, metrics, and health model while adding an interactive operator surface.

### Async Runtime

The async runtime uses an asyncio event loop instead of the thread-based handler model. When the async API is enabled, `run_bridge_async.py` launches the FastAPI server in a separate process while the bridge runtime continues on the main event loop.

## Message Queues

The bridge uses two internal queues:

- **to_meshtastic_queue**: Messages destined for Meshtastic network
- **to_external_queue**: Messages destined for external system

Both queues are thread-safe and have configurable maximum sizes. When a queue is full, incoming messages are dropped with a warning logged.

These queues are used directly by the synchronous bridge and the terminal command center. The async runtime uses async handler coordination instead of the synchronous queue pair.

## Connection Management

### Automatic Reconnection

All handlers implement automatic reconnection logic:

- **Meshtastic Handler**: Attempts reconnection on connection loss
- **Serial Handler**: Continuously attempts reconnection in receiver loop
- **MQTT Handler**: Uses paho-mqtt's built-in reconnection with callbacks

Reconnection attempts are logged and tracked in metrics.

### Health Monitoring

The health monitor tracks the status of all components:

- **HEALTHY**: Component is connected and functioning normally
- **DEGRADED**: Component has issues but is partially functional
- **UNHEALTHY**: Component is disconnected or has critical errors
- **UNKNOWN**: Component status is not yet determined

Health status is updated automatically when connections change.

## Security Features

1. **Message Validation**: All messages are validated before processing
2. **Input Sanitization**: Strings are sanitized to remove control characters
3. **Rate Limiting**: Prevents message flooding attacks
4. **Node ID Validation**: Prevents message spoofing
5. **TLS/SSL Support**: Secure MQTT connections with certificate validation

## Performance Considerations

1. **Thread-Safe Operations**: All shared data structures use locks
2. **Non-Blocking Logging**: Message logging uses background thread
3. **Efficient Rate Limiting**: Token bucket algorithm with O(1) operations
4. **Queue Management**: Bounded queues prevent memory issues
5. **Connection Pooling**: Reuses connections where possible

## Extensibility

### Adding New Protocols

To add a new serial protocol:

1. Create a class inheriting from `MeshcoreProtocolHandler`
2. Implement `read()`, `encode()`, and `decode()` methods
3. Register in `get_serial_protocol_handler()` factory function
4. Add configuration option

### Adding New Transports

To add a new external transport:

1. Create a handler class similar to `MeshcoreHandler` or `MQTTHandler`
2. Implement connection, send, and receive methods
3. Integrate with metrics, health, validation, and rate limiting
4. Add to `Bridge` class initialization
5. Update configuration handler

## Error Handling

The bridge implements comprehensive error handling:

- **Connection Errors**: Logged and trigger reconnection attempts
- **Message Errors**: Logged and tracked in metrics
- **Validation Errors**: Messages are rejected with warnings
- **Rate Limit Violations**: Logged and tracked separately
- **Critical Errors**: Logged with full stack traces

All errors are logged with appropriate severity levels and tracked in metrics.

## Monitoring and Observability

### Metrics

The metrics collector tracks:

- Message counts (received, sent, dropped, errors)
- Byte counts (received, sent)
- Connection statistics (uptime, connection/disconnection counts)
- Rate limit violations
- Timestamps of last activity

### Health Status

The health monitor provides:

- Overall system health status
- A shared health surface consumed by the REST API and the Textual command center
- Per-component health status
- Health check timestamps
- Component-specific details

### REST API

The REST API provides programmatic access to:

- Health status (`GET /api/health`)
- Metrics (`GET /api/metrics`)
- Combined status (`GET /api/status`)
- Bridge information (`GET /api/info`)
- Control actions (`POST /api/control`)

## Configuration

All configuration is loaded from `config.ini` at startup. The configuration handler validates all settings and provides type-safe access. See `configuration.md` for detailed configuration documentation.

## Logging

The bridge uses Python's standard logging module with configurable levels:

- **CRITICAL**: Critical errors that may cause shutdown
- **ERROR**: Errors that don't stop operation
- **WARNING**: Warnings about potential issues
- **INFO**: General operational information
- **DEBUG**: Detailed debugging information

Log format includes timestamp, thread name, level, module, and message.

## Shutdown Sequence

On shutdown (Ctrl+C or exception):

1. Shutdown event is set
2. API server is stopped
3. Health monitoring is stopped
4. All handlers are stopped (in reverse order)
5. Connections are closed
6. Threads are joined with timeout
7. Final log messages are written

The shutdown sequence ensures all resources are properly cleaned up.
