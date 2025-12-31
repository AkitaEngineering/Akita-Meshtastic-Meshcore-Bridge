# Architecture Documentation

**Last Updated: December 31, 2025**

This document describes the architecture and design of the Akita Meshtastic Meshcore Bridge (AMMB).

## Overview

AMMB is a bidirectional bridge that connects Meshtastic LoRa mesh networks with external systems via Serial or MQTT. The bridge operates as a message relay, translating and forwarding messages between the two networks while maintaining connection health and providing monitoring capabilities.

## System Architecture

### Core Components

1. **Bridge Orchestrator** (`ammb/bridge.py`)
   - Main coordination component
   - Manages handler lifecycle
   - Coordinates message queues
   - Handles graceful shutdown
   - Integrates metrics, health monitoring, and API server

2. **Meshtastic Handler** (`ammb/meshtastic_handler.py`)
   - Manages connection to Meshtastic device
   - Receives messages from Meshtastic network
   - Sends messages to Meshtastic network
   - Implements loopback prevention
   - Integrates with metrics, health monitoring, validation, and rate limiting

3. **External Handlers**
   - **Serial Handler** (`ammb/meshcore_handler.py`): Manages serial port communication
   - **MQTT Handler** (`ammb/mqtt_handler.py`): Manages MQTT broker communication
   - Both handlers support bidirectional message flow
   - Both integrate with metrics, health monitoring, validation, and rate limiting

4. **Protocol Handlers** (`ammb/protocol.py`)
   - Abstract base class for serial protocols
   - Implementations: `JsonNewlineProtocol`, `RawSerialProtocol`
   - Extensible for custom protocols

5. **Configuration Handler** (`ammb/config_handler.py`)
   - Loads and validates configuration from `config.ini`
   - Provides type-safe configuration access
   - Validates all settings

6. **Metrics Collector** (`ammb/metrics.py`)
   - Thread-safe metrics collection
   - Tracks message statistics (received, sent, dropped, errors)
   - Tracks connection statistics (uptime, connection counts)
   - Rate limit violation tracking
   - Global singleton instance

7. **Health Monitor** (`ammb/health.py`)
   - Real-time component health tracking
   - Health status levels: HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
   - Automatic stale component detection
   - Background monitoring thread
   - Global singleton instance

8. **REST API Server** (`ammb/api.py`)
   - HTTP server for monitoring and control
   - Provides endpoints for health, metrics, status, and info
   - Thread-safe implementation
   - Optional component (enabled via configuration)

9. **Message Validator** (`ammb/validator.py`)
   - Validates message format and content
   - Sanitizes input to prevent injection attacks
   - Validates Meshtastic node IDs
   - Validates message length and structure

10. **Rate Limiter** (`ammb/rate_limiter.py`)
    - Token bucket rate limiting algorithm
    - Prevents message flooding
    - Per-source rate limiting
    - Configurable limits

11. **Message Logger** (`ammb/message_logger.py`)
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

## Threading Model

The bridge uses multiple threads for concurrent operation:

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

## Message Queues

The bridge uses two internal queues:

- **to_meshtastic_queue**: Messages destined for Meshtastic network
- **to_external_queue**: Messages destined for external system

Both queues are thread-safe and have configurable maximum sizes. When a queue is full, incoming messages are dropped with a warning logged.

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

All configuration is loaded from `config.ini` at startup. The configuration handler validates all settings and provides type-safe access. See `docs/configuration.md` for detailed configuration documentation.

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
