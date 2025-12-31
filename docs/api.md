# REST API Documentation

**Last Updated: December 31, 2025**

The Akita Meshtastic Meshcore Bridge (AMMB) includes an optional REST API server for monitoring and controlling the bridge. The API is disabled by default and can be enabled by setting `API_ENABLED = True` in `config.ini`.

## Configuration

Configure the API in `config.ini`:

```ini
API_ENABLED = True
API_HOST = 127.0.0.1
API_PORT = 8080
```

* **API_ENABLED**: Enable or disable the API server (True/False)
* **API_HOST**: Host address to bind to (127.0.0.1 for localhost only, 0.0.0.0 for all interfaces)
* **API_PORT**: Port number for the API server (1-65535)

## Base URL

All API endpoints are relative to:
```
http://API_HOST:API_PORT
```

Default: `http://127.0.0.1:8080`

## Endpoints

### GET /api/health

Get the health status of all bridge components.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-31T10:00:00",
  "components": {
    "meshtastic": {
      "name": "meshtastic",
      "status": "healthy",
      "last_check": "2025-12-31T10:00:00",
      "message": "Connected",
      "details": {}
    },
    "external": {
      "name": "external",
      "status": "healthy",
      "last_check": "2025-12-31T10:00:00",
      "message": "Serial connected",
      "details": {}
    }
  }
}
```

**Status Values:**
* `healthy`: All components are functioning normally
* `degraded`: Some components have issues but are partially functional
* `unhealthy`: One or more components have critical errors
* `unknown`: Component status is not yet determined

**Example:**
```bash
curl http://localhost:8080/api/health
```

### GET /api/metrics

Get detailed metrics and statistics for the bridge.

**Response:**
```json
{
  "bridge": {
    "uptime_seconds": 3600.5,
    "start_time": "2025-12-31T09:00:00"
  },
  "meshtastic": {
    "messages": {
      "total_received": 150,
      "total_sent": 120,
      "total_dropped": 2,
      "total_errors": 1,
      "last_received": "2025-12-31T10:00:00",
      "last_sent": "2025-12-31T10:00:00",
      "bytes_received": 15000,
      "bytes_sent": 12000
    },
    "connection": {
      "connection_count": 1,
      "disconnection_count": 0,
      "last_connected": "2025-12-31T09:00:00",
      "last_disconnected": null,
      "total_uptime_seconds": 3600.5,
      "current_uptime_seconds": 3600.5
    }
  },
  "external": {
    "messages": {
      "total_received": 100,
      "total_sent": 95,
      "total_dropped": 0,
      "total_errors": 0,
      "last_received": "2025-12-31T10:00:00",
      "last_sent": "2025-12-31T10:00:00",
      "bytes_received": 10000,
      "bytes_sent": 9500
    },
    "connection": {
      "connection_count": 1,
      "disconnection_count": 0,
      "last_connected": "2025-12-31T09:00:00",
      "last_disconnected": null,
      "total_uptime_seconds": 3600.5,
      "current_uptime_seconds": 3600.5
    }
  },
  "rate_limits": {
    "meshtastic_sender": 0,
    "serial_receiver": 0
  }
}
```

**Example:**
```bash
curl http://localhost:8080/api/metrics
```

### GET /api/status

Get combined health and metrics information.

**Response:**
```json
{
  "health": {
    "status": "healthy",
    "timestamp": "2025-12-31T10:00:00",
    "components": { ... }
  },
  "metrics": {
    "bridge": { ... },
    "meshtastic": { ... },
    "external": { ... },
    "rate_limits": { ... }
  }
}
```

**Example:**
```bash
curl http://localhost:8080/api/status
```

### GET /api/info

Get basic bridge information.

**Response:**
```json
{
  "name": "Akita Meshtastic Meshcore Bridge",
  "version": "1.0.0",
  "external_transport": "serial",
  "meshtastic_connected": true,
  "external_connected": true
}
```

**Example:**
```bash
curl http://localhost:8080/api/info
```

### POST /api/control

Perform control actions on the bridge.

**Request Body:**
```json
{
  "action": "reset_metrics"
}
```

**Supported Actions:**
* `reset_metrics`: Reset all metrics counters to zero

**Response:**
```json
{
  "message": "Metrics reset"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/control \
  -H "Content-Type: application/json" \
  -d '{"action": "reset_metrics"}'
```

## Error Responses

All endpoints may return error responses in the following format:

**400 Bad Request:**
```json
{
  "error": "Invalid request body"
}
```

**404 Not Found:**
```json
{
  "error": "Not found"
}
```

**500 Internal Server Error:**
```json
{
  "error": "Internal server error"
}
```

## Security Considerations

1. **Access Control**: The API has no built-in authentication. If exposing the API to a network, ensure proper firewall rules are in place.

2. **Host Binding**: By default, the API binds to `127.0.0.1` (localhost only). Only bind to `0.0.0.0` if you have proper network security measures.

3. **Port Selection**: Choose a port that is not already in use and is not a well-known service port.

4. **HTTPS**: The API does not support HTTPS. For production deployments requiring encryption, use a reverse proxy (nginx, Apache) with SSL/TLS termination.

## Integration Examples

### Python

```python
import requests

base_url = "http://localhost:8080"

# Get health status
response = requests.get(f"{base_url}/api/health")
health = response.json()
print(f"Status: {health['status']}")

# Get metrics
response = requests.get(f"{base_url}/api/metrics")
metrics = response.json()
print(f"Messages received: {metrics['meshtastic']['messages']['total_received']}")
```

### JavaScript/Node.js

```javascript
const http = require('http');

const options = {
  hostname: 'localhost',
  port: 8080,
  path: '/api/health',
  method: 'GET'
};

const req = http.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    const health = JSON.parse(data);
    console.log(`Status: ${health.status}`);
  });
});

req.end();
```

### Shell Script

```bash
#!/bin/bash

API_URL="http://localhost:8080"

# Check health
health=$(curl -s "${API_URL}/api/health")
status=$(echo $health | jq -r '.status')

if [ "$status" != "healthy" ]; then
    echo "Bridge is not healthy: $status"
    exit 1
fi

# Get metrics
metrics=$(curl -s "${API_URL}/api/metrics")
received=$(echo $metrics | jq -r '.meshtastic.messages.total_received')
echo "Messages received: $received"
```

## Monitoring Tools

The API can be integrated with various monitoring tools:

* **Prometheus**: Use a Prometheus exporter or scrape the metrics endpoint
* **Grafana**: Create dashboards using the metrics endpoint
* **Nagios/Icinga**: Use health endpoint for service checks
* **Custom Dashboards**: Build custom monitoring dashboards using the API

## Rate Limiting

The API itself does not implement rate limiting. If you need to protect the API from excessive requests, use a reverse proxy with rate limiting capabilities.

## Troubleshooting

**API not responding:**
* Verify `API_ENABLED = True` in configuration
* Check if the API port is in use by another process
* Review error logs for connection issues

**Connection refused:**
* Verify API host and port settings
* Check firewall rules
* Ensure API server started successfully (check logs)

**Invalid JSON responses:**
* Check API server logs for errors
* Verify the bridge is running and not in error state

