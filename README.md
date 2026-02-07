# Akita Meshtastic Meshcore Bridge (AMMB)

**AMMB** is a flexible and robust software bridge designed by **Akita Engineering** to facilitate seamless, bidirectional communication between Meshtastic LoRa mesh networks and external systems via Serial or MQTT.

This bridge enables interoperability, allowing messages, sensor data (with appropriate translation), and potentially other information to flow between Meshtastic and devices connected via Serial (like MeshCore) or platforms integrated with MQTT.

---

## Features

### Core Functionality
- **Bidirectional Message Forwarding:** Relays messages originating from Meshtastic nodes to the configured external system (Serial or MQTT), and vice-versa.  
- **Multiple External Transports:** Supports connecting to the external system via:  
  - **Direct Serial:** Interfaces directly with devices (like MeshCore) via standard RS-232/USB serial ports.  
  - **MQTT:** Connects to an MQTT broker to exchange messages with IoT platforms or other MQTT clients.  
- **Configurable Serial Protocol:** Supports different serial communication protocols via `config.ini`. Includes `raw_serial` and `companion_radio` handlers for MeshCore Companion Mode (Binary + framed USB protocol).  
- **Robust Connection Management:** Automatically attempts to reconnect if connections are lost.

### Enhanced Features
- **REST API:** Built-in HTTP API for monitoring bridge status, metrics, and health (optional, configurable)
- **Health Monitoring:** Real-time health status tracking for all bridge components
- **Metrics Collection:** Comprehensive statistics on messages, connections, and performance
- **Message Validation:** Automatic validation and sanitization of all messages
- **Rate Limiting:** Configurable rate limiting to prevent message flooding
- **MQTT TLS/SSL Support:** Secure MQTT connections with TLS/SSL encryption
- **Comprehensive Logging:** Detailed logging with configurable log levels
- **Message Persistence:** Optional message logging to file for analysis and debugging  

---

## Installation & Usage

### Clone the Repository
    git clone https://github.com/AkitaEngineering/akita-meshtastic-meshcore-bridge.git
    cd akita-meshtastic-meshcore-bridge

### Set up Environment
    python -m venv venv
    source venv/bin/activate  # or .\venv\Scripts\activate on Windows
    pip install -r requirements.txt

### Configure
Copy `examples/config.ini.example` to `config.ini` and edit it.

- **For MeshCore (Companion USB):**  
  Set `EXTERNAL_TRANSPORT = serial` and `SERIAL_PROTOCOL = companion_radio`.

  Optional companion settings in `config.ini`:
  - `COMPANION_HANDSHAKE_ENABLED = True` (send initial device query/app start)
  - `COMPANION_CONTACTS_POLL_S = 0` (poll contacts/adverts; 0 disables)
  - `COMPANION_DEBUG = False` (enable raw byte logging)
  - `SERIAL_AUTO_SWITCH = True` (auto-switch between `json_newline` and `raw_serial` on repeated decode failures)

- **For MQTT:**  
  Set `EXTERNAL_TRANSPORT = mqtt` and configure broker details. Optionally enable TLS/SSL for secure connections.

- **For REST API (Optional):**  
  Set `API_ENABLED = True` and configure `API_HOST` and `API_PORT` to enable the monitoring API.


### Run (Sync or Async)

- **Synchronous (legacy):**
  python run_bridge.py

- **Async (recommended, for meshcore_py and async MQTT):**
  python run_bridge_async.py

The async entry point supports:
  - Async Meshcore integration (meshcore_py) with `CONTACT_MSG_RECV` and `CHANNEL_MSG_RECV` subscriptions
  - Async MQTT (asyncio-mqtt)
  - Async REST API (FastAPI, if enabled)

#### Async API Server
If `API_ENABLED = True` in your config, the async bridge will launch a FastAPI server for health, metrics, and control endpoints (see below).


### REST API Endpoints (if enabled)
Endpoints are available on the configured API host/port (default: http://127.0.0.1:8080):

- `GET /api/health` — Health status of all components
- `GET /api/metrics` — Detailed metrics and statistics
- `GET /api/status` — Combined health and metrics
- `GET /api/info` — Bridge information
- `POST /api/control` — Control actions (e.g., reset metrics)

Example:
  curl http://localhost:8080/api/health
  curl http://localhost:8080/api/metrics

---

## Maintainer / Contact
This project is maintained by **Akita Engineering**.  

- **Website:** [www.akitaengineering.com](http://www.akitaengineering.com)  
- **Contact:** info@akitaengineering.com  

---

## License
This project is licensed under the **GNU General Public License v3.0**.  
(See the LICENSE file for the full license text.)
```
