# Akita Meshtastic Meshcore Bridge Deployment Guide

## Prerequisites
- Python 3.9+ (recommended: 3.11+)
- All hardware connected and serial port identified (e.g., COM8)
- MQTT broker (if using MQTT transport)
- (Optional) FastAPI/uvicorn for REST API

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/AkitaEngineering/Akita-Meshtastic-Meshcore-Bridge.git
   cd Akita-Meshtastic-Meshcore-Bridge
   ```
2. Create and activate a virtual environment:
   ```sh
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Configuration
- Copy and edit `examples/config.ini.example` to `config.ini`.
- Set the correct serial port, baud rate, MQTT, and API settings as needed.
- Ensure the `SERIAL_PROTOCOL` matches your device (`raw_serial` or `json_newline`).

## Running the Bridge
```sh
python run_bridge_async.py
```
- The bridge will log to console by default. Adjust logging in `config.ini` if needed.

## Operational Notes
- Only one process can access the serial port at a time.
- To enable the REST API, set `api_enabled = true` in your config and ensure FastAPI/uvicorn are installed.
- For production, use a process manager (systemd, pm2, etc.) to keep the bridge running.
- Monitor logs for errors or disconnects.
- To update, pull the latest code and re-install requirements if needed.

## Troubleshooting
- **Serial port access denied:** Ensure no other process is using the port. Reboot if needed.
- **No messages/events:** Check device connection and config. Enable debug logging for more details.
- **Unhandled exceptions:** Review logs. All async tasks now have robust exception handling and will log errors.

## Support
- See README.md for more details and contact info.
