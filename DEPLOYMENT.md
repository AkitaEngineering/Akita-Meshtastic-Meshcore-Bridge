# Akita Meshtastic Meshcore Bridge Deployment Guide

## Prerequisites
- Python 3.10+ (recommended: 3.11 or 3.12)
- All hardware connected and serial ports identified
- MQTT broker (if using MQTT transport)
- A dedicated OS user that can access the serial devices (usually `dialout`)

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
- Copy `examples/config.ini.example` to `/etc/ammb/config.ini` (or `config.ini` in the working directory).
- Set the correct serial port, baud rate, MQTT, and API settings.
- Ensure `SERIAL_PROTOCOL` matches your device (`companion_radio` for MeshCore USB).
- For production MQTT, enable TLS (`MQTT_TLS_ENABLED = True`) and set credentials.
- If the REST API is enabled, set `API_TOKEN` and keep `API_HOST = 127.0.0.1` unless you terminate TLS at a reverse proxy.

## Production entry point
Use the headless production runtime:

```sh
python run_bridge.py --config /etc/ammb/config.ini
```

The same bridge is also available as:

```sh
python run_bridge_async.py --config /etc/ammb/config.ini
```

That wrapper adds an optional in-process FastAPI server. It is not a second protocol implementation.

Before first start:

```sh
python run_bridge_tui.py --check --config /etc/ammb/config.ini
```

## systemd
A unit file lives at `packaging/ammb.service`.

1. Copy the application to `/opt/ammb` and the unit to `/etc/systemd/system/ammb.service`.
2. Create user `ammb` and add it to `dialout`.
3. Install the venv and config as referenced in the unit.
4. Enable and start:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ammb.service
sudo systemctl status ammb.service
```

The unit restarts on failure. Watch logs with `journalctl -u ammb.service -f`.

## Operational Notes
- Only one process can access a serial port at a time.
- `MESHTASTIC_RETRY_ON_BOOT = True` keeps the process running if a radio appears after boot.
- Optional `MESSAGE_LOG_FILE` writes forwarded messages as JSON lines.
- Monitor `/api/health` when the API is enabled (`Authorization: Bearer <token>` if configured).
- To update, pull the latest code, reinstall requirements if needed, and restart the service.

## Troubleshooting
- **Serial port access denied:** Ensure no other process is using the port and the service user is in `dialout`.
- **No messages/events:** Check device connection and config. Enable debug logging for more details.
- **API 401:** An `API_TOKEN` is configured. Send `Authorization: Bearer <token>` or `X-API-Token`.

## Support
- See README.md for more details and contact info.
