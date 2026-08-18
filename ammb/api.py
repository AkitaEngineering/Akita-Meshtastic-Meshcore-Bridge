# ammb/api.py
"""
REST API for monitoring and controlling the bridge.
"""

import json
import logging
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse

from .health import get_health_monitor
from .metrics import get_metrics
from .version import __version__


def extract_request_token(
    authorization: Optional[str],
    x_api_token: Optional[str],
) -> Optional[str]:
    """Extract an API token from common request headers."""
    if x_api_token:
        return x_api_token.strip()
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value:
            return value.strip()
        if not value:
            return authorization.strip()
    return None


def token_matches(expected: Optional[str], provided: Optional[str]) -> bool:
    """Constant-time compare when a token is configured."""
    if not expected:
        return True
    if not provided:
        return False
    return secrets.compare_digest(expected, provided)


class BridgeAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the bridge API."""

    def __init__(self, bridge_instance, *args, **kwargs):
        self.bridge = bridge_instance
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Override to use our logger."""
        logger = logging.getLogger(__name__)
        logger.debug("%s - %s", self.address_string(), format % args)

    def _authorized(self) -> bool:
        expected = getattr(self.bridge.config, "api_token", None)
        provided = extract_request_token(
            self.headers.get("Authorization"),
            self.headers.get("X-API-Token"),
        )
        return token_matches(expected, provided)

    def do_GET(self):
        """Handle GET requests."""
        if not self._authorized():
            self._send_response(401, {"error": "Unauthorized"})
            return

        parsed_path = urlparse(self.path)
        path = parsed_path.path.rstrip("/")

        try:
            if path == "/api/health":
                self._handle_health()
            elif path == "/api/metrics":
                self._handle_metrics()
            elif path == "/api/status":
                self._handle_status()
            elif path == "/api/info":
                self._handle_info()
            else:
                self._send_response(404, {"error": "Not found"})
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error("Error handling API request: %s", e, exc_info=True)
            self._send_response(500, {"error": "Internal server error"})

    def do_POST(self):
        """Handle POST requests."""
        if not self._authorized():
            self._send_response(401, {"error": "Unauthorized"})
            return

        parsed_path = urlparse(self.path)
        path = parsed_path.path.rstrip("/")

        try:
            if path == "/api/control":
                self._handle_control()
            else:
                self._send_response(404, {"error": "Not found"})
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error("Error handling API request: %s", e, exc_info=True)
            self._send_response(500, {"error": "Internal server error"})

    def _handle_health(self):
        """Handle health check request."""
        health_monitor = get_health_monitor()
        health_data = health_monitor.get_overall_health()
        self._send_response(200, health_data)

    def _handle_metrics(self):
        """Handle metrics request."""
        metrics = get_metrics()
        metrics_data = metrics.get_all_stats()
        self._send_response(200, metrics_data)

    def _handle_status(self):
        """Handle status request (combined health and metrics)."""
        health_monitor = get_health_monitor()
        metrics = get_metrics()

        status = {
            "health": health_monitor.get_overall_health(),
            "metrics": metrics.get_all_stats(),
        }
        self._send_response(200, status)

    def _handle_info(self):
        """Handle info request."""
        info = {
            "name": "Akita Meshtastic Meshcore Bridge",
            "version": __version__,
            "external_transport": (
                self.bridge.config.external_transport
                if self.bridge.config
                else "unknown"
            ),
            "meshtastic_connected": (
                self.bridge.meshtastic_handler._is_connected.is_set()
                if self.bridge.meshtastic_handler
                else False
            ),
            "external_connected": (
                self.bridge.external_handler._is_connected.is_set()
                if hasattr(self.bridge.external_handler, "_is_connected")
                and self.bridge.external_handler
                else False
            ),
        }
        self._send_response(200, info)

    def _handle_control(self):
        """Handle control requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_response(400, {"error": "No request body"})
            return

        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode("utf-8"))
            action = data.get("action")

            if action == "reset_metrics":
                metrics = get_metrics()
                metrics.reset()
                self._send_response(200, {"message": "Metrics reset"})
            else:
                self._send_response(
                    400, {"error": f"Unknown action: {action}"}
                )
        except json.JSONDecodeError:
            self._send_response(400, {"error": "Invalid JSON"})

    def _send_response(self, status_code: int, data: dict):
        """Send JSON response."""
        response = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        if status_code == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(response)


class BridgeAPIServer:
    """REST API server for the bridge."""

    def __init__(
        self, bridge_instance, host: str = "127.0.0.1", port: int = 8080
    ):
        self.logger = logging.getLogger(__name__)
        self.bridge = bridge_instance
        self.host = host
        self.port = port
        self.server: Optional[ThreadingHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None

    def start(self):
        """Start the API server."""
        if self.server:
            return

        def handler_factory(*args, **kwargs):
            return BridgeAPIHandler(self.bridge, *args, **kwargs)

        try:
            self.server = ThreadingHTTPServer(
                (self.host, self.port), handler_factory
            )
            self.server.daemon_threads = True
            self.server.allow_reuse_address = True
            self.port = self.server.server_address[1]
            self.server_thread = threading.Thread(
                target=self._serve, daemon=True, name="BridgeAPI"
            )
            self.server_thread.start()
            token_state = (
                "token required"
                if getattr(self.bridge.config, "api_token", None)
                else "no token configured"
            )
            self.logger.info(
                "Bridge API server started on http://%s:%s (%s)",
                self.host,
                self.port,
                token_state,
            )
        except Exception as e:
            self.logger.error(
                "Failed to start API server: %s", e, exc_info=True
            )

    def stop(self):
        """Stop the API server."""
        if self.server:
            self.logger.info("Stopping Bridge API server...")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            if self.server_thread:
                self.server_thread.join(timeout=5)

    def _serve(self):
        """Run the server."""
        if self.server:
            self.server.serve_forever()
