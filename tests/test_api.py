import json
import threading
from queue import Queue
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from fastapi.testclient import TestClient

from ammb.api import BridgeAPIServer, extract_request_token, token_matches
from ammb.api_async import app, configure_async_api, reset_async_api
from ammb.metrics import get_metrics
from ammb.version import __version__
from tests.conftest import make_bridge_config


class _FakeBridge:
    def __init__(self, config):
        self.config = config
        self.meshtastic_handler = SimpleNamespace(
            _is_connected=threading.Event()
        )
        self.external_handler = SimpleNamespace(
            _is_connected=threading.Event()
        )
        self.to_meshtastic_queue = Queue()
        self.to_external_queue = Queue()


def _request(host, port, method, path, body=None, headers=None):
    payload = None
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    request = Request(
        f"http://{host}:{port}{path}",
        data=payload,
        headers=req_headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return response.status, data
    except HTTPError as exc:
        data = json.loads(exc.read().decode("utf-8"))
        return exc.code, data


def test_extract_request_token_supports_bearer_and_header():
    assert extract_request_token("Bearer secret", None) == "secret"
    assert extract_request_token(None, "header-secret") == "header-secret"
    assert extract_request_token(None, None) is None


def test_token_matches_allows_open_api_when_unset():
    assert token_matches(None, None) is True
    assert token_matches("abc", "abc") is True
    assert token_matches("abc", "nope") is False


def test_sync_api_info_uses_package_version():
    config = make_bridge_config(api_enabled=True, api_port=0)
    bridge = _FakeBridge(config)
    server = BridgeAPIServer(bridge, host="127.0.0.1", port=0)
    server.start()
    try:
        status, data = _request("127.0.0.1", server.port, "GET", "/api/info")
        assert status == 200
        assert data["version"] == __version__
        assert data["external_transport"] == "serial"
    finally:
        server.stop()


def test_sync_api_requires_token_when_configured():
    config = make_bridge_config(
        api_enabled=True,
        api_port=0,
        api_token="s3cret",
    )
    bridge = _FakeBridge(config)
    server = BridgeAPIServer(bridge, host="127.0.0.1", port=0)
    server.start()
    try:
        status, data = _request(
            "127.0.0.1", server.port, "GET", "/api/health"
        )
        assert status == 401
        assert data["error"] == "Unauthorized"

        status, data = _request(
            "127.0.0.1",
            server.port,
            "GET",
            "/api/health",
            headers={"Authorization": "Bearer s3cret"},
        )
        assert status == 200
        assert "status" in data
    finally:
        server.stop()


def test_sync_api_reset_metrics():
    get_metrics().record_meshtastic_received(4)
    config = make_bridge_config(api_enabled=True, api_port=0)
    bridge = _FakeBridge(config)
    server = BridgeAPIServer(bridge, host="127.0.0.1", port=0)
    server.start()
    try:
        status, data = _request(
            "127.0.0.1",
            server.port,
            "POST",
            "/api/control",
            body={"action": "reset_metrics"},
        )
        assert status == 200
        assert data["message"] == "Metrics reset"
        stats = get_metrics().get_all_stats()
        assert stats["meshtastic"]["messages"]["total_received"] == 0
    finally:
        server.stop()


def test_metrics_get_all_stats_does_not_deadlock():
    get_metrics().record_meshtastic_connection()
    stats = get_metrics().get_all_stats()
    assert "meshtastic" in stats
    assert "current_uptime_seconds" in stats["meshtastic"]["connection"]


def test_async_api_requires_token_and_reports_version():
    reset_async_api()
    configure_async_api(_FakeBridge(make_bridge_config()), token="tok")
    client = TestClient(app)
    denied = client.get("/api/info")
    assert denied.status_code == 401

    allowed = client.get(
        "/api/info", headers={"X-API-Token": "tok"}
    )
    assert allowed.status_code == 200
    assert allowed.json()["version"] == __version__
    reset_async_api()
