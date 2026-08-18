# ammb/api_async.py
"""
Async REST API for monitoring and controlling the bridge using FastAPI.
"""
from typing import Optional

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from ammb.api import extract_request_token, token_matches
from ammb.health import get_health_monitor
from ammb.metrics import get_metrics
from ammb.version import __version__

app = FastAPI()

_api_token: Optional[str] = None
_bridge = None


def configure_async_api(bridge=None, token: Optional[str] = None) -> None:
    """Attach the live bridge and optional API token to this process."""
    global _api_token, _bridge
    _bridge = bridge
    _api_token = token


def reset_async_api() -> None:
    """Clear process-wide async API state. Used by tests."""
    configure_async_api(bridge=None, token=None)


def _authorized(
    authorization: Optional[str],
    x_api_token: Optional[str],
) -> bool:
    provided = extract_request_token(authorization, x_api_token)
    return token_matches(_api_token, provided)


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"error": "Unauthorized"},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.get("/api/health")
async def health(
    authorization: Optional[str] = Header(default=None),
    x_api_token: Optional[str] = Header(default=None),
):
    if not _authorized(authorization, x_api_token):
        return _unauthorized()
    health_monitor = get_health_monitor()
    return JSONResponse(content=health_monitor.get_overall_health())


@app.get("/api/metrics")
async def metrics(
    authorization: Optional[str] = Header(default=None),
    x_api_token: Optional[str] = Header(default=None),
):
    if not _authorized(authorization, x_api_token):
        return _unauthorized()
    metrics_collector = get_metrics()
    return JSONResponse(content=metrics_collector.get_all_stats())


@app.get("/api/status")
async def status(
    authorization: Optional[str] = Header(default=None),
    x_api_token: Optional[str] = Header(default=None),
):
    if not _authorized(authorization, x_api_token):
        return _unauthorized()
    health_monitor = get_health_monitor()
    metrics_collector = get_metrics()
    return JSONResponse(
        content={
            "health": health_monitor.get_overall_health(),
            "metrics": metrics_collector.get_all_stats(),
        }
    )


@app.get("/api/info")
async def info(
    authorization: Optional[str] = Header(default=None),
    x_api_token: Optional[str] = Header(default=None),
):
    if not _authorized(authorization, x_api_token):
        return _unauthorized()
    transport = "unknown"
    meshtastic_connected = False
    external_connected = False
    if _bridge is not None and getattr(_bridge, "config", None) is not None:
        transport = _bridge.config.external_transport
        handler = getattr(_bridge, "meshtastic_handler", None)
        if handler is not None:
            meshtastic_connected = handler._is_connected.is_set()
        external = getattr(_bridge, "external_handler", None)
        if external is not None and hasattr(external, "_is_connected"):
            external_connected = external._is_connected.is_set()
    return JSONResponse(
        content={
            "name": "Akita Meshtastic Meshcore Bridge",
            "version": __version__,
            "external_transport": transport,
            "meshtastic_connected": meshtastic_connected,
            "external_connected": external_connected,
        }
    )


@app.post("/api/control")
async def control(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_token: Optional[str] = Header(default=None),
):
    if not _authorized(authorization, x_api_token):
        return _unauthorized()
    data = await request.json()
    action = data.get("action")
    if action == "reset_metrics":
        get_metrics().reset()
        return JSONResponse(content={"message": "Metrics reset"})
    return JSONResponse(
        content={"error": f"Unknown action: {action}"},
        status_code=400,
    )
