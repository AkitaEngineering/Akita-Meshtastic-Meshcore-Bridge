# ammb/api_async.py
"""
Async REST API for monitoring and controlling the bridge using FastAPI.
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import logging
from ammb.metrics import get_metrics
from ammb.health import get_health_monitor

app = FastAPI()
logger = logging.getLogger(__name__)

@app.get("/api/health")
async def health():
    health_monitor = get_health_monitor()
    health_data = health_monitor.get_overall_health()
    return JSONResponse(content=health_data)

@app.get("/api/metrics")
async def metrics():
    metrics = get_metrics()
    metrics_data = metrics.get_all_stats()
    return JSONResponse(content=metrics_data)

@app.get("/api/status")
async def status():
    health_monitor = get_health_monitor()
    metrics = get_metrics()
    status = {
        "health": health_monitor.get_overall_health(),
        "metrics": metrics.get_all_stats(),
    }
    return JSONResponse(content=status)

@app.get("/api/info")
async def info():
    # This endpoint should be extended to include async bridge state if needed
    return JSONResponse(content={
        "name": "Akita Meshtastic Meshcore Bridge",
        "version": "1.0.0",
        "external_transport": "async",
    })

@app.post("/api/control")
async def control(request: Request):
    data = await request.json()
    action = data.get("action")
    if action == "reset_metrics":
        metrics = get_metrics()
        metrics.reset()
        return JSONResponse(content={"message": "Metrics reset"})
    return JSONResponse(content={"error": f"Unknown action: {action}"}, status_code=400)
