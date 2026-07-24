import asyncio
import json
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from aisos.dashboard.broadcaster import ConnectionManager
import uvicorn

STATIC_DIR = Path(__file__).parent / "static"


class DashboardServer:
    """FastAPI-based real-time security dashboard server."""

    def __init__(self, engine=None, port: int = 8080):
        self.engine = engine
        self.port = port
        self.app = FastAPI(title="AI SOS Dashboard", docs_url=None)
        self.manager = ConnectionManager()
        self._setup_routes()
        self._setup_static()

    def _setup_routes(self):
        @self.app.get("/")
        async def index():
            index_path = STATIC_DIR / 'index.html'
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding='utf-8'))
            return HTMLResponse("<h1>AI SOS Dashboard</h1><p>Static files not found.</p>")

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await self.manager.connect(websocket)
            try:
                while True:
                    data = await websocket.receive_text()
                    try:
                        msg = json.loads(data)
                        if msg.get('type') == 'ping':
                            await websocket.send_text(json.dumps({'type': 'pong'}))
                    except json.JSONDecodeError:
                        pass
            except WebSocketDisconnect:
                self.manager.disconnect(websocket)

        @self.app.get("/api/status")
        async def status():
            if self.engine:
                return JSONResponse(self.engine.get_status())
            return JSONResponse({"status": "no engine connected"})

        @self.app.get("/api/metrics")
        async def metrics():
            if self.engine:
                return JSONResponse(self.engine.get_metrics())
            return JSONResponse({})

        @self.app.get("/api/events")
        async def events(limit: int = 50):
            return JSONResponse({"events": self.manager.event_history[-limit:]})

        @self.app.get("/api/agents")
        async def agents():
            if self.engine:
                try:
                    return JSONResponse({"agents": self.engine.brain.get_agent_statuses()})
                except AttributeError:
                    pass
            return JSONResponse({"agents": []})

        @self.app.get("/api/incidents")
        async def incidents():
            if self.engine:
                try:
                    return JSONResponse({"incidents": self.engine.memory_store.threats.get_incidents()})
                except AttributeError:
                    pass
            return JSONResponse({"incidents": []})

    def _setup_static(self):
        if STATIC_DIR.exists():
            self.app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    async def broadcast_event(self, event_dict: dict):
        """Called by SecurityEngine when an event is processed."""
        await self.manager.broadcast_event(event_dict)

    async def broadcast_incident(self, incident_dict: dict):
        """Called by SecurityEngine when an incident is created."""
        await self.manager.broadcast_incident(incident_dict)

    async def start_metrics_loop(self):
        """Background task that broadcasts metrics every 2 seconds."""
        while True:
            if self.engine:
                try:
                    metrics = self.engine.get_metrics()
                    await self.manager.broadcast_metrics(metrics)
                    statuses = self.engine.brain.get_agent_statuses()
                    await self.manager.broadcast_agent_status(statuses)
                except Exception:
                    pass
            await asyncio.sleep(2)

    def run(self):
        """Start the dashboard server (blocking)."""
        uvicorn.run(self.app, host="0.0.0.0", port=self.port, log_level="warning")

    async def run_async(self):
        """Start the dashboard server (async)."""
        config = uvicorn.Config(self.app, host="0.0.0.0", port=self.port, log_level="warning")
        server = uvicorn.Server(config)
        await server.serve()
