import asyncio
import json
from datetime import datetime
from typing import Set
from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events to all connected clients."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.event_history: list = []  # Last 500 events
        self.max_history = 500

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection and send event history."""
        await websocket.accept()
        self.active_connections.add(websocket)
        # Send last 50 events on connect so new clients get context
        if self.event_history:
            await websocket.send_text(json.dumps({
                "type": "history",
                "events": self.event_history[-50:]
            }))

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        """Broadcast a message to all active connections, removing dead ones."""
        if not self.active_connections:
            return
        text = json.dumps(message)
        dead = set()
        for ws in self.active_connections:
            try:
                await ws.send_text(text)
            except Exception:
                dead.add(ws)
        self.active_connections -= dead

    async def broadcast_event(self, event_dict: dict):
        """Store event in history and broadcast to all clients."""
        self.event_history.append(event_dict)
        if len(self.event_history) > self.max_history:
            self.event_history.pop(0)
        await self.broadcast({"type": "event", "data": event_dict})

    async def broadcast_metrics(self, metrics: dict):
        """Broadcast live metrics update."""
        await self.broadcast({"type": "metrics", "data": metrics})

    async def broadcast_agent_status(self, statuses: list):
        """Broadcast agent status update."""
        await self.broadcast({"type": "agents", "data": statuses})

    async def broadcast_incident(self, incident: dict):
        """Broadcast a new incident."""
        await self.broadcast({"type": "incident", "data": incident})


manager = ConnectionManager()  # Global singleton
