"""
aisos/adapters/fastapi.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
FastAPI / Starlette ASGI Middleware for AI SOS.

Passively observes both INBOUND requests and OUTBOUND responses.
Implements the Response Validation Layer:
  - If request is blocked before backend: Returns 403/429 JSON response.
  - If request passed to backend: Intercepts response stream, inspects outgoing payload,
    and sanitizes or blocks unsafe responses containing leaked secrets, PII, or system prompt leaks.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING, Callable

from aisos.core.event import Decision

if TYPE_CHECKING:
    from aisos.core.engine import SecurityEngine


class AISOSFastAPIMiddleware:
    """
    ASGI Middleware for FastAPI and Starlette (Bidirectional Request/Response Layer).

    Usage::

        from aisos import security
        app = FastAPI()
        security.attach(app)
    """

    def __init__(self, app: Callable, engine: "SecurityEngine") -> None:
        self.app = app
        self.engine = engine

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract inbound request metadata
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        raw_qs = scope.get("query_string", b"").decode("utf-8", errors="ignore")
        query_string = urllib.parse.unquote(raw_qs)
        headers = dict(
            (k.decode("utf-8", errors="ignore").lower(), v.decode("utf-8", errors="ignore"))
            for k, v in scope.get("headers", [])
        )

        client = scope.get("client")
        source_ip = client[0] if client else "127.0.0.1"

        if "x-forwarded-for" in headers:
            source_ip = headers["x-forwarded-for"].split(",")[0].strip()

        query_params = {}
        if query_string:
            for pair in query_string.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    query_params[k] = v

        # Read request body non-destructively
        body_bytes = b""
        more_body = True
        received_messages = []

        while more_body:
            message = await receive()
            received_messages.append(message)
            if message["type"] == "http.request":
                body_bytes += message.get("body", b"")
                more_body = message.get("more_body", False)

        async def replay_receive():
            if received_messages:
                return received_messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        # Stage 1-10 Inbound Request Evaluation
        inbound_event = await self.engine.process_request(
            {
                "method": method,
                "path": path,
                "source_ip": source_ip,
                "headers": headers,
                "body": body_bytes.decode("utf-8", errors="ignore") if body_bytes else "",
                "query_params": query_params,
            }
        )

        # Inbound Defensive Action
        if inbound_event.decision == Decision.BLOCK:
            response_body = json.dumps(
                {
                    "error": "Forbidden",
                    "message": "Request blocked by AI SOS Adaptive Security Layer",
                    "event_id": inbound_event.id,
                    "risk_score": inbound_event.risk_score,
                }
            ).encode("utf-8")

            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"x-aisos-decision", b"block"),
                        (b"x-aisos-risk", str(inbound_event.risk_score).encode("utf-8")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": response_body})
            return

        elif inbound_event.decision == Decision.RATE_LIMIT:
            response_body = json.dumps(
                {
                    "error": "Too Many Requests",
                    "message": "Rate limit imposed by AI SOS Adaptive Security Layer",
                    "event_id": inbound_event.id,
                }
            ).encode("utf-8")

            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"retry-after", b"60"),
                        (b"x-aisos-decision", b"rate_limit"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": response_body})
            return

        # Response Stream Interception (Outbound Response Validation Layer)
        response_status = 200
        response_headers = []
        response_body_chunks = []

        async def wrapping_send(message: dict) -> None:
            nonlocal response_status, response_headers
            if message["type"] == "http.response.start":
                response_status = message.get("status", 200)
                response_headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                chunk = message.get("body", b"")
                if chunk:
                    response_body_chunks.append(chunk)

                # Final chunk reached
                if not message.get("more_body", False):
                    full_resp_bytes = b"".join(response_body_chunks)
                    full_resp_text = full_resp_bytes.decode("utf-8", errors="ignore")

                    # Process through Response Validation Layer
                    outbound_event = await self.engine.process_response(
                        inbound_event=inbound_event,
                        status_code=response_status,
                        headers=dict(
                            (k.decode("utf-8", errors="ignore").lower(), v.decode("utf-8", errors="ignore"))
                            for k, v in response_headers
                        ),
                        body=full_resp_text,
                    )

                    # If response contains leaked secrets or critical threat, block/sanitize
                    if outbound_event.decision == Decision.BLOCK:
                        blocked_resp = json.dumps(
                            {
                                "error": "Security Blocked Response",
                                "message": "Backend response intercepted by AI SOS (sensitive data leakage prevented)",
                                "event_id": outbound_event.id,
                            }
                        ).encode("utf-8")

                        await send(
                            {
                                "type": "http.response.start",
                                "status": 403,
                                "headers": [(b"content-type", b"application/json")],
                            }
                        )
                        await send({"type": "http.response.body", "body": blocked_resp})
                        return

                    elif "sanitized_body" in outbound_event.raw_data:
                        sanitized_bytes = outbound_event.raw_data["sanitized_body"].encode("utf-8")
                        await send({"type": "http.response.start", "status": response_status, "headers": response_headers})
                        await send({"type": "http.response.body", "body": sanitized_bytes})
                        return

                    # Normal safe response path
                    await send({"type": "http.response.start", "status": response_status, "headers": response_headers})
                    await send({"type": "http.response.body", "body": full_resp_bytes})

        await self.app(scope, replay_receive, wrapping_send)
