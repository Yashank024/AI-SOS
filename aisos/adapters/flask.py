"""
aisos/adapters/flask.py
~~~~~~~~~~~~~~~~~~~~~~~~
Flask WSGI Middleware & Extension adapter for AI SOS.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aisos.core.engine import SecurityEngine


class AISOSFlaskMiddleware:
    """
    Flask Extension / Middleware for AI SOS.

    Usage::

        from aisos import security
        app = Flask(__name__)
        security.attach(app)
    """

    def __init__(self, app: Any = None, engine: "SecurityEngine" = None) -> None:
        self.engine = engine
        if app is not None and engine is not None:
            self.init_app(app, engine)

    def init_app(self, app: Any, engine: "SecurityEngine") -> None:
        self.engine = engine

        @app.before_request
        def _before_request():
            try:
                from flask import jsonify, request

                method = request.method
                path = request.path
                headers = dict(request.headers)
                source_ip = request.remote_addr or "127.0.0.1"

                # Run event processing
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If inside running event loop (e.g. uvicorn/gevent)
                    future = asyncio.run_coroutine_threadsafe(
                        self.engine.process_request(
                            {
                                "method": method,
                                "path": path,
                                "source_ip": source_ip,
                                "headers": headers,
                            }
                        ),
                        loop,
                    )
                    event = future.result(timeout=2.0)
                else:
                    event = loop.run_until_complete(
                        self.engine.process_request(
                            {
                                "method": method,
                                "path": path,
                                "source_ip": source_ip,
                                "headers": headers,
                            }
                        )
                    )

                if event.is_blocked:
                    return (
                        jsonify(
                            {
                                "error": "Forbidden",
                                "message": "Blocked by AI SOS Adaptive Security Layer",
                                "event_id": event.id,
                            }
                        ),
                        403,
                    )
            except Exception:
                pass
            return None
