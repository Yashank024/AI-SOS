"""
aisos/adapters/django.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Django Middleware adapter for AI SOS.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aisos.core.engine import SecurityEngine


class AISOSDjangoMiddleware:
    """
    Django Middleware for AI SOS.

    Usage in settings.py::

        MIDDLEWARE = [
            'aisos.adapters.django.AISOSDjangoMiddleware',
            ...
        ]
    """

    _engine: SecurityEngine | None = None

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response

    @classmethod
    def set_engine(cls, engine: SecurityEngine) -> None:
        cls._engine = engine

    def __call__(self, request: Any) -> Any:
        if self._engine:
            try:
                from django.http import JsonResponse

                source_ip = request.META.get("REMOTE_ADDR", "127.0.0.1")
                method = request.method
                path = request.path

                loop = asyncio.new_event_loop()
                event = loop.run_until_complete(
                    self._engine.process_request(
                        {
                            "method": method,
                            "path": path,
                            "source_ip": source_ip,
                        }
                    )
                )
                loop.close()

                if event.is_blocked:
                    return JsonResponse(
                        {
                            "error": "Forbidden",
                            "message": "Blocked by AI SOS Adaptive Security Layer",
                            "event_id": event.id,
                        },
                        status=403,
                    )
            except Exception:
                pass

        return self.get_response(request)
