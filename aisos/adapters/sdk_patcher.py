"""
aisos/adapters/sdk_patcher.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SDK Auto-Patcher for AI SOS.

Passively patches AI & HTTP client SDKs (`openai`, `anthropic`, `httpx`, `requests`, `mcp`)
so that every prompt, completion, tool call, or API call becomes an observed event
without requiring developers to rewrite their application code around custom SDK wrappers.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import sys
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from aisos.core.engine import SecurityEngine

logger = logging.getLogger("aisos.sdk_patcher")

_PATCHED_TARGETS: set[str] = set()


def auto_patch_all(engine: SecurityEngine) -> list[str]:
    """Auto-detect and patch all supported installed SDKs."""
    patched = []
    if patch_openai(engine):
        patched.append("openai")
    if patch_anthropic(engine):
        patched.append("anthropic")
    if patch_httpx(engine):
        patched.append("httpx")
    if patch_requests(engine):
        patched.append("requests")
    return patched


def patch_openai(engine: SecurityEngine) -> bool:
    """Passively patch OpenAI Python SDK (`openai`)."""
    if "openai" in _PATCHED_TARGETS:
        return True

    try:
        import openai

        # Patch sync chat completions create
        if hasattr(openai, "resources") and hasattr(openai.resources, "chat"):
            _patch_openai_chat_completions(openai.resources.chat.Completions, engine)
        elif hasattr(openai, "ChatCompletion"):
            _patch_openai_legacy(openai.ChatCompletion, engine)

        _PATCHED_TARGETS.add("openai")
        logger.info("AI SOS: OpenAI SDK passively attached")
        return True
    except ImportError:
        return False
    except Exception as exc:
        logger.warning("AI SOS: Failed to patch OpenAI SDK: %s", exc)
        return False


def _patch_openai_chat_completions(completions_cls: Any, engine: SecurityEngine) -> None:
    original_create = completions_cls.create
    original_async_create = getattr(completions_cls, "async_create", None)

    @functools.wraps(original_create)
    def patched_create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        prompt_text = _extract_messages_text(messages)

        # Record prompt event synchronously / via loop
        _dispatch_ai_event(engine, prompt_text, kwargs)

        return original_create(*args, **kwargs)

    completions_cls.create = patched_create


def _patch_openai_legacy(chat_comp: Any, engine: SecurityEngine) -> None:
    original_create = chat_comp.create

    @functools.wraps(original_create)
    def patched_create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        prompt_text = _extract_messages_text(messages)

        _dispatch_ai_event(engine, prompt_text, kwargs)
        return original_create(*args, **kwargs)

    chat_comp.create = patched_create


def patch_anthropic(engine: SecurityEngine) -> bool:
    """Passively patch Anthropic Python SDK (`anthropic`)."""
    if "anthropic" in _PATCHED_TARGETS:
        return True

    try:
        import anthropic

        if hasattr(anthropic, "resources") and hasattr(anthropic.resources, "messages"):
            original_create = anthropic.resources.messages.Messages.create

            @functools.wraps(original_create)
            def patched_create(*args: Any, **kwargs: Any) -> Any:
                messages = kwargs.get("messages", [])
                prompt_text = _extract_messages_text(messages)
                _dispatch_ai_event(engine, prompt_text, kwargs)
                return original_create(*args, **kwargs)

            anthropic.resources.messages.Messages.create = patched_create

        _PATCHED_TARGETS.add("anthropic")
        logger.info("AI SOS: Anthropic SDK passively attached")
        return True
    except ImportError:
        return False
    except Exception as exc:
        logger.warning("AI SOS: Failed to patch Anthropic SDK: %s", exc)
        return False


def patch_httpx(engine: SecurityEngine) -> bool:
    """Passively patch HTTPX client (`httpx`)."""
    if "httpx" in _PATCHED_TARGETS:
        return True

    try:
        import httpx

        original_send = httpx.AsyncClient.send

        @functools.wraps(original_send)
        async def patched_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
            url_str = str(request.url)
            method = request.method

            # Process event in background
            try:
                asyncio.create_task(
                    engine.process_request(
                        {
                            "method": method,
                            "path": url_str,
                            "headers": dict(request.headers),
                        }
                    )
                )
            except Exception:
                pass

            return await original_send(self, request, *args, **kwargs)

        httpx.AsyncClient.send = patched_send
        _PATCHED_TARGETS.add("httpx")
        logger.info("AI SOS: HTTPX client passively attached")
        return True
    except ImportError:
        return False
    except Exception as exc:
        logger.warning("AI SOS: Failed to patch HTTPX client: %s", exc)
        return False


def patch_requests(engine: SecurityEngine) -> bool:
    """Passively patch requests library (`requests`)."""
    if "requests" in _PATCHED_TARGETS:
        return True

    try:
        import requests

        original_send = requests.Session.send

        @functools.wraps(original_send)
        def patched_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
            url_str = str(request.url)
            method = request.method

            _dispatch_request_event(engine, method, url_str)
            return original_send(self, request, *args, **kwargs)

        requests.Session.send = patched_send
        _PATCHED_TARGETS.add("requests")
        logger.info("AI SOS: Requests library passively attached")
        return True
    except ImportError:
        return False
    except Exception as exc:
        logger.warning("AI SOS: Failed to patch requests library: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_messages_text(messages: list) -> str:
    parts = []
    for msg in messages:
        if isinstance(msg, dict):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        parts.append(str(item["text"]))
        elif hasattr(msg, "content"):
            parts.append(str(msg.content))
    return "\n".join(parts)


def _dispatch_ai_event(engine: SecurityEngine, prompt: str, context: dict) -> None:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(engine.process_ai_prompt(prompt=prompt, context=context))
        else:
            loop.run_until_complete(engine.process_ai_prompt(prompt=prompt, context=context))
    except Exception:
        pass


def _dispatch_request_event(engine: SecurityEngine, method: str, path: str) -> None:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(engine.process_request({"method": method, "path": path}))
        else:
            loop.run_until_complete(engine.process_request({"method": method, "path": path}))
    except Exception:
        pass
