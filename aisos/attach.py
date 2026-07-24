"""
aisos/attach.py
~~~~~~~~~~~~~~~~
Zero-Code-Rewrite Integration Engine for AI SOS.

Philosophy:
"Never replace the developer's stack. Silently observe it, protect it,
adapt to threats, and continuously improve through memory and learning
while remaining invisible during normal operation."

Usage:
>>> import aisos
>>> app = FastAPI()
>>> security = aisos.init()
>>> security.attach(app)  # Automatically observes web application & patches AI SDKs!
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from aisos.adapters.django import AISOSDjangoMiddleware
from aisos.adapters.fastapi import AISOSFastAPIMiddleware
from aisos.adapters.flask import AISOSFlaskMiddleware
from aisos.adapters.sdk_patcher import (
    auto_patch_all,
    patch_anthropic,
    patch_httpx,
    patch_openai,
    patch_requests,
)
from aisos.brain.ai_provider import create_ai_provider
from aisos.core.config import Config, load_config
from aisos.core.engine import SecurityEngine

logger = logging.getLogger("aisos.attach")

_GLOBAL_ENGINE: Optional[SecurityEngine] = None


def init(
    config: Optional[Config] = None,
    config_path: Optional[str] = None,
) -> SecurityEngine:
    """
    Initialize the AI SOS Security Engine singleton or new instance.

    Parameters
    ----------
    config : Config, optional
        Pre-constructed Config dataclass.
    config_path : str, optional
        Path to aisos.yaml configuration file.

    Returns
    -------
    SecurityEngine
        Initialized security engine instance.
    """
    global _GLOBAL_ENGINE
    if config is None:
        config = load_config(path=config_path)

    engine = SecurityEngine(config=config)
    _GLOBAL_ENGINE = engine
    return engine


def get_engine() -> SecurityEngine:
    """Return the global default SecurityEngine instance (auto-creating if needed)."""
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        _GLOBAL_ENGINE = init()
    return _GLOBAL_ENGINE


class SecurityContext:
    """
    User-facing interface wrapping the SecurityEngine.

    Provides `.attach(target)` and `.enable_ai(...)`.
    """

    def __init__(self, engine: SecurityEngine) -> None:
        self.engine = engine

    def attach(self, target: Any = None) -> list[str]:
        """
        Attach AI SOS to an application or SDK target.

        Supports:
          - FastAPI / Starlette apps
          - Flask apps
          - Django apps
          - String module names ("openai", "anthropic", "httpx", "requests", "all")
          - Default None: Auto-patches all detected SDKs in the environment.
        """
        attached: list[str] = []

        if target is None or target == "all":
            # Auto-patch all available SDKs
            patched = auto_patch_all(self.engine)
            attached.extend(patched)
            logger.info("AI SOS attached to environment SDKs: %s", patched)
            return attached

        # 1. FastAPI / Starlette
        if hasattr(target, "add_middleware"):
            target.add_middleware(AISOSFastAPIMiddleware, engine=self.engine)
            attached.append("fastapi/starlette")
            logger.info("AI SOS: attached FastAPI/Starlette middleware")

        # 2. Flask
        elif hasattr(target, "before_request"):
            AISOSFlaskMiddleware(target, self.engine)
            attached.append("flask")
            logger.info("AI SOS: attached Flask middleware")

        # 3. Django
        elif hasattr(target, "META") or (isinstance(target, str) and target.lower() == "django"):
            AISOSDjangoMiddleware.set_engine(self.engine)
            attached.append("django")
            logger.info("AI SOS: attached Django middleware")

        # 4. Explicit SDK names
        elif isinstance(target, str):
            t_lower = target.lower()
            if t_lower == "openai":
                if patch_openai(self.engine):
                    attached.append("openai")
            elif t_lower == "anthropic":
                if patch_anthropic(self.engine):
                    attached.append("anthropic")
            elif t_lower == "httpx":
                if patch_httpx(self.engine):
                    attached.append("httpx")
            elif t_lower == "requests":
                if patch_requests(self.engine):
                    attached.append("requests")

        # Always ensure global SDK patchers are active
        sdk_patched = auto_patch_all(self.engine)
        for p in sdk_patched:
            if p not in attached:
                attached.append(p)

        return attached

    def enable_ai(
        self,
        provider: str = "OpenAI",
        api_key: str = "",
        model: str = "",
        base_url: str = "",
    ) -> None:
        """
        Optionally enable AI-driven threat reasoning for SecurityBrain.

        Parameters
        ----------
        provider : str
            "OpenAI", "OpenRouter", "Anthropic", or "Ollama"
        api_key : str
            API Key for the provider.
        model : str
            Model identifier (e.g. "gpt-4o-mini", "claude-3-haiku").
        base_url : str, optional
            Custom base API URL.
        """
        ai_provider = create_ai_provider(
            provider_name=provider,
            api_key=api_key,
            model=model,
            base_url=base_url,
        )
        self.engine.set_ai_provider(ai_provider)
        logger.info("AI SOS: Enabled AI threat reasoning with provider '%s'", provider)


def attach(target: Any = None) -> list[str]:
    """Top-level convenience shortcut to attach default global security engine."""
    engine = get_engine()
    ctx = SecurityContext(engine)
    return ctx.attach(target)


def enable_ai(
    provider: str = "OpenAI",
    api_key: str = "",
    model: str = "",
    base_url: str = "",
) -> None:
    """Top-level shortcut to enable AI threat reasoning on default global engine."""
    engine = get_engine()
    ctx = SecurityContext(engine)
    ctx.enable_ai(provider=provider, api_key=api_key, model=model, base_url=base_url)
