"""
aisos/core/engine.py
~~~~~~~~~~~~~~~~~~~~~
Main SecurityEngine — the top-level orchestrator for the AI SOS framework.

Responsibilities
----------------
- Initialise all subsystems (MemoryStore, PolicyEngine, ActionEngine,
  SecurityBrain, EventPipeline)
- Provide a clean async API for processing events
- Run a background monitoring loop
- Expose metrics, health status, and plugin registration
- Broadcast processed events to subscribers (WebSocket dashboard, etc.)

Usage (programmatic)
--------------------
>>> from aisos.core.config import load_config
>>> from aisos.core.engine import SecurityEngine
>>> from aisos.core.event import SecurityEvent
>>>
>>> config = load_config()
>>> engine = SecurityEngine(config)
>>> await engine.start()
>>> event = await engine.process_request({"method": "GET", "path": "/admin"})
>>> await engine.stop()
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any, Callable, Optional

from aisos.core.config import Config
from aisos.core.event import AttackCategory, Decision, SecurityEvent, Severity
from aisos.core.logger import SecurityLogger, get_logger
from aisos.core.topology import AdaptiveTopologyManager, SecurityLayer
from aisos.core.capabilities import CapabilityManager
from aisos.brain.ai_provider import AIProvider, DummyOfflineAIProvider, create_ai_provider
from aisos.core.pipeline import (
    EventPipeline,
    _StubActionEngine,
    _StubMemoryStore,
    _StubPolicyEngine,
    _StubSecurityBrain,
)


# ---------------------------------------------------------------------------
# SecurityEngine
# ---------------------------------------------------------------------------

class SecurityEngine:
    """
    Top-level security engine.

    All subsystems are constructed here and wired together. The engine
    exposes a simple async API that higher-level adapters (middleware, CLI,
    dashboard) use to submit events.

    Parameters
    ----------
    config : Config
        Loaded and (optionally) validated configuration object.
    """

    VERSION = "0.2.0"

    def __init__(self, config: Config) -> None:
        self._config = config
        self._started_at: Optional[datetime] = None
        self._running = False
        self._background_task: Optional[asyncio.Task] = None

        # ── Logger ──────────────────────────────────────────────────────────
        self._security_logger = SecurityLogger(
            level=config.log_level,
            log_file=config.log_file,
        )
        self._log = get_logger("engine")

        # ── Topology Manager (Immune System 5-Layer Adaptive Security) ──────
        self._topology = AdaptiveTopologyManager(
            cooldown_seconds=60.0,
            on_layer_change=self._on_layer_transition,
        )

        # ── Capability Manager (Dynamic scanner/feature toggles) ──────────
        self._capabilities = CapabilityManager()
        self._capabilities.update_capabilities(SecurityLayer.LAYER_1_NORMAL)

        # ── Optional AI Provider (Offline default) ─────────────────────────
        self._ai_provider: AIProvider = DummyOfflineAIProvider()

        # ── Subsystems ──────────────────────────────────────────────────────
        self._memory = _StubMemoryStore()
        self._policy = _StubPolicyEngine(config)
        self._actions = _StubActionEngine(self._memory, self._security_logger)
        self._brain = _StubSecurityBrain()

        # ── Pipeline ────────────────────────────────────────────────────────
        self._pipeline = EventPipeline(
            config=config,
            brain=self._brain,
            memory_store=self._memory,
            policy_engine=self._policy,
            action_engine=self._actions,
            logger=self._security_logger,
            engine=self,
        )

        # ── Plugins ─────────────────────────────────────────────────────────
        self._plugins: list[Any] = []

        # ── Subscribers (dashboard WebSocket callbacks, etc.) ────────────────
        self._subscribers: list[Callable] = []

        # ── Metrics accumulators ─────────────────────────────────────────────
        self._total_events: int = 0
        self._threats_detected: int = 0
        self._blocks_issued: int = 0
        self._heartbeat_count: int = 0

    # ------------------------------------------------------------------ #
    # Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """
        Start the Security Engine.

        1. Marks the engine as running.
        2. Starts the background monitoring loop.
        3. Logs the startup event.
        """
        if self._running:
            self._log.warning("Engine.start() called but engine is already running")
            return

        self._running = True
        self._started_at = datetime.utcnow()

        self._security_logger.log_engine_start(
            version=self.VERSION,
            config_path=self._config.source_path,
        )

        # Start background monitoring loop
        self._background_task = asyncio.ensure_future(self._monitoring_loop())

        # Notify plugins
        for plugin in self._plugins:
            if hasattr(plugin, "on_engine_start"):
                try:
                    await _maybe_await(plugin.on_engine_start(self))
                except Exception as exc:  # noqa: BLE001
                    self._security_logger.log_error(
                        f"Plugin '{plugin}' raised during on_engine_start", exc=exc
                    )

        self._log.info("SecurityEngine started successfully")

    async def stop(self) -> None:
        """
        Gracefully shut down the Security Engine.

        1. Signals the monitoring loop to stop.
        2. Waits for the background task to complete (max 5 s).
        3. Notifies plugins.
        4. Logs the shutdown event.
        """
        if not self._running:
            return

        self._running = False

        # Cancel the background monitoring loop
        if self._background_task and not self._background_task.done():
            self._background_task.cancel()
            try:
                await asyncio.wait_for(self._background_task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        # Notify plugins
        for plugin in self._plugins:
            if hasattr(plugin, "on_engine_stop"):
                try:
                    await _maybe_await(plugin.on_engine_stop())
                except Exception as exc:  # noqa: BLE001
                    self._security_logger.log_error(
                        f"Plugin '{plugin}' raised during on_engine_stop", exc=exc
                    )

        self._security_logger.log_engine_stop()
        self._log.info("SecurityEngine stopped")

    # ------------------------------------------------------------------ #
    # Event Processing                                                    #
    # ------------------------------------------------------------------ #

    async def process_event(self, event: SecurityEvent) -> SecurityEvent:
        """
        Main event processing entry point.

        Runs the full 10-stage pipeline and then notifies engine-level
        subscribers.

        Parameters
        ----------
        event : SecurityEvent
            A pre-constructed SecurityEvent (any event_type).

        Returns
        -------
        SecurityEvent
            The fully enriched, decided event.
        """
        processed = await self._pipeline.process(event)

        # Update engine-level counters
        self._total_events += 1
        if processed.is_threat:
            self._threats_detected += 1
        if processed.is_blocked:
            self._blocks_issued += 1

        # Feed metrics to Adaptive Topology Manager (Layer 1..5)
        self._topology.record_event_metrics(processed.risk_score, processed.is_threat)

        # Invoke engine-level subscribers
        await self._on_event_processed(processed)

        return processed

    def attach(self, target: Any = None) -> list[str]:
        """Convenience method to attach engine to an app or SDK."""
        from aisos.attach import SecurityContext
        ctx = SecurityContext(self)
        return ctx.attach(target)

    def enable_ai(
        self,
        provider: str = "OpenAI",
        api_key: str = "",
        model: str = "",
        base_url: str = "",
    ) -> None:
        """Enable optional AI-driven threat reasoning for SecurityBrain."""
        ai_prov = create_ai_provider(
            provider_name=provider,
            api_key=api_key,
            model=model,
            base_url=base_url,
        )
        self.set_ai_provider(ai_prov)

    def set_ai_provider(self, provider: AIProvider) -> None:
        """Set the active AI provider for LLM threat reasoning."""
        self._ai_provider = provider
        self._log.info("AI Provider set to: %s", type(provider).__name__)

    def _on_layer_transition(self, old_layer: SecurityLayer, new_layer: SecurityLayer) -> None:
        """Internal callback when topology shifts layers."""
        self._log.warning(
            "IMMUNE SYSTEM TOPOLOGY SHIFT: [%s] → [%s]", old_layer.value, new_layer.value
        )
        self._security_logger.log_info(
            f"Adaptive Security Topology transition: {old_layer.value} -> {new_layer.value}"
        )
        # Dynamic capability recalculation
        self._capabilities.update_capabilities(new_layer)

    @property
    def topology(self) -> AdaptiveTopologyManager:
        return self._topology

    @property
    def capabilities(self) -> CapabilityManager:
        return self._capabilities

    @property
    def ai_provider(self) -> AIProvider:
        return self._ai_provider

    async def process_request(self, request_data: dict) -> SecurityEvent:
        """
        Convenience wrapper: create an HTTP request event from a dict and
        process it through the full pipeline.

        Expected keys in request_data
        ------------------------------
        method       : str  (e.g. "GET", "POST")
        path         : str  (e.g. "/api/users")
        source_ip    : str  (optional)
        headers      : dict (optional)
        body         : any  (optional)
        query_params : dict (optional)
        session_id   : str  (optional)
        user_id      : str  (optional)
        """
        event = SecurityEvent.from_http(
            method=request_data.get("method", "GET"),
            path=request_data.get("path", "/"),
            source_ip=request_data.get("source_ip", ""),
            headers=request_data.get("headers", {}),
            body=request_data.get("body"),
            query_params=request_data.get("query_params", {}),
            session_id=request_data.get("session_id"),
            user_id=request_data.get("user_id"),
        )
        return await self.process_event(event)

    async def process_ai_prompt(
        self, prompt: str, context: dict | None = None
    ) -> SecurityEvent:
        """Convenience: process an AI prompt through the pipeline."""
        event = SecurityEvent.from_ai_prompt(
            prompt=prompt,
            context=context or {},
        )
        return await self.process_event(event)

    async def process_db_query(
        self, query: str, params: list | None = None
    ) -> SecurityEvent:
        """Convenience: process a database query through the pipeline."""
        event = SecurityEvent.from_db_query(query=query, params=params or [])
        return await self.process_event(event)

    async def process_tool_call(
        self, tool_name: str, args: dict | None = None
    ) -> SecurityEvent:
        """Convenience: process an MCP/agent tool call through the pipeline."""
        event = SecurityEvent.from_tool_call(tool_name=tool_name, args=args or {})
        return await self.process_event(event)

    async def process_response(
        self,
        inbound_event: SecurityEvent,
        status_code: int,
        headers: dict,
        body: str,
    ) -> SecurityEvent:
        """Convenience: process outbound response validation through the pipeline."""
        return await self._pipeline.process_response(
            inbound_event=inbound_event,
            status_code=status_code,
            headers=headers,
            body=body,
        )

    # ------------------------------------------------------------------ #
    # Plugin Management                                                   #
    # ------------------------------------------------------------------ #

    def register_plugin(self, plugin: Any) -> None:
        """
        Attach a plugin to the engine.

        Plugins may implement any combination of:
        - on_engine_start(engine)
        - on_engine_stop()
        - on_event_processed(event)
        - process_event(event) → event  (interceptor)
        """
        if plugin not in self._plugins:
            self._plugins.append(plugin)
            plugin_name = getattr(plugin, "name", type(plugin).__name__)
            self._security_logger.log_plugin_registered(plugin_name)
            self._log.info("Plugin registered: %s", plugin_name)

    def get_plugins(self) -> list:
        """Return the list of registered plugins."""
        return list(self._plugins)

    # ------------------------------------------------------------------ #
    # Subscriber Management                                               #
    # ------------------------------------------------------------------ #

    def subscribe(self, callback: Callable) -> None:
        """
        Subscribe to processed events.

        The callback will be called with a single SecurityEvent argument
        after every event that completes the pipeline.  Async callbacks are
        supported.
        """
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable) -> None:
        """Unsubscribe a previously registered callback."""
        self._subscribers = [s for s in self._subscribers if s is not callback]

    # ------------------------------------------------------------------ #
    # Status & Metrics                                                    #
    # ------------------------------------------------------------------ #

    def get_status(self) -> dict:
        """
        Return a dictionary describing the current engine state.

        Suitable for health-check endpoints and the dashboard API.
        """
        uptime_seconds: Optional[float] = None
        if self._started_at:
            uptime_seconds = (datetime.utcnow() - self._started_at).total_seconds()

        return {
            "running": self._running,
            "version": self.VERSION,
            "started_at": self._started_at.isoformat() + "Z" if self._started_at else None,
            "uptime_seconds": uptime_seconds,
            "config_source": self._config.source_path,
            "monitoring_enabled": self._config.monitoring,
            "log_level": self._config.log_level,
            "topology": self._topology.get_status(),
            "ai_provider": type(self._ai_provider).__name__,
            "plugins": [
                getattr(p, "name", type(p).__name__) for p in self._plugins
            ],
            "pipeline_stats": self._pipeline.get_stats(),
            "engine_counters": {
                "total_events": self._total_events,
                "threats_detected": self._threats_detected,
                "blocks_issued": self._blocks_issued,
                "heartbeat_count": self._heartbeat_count,
            },
            "agents": {
                "TrafficAgent": "active",
                "ThreatAgent": "active",
                "RiskAgent": "active",
                "SecurityBrain": "active",
                "DecisionAgent": "active",
                "ActionEngine": "active",
            },
        }

    def get_metrics(self) -> dict:
        """
        Return detailed operational metrics.

        Extended version of get_status() — includes rates and ratios.
        """
        status = self.get_status()
        total = max(self._total_events, 1)
        uptime = status.get("uptime_seconds") or 1.0

        return {
            **status,
            "metrics": {
                "threat_detection_rate": round(self._threats_detected / total, 4),
                "block_rate": round(self._blocks_issued / total, 4),
                "events_per_second": round(self._total_events / uptime, 3),
                "threats_per_second": round(self._threats_detected / uptime, 3),
                "false_positive_count": self._pipeline.false_positives,
                "false_positive_rate": round(
                    self._pipeline.false_positives / total, 4
                ),
            },
        }

    # ------------------------------------------------------------------ #
    # Background Monitoring Loop                                          #
    # ------------------------------------------------------------------ #

    async def _monitoring_loop(self) -> None:
        """
        Background coroutine that runs continuously while the engine is active.

        Responsibilities
        ----------------
        - Emit a heartbeat log every 60 seconds
        - Future: active scanning, anomaly detection, threshold alerts
        """
        heartbeat_interval = 60  # seconds
        last_heartbeat = time.monotonic()

        self._log.debug("Background monitoring loop started")

        while self._running:
            try:
                await asyncio.sleep(1)  # 1-second tick

                now = time.monotonic()

                # Heartbeat
                if now - last_heartbeat >= heartbeat_interval:
                    last_heartbeat = now
                    self._heartbeat_count += 1
                    stats = self._pipeline.get_stats()
                    stats["uptime_seconds"] = (
                        (datetime.utcnow() - self._started_at).total_seconds()
                        if self._started_at
                        else 0
                    )
                    self._security_logger.log_heartbeat(stats)

            except asyncio.CancelledError:
                self._log.debug("Monitoring loop cancelled")
                break
            except Exception as exc:  # noqa: BLE001
                self._security_logger.log_error(
                    "Error in monitoring loop", exc=exc
                )
                # Don't crash the loop — keep running
                await asyncio.sleep(5)

        self._log.debug("Background monitoring loop exited")

    # ------------------------------------------------------------------ #
    # Internal hooks                                                      #
    # ------------------------------------------------------------------ #

    async def _on_event_processed(self, event: SecurityEvent) -> None:
        """
        Internal hook: called after every event completes the pipeline.

        1. Invokes plugin on_event_processed hooks.
        2. Notifies engine-level subscribers.
        """
        # Plugin hooks
        for plugin in self._plugins:
            if hasattr(plugin, "on_event_processed"):
                try:
                    await _maybe_await(plugin.on_event_processed(event))
                except Exception as exc:  # noqa: BLE001
                    self._security_logger.log_error(
                        f"Plugin '{plugin}' raised in on_event_processed", exc=exc
                    )

        # Subscriber callbacks
        for callback in self._subscribers:
            try:
                await _maybe_await(callback(event))
            except Exception as exc:  # noqa: BLE001
                self._security_logger.log_error(
                    f"Subscriber raised in on_event_processed", exc=exc
                )

    # ------------------------------------------------------------------ #
    # Properties                                                          #
    # ------------------------------------------------------------------ #

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def pipeline(self) -> EventPipeline:
        """Direct access to the pipeline (for testing / introspection)."""
        return self._pipeline

    @property
    def config(self) -> Config:
        return self._config

    @property
    def security_logger(self) -> SecurityLogger:
        return self._security_logger

    # ------------------------------------------------------------------ #
    # Context manager support                                             #
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "SecurityEngine":
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _maybe_await(result: Any) -> Any:
    """Await *result* if it is a coroutine, otherwise return it directly."""
    if asyncio.iscoroutine(result):
        return await result
    return result
