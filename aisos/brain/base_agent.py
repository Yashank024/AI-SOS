"""
aisos/brain/base_agent.py
--------------------------
Abstract base class for all security agents.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent, AgentReport


class AgentStatus(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    PROCESSING = "processing"
    ERROR = "error"
    OFFLINE = "offline"


class BaseAgent(ABC):
    """
    All security agents inherit from BaseAgent.

    The contract:
    - ``observe()``  — implemented by each agent; pure observation, NO decisions.
    - ``analyze()``  — template method; manages state, calls observe, updates counters.
    - ``get_status()`` — returns a dict for health-check / dashboard use.
    """

    def __init__(self, name: str, config: dict | None = None) -> None:
        self.name = name
        self.config: dict = config or {}
        self.status = AgentStatus.IDLE
        self.events_processed: int = 0
        self.threats_found: int = 0
        self.started_at: datetime = datetime.utcnow()
        self._logger = logging.getLogger(f"aisos.agent.{name}")

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def observe(self, event: "SecurityEvent") -> "AgentReport":
        """
        Observe a ``SecurityEvent`` and return an ``AgentReport``.

        **Rules:**
        - Never mutate ``event`` inside ``observe()``.
        - Never set ``event.decision`` here — that is the DecisionAgent's job.
        - Be fast; heavy I/O should be avoided or made async.
        """

    # ------------------------------------------------------------------
    # Template method
    # ------------------------------------------------------------------

    async def analyze(self, event: "SecurityEvent") -> "AgentReport":
        """
        Wraps ``observe()`` with status tracking and counter updates.
        Agents should not override this unless they have a compelling reason.
        """
        self._logger.debug("Analyzing event %s", event.id)
        self.status = AgentStatus.PROCESSING
        try:
            report = await self.observe(event)
            self.events_processed += 1
            if report.risk_contribution > 20:
                self.threats_found += 1
                self._logger.info(
                    "Threat signal from %s: risk_contribution=%.1f",
                    self.name,
                    report.risk_contribution,
                )
            self.status = AgentStatus.ACTIVE
            return report
        except Exception as exc:
            self.status = AgentStatus.ERROR
            self._logger.exception("Agent %s raised an error: %s", self.name, exc)
            raise

    # ------------------------------------------------------------------
    # Health / introspection
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "events_processed": self.events_processed,
            "threats_found": self.threats_found,
            "uptime_seconds": (datetime.utcnow() - self.started_at).total_seconds(),
        }
