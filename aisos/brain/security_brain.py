"""
aisos/brain/security_brain.py
-------------------------------
Orchestrates all 5 security agents in a deterministic pipeline:

  TrafficAgent → ThreatAgent → RiskAgent → DecisionAgent → NotificationAgent

Each agent adds its AgentReport to event.agent_reports.
The SecurityBrain also maintains a global threat_level based on recent events.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import TYPE_CHECKING

from aisos.brain.agents import (
    DecisionAgent,
    NotificationAgent,
    RiskAgent,
    ThreatAgent,
    TrafficAgent,
)
from aisos.core.event import AttackCategory, Decision, SecurityEvent, Severity

if TYPE_CHECKING:
    from aisos.memory.store import MemoryStore

logger = logging.getLogger("aisos.brain")

# Threat level thresholds (average risk of last N events)
_THREAT_LEVEL_THRESHOLDS = [
    (80, "critical"),
    (60, "high"),
    (40, "elevated"),
    (20, "guarded"),
    (0,  "low"),
]

_TRIGGER_NOTIFY: frozenset[Decision] = frozenset({
    Decision.BLOCK,
    Decision.ESCALATE,
    Decision.GENERATE_INCIDENT,
    Decision.NOTIFY_OWNER,
})


class SecurityBrain:
    """
    Central orchestrator for the AI-SOS multi-agent security system.

    Usage::

        brain = SecurityBrain(config=cfg, memory_store=store)
        processed_event = await brain.process(event)
    """

    def __init__(self, config: dict, memory_store: "MemoryStore") -> None:
        self.config = config
        self.memory_store = memory_store

        self.agents = {
            "traffic": TrafficAgent(config=config.get("agents", {}).get("traffic", {})),
            "threat": ThreatAgent(config=config.get("agents", {}).get("threat", {})),
            "risk": RiskAgent(
                memory_store=memory_store,
                config=config.get("agents", {}).get("risk", {}),
            ),
            "decision": DecisionAgent(config=config.get("agents", {}).get("decision", {})),
            "notification": NotificationAgent(
                config={
                    "notifications": config.get("notifications", {}),
                    **config.get("agents", {}).get("notification", {}),
                }
            ),
        }

        self.cycle_count: int = 0
        self.threat_level: str = "low"
        # Keep rolling window of recent risk scores for threat_level calculation
        self._recent_risk_scores: deque[float] = deque(
            maxlen=config.get("threat_level_window", 50)
        )

    # ------------------------------------------------------------------
    # Primary processing pipeline
    # ------------------------------------------------------------------

    async def process(self, event: SecurityEvent) -> SecurityEvent:
        """
        Run the full agent pipeline on a SecurityEvent.

        Pipeline
        --------
        1. TrafficAgent  — HTTP pattern analysis
        2. ThreatAgent   — Attack pattern classification
        3. RiskAgent     — Multi-signal risk aggregation (mutates event.risk_score / severity)
        4. DecisionAgent — Decision making (mutates event.decision / decision_reasoning)
        5. NotificationAgent — Alert dispatch (only if decision warrants it)

        Returns the mutated SecurityEvent.
        """
        self.cycle_count += 1
        logger.debug("Brain cycle #%d | event=%s", self.cycle_count, event.id)

        # --- Stage 1: Traffic analysis ---
        try:
            traffic_report = await self.agents["traffic"].analyze(event)
            event.agent_reports["traffic_agent"] = traffic_report
            logger.debug("Traffic risk: %.1f", traffic_report.risk_contribution)
        except Exception as exc:
            logger.error("TrafficAgent failed: %s", exc)

        # --- Stage 2: Threat classification ---
        try:
            threat_report = await self.agents["threat"].analyze(event)
            event.agent_reports["threat_agent"] = threat_report
            # Propagate primary category to event if not already set
            if (
                event.attack_category == AttackCategory.NONE
                and threat_report.metadata.get("primary_category")
            ):
                try:
                    event.attack_category = AttackCategory(
                        threat_report.metadata["primary_category"]
                    )
                except ValueError:
                    pass
            logger.debug("Threat risk: %.1f | category: %s",
                         threat_report.risk_contribution,
                         event.attack_category.value)
        except Exception as exc:
            logger.error("ThreatAgent failed: %s", exc)

        # --- Stage 3: Risk aggregation (mutates event.risk_score + event.severity) ---
        try:
            risk_report = await self.agents["risk"].analyze(event)
            event.agent_reports["risk_agent"] = risk_report
            logger.debug("Aggregated risk_score: %.1f | severity: %s",
                         event.risk_score, event.severity.value)
        except Exception as exc:
            logger.error("RiskAgent failed: %s", exc)

        # --- Stage 4: Decision (mutates event.decision + event.decision_reasoning) ---
        try:
            decision_report = await self.agents["decision"].analyze(event)
            event.agent_reports["decision_agent"] = decision_report
            logger.info(
                "Decision: %s | reasoning: %s",
                event.decision.value if event.decision else "NONE",
                event.decision_reasoning[:120],
            )
        except Exception as exc:
            logger.error("DecisionAgent failed: %s", exc)

        # --- Stage 5: Notification (conditional) ---
        if event.decision in _TRIGGER_NOTIFY:
            try:
                notif_report = await self.agents["notification"].analyze(event)
                event.agent_reports["notification_agent"] = notif_report
            except Exception as exc:
                logger.error("NotificationAgent failed: %s", exc)

        # --- Update memory ---
        try:
            self.memory_store.update_from_event(event)
        except Exception as exc:
            logger.error("MemoryStore update failed: %s", exc)

        # --- Update threat level ---
        self._recent_risk_scores.append(event.risk_score)
        self.update_threat_level(list(self._recent_risk_scores))

        return event

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_agent_statuses(self) -> list[dict]:
        return [agent.get_status() for agent in self.agents.values()]

    def get_threat_level(self) -> str:
        return self.threat_level

    def update_threat_level(self, recent_scores: list[float]) -> None:
        """Recompute threat_level from a list of recent risk scores."""
        if not recent_scores:
            self.threat_level = "low"
            return
        avg = sum(recent_scores) / len(recent_scores)
        for threshold, level in _THREAT_LEVEL_THRESHOLDS:
            if avg >= threshold:
                self.threat_level = level
                break

    def get_stats(self) -> dict:
        """Return a combined stats dict for dashboards."""
        return {
            "cycle_count": self.cycle_count,
            "threat_level": self.threat_level,
            "agents": self.get_agent_statuses(),
            "memory": self.memory_store.get_stats(),
        }
