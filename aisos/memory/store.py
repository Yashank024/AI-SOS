"""
aisos/memory/store.py
-----------------------
Unified MemoryStore — aggregates all 6 sub-stores into one interface.

All agents and the SecurityBrain interact with memory exclusively through
this class, ensuring a clean separation between agent logic and persistence.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aisos.memory.behaviour_memory import BehaviourMemory
from aisos.memory.ip_reputation import IPReputation
from aisos.memory.pattern_db import PatternDB
from aisos.memory.prompt_memory import PromptMemory
from aisos.memory.session_memory import SessionMemory
from aisos.memory.threat_memory import ThreatMemory

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

logger = logging.getLogger("aisos.memory")


class MemoryStore:
    """
    Central memory aggregator.

    Sub-stores
    ----------
    threats      — rolling threat event log (last 10 k)
    ip_reputation — per-IP EMA reputation scores
    sessions     — active session tracking + anomaly
    prompts      — AI prompt history + injection patterns
    behaviour    — per-user/IP behavioural baseline
    patterns     — learned + seeded detection patterns
    """

    def __init__(self) -> None:
        self.threats = ThreatMemory()
        self.ip_reputation = IPReputation()
        self.sessions = SessionMemory()
        self.prompts = PromptMemory()
        self.behaviour = BehaviourMemory()
        self.patterns = PatternDB()

    # ------------------------------------------------------------------
    # Primary update entry-point (called by SecurityBrain after processing)
    # ------------------------------------------------------------------

    def update_from_event(self, event: "SecurityEvent") -> None:
        """
        Fan out a processed SecurityEvent to all relevant sub-stores.
        Errors in individual sub-stores are caught and logged so a single
        store failure never disrupts the pipeline.
        """
        # Always update IP reputation
        try:
            self.ip_reputation.update(
                event.source_ip,
                event.risk_score,
                event.attack_category,
            )
        except Exception as exc:
            logger.error("ip_reputation.update failed: %s", exc)

        # Session tracking
        if event.session_id:
            try:
                self.sessions.update(event.session_id, event)
            except Exception as exc:
                logger.error("sessions.update failed: %s", exc)

        # AI prompt memory
        if event.event_type == "ai_prompt":
            try:
                self.prompts.record(event)
            except Exception as exc:
                logger.error("prompts.record failed: %s", exc)

        # Threat log (only for events that are actual threats)
        if event.is_threat:
            try:
                self.threats.record(event)
            except Exception as exc:
                logger.error("threats.record failed: %s", exc)

        # Behaviour baseline — always update
        try:
            self.behaviour.update(event)
        except Exception as exc:
            logger.error("behaviour.update failed: %s", exc)

        # Pattern learning — only from confirmed threats
        if event.is_threat:
            try:
                self.patterns.learn(event)
            except Exception as exc:
                logger.error("patterns.learn failed: %s", exc)

    # ------------------------------------------------------------------
    # Convenience accessors used by RiskAgent and others
    # ------------------------------------------------------------------

    def get_ip_risk(self, ip: str) -> float:
        """Return 0–100 reputation score for an IP."""
        return self.ip_reputation.get_score(ip)

    def get_session_anomaly_score(self, session_id: str) -> float:
        """Return 0–100 anomaly score for a session."""
        return self.sessions.get_anomaly_score(session_id)

    def get_recent_events(self, limit: int = 100) -> list[dict]:
        """Return the most recent threat events."""
        return self.threats.get_recent(limit)

    def get_stats(self) -> dict:
        """Summary statistics for dashboards / health endpoints."""
        return {
            "total_threats": self.threats.total,
            "tracked_ips": self.ip_reputation.count,
            "active_sessions": self.sessions.active_count,
            "known_patterns": self.patterns.count,
            "prompt_injection_patterns": self.prompts.pattern_count,
        }
