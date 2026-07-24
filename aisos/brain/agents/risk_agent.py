"""
aisos/brain/agents/risk_agent.py
----------------------------------
Multi-signal risk correlation agent.

Aggregates reports from traffic_agent and threat_agent alongside
memory-based IP reputation and session history to produce a single
authoritative risk_score for the event.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from aisos.brain.base_agent import BaseAgent
from aisos.core.event import AgentReport, AttackCategory, Decision, Severity

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent
    from aisos.memory.store import MemoryStore

logger = logging.getLogger("aisos.agent.risk")

# ---------------------------------------------------------------------------
# Weights (must sum to 1.0)
# ---------------------------------------------------------------------------
W_THREAT = 0.40
W_TRAFFIC = 0.20
W_IP_REP = 0.20
W_SESSION = 0.10
W_HISTORY = 0.10


def _score_to_severity(score: float) -> Severity:
    if score <= 20:
        return Severity.INFO
    if score <= 40:
        return Severity.LOW
    if score <= 60:
        return Severity.MEDIUM
    if score <= 80:
        return Severity.HIGH
    return Severity.CRITICAL


class RiskAgent(BaseAgent):
    """Correlates all available signals into a single risk score."""

    def __init__(self, memory_store: "MemoryStore", config: dict | None = None) -> None:
        super().__init__(name="risk_agent", config=config)
        self._memory = memory_store

    # ------------------------------------------------------------------
    async def observe(self, event: "SecurityEvent") -> AgentReport:
        observations: list[str] = []
        indicators: list[str] = []

        # 1. Collect agent-reported risk contributions
        threat_risk: float = 0.0
        traffic_risk: float = 0.0

        if "threat_agent" in event.agent_reports:
            threat_risk = event.agent_reports["threat_agent"].risk_contribution
            if threat_risk > 0:
                observations.append(
                    f"ThreatAgent contribution: {threat_risk:.1f}/100"
                )

        if "traffic_agent" in event.agent_reports:
            traffic_risk = event.agent_reports["traffic_agent"].risk_contribution
            if traffic_risk > 0:
                observations.append(
                    f"TrafficAgent contribution: {traffic_risk:.1f}/100"
                )

        # 2. IP reputation from memory
        ip_risk: float = 0.0
        try:
            ip_risk = self._memory.get_ip_risk(event.source_ip)
            if ip_risk > 0:
                observations.append(
                    f"IP reputation score for {event.source_ip}: {ip_risk:.1f}/100"
                )
                if ip_risk >= 70:
                    indicators.append(f"known_malicious_ip:{event.source_ip}")
        except Exception as exc:
            logger.warning("Could not retrieve IP risk: %s", exc)

        # 3. Session anomaly
        session_risk: float = 0.0
        if event.session_id:
            try:
                session_risk = self._memory.get_session_anomaly_score(event.session_id)
                if session_risk > 0:
                    observations.append(
                        f"Session anomaly score: {session_risk:.1f}/100"
                    )
                    if session_risk >= 60:
                        indicators.append(f"session_anomaly:{event.session_id}")
            except Exception as exc:
                logger.warning("Could not retrieve session anomaly: %s", exc)

        # 4. Historical risk from recent events for this IP
        historical_risk: float = 0.0
        try:
            recent = self._memory.threats.get_by_ip(event.source_ip)
            if recent:
                # Average risk_score of last 5 events from this IP
                scores = [e.get("risk_score", 0) for e in recent[-5:]]
                historical_risk = sum(scores) / len(scores) if scores else 0.0
                if historical_risk > 20:
                    observations.append(
                        f"Historical risk for {event.source_ip}: {historical_risk:.1f}/100"
                    )
        except Exception as exc:
            logger.warning("Could not retrieve historical risk: %s", exc)

        # 5. Weighted aggregation
        risk_score: float = (
            W_THREAT * threat_risk
            + W_TRAFFIC * traffic_risk
            + W_IP_REP * ip_risk
            + W_SESSION * session_risk
            + W_HISTORY * historical_risk
        )
        risk_score = min(round(risk_score, 2), 100.0)

        # 6. Derive severity
        severity = _score_to_severity(risk_score)

        # Mutate the event directly so downstream agents see updated values
        event.risk_score = risk_score
        event.severity = severity

        observations.append(
            f"Aggregated risk_score={risk_score:.1f} → severity={severity.value}"
        )

        confidence = min(risk_score / 100.0, 1.0)

        return AgentReport(
            agent_name=self.name,
            observations=observations,
            risk_contribution=risk_score,
            attack_indicators=indicators,
            recommended_action=None,  # RiskAgent does NOT recommend actions
            confidence=confidence,
            metadata={
                "threat_risk": threat_risk,
                "traffic_risk": traffic_risk,
                "ip_risk": ip_risk,
                "session_risk": session_risk,
                "historical_risk": historical_risk,
                "weights": {
                    "threat": W_THREAT,
                    "traffic": W_TRAFFIC,
                    "ip_reputation": W_IP_REP,
                    "session": W_SESSION,
                    "history": W_HISTORY,
                },
            },
        )
