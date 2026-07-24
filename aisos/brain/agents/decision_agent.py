"""
aisos/brain/agents/decision_agent.py
--------------------------------------
Security decision-maker — the ONLY agent that sets event.decision.

Applies the principle of minimum necessary action: always picks the
least disruptive response that adequately addresses the risk.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aisos.brain.base_agent import BaseAgent
from aisos.core.event import AgentReport, AttackCategory, Decision, Severity

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

logger = logging.getLogger("aisos.agent.decision")


class DecisionAgent(BaseAgent):
    """Translates aggregated risk into a concrete security decision."""

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(name="decision_agent", config=config)

    # ------------------------------------------------------------------
    async def observe(self, event: "SecurityEvent") -> AgentReport:
        risk = event.risk_score
        category = event.attack_category
        observations: list[str] = []
        indicators: list[str] = []
        decisions_taken: list[Decision] = []
        reasoning_parts: list[str] = []

        # ---- Special-case category overrides (highest priority) --------

        if category == AttackCategory.SESSION_HIJACKING:
            decisions_taken.append(Decision.INVALIDATE_SESSION)
            reasoning_parts.append(
                "Session hijacking detected — session invalidated immediately."
            )
            indicators.append("session_hijacking")

        if category == AttackCategory.CREDENTIAL_STUFFING:
            decisions_taken.append(Decision.RATE_LIMIT)
            decisions_taken.append(Decision.REQUIRE_AUTH)
            reasoning_parts.append(
                "Credential stuffing pattern — rate limiting applied and re-authentication required."
            )
            indicators.append("credential_stuffing")

        if category == AttackCategory.DDOS:
            decisions_taken.append(Decision.RATE_LIMIT)
            decisions_taken.append(Decision.ENABLE_SECURITY_MODE)
            reasoning_parts.append(
                "DDoS/high-volume traffic detected — rate limiting engaged and security mode activated."
            )
            indicators.append("ddos")

        # ---- Risk-score tiers ------------------------------------------

        if risk >= 90:
            decisions_taken.append(Decision.BLOCK)
            decisions_taken.append(Decision.GENERATE_INCIDENT)
            reasoning_parts.append(
                f"risk_score={risk:.1f} ≥ 90 — BLOCK and incident generated. "
                f"Signals: {', '.join(self._collect_signal_names(event))}."
            )
            indicators.append("risk_critical")

        elif risk >= 75:
            decisions_taken.append(Decision.BLOCK)
            decisions_taken.append(Decision.NOTIFY_OWNER)
            reasoning_parts.append(
                f"risk_score={risk:.1f} ≥ 75 — BLOCK; owner notified. "
                f"Signals: {', '.join(self._collect_signal_names(event))}."
            )
            indicators.append("risk_high_block")

        elif risk >= 60:
            decisions_taken.append(Decision.CHALLENGE)
            decisions_taken.append(Decision.INCREASE_LOGGING)
            reasoning_parts.append(
                f"risk_score={risk:.1f} ≥ 60 — CHALLENGE issued; logging intensified."
            )
            indicators.append("risk_elevated")

        elif risk >= 40:
            decisions_taken.append(Decision.RATE_LIMIT)
            decisions_taken.append(Decision.MONITOR)
            reasoning_parts.append(
                f"risk_score={risk:.1f} ≥ 40 — RATE_LIMIT applied; event monitored."
            )
            indicators.append("risk_moderate")

        elif risk >= 20:
            decisions_taken.append(Decision.MONITOR)
            reasoning_parts.append(
                f"risk_score={risk:.1f} ≥ 20 — Event flagged for monitoring only."
            )
            indicators.append("risk_low")

        else:
            decisions_taken.append(Decision.ALLOW)
            reasoning_parts.append(
                f"risk_score={risk:.1f} < 20 — No significant threat; request allowed."
            )

        # ---- Deduplicate and pick primary decision ----------------------
        seen: set[Decision] = set()
        unique_decisions: list[Decision] = []
        for d in decisions_taken:
            if d not in seen:
                seen.add(d)
                unique_decisions.append(d)

        primary_decision = unique_decisions[0] if unique_decisions else Decision.ALLOW
        reasoning = " | ".join(reasoning_parts)

        # Mutate event
        event.decision = primary_decision
        event.decision_reasoning = reasoning
        # All decisions become actions_taken
        event.actions_taken = [d.value for d in unique_decisions]

        observations.append(f"Primary decision: {primary_decision.value}")
        observations.append(f"All actions: {[d.value for d in unique_decisions]}")
        observations.append(f"Reasoning: {reasoning}")

        return AgentReport(
            agent_name=self.name,
            observations=observations,
            risk_contribution=0.0,   # DecisionAgent does not add risk
            attack_indicators=indicators,
            recommended_action=primary_decision,
            confidence=min(risk / 100.0, 1.0),
            metadata={
                "primary_decision": primary_decision.value,
                "all_decisions": [d.value for d in unique_decisions],
                "risk_score_at_decision": risk,
                "reasoning": reasoning,
            },
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _collect_signal_names(event: "SecurityEvent") -> list[str]:
        """Gather short signal labels from all agent reports."""
        signals: list[str] = []
        for report in event.agent_reports.values():
            signals.extend(report.attack_indicators[:3])  # top 3 per agent
        return signals or ["no_specific_signals"]
