"""
aisos/brain/agents/notification_agent.py
------------------------------------------
Alert dispatch agent.

Triggered when event.decision is one of:
  BLOCK | ESCALATE | GENERATE_INCIDENT | NOTIFY_OWNER

Supports
--------
- Email (mock log)
- Discord webhook (real httpx POST with rich embed)
- Slack webhook (real httpx POST with attachments)

Rate limiting: max 10 notifications / 60 seconds to prevent flooding.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

import httpx

from aisos.brain.base_agent import BaseAgent
from aisos.core.event import AgentReport, Decision, Severity

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

logger = logging.getLogger("aisos.agent.notification")

# Decisions that trigger notifications
NOTIFY_DECISIONS: frozenset[Decision] = frozenset({
    Decision.BLOCK,
    Decision.ESCALATE,
    Decision.GENERATE_INCIDENT,
    Decision.NOTIFY_OWNER,
})

# Severity → Discord embed colour (decimal int)
SEVERITY_COLOURS: dict[Severity, int] = {
    Severity.INFO:     0x3498DB,   # blue
    Severity.LOW:      0x2ECC71,   # green
    Severity.MEDIUM:   0xF39C12,   # orange
    Severity.HIGH:     0xE67E22,   # dark orange
    Severity.CRITICAL: 0xE74C3C,   # red
}

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.INFO:     "ℹ️",
    Severity.LOW:      "🟢",
    Severity.MEDIUM:   "🟡",
    Severity.HIGH:     "🟠",
    Severity.CRITICAL: "🔴",
}


@dataclass
class NotificationConfig:
    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    email_to: Optional[str] = None
    min_severity: Severity = Severity.MEDIUM
    rate_limit_window: int = 60        # seconds
    rate_limit_max: int = 10           # max notifications per window


class _RateLimiter:
    def __init__(self, window: int = 60, limit: int = 10) -> None:
        self._window = window
        self._limit = limit
        self._timestamps: deque[float] = deque()

    def is_allowed(self) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        if len(self._timestamps) >= self._limit:
            return False
        self._timestamps.append(now)
        return True

    @property
    def current_count(self) -> int:
        now = time.monotonic()
        cutoff = now - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        return len(self._timestamps)


class NotificationAgent(BaseAgent):
    """Sends security alerts through configured channels."""

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(name="notification_agent", config=config)
        cfg = self.config.get("notifications", {})
        self._notif_config = NotificationConfig(
            discord_webhook_url=cfg.get("discord_webhook_url"),
            slack_webhook_url=cfg.get("slack_webhook_url"),
            email_to=cfg.get("email_to"),
            min_severity=Severity(cfg.get("min_severity", "MEDIUM")),
            rate_limit_window=cfg.get("rate_limit_window", 60),
            rate_limit_max=cfg.get("rate_limit_max", 10),
        )
        self._rate_limiter = _RateLimiter(
            window=self._notif_config.rate_limit_window,
            limit=self._notif_config.rate_limit_max,
        )

    # ------------------------------------------------------------------
    async def observe(self, event: "SecurityEvent") -> AgentReport:
        """Notification agent only acts when a triggering decision exists."""
        observations: list[str] = []
        sent_channels: list[str] = []

        if event.decision not in NOTIFY_DECISIONS:
            return AgentReport(
                agent_name=self.name,
                observations=["Decision does not require notification."],
                risk_contribution=0.0,
                attack_indicators=[],
                confidence=1.0,
            )

        # Severity gate
        severity_order = list(Severity)
        if severity_order.index(event.severity) < severity_order.index(self._notif_config.min_severity):
            return AgentReport(
                agent_name=self.name,
                observations=[
                    f"Severity {event.severity.value} below notification threshold "
                    f"{self._notif_config.min_severity.value}."
                ],
                risk_contribution=0.0,
                attack_indicators=[],
                confidence=1.0,
            )

        # Rate-limit check
        if not self._rate_limiter.is_allowed():
            observations.append(
                f"Rate limit reached ({self._notif_config.rate_limit_max}/"
                f"{self._notif_config.rate_limit_window}s). Notification suppressed."
            )
            return AgentReport(
                agent_name=self.name,
                observations=observations,
                risk_contribution=0.0,
                attack_indicators=["notification_rate_limited"],
                confidence=1.0,
            )

        # Build message
        summary = self._build_summary(event)

        # Send to channels
        if self._notif_config.discord_webhook_url:
            ok = await self._send_discord(event, summary)
            if ok:
                sent_channels.append("discord")
                observations.append("Discord alert sent.")
            else:
                observations.append("Discord alert FAILED.")

        if self._notif_config.slack_webhook_url:
            ok = await self._send_slack(event, summary)
            if ok:
                sent_channels.append("slack")
                observations.append("Slack alert sent.")
            else:
                observations.append("Slack alert FAILED.")

        if self._notif_config.email_to:
            self._mock_email(event, summary)
            sent_channels.append("email")
            observations.append(f"Email alert logged for {self._notif_config.email_to}.")

        if not sent_channels:
            observations.append("No notification channels configured.")

        return AgentReport(
            agent_name=self.name,
            observations=observations,
            risk_contribution=0.0,
            attack_indicators=[],
            confidence=1.0,
            metadata={
                "channels_notified": sent_channels,
                "rate_limit_remaining": self._notif_config.rate_limit_max - self._rate_limiter.current_count,
            },
        )

    # ------------------------------------------------------------------
    # Main public method (can be called directly without analyze())
    # ------------------------------------------------------------------

    async def notify(self, event: "SecurityEvent", config: Optional[NotificationConfig] = None) -> None:
        """Direct notification trigger — skips BaseAgent analyze() lifecycle."""
        if config:
            self._notif_config = config
            self._rate_limiter = _RateLimiter(config.rate_limit_window, config.rate_limit_max)
        await self.observe(event)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_summary(self, event: "SecurityEvent") -> str:
        emoji = SEVERITY_EMOJI.get(event.severity, "⚠️")
        lines = [
            f"{emoji} **AI-SOS Security Alert** {emoji}",
            f"**Decision:** `{event.decision.value if event.decision else 'NONE'}`",
            f"**Severity:** `{event.severity.value}`",
            f"**Attack Category:** `{event.attack_category.value}`",
            f"**Source IP:** `{event.source_ip}`",
            f"**Path:** `{event.method} {event.path}`",
            f"**Risk Score:** `{event.risk_score:.1f}/100`",
            f"**Event ID:** `{event.id}`",
            f"**Timestamp:** `{event.timestamp.isoformat()}`",
            f"**Reasoning:** {event.decision_reasoning[:300]}",
        ]
        return "\n".join(lines)

    async def _send_discord(self, event: "SecurityEvent", summary: str) -> bool:
        colour = SEVERITY_COLOURS.get(event.severity, 0xCCCCCC)
        payload = {
            "embeds": [{
                "title": f"🚨 Security Alert — {event.severity.value}",
                "description": summary,
                "color": colour,
                "fields": [
                    {"name": "Event ID", "value": event.id, "inline": True},
                    {"name": "Category", "value": event.attack_category.value, "inline": True},
                    {"name": "Decision", "value": event.decision.value if event.decision else "N/A", "inline": True},
                    {"name": "Source IP", "value": event.source_ip, "inline": True},
                    {"name": "Risk Score", "value": f"{event.risk_score:.1f}", "inline": True},
                    {"name": "Country", "value": event.country or "Unknown", "inline": True},
                ],
                "footer": {"text": "AI-SOS Security Framework"},
                "timestamp": event.timestamp.isoformat(),
            }]
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    self._notif_config.discord_webhook_url,  # type: ignore[arg-type]
                    json=payload,
                )
                resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Discord notification failed: %s", exc)
            return False

    async def _send_slack(self, event: "SecurityEvent", summary: str) -> bool:
        colour_map = {
            Severity.INFO: "#3498DB",
            Severity.LOW: "#2ECC71",
            Severity.MEDIUM: "#F39C12",
            Severity.HIGH: "#E67E22",
            Severity.CRITICAL: "#E74C3C",
        }
        colour = colour_map.get(event.severity, "#cccccc")
        payload = {
            "attachments": [{
                "fallback": f"Security Alert: {event.severity.value} — {event.attack_category.value}",
                "color": colour,
                "title": f"🚨 AI-SOS Alert: {event.severity.value} — {event.attack_category.value}",
                "text": summary,
                "fields": [
                    {"title": "Decision", "value": event.decision.value if event.decision else "N/A", "short": True},
                    {"title": "IP", "value": event.source_ip, "short": True},
                    {"title": "Path", "value": f"{event.method} {event.path}", "short": False},
                ],
                "footer": "AI-SOS Security Framework",
                "ts": int(event.timestamp.timestamp()),
            }]
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    self._notif_config.slack_webhook_url,  # type: ignore[arg-type]
                    json=payload,
                )
                resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
            return False

    def _mock_email(self, event: "SecurityEvent", summary: str) -> None:
        logger.warning(
            "[EMAIL MOCK] To: %s | Subject: AI-SOS Alert %s | Body:\n%s",
            self._notif_config.email_to,
            event.id,
            summary,
        )
