"""
aisos/core/event.py
~~~~~~~~~~~~~~~~~~~
Core event model — every piece of security intelligence the framework produces
is captured in these dataclasses.  They are intentionally stdlib-only so they
can be imported anywhere without pulling in heavyweight dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid


# ---------------------------------------------------------------------------
# Severity Enum
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Risk severity levels.  Each level maps to a numeric score (0–100)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        """Return numeric score for this severity level."""
        return {
            "info": 0,
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 100,
        }[self.value]

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Derive a Severity from a numeric risk score (0–100)."""
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 45:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        return cls.INFO


# ---------------------------------------------------------------------------
# Attack Category Enum
# ---------------------------------------------------------------------------

class AttackCategory(Enum):
    """Taxonomy of attack types the framework can identify."""

    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    API_ENUMERATION = "api_enumeration"
    CREDENTIAL_STUFFING = "credential_stuffing"
    TOKEN_ABUSE = "token_abuse"
    SESSION_HIJACKING = "session_hijacking"
    DDOS = "ddos"
    BOT_TRAFFIC = "bot_traffic"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    MCP_ABUSE = "mcp_abuse"
    RAG_EXFILTRATION = "rag_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SECRET_DISCOVERY = "secret_discovery"


# ---------------------------------------------------------------------------
# Decision Enum
# ---------------------------------------------------------------------------

class Decision(Enum):
    """Actions the Security Brain can take in response to a threat."""

    ALLOW = "allow"
    MONITOR = "monitor"
    CHALLENGE = "challenge"
    RATE_LIMIT = "rate_limit"
    REQUIRE_AUTH = "require_auth"
    BLOCK = "block"
    INVALIDATE_SESSION = "invalidate_session"
    ROTATE_CREDENTIALS = "rotate_credentials"
    ENABLE_SECURITY_MODE = "enable_security_mode"
    INCREASE_LOGGING = "increase_logging"
    NOTIFY_OWNER = "notify_owner"
    ESCALATE = "escalate"
    GENERATE_INCIDENT = "generate_incident"

    @property
    def is_blocking(self) -> bool:
        """Return True if the decision stops the request from proceeding."""
        return self in {Decision.BLOCK, Decision.INVALIDATE_SESSION, Decision.RATE_LIMIT}

    @property
    def requires_user_action(self) -> bool:
        """Return True if the decision requires some end-user interaction."""
        return self in {Decision.CHALLENGE, Decision.REQUIRE_AUTH}


# ---------------------------------------------------------------------------
# Agent Report
# ---------------------------------------------------------------------------

@dataclass
class AgentReport:
    """Report produced by a single security agent for a specific event."""

    agent_name: str
    observations: list[str] = field(default_factory=list)
    risk_contribution: float = 0.0           # 0.0 – 1.0 contribution to overall risk score
    attack_indicators: list[str] = field(default_factory=list)
    recommended_action: Optional[Decision] = None
    confidence: float = 0.0                  # 0.0 – 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "observations": self.observations,
            "risk_contribution": round(self.risk_contribution, 4),
            "attack_indicators": self.attack_indicators,
            "recommended_action": self.recommended_action.value if self.recommended_action else None,
            "confidence": round(self.confidence, 4),
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Security Event (primary event model)
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """
    Central event model.  Created at the edge of the framework (middleware,
    interceptor, etc.) and progressively enriched as it flows through the
    10-stage pipeline.
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Source context
    source_ip: str = ""
    user_id: Optional[str] = None
    session_id: Optional[str] = None

    # Event type — one of:
    # http_request | ai_prompt | db_query | file_access | tool_call |
    # mcp_request  | rag_query | heartbeat
    event_type: str = ""

    # HTTP fields (populated for http_request events)
    method: str = ""
    path: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    query_params: dict[str, str] = field(default_factory=dict)

    # Raw payload for non-HTTP events (ai_prompt text, db query string, etc.)
    raw_data: dict[str, Any] = field(default_factory=dict)

    # ---------- Threat Analysis (populated by pipeline stages 3-5) ----------
    severity: Severity = Severity.INFO
    confidence: float = 0.0          # 0.0 – 1.0
    risk_score: float = 0.0          # 0.0 – 100.0
    attack_category: AttackCategory = AttackCategory.NONE
    attack_indicators: list[str] = field(default_factory=list)

    # ---------- Brain Output (populated by stage 7) ----------
    decision: Optional[Decision] = None
    decision_reasoning: str = ""
    actions_taken: list[str] = field(default_factory=list)

    # ---------- Per-agent Reports (keyed by agent name) ----------
    agent_reports: dict[str, AgentReport] = field(default_factory=dict)

    # ---------- Geo / Network ----------
    tags: list[str] = field(default_factory=list)
    country: str = "unknown"
    asn: str = ""

    # ---------- Processing metadata ----------
    processing_time_ms: float = 0.0
    pipeline_version: str = "1.0"

    def explain(self) -> dict:
        """
        Explain the decision-making process for this security event.
        Returns a structured dictionary explaining the risk context.
        """
        return {
            "decision": self.decision.value if self.decision else "allow",
            "confidence": round(self.confidence, 2),
            "risk": round(self.risk_score, 1),
            "reasons": list(self.attack_indicators) if self.attack_indicators else ["Normal clean request profile"],
            "policy": "policy-override" if "policy-applied" in self.tags else "adaptive-threat-matrix",
        }

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "source_ip": self.source_ip,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "method": self.method,
            "path": self.path,
            "query_params": self.query_params,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "risk_score": round(self.risk_score, 2),
            "attack_category": self.attack_category.value,
            "attack_indicators": self.attack_indicators,
            "decision": self.decision.value if self.decision else None,
            "explain": self.explain(),
            "decision_reasoning": self.decision_reasoning,
            "actions_taken": self.actions_taken,
            "agent_reports": {k: v.to_dict() for k, v in self.agent_reports.items()},
            "tags": self.tags,
            "country": self.country,
            "asn": self.asn,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "pipeline_version": self.pipeline_version,
        }

    @classmethod
    def from_http(
        cls,
        method: str,
        path: str,
        source_ip: str = "",
        headers: dict | None = None,
        body: Any = None,
        query_params: dict | None = None,
        session_id: str | None = None,
        user_id: str | None = None,
    ) -> "SecurityEvent":
        """Factory: create an HTTP request event."""
        return cls(
            event_type="http_request",
            method=method.upper(),
            path=path,
            source_ip=source_ip,
            headers=headers or {},
            body=body,
            query_params=query_params or {},
            session_id=session_id,
            user_id=user_id,
        )

    @classmethod
    def from_ai_prompt(
        cls,
        prompt: str,
        source_ip: str = "",
        user_id: str | None = None,
        context: dict | None = None,
    ) -> "SecurityEvent":
        """Factory: create an AI prompt event."""
        return cls(
            event_type="ai_prompt",
            source_ip=source_ip,
            user_id=user_id,
            raw_data={"prompt": prompt, "context": context or {}},
        )

    @classmethod
    def from_db_query(
        cls,
        query: str,
        params: list | None = None,
        source_ip: str = "",
        user_id: str | None = None,
    ) -> "SecurityEvent":
        """Factory: create a database query event."""
        return cls(
            event_type="db_query",
            source_ip=source_ip,
            user_id=user_id,
            raw_data={"query": query, "params": params or []},
        )

    @classmethod
    def from_tool_call(
        cls,
        tool_name: str,
        args: dict | None = None,
        source_ip: str = "",
        user_id: str | None = None,
    ) -> "SecurityEvent":
        """Factory: create a tool call event (MCP/agent tool use)."""
        return cls(
            event_type="tool_call",
            source_ip=source_ip,
            user_id=user_id,
            raw_data={"tool_name": tool_name, "args": args or {}},
        )

    @property
    def is_threat(self) -> bool:
        """Return True if this event represents an identified threat."""
        return self.attack_category != AttackCategory.NONE

    @property
    def is_blocked(self) -> bool:
        """Return True if the event's decision blocks the request."""
        return self.decision in (Decision.BLOCK, Decision.INVALIDATE_SESSION)

    @property
    def severity_label(self) -> str:
        return self.severity.value.upper()

    def add_indicator(self, indicator: str) -> None:
        """Thread-safe append to attack_indicators (idempotent)."""
        if indicator not in self.attack_indicators:
            self.attack_indicators.append(indicator)

    def add_tag(self, tag: str) -> None:
        """Append a metadata tag (idempotent)."""
        if tag not in self.tags:
            self.tags.append(tag)

    def set_agent_report(self, report: AgentReport) -> None:
        """Store (or overwrite) an agent's report."""
        self.agent_reports[report.agent_name] = report

    def compute_aggregate_risk(self) -> float:
        """
        Compute a weighted aggregate risk score from all agent reports.
        Returns the score in the 0–100 range and sets self.risk_score.
        """
        if not self.agent_reports:
            return self.risk_score

        total_weight = sum(r.risk_contribution for r in self.agent_reports.values())
        if total_weight == 0:
            return self.risk_score

        weighted = sum(
            r.confidence * r.risk_contribution for r in self.agent_reports.values()
        )
        # Normalise to 0–100
        self.risk_score = (weighted / total_weight) * 100.0
        self.confidence = weighted / total_weight
        return self.risk_score


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    """
    Represents a correlated security incident, potentially grouping multiple
    SecurityEvents that share an attacker IP, session, or attack pattern.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    severity: Severity = Severity.MEDIUM
    attack_category: AttackCategory = AttackCategory.NONE
    source_ip: str = ""

    # Ordered list of {"timestamp": ..., "event_id": ..., "description": ...}
    timeline: list[dict] = field(default_factory=list)

    # High-level indicators of compromise
    indicators: list[str] = field(default_factory=list)

    # Human-readable recommended responses
    recommended_actions: list[str] = field(default_factory=list)

    # IDs of SecurityEvents that contributed to this incident
    related_events: list[str] = field(default_factory=list)

    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolution_notes: str = ""

    def add_event(self, event: "SecurityEvent") -> None:
        """Attach a SecurityEvent to this incident and update the timeline."""
        if event.id not in self.related_events:
            self.related_events.append(event.id)
        self.timeline.append({
            "timestamp": event.timestamp.isoformat() + "Z",
            "event_id": event.id,
            "description": f"{event.event_type} — {event.attack_category.value} "
                           f"(severity={event.severity.value})",
            "path": event.path,
            "method": event.method,
            "decision": event.decision.value if event.decision else None,
        })
        self.updated_at = datetime.utcnow()

    def resolve(self, notes: str = "") -> None:
        """Mark the incident as resolved."""
        self.resolved = True
        self.resolved_at = datetime.utcnow()
        self.resolution_notes = notes
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "created_at": self.created_at.isoformat() + "Z",
            "updated_at": self.updated_at.isoformat() + "Z",
            "severity": self.severity.value,
            "attack_category": self.attack_category.value,
            "source_ip": self.source_ip,
            "timeline": self.timeline,
            "indicators": self.indicators,
            "recommended_actions": self.recommended_actions,
            "related_events": self.related_events,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() + "Z" if self.resolved_at else None,
            "resolution_notes": self.resolution_notes,
        }
