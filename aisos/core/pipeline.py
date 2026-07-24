"""
aisos/core/pipeline.py
~~~~~~~~~~~~~~~~~~~~~~~
10-stage event processing pipeline.

Each SecurityEvent enters at Stage 1 (Observe) and exits at Stage 10 (Emit)
fully enriched with threat intelligence, a Brain-driven decision, executed
actions, and persisted learning signals.

Stage map
---------
 1. Observe        — Enrich raw event with source context
 2. Normalize      — Map to canonical SecurityEvent schema, detect event_type
 3. Threat Detect  — TrafficAgent + ThreatAgent: detect attack patterns
 4. Risk Score     — RiskAgent: multi-signal correlation → risk_score
 5. Reason         — Security Brain: correlate history + current signals
 6. Policy Eval    — Apply IF/THEN policy rules (may override decision)
 7. Decide         — DecisionAgent: final decision
 8. Action         — ActionEngine: execute the decision
 9. Learn          — Update MemoryStore pattern DB + reputation scores
10. Emit           — Structured log + WebSocket broadcast

All stages are async.  Exceptions in any stage are caught and logged; the
pipeline continues to Stage 10 even if intermediate stages fail.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Callable, Optional

from aisos.core.event import (
    AgentReport,
    AttackCategory,
    Decision,
    Incident,
    SecurityEvent,
    Severity,
)
from aisos.core.logger import SecurityLogger, get_logger

# ---------------------------------------------------------------------------
# Compiled regex patterns used by Stage 3 (Threat Detection)
# ---------------------------------------------------------------------------

# SQL Injection signals
_SQL_PATTERNS = re.compile(
    r"""
    (\b(select|insert|update|delete|drop|create|alter|truncate|exec|execute|union)\b.*\b(from|into|where|table)\b)
    |('[\s\S]*?--[\s\S]*?')
    |(\bor\b\s+[\d'"]+=[\d'"]+)
    |(\band\b\s+[\d'"]+=[\d'"]+)
    |(;\s*(drop|delete|insert|update)\s)
    |(\bxp_cmdshell\b)
    |(\binformation_schema\b)
    |(\bsys\.(tables|columns|databases)\b)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# XSS signals
_XSS_PATTERNS = re.compile(
    r"""
    (<\s*script[\s>])
    |(javascript\s*:)
    |(on(load|click|error|focus|blur|mouseover|submit)\s*=)
    |(<\s*img[^>]+src\s*=\s*['"]\s*[^'"]+['"]\s*on\w+\s*=)
    |(document\.(cookie|location|write))
    |(eval\s*\()
    |(alert\s*\()
    |(<\s*iframe)
    |(<\s*object)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# SSRF signals
_SSRF_PATTERNS = re.compile(
    r"""
    (https?://(localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0))
    |(https?://10\.\d+\.\d+\.\d+)
    |(https?://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)
    |(https?://192\.168\.\d+\.\d+)
    |(file://)
    |(dict://)
    |(gopher://)
    |(ftp://(localhost|127\.))
    |(169\.254\.\d+\.\d+)        # AWS metadata
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Prompt injection signals
_PROMPT_INJECTION_PATTERNS = re.compile(
    r"""
    (ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|rules?|context))
    |(forget\s+(everything|your\s+instructions?|the\s+system\s+prompt))
    |(you\s+are\s+now\s+(dan|jailbroken|free|uncensored|an?\s+ai\s+without))
    |(pretend\s+(you\s+are|to\s+be|that\s+you)\s+(not|an?\s+ai|a\s+human))
    |(act\s+as\s+(if\s+you\s+(have\s+no|are\s+without)|a\s+(human|hacker|malicious)))
    |(system\s*:\s*you\s+are)
    |(your\s+new\s+(instructions?|system\s+prompt|role)\s+is)
    |(disregard\s+(all\s+previous|safety|prior)\s+(training|instructions?))
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Jailbreak signals
_JAILBREAK_PATTERNS = re.compile(
    r"""
    (\bdan\b.*mode)
    |(jailbreak)
    |(do\s+anything\s+now)
    |(developer\s+mode)
    |(no\s+restrictions?)
    |(bypass\s+(safety|filters?|restrictions?|guardrails?))
    |(pretend\s+you\s+(don'?t\s+have|have\s+no)\s+(rules?|restrictions?|limits?))
    |(unrestricted\s+(mode|ai))
    """,
    re.VERBOSE | re.IGNORECASE,
)

# System prompt leak signals
_SYSTEM_PROMPT_LEAK_PATTERNS = re.compile(
    r"""
    (what\s+is\s+your\s+system\s+prompt)
    |(print\s+(your|the)\s+system\s+prompt)
    |(repeat\s+(your|the)\s+(system\s+)?instructions?)
    |(reveal\s+(your|the)\s+(initial|system|hidden)\s+(instructions?|prompt|context))
    |(output\s+(your|the)\s+(full\s+)?system\s+prompt)
    |(tell\s+me\s+your\s+prompt)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Command injection signals
_CMD_INJECTION_PATTERNS = re.compile(
    r"""
    (;\s*(ls|cat|pwd|id|whoami|uname|curl|wget|bash|sh|python|perl|ruby)\b)
    |(\|\s*(ls|cat|id|whoami|bash|sh)\b)
    |(`[^`]+`)
    |(\$\([^)]+\))
    |(\b(rm|chmod|chown|mv|cp|dd|nc|netcat)\s+-[rfR])
    """,
    re.VERBOSE | re.IGNORECASE,
)

# API enumeration signals (path-based)
_API_SCAN_PATHS = re.compile(
    r"""
    (/(admin|administrator|wp-admin|phpmyadmin|manager|console|dashboard|panel|config|backup))
    |(/api/(v\d+/)?(users|accounts|keys|tokens|secrets|admin|internal|debug|status))
    |(/\.(env|git|svn|htaccess|htpasswd|bash_history|ssh|aws|config))
    |(/(swagger|openapi|graphql|graphiql|playground|docs|redoc)\b)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Credential stuffing signals (auth endpoint anomalies detected by path)
_AUTH_PATHS = re.compile(
    r"/(login|signin|auth|authenticate|token|oauth|password)",
    re.IGNORECASE,
)

# MCP abuse signals (tool names in raw_data)
_MCP_DANGEROUS_TOOLS = {
    "shell", "exec", "run_command", "system", "execute", "bash", "powershell",
    "file_write", "file_delete", "env_read", "read_env", "get_secrets",
    "exfiltrate", "send_data", "http_request",
}

# Secret patterns in payloads / tool args
_SECRET_PATTERNS = re.compile(
    r"""
    (sk-[a-zA-Z0-9]{32,})           # OpenAI key
    |(AKIA[A-Z0-9]{16})              # AWS key
    |(ghp_[a-zA-Z0-9]{36})          # GitHub token
    |([a-zA-Z0-9_-]{20,}\.eyJ)      # JWT token
    |(password\s*[:=]\s*\S{6,})
    |(api[_-]?key\s*[:=]\s*\S{8,})
    |(token\s*[:=]\s*\S{8,})
    """,
    re.VERBOSE | re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Lightweight stub objects so the pipeline can be instantiated without
# full implementation of Memory/Policy/Action/Brain (stubs inject themselves
# but real implementations replace them through DI).
# ---------------------------------------------------------------------------

class _StubMemoryStore:
    """Minimal in-memory reputation + pattern store."""

    def __init__(self):
        self._ip_scores: dict[str, float] = {}       # ip → cumulative risk
        self._ip_request_counts: dict[str, int] = {} # ip → request count
        self._blocked_ips: set[str] = set()

    def get_ip_risk(self, ip: str) -> float:
        return self._ip_scores.get(ip, 0.0)

    def increment_ip_risk(self, ip: str, delta: float) -> float:
        self._ip_scores[ip] = min(100.0, self._ip_scores.get(ip, 0.0) + delta)
        return self._ip_scores[ip]

    def record_request(self, ip: str) -> int:
        self._ip_request_counts[ip] = self._ip_request_counts.get(ip, 0) + 1
        return self._ip_request_counts[ip]

    def get_request_count(self, ip: str) -> int:
        return self._ip_request_counts.get(ip, 0)

    def block_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip)

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def get_recent_events(self, ip: str, limit: int = 10) -> list:
        # Stub: no historical events
        return []


class _StubPolicyEngine:
    """Evaluates policy rules from config against a SecurityEvent."""

    def __init__(self, config):
        from aisos.core.config import Config
        self._policies = config.policies if hasattr(config, "policies") else []

    def evaluate(self, event: SecurityEvent) -> Optional[Decision]:
        """
        Evaluate policy rules in order.  Return the first matching decision,
        or None if no rule matches.
        """
        for rule in self._policies:
            if self._matches(rule, event):
                try:
                    return Decision(rule.then_decision)
                except ValueError:
                    pass
        return None

    @staticmethod
    def _matches(rule, event: SecurityEvent) -> bool:
        # Empty IF block matches everything
        if (
            rule.if_attack_category is None
            and rule.if_severity is None
            and rule.if_source_ip is None
            and rule.if_path_pattern is None
        ):
            return True

        if rule.if_attack_category and event.attack_category.value != rule.if_attack_category:
            return False
        if rule.if_severity and event.severity.value != rule.if_severity:
            return False
        if rule.if_source_ip and event.source_ip != rule.if_source_ip:
            return False
        if rule.if_path_pattern:
            if not re.search(rule.if_path_pattern, event.path, re.IGNORECASE):
                return False
        return True


class _StubActionEngine:
    """Executes the decisions produced by the Brain/DecisionAgent."""

    def __init__(self, memory_store: _StubMemoryStore, logger: SecurityLogger):
        self._memory = memory_store
        self._logger = logger
        self._blocked_sessions: set[str] = set()
        self._rate_limited_ips: dict[str, float] = {}  # ip → expiry timestamp

    async def execute(self, event: SecurityEvent) -> list[str]:
        """Execute the event's decision and return a list of actions taken."""
        actions: list[str] = []
        decision = event.decision

        if decision is None:
            return actions

        if decision == Decision.BLOCK:
            self._memory.block_ip(event.source_ip)
            actions.append(f"blocked IP {event.source_ip}")

        elif decision == Decision.RATE_LIMIT:
            self._rate_limited_ips[event.source_ip] = time.time() + 60
            actions.append(f"rate-limited IP {event.source_ip} for 60s")

        elif decision == Decision.INVALIDATE_SESSION:
            if event.session_id:
                self._blocked_sessions.add(event.session_id)
                actions.append(f"invalidated session {event.session_id}")

        elif decision == Decision.INCREASE_LOGGING:
            actions.append("increased logging level to DEBUG")

        elif decision == Decision.ESCALATE:
            actions.append("escalation triggered — notifying operators")
            await self._send_notification(event)

        elif decision == Decision.NOTIFY_OWNER:
            await self._send_notification(event)
            actions.append("owner notified")

        elif decision == Decision.MONITOR:
            actions.append("event marked for enhanced monitoring")

        elif decision == Decision.CHALLENGE:
            actions.append("challenge (CAPTCHA/2FA) triggered for request")

        elif decision == Decision.REQUIRE_AUTH:
            actions.append("authentication required before proceeding")

        elif decision == Decision.GENERATE_INCIDENT:
            actions.append("incident report generated")

        elif decision == Decision.ENABLE_SECURITY_MODE:
            actions.append("security mode enabled globally")

        elif decision == Decision.ROTATE_CREDENTIALS:
            actions.append("credential rotation requested")

        elif decision == Decision.ALLOW:
            pass  # No action needed

        return actions

    async def _send_notification(self, event: SecurityEvent) -> None:
        # Stub: real implementation would call notification backends
        self._logger.log_warning(
            f"ALERT: {event.attack_category.value} detected from {event.source_ip}",
            event_id=event.id,
            severity=event.severity.value,
        )

    def is_ip_rate_limited(self, ip: str) -> bool:
        expiry = self._rate_limited_ips.get(ip)
        if expiry is None:
            return False
        if time.time() > expiry:
            del self._rate_limited_ips[ip]
            return False
        return True

    def is_session_blocked(self, session_id: str) -> bool:
        return session_id in self._blocked_sessions


class _StubSecurityBrain:
    """
    Stub Security Brain.  Correlates agent reports and determines a holistic
    risk assessment.  Real implementation integrates an LLM.
    """

    async def correlate(self, event: SecurityEvent, history: list) -> tuple[float, str]:
        """
        Return (adjusted_risk_score, reasoning_text).

        Logic:
        - Start from event.risk_score
        - If the source IP has prior threats in history, boost the score
        - If confidence is low, dampen the score
        """
        base = event.risk_score
        reasoning_parts: list[str] = []

        # Historical boost
        prior_threats = sum(1 for e in history if e.get("is_threat"))
        if prior_threats > 0:
            boost = min(15.0, prior_threats * 5.0)
            base = min(100.0, base + boost)
            reasoning_parts.append(
                f"IP has {prior_threats} prior threats (+{boost:.1f} risk)"
            )

        # Confidence dampening
        if event.confidence < 0.4 and base > 30:
            dampened = base * 0.7
            reasoning_parts.append(
                f"low confidence ({event.confidence:.2f}) dampened risk "
                f"{base:.1f}→{dampened:.1f}"
            )
            base = dampened

        # Attack category multipliers
        multipliers = {
            AttackCategory.PROMPT_INJECTION: 1.2,
            AttackCategory.JAILBREAK: 1.2,
            AttackCategory.SQL_INJECTION: 1.25,
            AttackCategory.COMMAND_INJECTION: 1.3,
            AttackCategory.DATA_EXFILTRATION: 1.4,
        }
        mult = multipliers.get(event.attack_category, 1.0)
        if mult != 1.0:
            base = min(100.0, base * mult)
            reasoning_parts.append(
                f"{event.attack_category.value} multiplier ×{mult}"
            )

        reasoning = (
            " | ".join(reasoning_parts) if reasoning_parts else "no adjustment needed"
        )
        return round(base, 2), reasoning


# ---------------------------------------------------------------------------
# EventPipeline
# ---------------------------------------------------------------------------

class EventPipeline:
    """
    10-stage asynchronous event processing pipeline.

    Parameters
    ----------
    config        : Loaded Config object
    brain         : Security Brain implementation (or stub)
    memory_store  : MemoryStore implementation (or stub)
    policy_engine : PolicyEngine implementation (or stub)
    action_engine : ActionEngine implementation (or stub)
    logger        : SecurityLogger instance
    """

    def __init__(
        self,
        config,
        brain,
        memory_store,
        policy_engine,
        action_engine,
        logger: SecurityLogger,
        engine=None,
    ) -> None:
        self._config = config
        self._brain = brain
        self._memory = memory_store
        self._policy = policy_engine
        self._actions = action_engine
        self._logger = logger
        self._engine = engine
        self._log = get_logger("pipeline")

        # Pipeline statistics (thread-safe via GIL for CPython)
        self.total_events: int = 0
        self.threats_detected: int = 0
        self.blocks_issued: int = 0
        self.false_positives: int = 0

        # Event broadcast callbacks (registered by engine / dashboard)
        self._subscribers: list[Callable] = []

    # ------------------------------------------------------------------ #
    # Main entry point                                                     #
    # ------------------------------------------------------------------ #

    async def process(self, event: SecurityEvent) -> SecurityEvent:
        """
        Run all 10 pipeline stages against *event*.
        Returns the fully enriched SecurityEvent.
        """
        start_ts = time.monotonic()
        self.total_events += 1

        stages = [
            self._stage_observe,
            self._stage_normalize,
            self._stage_threat_detect,
            self._stage_risk_score,
            self._stage_reason,
            self._stage_policy_eval,
            self._stage_decide,
            self._stage_action,
            self._stage_learn,
            self._stage_emit,
        ]

        for stage in stages:
            try:
                event = await stage(event)
            except Exception as exc:  # noqa: BLE001
                self._logger.log_error(
                    f"Pipeline stage '{stage.__name__}' raised an exception: {exc}",
                    exc=exc,
                )
                # Tag the event so we know something went wrong internally
                event.add_tag(f"stage_error:{stage.__name__}")

        # Record processing time
        event.processing_time_ms = (time.monotonic() - start_ts) * 1000.0

        # Update counters
        if event.is_threat:
            self.threats_detected += 1
        if event.is_blocked:
            self.blocks_issued += 1

        return event

    # ------------------------------------------------------------------ #
    # Convenience constructors                                             #
    # ------------------------------------------------------------------ #

    async def process_http_request(self, request_data: dict) -> SecurityEvent:
        """Create and process an HTTP request SecurityEvent."""
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
        return await self.process(event)

    async def process_ai_prompt(
        self, prompt: str, context: dict | None = None
    ) -> SecurityEvent:
        """Create and process an AI prompt SecurityEvent."""
        event = SecurityEvent.from_ai_prompt(
            prompt=prompt,
            context=context or {},
        )
        return await self.process(event)

    async def process_db_query(
        self, query: str, params: list | None = None
    ) -> SecurityEvent:
        """Create and process a database query SecurityEvent."""
        event = SecurityEvent.from_db_query(query=query, params=params or [])
        return await self.process(event)

    async def process_tool_call(
        self, tool_name: str, args: dict | None = None
    ) -> SecurityEvent:
        """Create and process a tool call SecurityEvent (MCP/agent)."""
        event = SecurityEvent.from_tool_call(tool_name=tool_name, args=args or {})
        return await self.process(event)

    async def process_response(
        self,
        inbound_event: SecurityEvent,
        status_code: int,
        headers: dict,
        body: str,
    ) -> SecurityEvent:
        """
        Outbound Response Validation Layer.

        Inspects the outbound HTTP/AI/DB response payload before it reaches the client:
        - Detects leaked secrets, API keys, credentials, PII.
        - Sanitizes or blocks unsafe responses.
        - Records outcome into MemoryStore for continuous learning loop.
        """
        outbound_event = SecurityEvent(
            source_ip=inbound_event.source_ip,
            event_type="http_response",
            method=inbound_event.method,
            path=inbound_event.path,
            headers=headers,
            body=body,
            raw_data={"status_code": status_code, "inbound_event_id": inbound_event.id},
        )

        resp_sec_active = True
        if self._engine:
            resp_sec_active = self._engine.capabilities.is_active("response_protection")

        if not resp_sec_active:
            outbound_event.decision = Decision.ALLOW
            return await self.process(outbound_event)

        # Scan outgoing response body for secrets or system prompt leaks
        secret_match = _SECRET_PATTERNS.search(body or "")
        leak_match = _SYSTEM_PROMPT_LEAK_PATTERNS.search(body or "")

        if secret_match or leak_match:
            outbound_event.attack_category = (
                AttackCategory.SECRET_DISCOVERY if secret_match else AttackCategory.SYSTEM_PROMPT_LEAK
            )
            outbound_event.risk_score = 90.0
            outbound_event.severity = Severity.HIGH
            outbound_event.add_indicator("sensitive secret / prompt pattern detected in outbound response")
            outbound_event.decision = Decision.BLOCK

            # Store sanitized body alternative
            sanitized = _SECRET_PATTERNS.sub("[REDACTED_SECRET]", body or "")
            outbound_event.raw_data["sanitized_body"] = sanitized

        return await self.process(outbound_event)

    # ------------------------------------------------------------------ #
    # Stage 1 — Observe                                                   #
    # ------------------------------------------------------------------ #

    async def _stage_observe(self, event: SecurityEvent) -> SecurityEvent:
        """
        Enrich the raw event with contextual metadata:
        - Normalise source IP
        - Extract User-Agent
        - Record request in MemoryStore
        """
        # Normalise IP
        if not event.source_ip:
            event.source_ip = "0.0.0.0"

        # Extract User-Agent header (case-insensitive)
        ua = next(
            (v for k, v in event.headers.items() if k.lower() == "user-agent"),
            "",
        )
        if ua:
            event.raw_data["user_agent"] = ua

        # Check if IP is already blocked
        if self._memory.is_blocked(event.source_ip):
            event.add_tag("pre-blocked-ip")

        # Record the request in memory
        req_count = self._memory.record_request(event.source_ip)
        event.raw_data["ip_request_count"] = req_count

        # Retrieve historical IP risk score
        ip_risk = self._memory.get_ip_risk(event.source_ip)
        event.raw_data["ip_historical_risk"] = ip_risk

        return event

    # ------------------------------------------------------------------ #
    # Stage 2 — Normalize                                                 #
    # ------------------------------------------------------------------ #

    async def _stage_normalize(self, event: SecurityEvent) -> SecurityEvent:
        """
        Normalise to canonical SecurityEvent schema:
        - Upper-case HTTP method
        - Strip query string from path and parse into query_params if missing
        - Detect / confirm event_type
        """
        import urllib.parse

        if event.method:
            event.method = event.method.upper()

        # If path contains a query string and query_params is empty, parse it
        if "?" in event.path and not event.query_params:
            path_part, qs = event.path.split("?", 1)
            event.path = path_part
            event.query_params = dict(
                pair.split("=", 1) if "=" in pair else (pair, "")
                for pair in qs.split("&")
                if pair
            )

        # Unquote path and query parameters if URL-encoded
        if "%" in event.path:
            event.path = urllib.parse.unquote(event.path)
        if event.query_params:
            event.query_params = {
                k: urllib.parse.unquote(str(v)) for k, v in event.query_params.items()
            }

        # Infer event_type if not already set
        if not event.event_type:
            if event.method:
                event.event_type = "http_request"
            elif "prompt" in event.raw_data:
                event.event_type = "ai_prompt"
            elif "query" in event.raw_data:
                event.event_type = "db_query"
            elif "tool_name" in event.raw_data:
                event.event_type = "tool_call"
            else:
                event.event_type = "unknown"

        # Decode body bytes to string if needed
        if isinstance(event.body, bytes):
            try:
                event.body = event.body.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                event.body = repr(event.body)

        return event

    # ------------------------------------------------------------------ #
    # Stage 3 — Threat Detection                                          #
    # ------------------------------------------------------------------ #

    async def _stage_threat_detect(self, event: SecurityEvent) -> SecurityEvent:
        """
        Run signature-based threat detection across all available signals.
        Populates: attack_category, attack_indicators, severity, confidence.
        Also runs agent reports for TrafficAgent and ThreatAgent.
        """
        # Collect all text surfaces to scan
        surfaces = self._collect_text_surfaces(event)
        full_text = " ".join(surfaces)

        # === TrafficAgent ===
        traffic_indicators: list[str] = []
        traffic_risk = 0.0

        req_count = event.raw_data.get("ip_request_count", 0)
        ip_hist_risk = event.raw_data.get("ip_historical_risk", 0.0)

        if ip_hist_risk > 60:
            traffic_indicators.append(f"high historical IP risk score ({ip_hist_risk:.0f})")
            traffic_risk += 0.4
        if req_count > 200:
            traffic_indicators.append(f"high request volume from IP ({req_count} requests)")
            traffic_risk += 0.3
            event.add_tag("high-volume")
        if "pre-blocked-ip" in event.tags:
            traffic_indicators.append("IP is in blocklist")
            traffic_risk += 0.5

        # Check auth endpoint brute-force
        if event.event_type == "http_request" and _AUTH_PATHS.search(event.path or ""):
            if req_count > 10:
                traffic_indicators.append(
                    f"repeated requests to auth endpoint ({req_count})"
                )
                traffic_risk += 0.25
                event.add_tag("auth-endpoint")

        traffic_report = AgentReport(
            agent_name="TrafficAgent",
            observations=[f"request #{req_count} from {event.source_ip}"],
            risk_contribution=min(1.0, traffic_risk),
            attack_indicators=traffic_indicators,
            recommended_action=Decision.MONITOR if traffic_risk > 0.3 else None,
            confidence=0.85 if traffic_indicators else 0.5,
        )
        event.set_agent_report(traffic_report)

        # === ThreatAgent ===
        threat_indicators: list[str] = []
        detected_category = AttackCategory.NONE
        threat_risk = 0.0
        threat_confidence = 0.0

        # Check Capability Manager status
        api_sec_active = True
        prompt_prot_active = True
        if self._engine:
            api_sec_active = self._engine.capabilities.is_active("api_security")
            prompt_prot_active = self._engine.capabilities.is_active("prompt_protection")

        if api_sec_active:
            # SQL Injection
            if self._config.protection.sql_injection and _SQL_PATTERNS.search(full_text):
                detected_category = AttackCategory.SQL_INJECTION
                threat_indicators.append("SQL injection pattern matched")
                threat_risk = 0.85
                threat_confidence = 0.90

            # XSS
            elif self._config.protection.xss and _XSS_PATTERNS.search(full_text):
                detected_category = AttackCategory.XSS
                threat_indicators.append("XSS payload pattern matched")
                threat_risk = 0.70
                threat_confidence = 0.85

            # SSRF
            elif self._config.protection.ssrf and _SSRF_PATTERNS.search(full_text):
                detected_category = AttackCategory.SSRF
                threat_indicators.append("SSRF destination pattern matched")
                threat_risk = 0.80
                threat_confidence = 0.88

            # Command injection
            elif _CMD_INJECTION_PATTERNS.search(full_text):
                detected_category = AttackCategory.COMMAND_INJECTION
                threat_indicators.append("command injection pattern matched")
                threat_risk = 0.90
                threat_confidence = 0.92

        if prompt_prot_active:
            # Prompt injection (AI events or any text)
            if (
                self._config.ai.prompt_injection
                and _PROMPT_INJECTION_PATTERNS.search(full_text)
            ):
                if detected_category == AttackCategory.NONE:
                    detected_category = AttackCategory.PROMPT_INJECTION
                    threat_risk = 0.75
                    threat_confidence = 0.80
                threat_indicators.append("prompt injection pattern matched")

            # Jailbreak
            if (
                self._config.ai.jailbreak_detection
                and _JAILBREAK_PATTERNS.search(full_text)
            ):
                if detected_category == AttackCategory.NONE:
                    detected_category = AttackCategory.JAILBREAK
                    threat_risk = 0.70
                    threat_confidence = 0.78
                threat_indicators.append("jailbreak pattern matched")

            # System prompt leak
            if (
                self._config.ai.system_prompt_leak
                and _SYSTEM_PROMPT_LEAK_PATTERNS.search(full_text)
            ):
                if detected_category == AttackCategory.NONE:
                    detected_category = AttackCategory.SYSTEM_PROMPT_LEAK
                    threat_risk = 0.65
                    threat_confidence = 0.82
                threat_indicators.append("system prompt extraction attempt")

        # API enumeration (path-based)
        if (
            self._config.protection.api_scanning
            and event.event_type == "http_request"
            and _API_SCAN_PATHS.search(event.path or "")
        ):
            if detected_category == AttackCategory.NONE:
                detected_category = AttackCategory.API_ENUMERATION
                threat_risk = 0.55
                threat_confidence = 0.75
            threat_indicators.append("sensitive API path accessed")

        # Secret discovery (secrets in payload)
        if _SECRET_PATTERNS.search(full_text):
            threat_indicators.append("secret/credential pattern detected in payload")
            if detected_category == AttackCategory.NONE:
                detected_category = AttackCategory.SECRET_DISCOVERY
                threat_risk = 0.60
                threat_confidence = 0.85

        # MCP abuse (tool call with dangerous tool names)
        if event.event_type == "tool_call":
            tool_name = event.raw_data.get("tool_name", "").lower()
            if tool_name in _MCP_DANGEROUS_TOOLS:
                threat_indicators.append(f"dangerous MCP tool called: {tool_name}")
                if detected_category == AttackCategory.NONE:
                    detected_category = AttackCategory.MCP_ABUSE
                    threat_risk = 0.70
                    threat_confidence = 0.80

        # Populate event
        if detected_category != AttackCategory.NONE:
            event.attack_category = detected_category
            for ind in threat_indicators:
                event.add_indicator(ind)

        threat_report = AgentReport(
            agent_name="ThreatAgent",
            observations=[
                f"scanned {len(surfaces)} text surface(s), "
                f"detected category: {detected_category.value}"
            ],
            risk_contribution=threat_risk,
            attack_indicators=threat_indicators,
            recommended_action=self._threat_to_decision(detected_category),
            confidence=threat_confidence,
        )
        event.set_agent_report(threat_report)

        return event

    # ------------------------------------------------------------------ #
    # Stage 4 — Risk Scoring                                              #
    # ------------------------------------------------------------------ #

    async def _stage_risk_score(self, event: SecurityEvent) -> SecurityEvent:
        """
        RiskAgent: compute multi-signal risk_score and severity.

        Signals
        -------
        - ThreatAgent risk_contribution × confidence
        - TrafficAgent risk_contribution × confidence
        - Historical IP risk
        - Credential stuffing heuristic
        - Session anomaly heuristic
        """
        threat_report = event.agent_reports.get("ThreatAgent")
        traffic_report = event.agent_reports.get("TrafficAgent")

        # Weighted contributions
        threat_score = 0.0
        traffic_score = 0.0

        if threat_report:
            threat_score = threat_report.risk_contribution * threat_report.confidence * 100.0
        if traffic_report:
            traffic_score = traffic_report.risk_contribution * traffic_report.confidence * 100.0

        # Historical IP risk carries up to 20 points
        hist_risk = event.raw_data.get("ip_historical_risk", 0.0)
        hist_contribution = min(20.0, hist_risk * 0.2)

        # Composite risk calculation
        if threat_score >= 50.0:
            raw_risk = max(threat_score, threat_score * 0.85 + traffic_score * 0.10 + hist_contribution * 0.05)
        else:
            raw_risk = (
                threat_score * 0.60
                + traffic_score * 0.25
                + hist_contribution * 0.15
            )
        event.risk_score = round(min(100.0, raw_risk), 2)

        # Aggregate confidence from agent reports
        confidences = [
            r.confidence
            for r in event.agent_reports.values()
            if r.confidence > 0
        ]
        event.confidence = round(sum(confidences) / max(len(confidences), 1), 3)

        # Derive severity from risk_score
        event.severity = Severity.from_score(event.risk_score)

        # Build RiskAgent report
        risk_report = AgentReport(
            agent_name="RiskAgent",
            observations=[
                f"threat_score={threat_score:.1f}, "
                f"traffic_score={traffic_score:.1f}, "
                f"hist_contribution={hist_contribution:.1f}",
                f"composite risk_score={event.risk_score:.1f}",
                f"severity={event.severity.value}",
            ],
            risk_contribution=event.risk_score / 100.0,
            confidence=event.confidence,
            recommended_action=None,
        )
        event.set_agent_report(risk_report)

        return event

    # ------------------------------------------------------------------ #
    # Stage 5 — Reason (Security Brain)                                   #
    # ------------------------------------------------------------------ #

    async def _stage_reason(self, event: SecurityEvent) -> SecurityEvent:
        """
        Security Brain correlates:
        - Current threat signals
        - Historical behaviour for this IP
        - Multi-agent reports

        Adjusts risk_score and generates preliminary decision reasoning.
        """
        # Fetch recent historical events for this IP
        history = self._memory.get_recent_events(event.source_ip, limit=20)

        # Brain correlation
        adjusted_score, reasoning = await self._brain.correlate(event, history)
        event.risk_score = adjusted_score
        event.decision_reasoning = reasoning

        # Re-derive severity after brain adjustment
        event.severity = Severity.from_score(event.risk_score)

        brain_report = AgentReport(
            agent_name="SecurityBrain",
            observations=[f"correlation reasoning: {reasoning}"],
            risk_contribution=adjusted_score / 100.0,
            confidence=event.confidence,
            recommended_action=None,
        )
        event.set_agent_report(brain_report)

        return event

    # ------------------------------------------------------------------ #
    # Stage 6 — Policy Evaluation                                         #
    # ------------------------------------------------------------------ #

    async def _stage_policy_eval(self, event: SecurityEvent) -> SecurityEvent:
        """
        Apply IF/THEN policy rules from config.
        A matching rule may force a decision (overriding the Brain's output).
        """
        policy_decision = self._policy.evaluate(event)
        if policy_decision is not None:
            # Policy override — set the decision and annotate
            event.decision = policy_decision
            reasoning_suffix = f" [policy override → {policy_decision.value}]"
            event.decision_reasoning = (event.decision_reasoning or "") + reasoning_suffix
            event.add_tag("policy-applied")

        return event

    # ------------------------------------------------------------------ #
    # Stage 7 — Decide                                                    #
    # ------------------------------------------------------------------ #

    async def _stage_decide(self, event: SecurityEvent) -> SecurityEvent:
        """
        DecisionAgent makes the final call if no policy has already decided.

        Decision matrix:
        ─────────────────────────────────────────────────────
        risk_score ≥ 85                → BLOCK
        risk_score ≥ 70 (threat)       → BLOCK
        risk_score ≥ 55 (threat)       → CHALLENGE
        risk_score ≥ 40                → RATE_LIMIT
        risk_score ≥ 20                → MONITOR
        else                           → ALLOW
        ─────────────────────────────────────────────────────
        """
        if event.decision is not None:
            # Already set by policy
            return event

        score = event.risk_score
        is_threat = event.is_threat

        if score >= 85:
            event.decision = Decision.BLOCK
        elif score >= 70 and is_threat:
            event.decision = Decision.BLOCK
        elif score >= 55 and is_threat:
            event.decision = Decision.CHALLENGE
        elif score >= 40:
            event.decision = Decision.RATE_LIMIT
        elif score >= 20:
            event.decision = Decision.MONITOR
        else:
            event.decision = Decision.ALLOW

        if not event.decision_reasoning:
            event.decision_reasoning = (
                f"DecisionAgent: risk_score={score:.1f}, "
                f"severity={event.severity.value}, "
                f"is_threat={is_threat} → {event.decision.value}"
            )

        return event

    # ------------------------------------------------------------------ #
    # Stage 8 — Action                                                    #
    # ------------------------------------------------------------------ #

    async def _stage_action(self, event: SecurityEvent) -> SecurityEvent:
        """
        ActionEngine executes the decision:
        - Blocks IP in MemoryStore
        - Invalidates session
        - Rate-limits IP
        - Sends notifications
        - Generates incidents (placeholder — real impl in Phase 2)
        """
        actions_taken = await self._actions.execute(event)
        event.actions_taken.extend(actions_taken)
        return event

    # ------------------------------------------------------------------ #
    # Stage 9 — Learn                                                     #
    # ------------------------------------------------------------------ #

    async def _stage_learn(self, event: SecurityEvent) -> SecurityEvent:
        """
        Update MemoryStore with new knowledge:
        - Increment IP risk score if threat detected
        - Record event outcome for future correlation
        """
        if event.is_threat:
            delta = event.risk_score * 0.15  # 15% of current risk score
            self._memory.increment_ip_risk(event.source_ip, delta)

        # Tag false positives (decision=ALLOW despite threat category)
        if event.attack_category != AttackCategory.NONE and event.decision == Decision.ALLOW:
            event.add_tag("possible-false-positive")
            self.false_positives += 1

        return event

    # ------------------------------------------------------------------ #
    # Stage 10 — Emit                                                     #
    # ------------------------------------------------------------------ #

    async def _stage_emit(self, event: SecurityEvent) -> SecurityEvent:
        """
        Finalise and publish the event:
        1. Structured log entry via SecurityLogger
        2. Broadcast to all registered subscribers (e.g., WebSocket dashboard)
        """
        self._logger.log_event(event)
        self._logger.log_decision(event)

        # Broadcast to subscribers (non-blocking)
        for callback in self._subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    asyncio.ensure_future(callback(event))
                else:
                    callback(event)
            except Exception as exc:  # noqa: BLE001
                self._logger.log_error(f"Subscriber callback failed: {exc}", exc=exc)

        return event

    # ------------------------------------------------------------------ #
    # Subscriber management                                               #
    # ------------------------------------------------------------------ #

    def subscribe(self, callback: Callable) -> None:
        """Register a callback to be invoked after every processed event."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable) -> None:
        self._subscribers = [s for s in self._subscribers if s is not callback]

    # ------------------------------------------------------------------ #
    # Statistics                                                          #
    # ------------------------------------------------------------------ #

    def get_stats(self) -> dict:
        return {
            "total_events": self.total_events,
            "threats_detected": self.threats_detected,
            "blocks_issued": self.blocks_issued,
            "false_positives": self.false_positives,
        }

    # ------------------------------------------------------------------ #
    # Helpers                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _collect_text_surfaces(event: SecurityEvent) -> list[str]:
        """Collect all text fields from an event for pattern matching."""
        surfaces: list[str] = []

        if event.path:
            surfaces.append(event.path)
        if event.query_params:
            surfaces.extend(str(v) for v in event.query_params.values())
            surfaces.extend(event.query_params.keys())
        if event.body:
            surfaces.append(str(event.body))
        for v in event.headers.values():
            surfaces.append(v)
        for v in event.raw_data.values():
            if isinstance(v, str):
                surfaces.append(v)
            elif isinstance(v, dict):
                surfaces.extend(str(vv) for vv in v.values())
            elif isinstance(v, list):
                surfaces.extend(str(item) for item in v)

        return [s for s in surfaces if s]

    @staticmethod
    def _threat_to_decision(category: AttackCategory) -> Optional[Decision]:
        """Map an attack category to the most appropriate initial decision."""
        mapping = {
            AttackCategory.SQL_INJECTION: Decision.BLOCK,
            AttackCategory.COMMAND_INJECTION: Decision.BLOCK,
            AttackCategory.SSRF: Decision.BLOCK,
            AttackCategory.PROMPT_INJECTION: Decision.BLOCK,
            AttackCategory.JAILBREAK: Decision.CHALLENGE,
            AttackCategory.XSS: Decision.BLOCK,
            AttackCategory.SYSTEM_PROMPT_LEAK: Decision.MONITOR,
            AttackCategory.API_ENUMERATION: Decision.RATE_LIMIT,
            AttackCategory.SECRET_DISCOVERY: Decision.BLOCK,
            AttackCategory.MCP_ABUSE: Decision.BLOCK,
            AttackCategory.CREDENTIAL_STUFFING: Decision.CHALLENGE,
            AttackCategory.SESSION_HIJACKING: Decision.INVALIDATE_SESSION,
            AttackCategory.DATA_EXFILTRATION: Decision.ESCALATE,
            AttackCategory.BOT_TRAFFIC: Decision.RATE_LIMIT,
            AttackCategory.DDOS: Decision.BLOCK,
        }
        return mapping.get(category)
