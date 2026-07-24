"""
aisos/brain/agents/threat_agent.py
------------------------------------
Pattern-based threat classification agent.

Detects
-------
- Prompt Injection / Jailbreak
- SQL Injection (classic, blind, error-based)
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- Command Injection
- Secret / Credential Discovery
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

from aisos.brain.base_agent import BaseAgent
from aisos.core.event import AgentReport, AttackCategory, Decision, Severity

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

logger = logging.getLogger("aisos.agent.threat")


# ---------------------------------------------------------------------------
# Detection rule primitives
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    name: str
    pattern: re.Pattern
    category: AttackCategory
    severity: Severity
    confidence: float
    risk_score: float


def _compile(pattern: str, flags: int = re.I | re.S) -> re.Pattern:
    return re.compile(pattern, flags)


_RULES: list[_Rule] = [
    # ---- Prompt Injection --------------------------------------------------
    _Rule("pi_ignore_prev",
          _compile(r"ignore\s+(?:previous|prior|all)\s+instructions?"),
          AttackCategory.PROMPT_INJECTION, Severity.HIGH, 0.90, 75.0),
    _Rule("pi_disregard_system",
          _compile(r"disregard\s+(?:your\s+)?(?:system\s+)?prompt"),
          AttackCategory.PROMPT_INJECTION, Severity.HIGH, 0.90, 75.0),
    _Rule("pi_forget_told",
          _compile(r"forget\s+(?:what\s+)?(?:you\s+were\s+told|everything)"),
          AttackCategory.PROMPT_INJECTION, Severity.HIGH, 0.85, 70.0),
    _Rule("pi_pretend",
          _compile(r"(?:pretend|act\s+as\s+if|you\s+are\s+now|new\s+persona|DAN\s+mode)"),
          AttackCategory.PROMPT_INJECTION, Severity.MEDIUM, 0.80, 60.0),
    _Rule("pi_roleplay",
          _compile(r"(?:role\s*play|roleplay)\s+as"),
          AttackCategory.PROMPT_INJECTION, Severity.LOW, 0.50, 30.0),
    _Rule("pi_escape_tokens",
          _compile(r"(?:</s>|\[INST\]|###Human|<\|im_start\|>|SYSTEM:)"),
          AttackCategory.PROMPT_INJECTION, Severity.HIGH, 0.95, 80.0),
    _Rule("pi_extract_system",
          _compile(r"(?:what\s+is\s+your\s+system\s+prompt|reveal\s+your\s+instructions|show\s+me\s+your\s+prompt)"),
          AttackCategory.SYSTEM_PROMPT_LEAK, Severity.HIGH, 0.90, 80.0),
    _Rule("pi_jailbreak",
          _compile(r"(?:jailbreak|bypass\s+safety|ignore\s+ethics|no\s+restrictions)"),
          AttackCategory.JAILBREAK, Severity.CRITICAL, 0.95, 90.0),

    # ---- SQL Injection ------------------------------------------------------
    _Rule("sqli_or_1_1",
          _compile(r"'\s*OR\s*'?1'?\s*=\s*'?1"),
          AttackCategory.SQL_INJECTION, Severity.CRITICAL, 0.97, 95.0),
    _Rule("sqli_drop_table",
          _compile(r";\s*DROP\s+TABLE"),
          AttackCategory.SQL_INJECTION, Severity.CRITICAL, 0.98, 95.0),
    _Rule("sqli_union_select",
          _compile(r"UNION\s+(?:ALL\s+)?SELECT"),
          AttackCategory.SQL_INJECTION, Severity.CRITICAL, 0.96, 90.0),
    _Rule("sqli_comment",
          _compile(r"(?:--|#|/\*|\*/)\s*(?:$|[\r\n])"),
          AttackCategory.SQL_INJECTION, Severity.MEDIUM, 0.60, 40.0),
    _Rule("sqli_xp_cmdshell",
          _compile(r"xp_cmdshell"),
          AttackCategory.SQL_INJECTION, Severity.CRITICAL, 0.99, 95.0),
    _Rule("sqli_blind_and",
          _compile(r"\b1\s+AND\s+1\s*=\s*1\b"),
          AttackCategory.SQL_INJECTION, Severity.HIGH, 0.80, 70.0),
    _Rule("sqli_sleep",
          _compile(r"(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\("),
          AttackCategory.SQL_INJECTION, Severity.CRITICAL, 0.95, 90.0),
    _Rule("sqli_extract",
          _compile(r"(?:EXTRACTVALUE|UPDATEXML)\s*\("),
          AttackCategory.SQL_INJECTION, Severity.CRITICAL, 0.92, 85.0),

    # ---- XSS ----------------------------------------------------------------
    _Rule("xss_script_tag",
          _compile(r"<\s*script[\s>]"),
          AttackCategory.XSS, Severity.HIGH, 0.95, 85.0),
    _Rule("xss_javascript_proto",
          _compile(r"javascript\s*:"),
          AttackCategory.XSS, Severity.HIGH, 0.90, 80.0),
    _Rule("xss_event_handler",
          _compile(r"\bon(?:error|load|click|mouseover|focus|blur)\s*="),
          AttackCategory.XSS, Severity.HIGH, 0.88, 75.0),
    _Rule("xss_alert",
          _compile(r"alert\s*\("),
          AttackCategory.XSS, Severity.MEDIUM, 0.70, 55.0),
    _Rule("xss_document_cookie",
          _compile(r"document\.cookie"),
          AttackCategory.XSS, Severity.HIGH, 0.85, 70.0),
    _Rule("xss_eval",
          _compile(r"\beval\s*\("),
          AttackCategory.XSS, Severity.HIGH, 0.80, 65.0),
    _Rule("xss_img_src_x",
          _compile(r"<\s*img\s+[^>]*src\s*=\s*[\"']?x[\"']?"),
          AttackCategory.XSS, Severity.MEDIUM, 0.75, 60.0),

    # ---- SSRF ---------------------------------------------------------------
    _Rule("ssrf_localhost",
          _compile(r"(?:http|https|ftp|dict|gopher)://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1)"),
          AttackCategory.SSRF, Severity.CRITICAL, 0.95, 90.0),
    _Rule("ssrf_metadata",
          _compile(r"169\.254\.169\.254"),
          AttackCategory.SSRF, Severity.CRITICAL, 0.99, 95.0),
    _Rule("ssrf_file_scheme",
          _compile(r"file://"),
          AttackCategory.SSRF, Severity.HIGH, 0.90, 80.0),
    _Rule("ssrf_internal_range",
          _compile(r"(?:dict|gopher|ftp)://"),
          AttackCategory.SSRF, Severity.HIGH, 0.85, 75.0),
    _Rule("ssrf_private_range",
          _compile(r"(?:http|https)://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"),
          AttackCategory.SSRF, Severity.HIGH, 0.80, 70.0),

    # ---- Command Injection --------------------------------------------------
    _Rule("cmdi_semicolon",
          _compile(r";\s*(?:ls|cat|id|pwd|whoami|uname|curl|wget|bash|sh|python|perl|ruby)"),
          AttackCategory.COMMAND_INJECTION, Severity.CRITICAL, 0.95, 90.0),
    _Rule("cmdi_pipe",
          _compile(r"\|\s*(?:cat|ls|id|bash|sh|nc|curl|wget)"),
          AttackCategory.COMMAND_INJECTION, Severity.CRITICAL, 0.95, 90.0),
    _Rule("cmdi_and_chain",
          _compile(r"&&\s*(?:id|ls|cat|pwd|whoami)"),
          AttackCategory.COMMAND_INJECTION, Severity.CRITICAL, 0.95, 90.0),
    _Rule("cmdi_subshell",
          _compile(r"\$\([^)]*\)|`[^`]+`"),
          AttackCategory.COMMAND_INJECTION, Severity.HIGH, 0.80, 70.0),
    _Rule("cmdi_newline_shell",
          _compile(r"(?:\\n|%0a)\s*(?:/bin/sh|/bin/bash|cmd\.exe)"),
          AttackCategory.COMMAND_INJECTION, Severity.CRITICAL, 0.90, 85.0),

    # ---- Secret / Credential Discovery -------------------------------------
    _Rule("secret_dotenv",
          _compile(r"/\.env(?:\b|$)"),
          AttackCategory.SECRET_DISCOVERY, Severity.HIGH, 0.90, 80.0),
    _Rule("secret_git_config",
          _compile(r"/\.git(?:/config)?(?:\b|$)"),
          AttackCategory.SECRET_DISCOVERY, Severity.HIGH, 0.90, 80.0),
    _Rule("secret_etc_passwd",
          _compile(r"/etc/passwd"),
          AttackCategory.SECRET_DISCOVERY, Severity.CRITICAL, 0.98, 90.0),
    _Rule("secret_proc",
          _compile(r"/proc/(?:self|[0-9]+)/"),
          AttackCategory.SECRET_DISCOVERY, Severity.HIGH, 0.85, 75.0),
    _Rule("secret_param_keys",
          _compile(r"(?:api_key|secret|password|passwd|token|private_key)\s*=\s*\S+", re.I),
          AttackCategory.SECRET_DISCOVERY, Severity.MEDIUM, 0.65, 50.0),
]


def _flatten_to_string(value: Any, depth: int = 0) -> str:
    """Recursively flatten any body/param structure to a single string for scanning."""
    if depth > 5:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if isinstance(value, dict):
        return " ".join(_flatten_to_string(v, depth + 1) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten_to_string(v, depth + 1) for v in value)
    return str(value)


class ThreatAgent(BaseAgent):
    """Pattern-based threat classifier."""

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(name="threat_agent", config=config)

    async def observe(self, event: "SecurityEvent") -> AgentReport:
        observations: list[str] = []
        indicators: list[str] = []
        total_risk: float = 0.0
        best_confidence: float = 0.0
        primary_category: AttackCategory = AttackCategory.NONE
        primary_severity: Severity = Severity.INFO
        recommended: Decision | None = None

        # Build corpus to scan
        # For AI prompts only scan body; for HTTP scan path + body + headers
        corpora: dict[str, str] = {}

        corpora["path"] = event.path or ""
        corpora["body"] = _flatten_to_string(event.body)

        # Also stringify any query parameters embedded in the path
        if "?" in event.path:
            corpora["query"] = event.path.split("?", 1)[1]

        # For ai_prompt events, include prompt specifically
        if event.event_type == "ai_prompt":
            if isinstance(event.body, dict):
                prompt = event.body.get("prompt") or event.body.get("message") or ""
                corpora["ai_prompt"] = _flatten_to_string(prompt)

        matched_rules: list[_Rule] = []

        for rule in _RULES:
            for corpus_name, text in corpora.items():
                if rule.pattern.search(text):
                    if rule not in matched_rules:
                        matched_rules.append(rule)
                        observations.append(
                            f"[{rule.category.value}] Rule '{rule.name}' matched in {corpus_name}."
                        )
                        indicators.append(f"{rule.name}@{corpus_name}")
                        total_risk += rule.risk_score
                        if rule.confidence > best_confidence:
                            best_confidence = rule.confidence
                            primary_category = rule.category
                            primary_severity = rule.severity
                    break  # rule already matched, move to next rule

        # Determine recommended action from highest-severity match
        if total_risk >= 90:
            recommended = Decision.BLOCK
        elif total_risk >= 60:
            recommended = Decision.CHALLENGE
        elif total_risk >= 30:
            recommended = Decision.MONITOR

        total_risk = min(total_risk, 100.0)

        if not observations:
            observations.append("No known attack patterns detected.")

        return AgentReport(
            agent_name=self.name,
            observations=observations,
            risk_contribution=total_risk,
            attack_indicators=indicators,
            recommended_action=recommended,
            confidence=best_confidence,
            metadata={
                "primary_category": primary_category.value,
                "primary_severity": primary_severity.value,
                "matched_rules": [r.name for r in matched_rules],
                "rule_count": len(matched_rules),
            },
        )
