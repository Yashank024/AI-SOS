"""
aisos/memory/pattern_db.py
-----------------------------
Learned detection pattern database.

Starts with 20 pre-seeded patterns for common attacks.
New patterns are extracted from confirmed threats via learn().
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent


@dataclass
class _Pattern:
    name: str
    regex: str
    category: str
    confidence: float
    occurrences: int = 0
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.regex, re.I | re.S)
        return self._compiled

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "regex": self.regex,
            "category": self.category,
            "confidence": self.confidence,
            "occurrences": self.occurrences,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


# ---------------------------------------------------------------------------
# Pre-seeded patterns (20 patterns for common attacks)
# ---------------------------------------------------------------------------
_SEED_PATTERNS: list[dict] = [
    # SQLi
    {"name": "sqli_union_select",       "regex": r"UNION\s+(?:ALL\s+)?SELECT",       "category": "SQL_INJECTION",       "confidence": 0.97},
    {"name": "sqli_or_true",            "regex": r"'\s*OR\s*'?1'?\s*=\s*'?1",        "category": "SQL_INJECTION",       "confidence": 0.97},
    {"name": "sqli_drop",               "regex": r";\s*DROP\s+TABLE",                "category": "SQL_INJECTION",       "confidence": 0.99},
    {"name": "sqli_sleep",              "regex": r"(?:SLEEP|BENCHMARK)\s*\(",        "category": "SQL_INJECTION",       "confidence": 0.93},
    {"name": "sqli_xp_cmdshell",        "regex": r"xp_cmdshell",                     "category": "SQL_INJECTION",       "confidence": 0.99},
    # XSS
    {"name": "xss_script",             "regex": r"<\s*script[\s>]",                 "category": "XSS",                 "confidence": 0.96},
    {"name": "xss_onerror",            "regex": r"\bonerror\s*=",                   "category": "XSS",                 "confidence": 0.90},
    {"name": "xss_javascript",         "regex": r"javascript\s*:",                  "category": "XSS",                 "confidence": 0.90},
    {"name": "xss_eval",               "regex": r"\beval\s*\(",                      "category": "XSS",                 "confidence": 0.82},
    # Prompt Injection
    {"name": "pi_ignore_instructions", "regex": r"ignore\s+(?:previous|prior)\s+instructions?", "category": "PROMPT_INJECTION", "confidence": 0.92},
    {"name": "pi_jailbreak_keyword",   "regex": r"\bjailbreak\b",                   "category": "JAILBREAK",           "confidence": 0.88},
    {"name": "pi_dan_mode",            "regex": r"DAN\s+mode",                      "category": "JAILBREAK",           "confidence": 0.95},
    {"name": "pi_escape_token",        "regex": r"(?:</s>|\[INST\]|<\|im_start\|>)", "category": "PROMPT_INJECTION",   "confidence": 0.95},
    # SSRF
    {"name": "ssrf_metadata_server",   "regex": r"169\.254\.169\.254",              "category": "SSRF",                "confidence": 0.99},
    {"name": "ssrf_localhost",         "regex": r"(?:http|https)://localhost",       "category": "SSRF",                "confidence": 0.96},
    {"name": "ssrf_file_scheme",       "regex": r"file://",                         "category": "SSRF",                "confidence": 0.92},
    # Command Injection
    {"name": "cmdi_subshell",          "regex": r"\$\([^)]+\)",                     "category": "COMMAND_INJECTION",   "confidence": 0.83},
    {"name": "cmdi_pipe_cmd",          "regex": r"\|\s*(?:cat|id|ls|bash|sh)",       "category": "COMMAND_INJECTION",   "confidence": 0.93},
    # Secret Discovery
    {"name": "secret_env_file",        "regex": r"/\.env(?:\b|$)",                  "category": "SECRET_DISCOVERY",    "confidence": 0.92},
    {"name": "secret_etc_passwd",      "regex": r"/etc/passwd",                     "category": "SECRET_DISCOVERY",    "confidence": 0.99},
]


class PatternDB:
    """
    Database of named regex patterns used for attack detection.
    Patterns can be learned from confirmed threats at runtime.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, _Pattern] = {}
        self._lock = threading.Lock()
        # Seed initial patterns
        for p in _SEED_PATTERNS:
            self._patterns[p["name"]] = _Pattern(**p)

    # ------------------------------------------------------------------

    def learn(self, event: "SecurityEvent") -> None:
        """Extract and store new patterns from a confirmed threat event."""
        now = datetime.utcnow().isoformat()
        with self._lock:
            for indicator in event.attack_indicators:
                if indicator not in self._patterns:
                    # Create a loose literal pattern from the indicator name
                    # (production systems would use NLP/ML here)
                    safe_regex = re.escape(indicator.split(":")[0])
                    self._patterns[indicator] = _Pattern(
                        name=indicator,
                        regex=safe_regex,
                        category=event.attack_category.value,
                        confidence=min(event.confidence * 0.8, 0.85),
                        occurrences=1,
                        first_seen=now,
                        last_seen=now,
                    )
                else:
                    pat = self._patterns[indicator]
                    pat.occurrences += 1
                    pat.last_seen = now
                    # Boost confidence as we see more occurrences
                    pat.confidence = min(pat.confidence + 0.01, 1.0)

    def match(self, text: str) -> list[str]:
        """Return names of all patterns that match the given text."""
        matched: list[str] = []
        with self._lock:
            patterns = list(self._patterns.values())
        for pat in patterns:
            try:
                if pat.compile().search(text):
                    matched.append(pat.name)
            except re.error:
                pass
        return matched

    def get_all_patterns(self) -> list[dict]:
        with self._lock:
            return [p.to_dict() for p in self._patterns.values()]

    @property
    def count(self) -> int:
        return len(self._patterns)
