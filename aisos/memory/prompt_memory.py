"""
aisos/memory/prompt_memory.py
--------------------------------
AI prompt history and injection pattern tracking.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

_MAX_PROMPTS = 5_000
_MAX_PER_SESSION = 200


@dataclass
class _PromptRecord:
    event_id: str
    session_id: Optional[str]
    user_id: Optional[str]
    timestamp: str
    prompt: str
    injection_detected: bool
    attack_indicators: list[str]
    risk_score: float


class PromptMemory:
    """Stores AI prompt history and injection patterns."""

    def __init__(self) -> None:
        self._records: deque[_PromptRecord] = deque(maxlen=_MAX_PROMPTS)
        self._by_session: dict[str, deque[_PromptRecord]] = defaultdict(
            lambda: deque(maxlen=_MAX_PER_SESSION)
        )
        self._injection_patterns: list[str] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------

    def record(self, event: "SecurityEvent") -> None:
        prompt_text = ""
        if isinstance(event.body, dict):
            prompt_text = (
                event.body.get("prompt")
                or event.body.get("message")
                or event.body.get("text")
                or str(event.body)
            )
        elif isinstance(event.body, str):
            prompt_text = event.body

        injection_detected = event.risk_score > 30 or bool(event.attack_indicators)

        rec = _PromptRecord(
            event_id=event.id,
            session_id=event.session_id,
            user_id=event.user_id,
            timestamp=event.timestamp.isoformat(),
            prompt=prompt_text[:2000],   # cap stored length
            injection_detected=injection_detected,
            attack_indicators=list(event.attack_indicators),
            risk_score=event.risk_score,
        )

        with self._lock:
            self._records.append(rec)
            if event.session_id:
                self._by_session[event.session_id].append(rec)
            # Learn new injection patterns
            if injection_detected:
                for indicator in event.attack_indicators:
                    if indicator not in self._injection_patterns:
                        self._injection_patterns.append(indicator)

    def get_injection_patterns(self) -> list[str]:
        with self._lock:
            return list(self._injection_patterns)

    def was_injected(self, session_id: str) -> bool:
        with self._lock:
            records = self._by_session.get(session_id, deque())
            return any(r.injection_detected for r in records)

    def get_prompt_history(self, session_id: str) -> list[dict]:
        with self._lock:
            records = self._by_session.get(session_id, deque())
            return [
                {
                    "event_id": r.event_id,
                    "timestamp": r.timestamp,
                    "prompt": r.prompt,
                    "injection_detected": r.injection_detected,
                    "attack_indicators": r.attack_indicators,
                    "risk_score": r.risk_score,
                }
                for r in records
            ]

    @property
    def pattern_count(self) -> int:
        return len(self._injection_patterns)
