"""
aisos/memory/threat_memory.py
-------------------------------
Attack history log — stores the last 10,000 events in a deque.
"""

from __future__ import annotations

import threading
from collections import deque, defaultdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

_MAX_EVENTS = 10_000


class ThreatMemory:
    """In-memory rolling log of threat events."""

    def __init__(self) -> None:
        self._events: deque[dict] = deque(maxlen=_MAX_EVENTS)
        self._by_ip: dict[str, list[dict]] = defaultdict(list)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------

    def record(self, event: "SecurityEvent") -> None:
        """Store a threat event."""
        record = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "user_id": event.user_id,
            "session_id": event.session_id,
            "event_type": event.event_type,
            "method": event.method,
            "path": event.path,
            "severity": event.severity.value,
            "risk_score": event.risk_score,
            "attack_category": event.attack_category.value,
            "attack_indicators": event.attack_indicators,
            "decision": event.decision.value if event.decision else None,
            "decision_reasoning": event.decision_reasoning,
            "country": event.country,
            "asn": event.asn,
            "is_incident": event.decision is not None and event.decision.value in (
                "GENERATE_INCIDENT", "ESCALATE"
            ),
        }
        with self._lock:
            self._events.append(record)
            # Also index by IP (keep last 500 per IP to avoid unbounded growth)
            ip_list = self._by_ip[event.source_ip]
            ip_list.append(record)
            if len(ip_list) > 500:
                self._by_ip[event.source_ip] = ip_list[-500:]

    def get_recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            events = list(self._events)
        return events[-limit:][::-1]   # most-recent first

    def get_by_ip(self, ip: str) -> list[dict]:
        with self._lock:
            return list(self._by_ip.get(ip, []))

    def get_incidents(self) -> list[dict]:
        with self._lock:
            return [e for e in self._events if e.get("is_incident")]

    def get_attack_count_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        with self._lock:
            for e in self._events:
                counts[e["attack_category"]] += 1
        return dict(counts)

    @property
    def total(self) -> int:
        return len(self._events)
