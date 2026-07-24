"""
aisos/memory/session_memory.py
---------------------------------
Active session tracking with anomaly scoring and auto-expiry.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

_SESSION_TTL_HOURS = 2
_ANOMALY_WEIGHT = 20.0    # risk added per anomaly flag


@dataclass
class _Session:
    session_id: str
    user_id: Optional[str]
    ip: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    request_count: int = 0
    anomaly_flags: list[str] = field(default_factory=list)
    risk_history: list[float] = field(default_factory=list)
    invalidated: bool = False


class SessionMemory:
    """Tracks active sessions and computes anomaly scores."""

    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------

    def update(self, session_id: str, event: "SecurityEvent") -> None:
        now = datetime.utcnow()
        with self._lock:
            self._evict_expired()
            if session_id not in self._sessions:
                self._sessions[session_id] = _Session(
                    session_id=session_id,
                    user_id=event.user_id,
                    ip=event.source_ip,
                )
            session = self._sessions[session_id]
            session.last_seen = now
            session.request_count += 1
            session.risk_history.append(event.risk_score)
            if len(session.risk_history) > 100:
                session.risk_history = session.risk_history[-100:]

            # IP change detection
            if session.ip != event.source_ip:
                session.anomaly_flags.append(
                    f"ip_change:{session.ip}->{event.source_ip}"
                )
                session.ip = event.source_ip

    def get_anomaly_score(self, session_id: str) -> float:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return 0.0
            base = len(session.anomaly_flags) * _ANOMALY_WEIGHT
            risk_avg = (
                sum(session.risk_history[-10:]) / len(session.risk_history[-10:])
                if session.risk_history else 0.0
            )
            return min(base + risk_avg * 0.3, 100.0)

    def flag_anomaly(self, session_id: str, reason: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].anomaly_flags.append(reason)

    def invalidate(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].invalidated = True

    @property
    def active_count(self) -> int:
        with self._lock:
            self._evict_expired()
            return sum(1 for s in self._sessions.values() if not s.invalidated)

    # ------------------------------------------------------------------

    def _evict_expired(self) -> None:
        """Remove sessions older than TTL (must be called under lock)."""
        cutoff = datetime.utcnow() - timedelta(hours=_SESSION_TTL_HOURS)
        expired = [
            sid for sid, s in self._sessions.items()
            if s.last_seen < cutoff
        ]
        for sid in expired:
            del self._sessions[sid]
