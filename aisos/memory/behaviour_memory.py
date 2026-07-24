"""
aisos/memory/behaviour_memory.py
----------------------------------
User and IP behavioural baseline tracking using EMA.

Tracks: request rate, path diversity, method distribution, timing.
Drift score measures how far a current request deviates from baseline.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

_EMA_ALPHA = 0.1   # slow-moving baseline


@dataclass
class _Baseline:
    key: str                           # user_id or IP
    request_count: int = 0
    avg_risk: float = 0.0
    method_counts: dict[str, int] = field(default_factory=dict)
    path_set: set[str] = field(default_factory=set)
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # EMA baselines
    ema_risk: float = 0.0
    ema_path_diversity: float = 0.0    # unique paths / total requests


class BehaviourMemory:
    """Tracks behavioural baselines and computes drift scores."""

    def __init__(self) -> None:
        self._baselines: dict[str, _Baseline] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------

    def update(self, event: "SecurityEvent") -> None:
        keys: list[str] = [event.source_ip]
        if event.user_id:
            keys.append(event.user_id)

        with self._lock:
            for key in keys:
                if key not in self._baselines:
                    self._baselines[key] = _Baseline(key=key)
                bl = self._baselines[key]
                bl.request_count += 1
                bl.last_seen = event.timestamp.isoformat()
                # Update method distribution
                method = (event.method or "UNKNOWN").upper()
                bl.method_counts[method] = bl.method_counts.get(method, 0) + 1
                # Update path set
                bl.path_set.add(event.path.split("?")[0])
                # EMA risk
                bl.ema_risk = _EMA_ALPHA * event.risk_score + (1 - _EMA_ALPHA) * bl.ema_risk
                # EMA path diversity
                diversity = len(bl.path_set) / bl.request_count
                bl.ema_path_diversity = (
                    _EMA_ALPHA * diversity + (1 - _EMA_ALPHA) * bl.ema_path_diversity
                )

    def get_drift_score(self, user_id_or_ip: str) -> float:
        """
        Returns 0–100. Higher = more anomalous vs baseline.
        Considers: sudden risk spike, method anomaly, path explosion.
        """
        with self._lock:
            bl = self._baselines.get(user_id_or_ip)
            if not bl or bl.request_count < 5:
                return 0.0

            risk_drift = abs(bl.ema_risk - (bl.avg_risk or bl.ema_risk))
            diversity_drift = bl.ema_path_diversity * 100  # high diversity = scanning
            method_variety = len(bl.method_counts) * 10   # many methods = suspicious
            drift = risk_drift * 0.5 + diversity_drift * 0.3 + method_variety * 0.2
            return min(round(drift, 2), 100.0)

    def get_baseline(self, user_id_or_ip: str) -> dict:
        with self._lock:
            bl = self._baselines.get(user_id_or_ip)
            if not bl:
                return {}
            return {
                "key": bl.key,
                "request_count": bl.request_count,
                "ema_risk": round(bl.ema_risk, 2),
                "ema_path_diversity": round(bl.ema_path_diversity, 4),
                "method_counts": dict(bl.method_counts),
                "unique_paths": len(bl.path_set),
                "first_seen": bl.first_seen,
                "last_seen": bl.last_seen,
            }
