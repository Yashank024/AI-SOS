"""
aisos/memory/ip_reputation.py
--------------------------------
Per-IP reputation scoring using exponential moving average.
Pre-seeded with known bad actor IPs.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from aisos.core.event import AttackCategory

# EMA smoothing factor — higher = older history decays faster
_EMA_ALPHA = 0.3
_MALICIOUS_THRESHOLD = 70.0

# ---- Pre-seeded threat intel -------------------------------------------
_KNOWN_BAD_IPS: dict[str, float] = {
    "45.33.32.156":   95.0,    # Shodan scanner
    "80.82.77.139":   92.0,    # Shodan scanner
    "185.220.101.33": 90.0,    # Tor exit node
    "193.32.162.157": 88.0,    # Known scanner
    "89.248.165.116": 85.0,    # MassScanner
}


@dataclass
class _IPProfile:
    ip: str
    score: float = 0.0
    country: str = ""
    asn: str = ""
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    attack_count: int = 0
    attack_types: list[str] = field(default_factory=list)


class IPReputation:
    """Tracks per-IP reputation scores."""

    def __init__(self) -> None:
        self._profiles: dict[str, _IPProfile] = {}
        self._lock = threading.Lock()
        # Pre-seed
        for ip, score in _KNOWN_BAD_IPS.items():
            self._profiles[ip] = _IPProfile(ip=ip, score=score)

    # ------------------------------------------------------------------

    def update(self, ip: str, risk_score: float, attack_category: "AttackCategory") -> None:
        """Update or create an IP profile using EMA."""
        now = datetime.utcnow().isoformat()
        with self._lock:
            if ip not in self._profiles:
                self._profiles[ip] = _IPProfile(ip=ip, score=0.0, first_seen=now)
            profile = self._profiles[ip]
            # EMA update
            profile.score = _EMA_ALPHA * risk_score + (1 - _EMA_ALPHA) * profile.score
            profile.score = round(min(profile.score, 100.0), 2)
            profile.last_seen = now
            if risk_score > 20:
                profile.attack_count += 1
                cat_val = attack_category.value if hasattr(attack_category, "value") else str(attack_category)
                if cat_val not in profile.attack_types:
                    profile.attack_types.append(cat_val)

    def get_score(self, ip: str) -> float:
        with self._lock:
            profile = self._profiles.get(ip)
            return profile.score if profile else 0.0

    def get_profile(self, ip: str) -> dict:
        with self._lock:
            profile = self._profiles.get(ip)
            if not profile:
                return {}
            return {
                "ip": profile.ip,
                "score": profile.score,
                "country": profile.country,
                "asn": profile.asn,
                "first_seen": profile.first_seen,
                "last_seen": profile.last_seen,
                "attack_count": profile.attack_count,
                "attack_types": profile.attack_types,
            }

    def is_known_malicious(self, ip: str) -> bool:
        return self.get_score(ip) >= _MALICIOUS_THRESHOLD

    @property
    def count(self) -> int:
        return len(self._profiles)
