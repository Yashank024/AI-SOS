"""
aisos/core/topology.py
~~~~~~~~~~~~~~~~~~~~~~~
Adaptive Security Topology Engine for AI SOS.

Implements the 5-layer Immune System architecture:
  Layer 1: Normal Monitoring      — Low overhead, passive observation, default logging.
  Layer 2: Suspicious Activity    — Deep inspection enabled, prompt scanner, lower thresholds.
  Layer 3: Active Protection      — Strict validation, aggressive rate limits, prompt/response inspection.
  Layer 4: Critical Lockdown      — Deep Packet Analysis, auto IP/session block, emergency incident alert.
  Layer 5: Recovery               — Automatic step-down & decay back to Layer 1 after threats subside.

The host application NEVER changes its code. Only AI SOS dynamically shifts its
internal security posture based on continuous event analysis.
"""

from __future__ import annotations

import time
from collections import deque
from enum import Enum
from typing import Any, Callable, Optional, Dict, List


class SecurityLayer(str, Enum):
    """5-level adaptive security posture layers."""
    LAYER_1_NORMAL = "Layer 1: Normal Monitoring"
    LAYER_2_SUSPICIOUS = "Layer 2: Suspicious Activity"
    LAYER_3_ACTIVE_PROTECTION = "Layer 3: Active Protection"
    LAYER_4_CRITICAL_LOCKDOWN = "Layer 4: Critical Lockdown"
    LAYER_5_RECOVERY = "Layer 5: Recovery"

    @property
    def level_number(self) -> int:
        mapping = {
            SecurityLayer.LAYER_1_NORMAL: 1,
            SecurityLayer.LAYER_2_SUSPICIOUS: 2,
            SecurityLayer.LAYER_3_ACTIVE_PROTECTION: 3,
            SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN: 4,
            SecurityLayer.LAYER_5_RECOVERY: 5,
        }
        return mapping[self]


class LayerCapabilities:
    """Configurable pipeline execution flags per layer."""

    def __init__(
        self,
        deep_packet_analysis: bool = False,
        prompt_scanner_strict: bool = False,
        response_inspection: bool = False,
        heavy_logging: bool = False,
        rate_limit_multiplier: float = 1.0,
        block_threshold_score: float = 85.0,
        challenge_threshold_score: float = 65.0,
        require_session_validation: bool = False,
    ) -> None:
        self.deep_packet_analysis = deep_packet_analysis
        self.prompt_scanner_strict = prompt_scanner_strict
        self.response_inspection = response_inspection
        self.heavy_logging = heavy_logging
        self.rate_limit_multiplier = rate_limit_multiplier
        self.block_threshold_score = block_threshold_score
        self.challenge_threshold_score = challenge_threshold_score
        self.require_session_validation = require_session_validation

    def to_dict(self) -> dict:
        return {
            "deep_packet_analysis": self.deep_packet_analysis,
            "prompt_scanner_strict": self.prompt_scanner_strict,
            "response_inspection": self.response_inspection,
            "heavy_logging": self.heavy_logging,
            "rate_limit_multiplier": self.rate_limit_multiplier,
            "block_threshold_score": self.block_threshold_score,
            "challenge_threshold_score": self.challenge_threshold_score,
            "require_session_validation": self.require_session_validation,
        }


# Default capability maps per layer
LAYER_DEFAULTS: Dict[SecurityLayer, LayerCapabilities] = {
    SecurityLayer.LAYER_1_NORMAL: LayerCapabilities(
        deep_packet_analysis=False,
        prompt_scanner_strict=False,
        response_inspection=False,
        heavy_logging=False,
        rate_limit_multiplier=1.0,
        block_threshold_score=85.0,
        challenge_threshold_score=70.0,
        require_session_validation=False,
    ),
    SecurityLayer.LAYER_2_SUSPICIOUS: LayerCapabilities(
        deep_packet_analysis=False,
        prompt_scanner_strict=True,
        response_inspection=True,
        heavy_logging=True,
        rate_limit_multiplier=1.5,
        block_threshold_score=75.0,
        challenge_threshold_score=55.0,
        require_session_validation=False,
    ),
    SecurityLayer.LAYER_3_ACTIVE_PROTECTION: LayerCapabilities(
        deep_packet_analysis=True,
        prompt_scanner_strict=True,
        response_inspection=True,
        heavy_logging=True,
        rate_limit_multiplier=2.5,
        block_threshold_score=65.0,
        challenge_threshold_score=45.0,
        require_session_validation=True,
    ),
    SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN: LayerCapabilities(
        deep_packet_analysis=True,
        prompt_scanner_strict=True,
        response_inspection=True,
        heavy_logging=True,
        rate_limit_multiplier=5.0,
        block_threshold_score=50.0,
        challenge_threshold_score=30.0,
        require_session_validation=True,
    ),
    SecurityLayer.LAYER_5_RECOVERY: LayerCapabilities(
        deep_packet_analysis=False,
        prompt_scanner_strict=True,
        response_inspection=False,
        heavy_logging=True,
        rate_limit_multiplier=1.2,
        block_threshold_score=80.0,
        challenge_threshold_score=60.0,
        require_session_validation=False,
    ),
}


class AdaptiveTopologyManager:
    """
    Manages live security topology transitions and decay.

    Monitors rolling risk metrics and automatically moves between Layer 1..5.
    """

    def __init__(
        self,
        cooldown_seconds: float = 60.0,
        history_window_size: int = 50,
        on_layer_change: Optional[Callable[[SecurityLayer, SecurityLayer], None]] = None,
    ) -> None:
        self._current_layer: SecurityLayer = SecurityLayer.LAYER_1_NORMAL
        self._cooldown_seconds: float = cooldown_seconds
        self._last_high_threat_time: float = 0.0
        self._recent_scores: deque[float] = deque(maxlen=history_window_size)
        self._recent_threat_counts: deque[bool] = deque(maxlen=history_window_size)
        self._layer_transition_history: List[dict] = []
        self._on_layer_change = on_layer_change

    @property
    def current_layer(self) -> SecurityLayer:
        return self._current_layer

    @property
    def capabilities(self) -> LayerCapabilities:
        return LAYER_DEFAULTS[self._current_layer]

    def record_event_metrics(self, risk_score: float, is_threat: bool) -> SecurityLayer:
        """
        Record event metrics and evaluate layer transition.
        Returns the active SecurityLayer post-evaluation.
        """
        now = time.monotonic()
        self._recent_scores.append(risk_score)
        self._recent_threat_counts.append(is_threat)

        if is_threat or risk_score >= 60.0:
            self._last_high_threat_time = now

        # Calculate average risk over rolling window
        avg_risk = (
            sum(self._recent_scores) / len(self._recent_scores)
            if self._recent_scores
            else 0.0
        )
        recent_threat_ratio = (
            sum(1 for t in self._recent_threat_counts if t) / len(self._recent_threat_counts)
            if self._recent_threat_counts
            else 0.0
        )

        target_layer = self._determine_target_layer(risk_score, avg_risk, recent_threat_ratio, is_threat)

        # Handle decay / recovery logic
        time_since_threat = now - self._last_high_threat_time if self._last_high_threat_time > 0 else 99999.0

        if target_layer.level_number < self._current_layer.level_number:
            # Step down only if cooldown window has elapsed
            if time_since_threat >= self._cooldown_seconds:
                if self._current_layer == SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN:
                    # Transition to Layer 5 (Recovery) first
                    self._transition_to(SecurityLayer.LAYER_5_RECOVERY, "threat subsided — entering recovery")
                elif self._current_layer == SecurityLayer.LAYER_5_RECOVERY:
                    self._transition_to(SecurityLayer.LAYER_1_NORMAL, "recovery period complete — normal monitoring")
                else:
                    self._transition_to(target_layer, f"decay window reached ({time_since_threat:.1f}s clean)")
        elif target_layer.level_number > self._current_layer.level_number:
            # Step up immediately upon threat elevation
            self._transition_to(target_layer, f"threat elevated (score={risk_score:.1f}, avg={avg_risk:.1f})")

        return self._current_layer

    def _determine_target_layer(
        self, score: float, avg_risk: float, threat_ratio: float, is_critical_threat: bool
    ) -> SecurityLayer:
        if score >= 85.0 or (avg_risk >= 70.0 and threat_ratio >= 0.3):
            return SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN
        elif score >= 65.0 or avg_risk >= 50.0 or threat_ratio >= 0.2:
            return SecurityLayer.LAYER_3_ACTIVE_PROTECTION
        elif score >= 40.0 or avg_risk >= 30.0 or threat_ratio >= 0.1:
            return SecurityLayer.LAYER_2_SUSPICIOUS
        else:
            return SecurityLayer.LAYER_1_NORMAL

    def _transition_to(self, new_layer: SecurityLayer, reason: str) -> None:
        old_layer = self._current_layer
        if old_layer == new_layer:
            return

        self._current_layer = new_layer
        transition_record = {
            "timestamp": time.time(),
            "from": old_layer.value,
            "to": new_layer.value,
            "reason": reason,
        }
        self._layer_transition_history.append(transition_record)
        if len(self._layer_transition_history) > 100:
            self._layer_transition_history.pop(0)

        if self._on_layer_change:
            try:
                self._on_layer_change(old_layer, new_layer)
            except Exception:
                pass

    def force_layer(self, layer: SecurityLayer, reason: str = "manual override") -> None:
        """Manually override current layer (e.g. for testing or operator lockdown)."""
        self._transition_to(layer, reason)

    def get_status(self) -> dict:
        return {
            "current_layer": self._current_layer.value,
            "layer_level": self._current_layer.level_number,
            "capabilities": self.capabilities.to_dict(),
            "rolling_avg_risk": (
                round(sum(self._recent_scores) / max(len(self._recent_scores), 1), 2)
            ),
            "recent_threat_ratio": (
                round(
                    sum(1 for t in self._recent_threat_counts if t)
                    / max(len(self._recent_threat_counts), 1),
                    2,
                )
            ),
            "recent_transitions": self._layer_transition_history[-5:],
        }
