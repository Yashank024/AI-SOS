"""
tests/test_topology.py
~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for the 5-layer Immune System Adaptive Security Topology.
"""

import time
import pytest
from aisos.core.topology import AdaptiveTopologyManager, SecurityLayer


def test_initial_layer_is_normal():
    mgr = AdaptiveTopologyManager(cooldown_seconds=1.0)
    assert mgr.current_layer == SecurityLayer.LAYER_1_NORMAL
    assert mgr.current_layer.level_number == 1
    assert mgr.capabilities.deep_packet_analysis is False


def test_layer_transition_to_suspicious():
    mgr = AdaptiveTopologyManager(cooldown_seconds=1.0)
    # Risk score 45 triggers Layer 2: Suspicious
    active = mgr.record_event_metrics(risk_score=45.0, is_threat=False)
    assert active == SecurityLayer.LAYER_2_SUSPICIOUS
    assert mgr.capabilities.prompt_scanner_strict is True


def test_layer_transition_to_active_protection():
    mgr = AdaptiveTopologyManager(cooldown_seconds=1.0)
    # Risk score 68 triggers Layer 3: Active Protection
    active = mgr.record_event_metrics(risk_score=68.0, is_threat=False)
    assert active == SecurityLayer.LAYER_3_ACTIVE_PROTECTION
    assert mgr.capabilities.rate_limit_multiplier == 2.5


def test_layer_transition_to_critical_lockdown():
    mgr = AdaptiveTopologyManager(cooldown_seconds=1.0)
    # Risk score 90 triggers Layer 4: Critical Lockdown
    active = mgr.record_event_metrics(risk_score=90.0, is_threat=True)
    assert active == SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN
    assert mgr.capabilities.deep_packet_analysis is True
    assert mgr.capabilities.rate_limit_multiplier == 5.0


def test_recovery_stepdown_after_cooldown():
    mgr = AdaptiveTopologyManager(cooldown_seconds=0.1)
    # Force to Lockdown first
    mgr.record_event_metrics(risk_score=95.0, is_threat=True)
    assert mgr.current_layer == SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN

    # Sleep past cooldown window
    time.sleep(0.15)

    # Low risk clean event triggers step-down to Layer 5 (Recovery)
    layer = mgr.record_event_metrics(risk_score=10.0, is_threat=False)
    assert layer == SecurityLayer.LAYER_5_RECOVERY

    # Subsequent clean event past cooldown completes recovery back to Layer 1 (Normal)
    time.sleep(0.15)
    layer_final = mgr.record_event_metrics(risk_score=5.0, is_threat=False)
    assert layer_final == SecurityLayer.LAYER_1_NORMAL
