"""
aisos/core/capabilities.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Capability Manager for AI SOS.

Loads only the security components required by the host application and active
threat layer to maintain a lightweight footprint.
"""

from __future__ import annotations

import logging
from typing import Set

from aisos.core.topology import SecurityLayer

logger = logging.getLogger("aisos.capabilities")


class Capability:
    """Represents a discrete security verification capability."""
    PROMPT_PROTECTION = "prompt_protection"
    API_SECURITY = "api_security"
    RESPONSE_PROTECTION = "response_protection"


class CapabilityManager:
    """
    Manages active capabilities dynamically based on the current SecurityLayer.
    Avoids running unnecessary scanners to keep CPU overhead minimal during Normal Monitoring.
    """

    def __init__(self, disabled_capabilities: Set[str] | None = None) -> None:
        self._disabled = disabled_capabilities or set()
        self._active_capabilities: Set[str] = {
            Capability.API_SECURITY,
            Capability.PROMPT_PROTECTION,
            Capability.RESPONSE_PROTECTION,
        }

    def update_capabilities(self, layer: SecurityLayer) -> None:
        """Update active security modules based on the immune layer."""
        # Capabilities are enabled by default and tuned dynamically.
        # Developer overrides/disabled capabilities are honored.
        self._active_capabilities = {
            Capability.API_SECURITY,
            Capability.PROMPT_PROTECTION,
            Capability.RESPONSE_PROTECTION,
        } - self._disabled

        logger.debug("AI SOS: Active security capabilities: %s", self._active_capabilities)

    def is_active(self, capability: str) -> bool:
        """Check if a specific capability should be executed in the current pipeline run."""
        return capability in self._active_capabilities

    def disable_capability(self, capability: str) -> None:
        self._disabled.add(capability)

    def enable_capability(self, capability: str) -> None:
        if capability in self._disabled:
            self._disabled.remove(capability)
