"""
AI SOS — Production-Grade Adaptive Security Layer Framework

"Never replace the developer's existing stack. Silently observe it,
protect it, adapt to threats, and continuously improve through memory
and learning while remaining invisible during normal operation."

Usage:
>>> import aisos
>>> security = aisos.init()
>>> security.attach(app)  # FastAPI, Flask, Django, OpenAI, etc.
"""

from aisos.attach import attach, enable_ai, get_engine, init, SecurityContext
from aisos.core.config import Config, load_config
from aisos.core.engine import SecurityEngine
from aisos.core.event import AttackCategory, Decision, SecurityEvent, Severity
from aisos.core.topology import SecurityLayer

__version__ = "0.2.0"

__all__ = [
    "init",
    "attach",
    "enable_ai",
    "get_engine",
    "SecurityContext",
    "SecurityEngine",
    "SecurityEvent",
    "Decision",
    "AttackCategory",
    "Severity",
    "SecurityLayer",
    "Config",
    "load_config",
]
