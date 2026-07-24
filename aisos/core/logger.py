"""
aisos/core/logger.py
~~~~~~~~~~~~~~~~~~~~~
Structured security logger for the AI SOS framework.

Features
--------
- JSON-formatted log records (machine-parseable by SIEM / log aggregators)
- Optional rich-colored console output when the `rich` library is available
- Per-event, per-decision, per-incident, and per-agent-report logging helpers
- Thread-safe — uses the stdlib `logging` module under the hood
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import traceback
from datetime import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from aisos.core.event import AgentReport, Incident, SecurityEvent

# ---------------------------------------------------------------------------
# Try to import Rich for pretty console output (optional)
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.logging import RichHandler

    _RICH_AVAILABLE = True
    _rich_console = Console(stderr=True)
except ImportError:
    _RICH_AVAILABLE = False
    _rich_console = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Severity → logging level mapping
# ---------------------------------------------------------------------------
_SEVERITY_TO_LEVEL = {
    "info": logging.INFO,
    "low": logging.INFO,
    "medium": logging.WARNING,
    "high": logging.ERROR,
    "critical": logging.CRITICAL,
}


# ---------------------------------------------------------------------------
# JSON log formatter
# ---------------------------------------------------------------------------

class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    RESERVED_ATTRS = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName",
    }

    def format(self, record: logging.LogRecord) -> str:
        # Build the base dict
        log_dict: dict = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach exc_info if present
        if record.exc_info:
            log_dict["exception"] = self.formatException(record.exc_info)

        # Attach any extra fields the caller passed
        for key, val in record.__dict__.items():
            if key not in self.RESERVED_ATTRS and not key.startswith("_"):
                try:
                    # Ensure serializability
                    json.dumps(val)
                    log_dict[key] = val
                except (TypeError, ValueError):
                    log_dict[key] = str(val)

        return json.dumps(log_dict, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Module-level setup helpers
# ---------------------------------------------------------------------------

_root_configured = False


def setup_logger(
    level: str = "info",
    log_file: str | None = None,
    use_rich: bool = True,
    logger_name: str = "aisos",
) -> logging.Logger:
    """
    Configure and return the root aisos logger.

    Parameters
    ----------
    level:       Minimum log level (debug | info | warning | error | critical).
    log_file:    Optional path to a JSON log file.  Rotated at 10 MB, keeping
                 3 backups.
    use_rich:    Use Rich colored console output if available.
    logger_name: Name of the root logger (default: "aisos").
    """
    global _root_configured

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger(logger_name)

    if _root_configured:
        # Update level only; don't add duplicate handlers
        logger.setLevel(numeric_level)
        return logger

    logger.setLevel(numeric_level)
    logger.propagate = False

    # ---------- Console handler ----------
    if use_rich and _RICH_AVAILABLE:
        console_handler = RichHandler(
            console=_rich_console,  # type: ignore[arg-type]
            show_time=True,
            show_level=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(_JsonFormatter())

    console_handler.setLevel(numeric_level)
    logger.addHandler(console_handler)

    # ---------- File handler (JSON) ----------
    if log_file:
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=3,
                encoding="utf-8",
            )
            file_handler.setFormatter(_JsonFormatter())
            file_handler.setLevel(numeric_level)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("Could not open log file '%s': %s", log_file, exc)

    _root_configured = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the 'aisos' namespace.

    Example
    -------
    >>> log = get_logger("core.pipeline")
    # produces the logger "aisos.core.pipeline"
    """
    return logging.getLogger(f"aisos.{name}")


# ---------------------------------------------------------------------------
# SecurityLogger — domain-specific logging helper
# ---------------------------------------------------------------------------

class SecurityLogger:
    """
    High-level logging facade for security events, decisions, incidents,
    and agent reports.

    Usage
    -----
    >>> sec_log = SecurityLogger()
    >>> sec_log.log_event(event)
    >>> sec_log.log_decision(event)
    """

    def __init__(
        self,
        level: str = "info",
        log_file: str | None = None,
        use_rich: bool = True,
    ) -> None:
        self._root = setup_logger(level=level, log_file=log_file, use_rich=use_rich)
        self._logger = get_logger("security")

    # ------------------------------------------------------------------ #
    # Public logging methods                                               #
    # ------------------------------------------------------------------ #

    def log_event(self, event: "SecurityEvent") -> None:
        """Log a SecurityEvent at the level matching its severity."""
        from aisos.core.event import AttackCategory

        log_level = _SEVERITY_TO_LEVEL.get(event.severity.value, logging.INFO)

        msg = self._format_event_message(event)
        extra = self._event_extra(event)

        self._logger.log(log_level, msg, extra=extra)

    def log_decision(self, event: "SecurityEvent") -> None:
        """Log the Brain's decision and reasoning for a SecurityEvent."""
        if event.decision is None:
            return

        decision_str = event.decision.value.upper()
        msg = (
            f"[DECISION] {decision_str} — {event.event_type} "
            f"from {event.source_ip or 'unknown'} "
            f"(risk={event.risk_score:.1f}, confidence={event.confidence:.2f})"
        )
        if event.decision_reasoning:
            msg += f" | Reason: {event.decision_reasoning}"

        level = logging.WARNING if event.is_blocked else logging.INFO
        extra = {
            **self._event_extra(event),
            "decision": event.decision.value,
            "decision_reasoning": event.decision_reasoning,
            "actions_taken": event.actions_taken,
        }
        self._logger.log(level, msg, extra=extra)

    def log_incident(self, incident: "Incident") -> None:
        """Log a generated security incident."""
        level = _SEVERITY_TO_LEVEL.get(incident.severity.value, logging.WARNING)
        msg = (
            f"[INCIDENT] {incident.title} — "
            f"severity={incident.severity.value.upper()}, "
            f"category={incident.attack_category.value}, "
            f"source_ip={incident.source_ip or 'unknown'}, "
            f"events={len(incident.related_events)}"
        )
        extra = {
            "incident_id": incident.id,
            "incident_title": incident.title,
            "incident_severity": incident.severity.value,
            "attack_category": incident.attack_category.value,
            "source_ip": incident.source_ip,
            "related_event_count": len(incident.related_events),
        }
        self._logger.log(level, msg, extra=extra)

    def log_agent_report(self, agent_name: str, report: "AgentReport") -> None:
        """Log a security agent's findings."""
        indicators = ", ".join(report.attack_indicators) if report.attack_indicators else "none"
        action = report.recommended_action.value if report.recommended_action else "none"
        msg = (
            f"[AGENT:{agent_name}] risk_contribution={report.risk_contribution:.2f}, "
            f"confidence={report.confidence:.2f}, "
            f"recommended_action={action}, "
            f"indicators=[{indicators}]"
        )
        if report.observations:
            msg += f" | observations: {'; '.join(report.observations[:3])}"

        extra = {
            "agent_name": agent_name,
            "risk_contribution": report.risk_contribution,
            "confidence": report.confidence,
            "attack_indicators": report.attack_indicators,
            "recommended_action": action,
        }
        self._logger.info(msg, extra=extra)

    def log_engine_start(self, version: str, config_path: str | None) -> None:
        """Log engine startup."""
        self._logger.info(
            f"[ENGINE] AI SOS Security Engine v{version} starting — "
            f"config={config_path or 'defaults'}",
            extra={"engine_version": version, "config_path": config_path},
        )

    def log_engine_stop(self) -> None:
        """Log engine shutdown."""
        self._logger.info("[ENGINE] Security Engine stopped gracefully")

    def log_heartbeat(self, stats: dict) -> None:
        """Log a periodic heartbeat with engine statistics."""
        self._logger.debug(
            "[HEARTBEAT] Engine alive — "
            f"events={stats.get('total_events', 0)}, "
            f"threats={stats.get('threats_detected', 0)}, "
            f"blocks={stats.get('blocks_issued', 0)}",
            extra={"heartbeat": True, **stats},
        )

    def log_plugin_registered(self, plugin_name: str) -> None:
        self._logger.info(
            f"[PLUGIN] Registered: {plugin_name}",
            extra={"plugin_name": plugin_name},
        )

    def log_error(self, message: str, exc: Exception | None = None) -> None:
        """Log a framework error."""
        extra: dict = {"error_type": type(exc).__name__ if exc else "unknown"}
        if exc:
            extra["traceback"] = traceback.format_exc()
        self._logger.error(f"[ERROR] {message}", extra=extra, exc_info=exc is not None)

    def log_warning(self, message: str, **kwargs) -> None:
        """Log a framework warning."""
        self._logger.warning(f"[WARN] {message}", extra=kwargs)

    def log_info(self, message: str, **kwargs) -> None:
        """Log a general info message."""
        self._logger.info(message, extra=kwargs)

    def log_debug(self, message: str, **kwargs) -> None:
        """Log a debug message."""
        self._logger.debug(message, extra=kwargs)

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _format_event_message(event: "SecurityEvent") -> str:
        parts = [f"[{event.event_type.upper()}]"]

        if event.is_threat:
            parts.append(f"THREAT:{event.attack_category.value}")
        else:
            parts.append("clean")

        if event.method and event.path:
            parts.append(f"{event.method} {event.path}")
        elif event.raw_data:
            # Truncate to avoid flooding logs with large payloads
            raw_repr = str(event.raw_data)[:120]
            parts.append(raw_repr)

        parts.append(f"ip={event.source_ip or 'unknown'}")
        parts.append(f"severity={event.severity.value}")
        parts.append(f"risk={event.risk_score:.1f}")

        if event.decision:
            parts.append(f"decision={event.decision.value}")

        return " | ".join(parts)

    @staticmethod
    def _event_extra(event: "SecurityEvent") -> dict:
        return {
            "event_id": event.id,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "severity": event.severity.value,
            "risk_score": round(event.risk_score, 2),
            "confidence": round(event.confidence, 3),
            "attack_category": event.attack_category.value,
            "attack_indicators": event.attack_indicators,
            "decision": event.decision.value if event.decision else None,
            "method": event.method,
            "path": event.path,
            "user_id": event.user_id,
            "session_id": event.session_id,
            "country": event.country,
            "processing_time_ms": event.processing_time_ms,
        }
