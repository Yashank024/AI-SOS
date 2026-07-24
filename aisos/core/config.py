"""
aisos/core/config.py
~~~~~~~~~~~~~~~~~~~~~
Configuration loader for the AI SOS security framework.

Search order for the config file:
  1. Explicit path passed to load_config()
  2. ./aisos.yaml  (current working directory)
  3. Walk up the directory tree until the filesystem root
  4. Falls back to DEFAULT_CONFIG if nothing is found.
"""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

import yaml


# ---------------------------------------------------------------------------
# Nested config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EmailConfig:
    enabled: bool = False
    address: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "EmailConfig":
        return cls(
            enabled=bool(data.get("enabled", False)),
            address=str(data.get("address", "")),
        )

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "address": self.address}

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.enabled and not self.address:
            errors.append("notifications.email.address is required when email notifications are enabled")
        if self.enabled and "@" not in self.address:
            errors.append(f"notifications.email.address '{self.address}' does not look like a valid email")
        return errors


@dataclass
class DiscordConfig:
    enabled: bool = False
    webhook: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "DiscordConfig":
        return cls(
            enabled=bool(data.get("enabled", False)),
            webhook=str(data.get("webhook", "")),
        )

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "webhook": self.webhook}

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.enabled and not self.webhook:
            errors.append("notifications.discord.webhook is required when Discord notifications are enabled")
        if self.enabled and not self.webhook.startswith("https://discord.com/api/webhooks/"):
            errors.append("notifications.discord.webhook does not look like a valid Discord webhook URL")
        return errors


@dataclass
class SlackConfig:
    enabled: bool = False
    webhook: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "SlackConfig":
        return cls(
            enabled=bool(data.get("enabled", False)),
            webhook=str(data.get("webhook", "")),
        )

    def to_dict(self) -> dict:
        return {"enabled": self.enabled, "webhook": self.webhook}

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.enabled and not self.webhook:
            errors.append("notifications.slack.webhook is required when Slack notifications are enabled")
        if self.enabled and not self.webhook.startswith("https://hooks.slack.com/"):
            errors.append("notifications.slack.webhook does not look like a valid Slack webhook URL")
        return errors


@dataclass
class NotificationConfig:
    email: EmailConfig = field(default_factory=EmailConfig)
    discord: DiscordConfig = field(default_factory=DiscordConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)

    @classmethod
    def from_dict(cls, data: dict) -> "NotificationConfig":
        return cls(
            email=EmailConfig.from_dict(data.get("email", {})),
            discord=DiscordConfig.from_dict(data.get("discord", {})),
            slack=SlackConfig.from_dict(data.get("slack", {})),
        )

    def to_dict(self) -> dict:
        return {
            "email": self.email.to_dict(),
            "discord": self.discord.to_dict(),
            "slack": self.slack.to_dict(),
        }

    def validate(self) -> list[str]:
        return self.email.validate() + self.discord.validate() + self.slack.validate()

    @property
    def any_enabled(self) -> bool:
        return self.email.enabled or self.discord.enabled or self.slack.enabled


@dataclass
class AIConfig:
    """Configuration for AI-specific security detections."""

    # One of: openrouter | ollama | openai
    provider: str = "openrouter"
    api_key: str = ""
    model: str = ""
    base_url: str = ""

    prompt_injection: bool = True
    jailbreak_detection: bool = True
    system_prompt_leak: bool = True

    # Confidence threshold below which AI detections are suppressed (0–1)
    min_confidence: float = 0.6

    @classmethod
    def from_dict(cls, data: dict) -> "AIConfig":
        return cls(
            provider=str(data.get("provider", "openrouter")).lower(),
            api_key=str(data.get("api_key", "")),
            model=str(data.get("model", "")),
            base_url=str(data.get("base_url", "")),
            prompt_injection=bool(data.get("prompt_injection", True)),
            jailbreak_detection=bool(data.get("jailbreak_detection", True)),
            system_prompt_leak=bool(data.get("system_prompt_leak", True)),
            min_confidence=float(data.get("min_confidence", 0.6)),
        )

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "api_key": "***" if self.api_key else "",
            "model": self.model,
            "base_url": self.base_url,
            "prompt_injection": self.prompt_injection,
            "jailbreak_detection": self.jailbreak_detection,
            "system_prompt_leak": self.system_prompt_leak,
            "min_confidence": self.min_confidence,
        }

    def validate(self) -> list[str]:
        errors: list[str] = []
        valid_providers = {"openrouter", "ollama", "openai"}
        if self.provider not in valid_providers:
            errors.append(f"security.ai.provider must be one of {valid_providers}, got '{self.provider}'")
        if not (0.0 <= self.min_confidence <= 1.0):
            errors.append(f"security.ai.min_confidence must be between 0.0 and 1.0, got {self.min_confidence}")
        return errors


@dataclass
class ProtectionConfig:
    """Classic web / API protection toggles."""

    sql_injection: bool = True
    xss: bool = True
    csrf: bool = True
    ssrf: bool = True
    api_scanning: bool = True
    credential_stuffing: bool = True
    session_hijacking: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "ProtectionConfig":
        return cls(
            sql_injection=bool(data.get("sql_injection", True)),
            xss=bool(data.get("xss", True)),
            csrf=bool(data.get("csrf", True)),
            ssrf=bool(data.get("ssrf", True)),
            api_scanning=bool(data.get("api_scanning", True)),
            credential_stuffing=bool(data.get("credential_stuffing", True)),
            session_hijacking=bool(data.get("session_hijacking", True)),
        )

    def to_dict(self) -> dict:
        return {
            "sql_injection": self.sql_injection,
            "xss": self.xss,
            "csrf": self.csrf,
            "ssrf": self.ssrf,
            "api_scanning": self.api_scanning,
            "credential_stuffing": self.credential_stuffing,
            "session_hijacking": self.session_hijacking,
        }

    def validate(self) -> list[str]:
        return []  # All fields are boolean — no validation required


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    # Per-IP requests per minute (0 = unlimited)
    requests_per_minute: int = 120

    # Max failed auth attempts before temporary lockout
    auth_attempts: int = 5

    # Duration in seconds for auth lockout
    lockout_seconds: int = 300

    @classmethod
    def from_dict(cls, data: dict) -> "RateLimitConfig":
        return cls(
            requests_per_minute=int(data.get("requests_per_minute", 120)),
            auth_attempts=int(data.get("auth_attempts", 5)),
            lockout_seconds=int(data.get("lockout_seconds", 300)),
        )

    def to_dict(self) -> dict:
        return {
            "requests_per_minute": self.requests_per_minute,
            "auth_attempts": self.auth_attempts,
            "lockout_seconds": self.lockout_seconds,
        }

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.requests_per_minute < 0:
            errors.append("security.rate_limits.requests_per_minute must be >= 0")
        if self.auth_attempts < 1:
            errors.append("security.rate_limits.auth_attempts must be >= 1")
        if self.lockout_seconds < 0:
            errors.append("security.rate_limits.lockout_seconds must be >= 0")
        return errors


@dataclass
class DashboardConfig:
    """Real-time security dashboard settings."""

    enabled: bool = True
    port: int = 8765
    auth: bool = False
    username: str = "admin"
    password: str = ""
    host: str = "127.0.0.1"

    @classmethod
    def from_dict(cls, data: dict) -> "DashboardConfig":
        return cls(
            enabled=bool(data.get("enabled", True)),
            port=int(data.get("port", 8765)),
            auth=bool(data.get("auth", False)),
            username=str(data.get("username", "admin")),
            password=str(data.get("password", "")),
            host=str(data.get("host", "127.0.0.1")),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "port": self.port,
            "auth": self.auth,
            "username": self.username,
            "password": "***" if self.password else "",
            "host": self.host,
        }

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.port < 1 or self.port > 65535:
            errors.append(f"security.dashboard.port must be between 1 and 65535, got {self.port}")
        if self.auth and not self.password:
            errors.append("security.dashboard.password is required when dashboard auth is enabled")
        return errors


@dataclass
class PolicyRule:
    """A single IF/THEN policy rule."""

    id: str = ""
    description: str = ""
    # IF conditions — all must match (None / missing = wildcard)
    if_attack_category: Optional[str] = None
    if_severity: Optional[str] = None
    if_source_ip: Optional[str] = None
    if_path_pattern: Optional[str] = None
    # THEN actions
    then_decision: str = "allow"
    then_notify: bool = False
    then_generate_incident: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "PolicyRule":
        if_block = data.get("if", {})
        then_block = data.get("then", {})
        return cls(
            id=str(data.get("id", "")),
            description=str(data.get("description", "")),
            if_attack_category=if_block.get("attack_category"),
            if_severity=if_block.get("severity"),
            if_source_ip=if_block.get("source_ip"),
            if_path_pattern=if_block.get("path_pattern"),
            then_decision=str(then_block.get("decision", "allow")),
            then_notify=bool(then_block.get("notify", False)),
            then_generate_incident=bool(then_block.get("generate_incident", False)),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "if": {
                k: v for k, v in {
                    "attack_category": self.if_attack_category,
                    "severity": self.if_severity,
                    "source_ip": self.if_source_ip,
                    "path_pattern": self.if_path_pattern,
                }.items() if v is not None
            },
            "then": {
                "decision": self.then_decision,
                "notify": self.then_notify,
                "generate_incident": self.then_generate_incident,
            },
        }


# ---------------------------------------------------------------------------
# Root Config
# ---------------------------------------------------------------------------

_VALID_LOG_LEVELS = {"debug", "info", "warning", "error", "critical"}


@dataclass
class Config:
    """Root configuration object for the AI SOS framework."""

    monitoring: bool = True
    log_level: str = "info"
    log_file: Optional[str] = None

    ai: AIConfig = field(default_factory=AIConfig)
    protection: ProtectionConfig = field(default_factory=ProtectionConfig)
    rate_limits: RateLimitConfig = field(default_factory=RateLimitConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    policies: list[PolicyRule] = field(default_factory=list)

    # Where the config file was loaded from (None = defaults)
    _source_path: Optional[str] = field(default=None, repr=False, compare=False)

    # ------------------------------------------------------------------ #
    # Construction helpers                                                 #
    # ------------------------------------------------------------------ #

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """Build a Config from a raw dictionary (e.g., parsed YAML)."""
        security = data.get("security", {})
        raw_policies = data.get("policies", [])

        return cls(
            monitoring=bool(security.get("monitoring", True)),
            log_level=str(security.get("log_level", "info")).lower(),
            log_file=security.get("log_file"),
            ai=AIConfig.from_dict(security.get("ai", {})),
            protection=ProtectionConfig.from_dict(security.get("protection", {})),
            rate_limits=RateLimitConfig.from_dict(security.get("rate_limits", {})),
            notifications=NotificationConfig.from_dict(security.get("notifications", {})),
            dashboard=DashboardConfig.from_dict(security.get("dashboard", {})),
            policies=[PolicyRule.from_dict(p) for p in raw_policies if isinstance(p, dict)],
        )

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        """Load config from a YAML file path."""
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        cfg = cls.from_dict(raw)
        cfg._source_path = path
        return cfg

    # ------------------------------------------------------------------ #
    # Serialisation                                                        #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Serialise config to a nested dictionary (secrets redacted)."""
        return {
            "security": {
                "monitoring": self.monitoring,
                "log_level": self.log_level,
                "log_file": self.log_file,
                "ai": self.ai.to_dict(),
                "protection": self.protection.to_dict(),
                "rate_limits": self.rate_limits.to_dict(),
                "notifications": self.notifications.to_dict(),
                "dashboard": self.dashboard.to_dict(),
            },
            "policies": [p.to_dict() for p in self.policies],
            "_meta": {
                "source_path": self._source_path,
            },
        }

    # ------------------------------------------------------------------ #
    # Validation                                                           #
    # ------------------------------------------------------------------ #

    def validate(self) -> list[str]:
        """Return a list of validation error strings (empty = valid)."""
        errors: list[str] = []

        if self.log_level not in _VALID_LOG_LEVELS:
            errors.append(
                f"security.log_level must be one of {_VALID_LOG_LEVELS}, got '{self.log_level}'"
            )

        errors.extend(self.ai.validate())
        errors.extend(self.protection.validate())
        errors.extend(self.rate_limits.validate())
        errors.extend(self.notifications.validate())
        errors.extend(self.dashboard.validate())

        return errors

    def is_valid(self) -> bool:
        return len(self.validate()) == 0

    # ------------------------------------------------------------------ #
    # Convenience accessors                                                #
    # ------------------------------------------------------------------ #

    @property
    def source_path(self) -> Optional[str]:
        return self._source_path


# ---------------------------------------------------------------------------
# DEFAULT_CONFIG constant
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = Config()


# ---------------------------------------------------------------------------
# File discovery + loader
# ---------------------------------------------------------------------------

_CONFIG_FILENAMES = ("aisos.yaml", "aisos.yml", ".aisos.yaml", ".aisos.yml")


def _find_config_file(start_dir: str | None = None) -> Optional[str]:
    """
    Walk from *start_dir* (default: cwd) upwards, looking for a config file.
    Returns the absolute path of the first match, or None.
    """
    search_dir = Path(start_dir or os.getcwd()).resolve()
    root = Path(search_dir.anchor)

    while True:
        for name in _CONFIG_FILENAMES:
            candidate = search_dir / name
            if candidate.is_file():
                return str(candidate)
        if search_dir == root:
            break
        search_dir = search_dir.parent

    return None


def load_config(path: str | None = None) -> "Config":
    """
    Load and return a Config object.

    Search order:
      1. *path* if explicitly provided
      2. Auto-discovery from cwd upwards
      3. Returns DEFAULT_CONFIG (built-in defaults) if nothing is found

    Validation warnings are printed to stderr but do NOT raise exceptions —
    the framework should still start with an invalid config so operators can
    fix the file without a hard crash.
    """
    import sys

    # 1. Explicit path
    if path is not None:
        resolved = str(Path(path).resolve())
        if not Path(resolved).is_file():
            print(
                f"[aisos] WARNING: config file not found at '{resolved}', using defaults",
                file=sys.stderr,
            )
            return copy.deepcopy(DEFAULT_CONFIG)
        try:
            cfg = Config.from_yaml(resolved)
        except yaml.YAMLError as exc:
            print(f"[aisos] ERROR: failed to parse YAML config at '{resolved}': {exc}", file=sys.stderr)
            return copy.deepcopy(DEFAULT_CONFIG)
        _emit_validation_warnings(cfg, resolved)
        return cfg

    # 2. Auto-discovery
    discovered = _find_config_file()
    if discovered:
        try:
            cfg = Config.from_yaml(discovered)
        except yaml.YAMLError as exc:
            print(f"[aisos] ERROR: failed to parse YAML config at '{discovered}': {exc}", file=sys.stderr)
            return copy.deepcopy(DEFAULT_CONFIG)
        _emit_validation_warnings(cfg, discovered)
        return cfg

    # 3. Defaults
    print("[aisos] INFO: no config file found — using built-in defaults", file=sys.stderr)
    return copy.deepcopy(DEFAULT_CONFIG)


def _emit_validation_warnings(cfg: Config, path: str) -> None:
    """Print validation errors to stderr (non-fatal)."""
    import sys
    errors = cfg.validate()
    for err in errors:
        print(f"[aisos] CONFIG WARNING [{path}]: {err}", file=sys.stderr)
