"""
aisos/brain/agents/traffic_agent.py
-------------------------------------
HTTP / API traffic analysis agent.

Responsibilities
----------------
- High-frequency / DDoS detection (per-IP sliding-window rate tracking)
- API enumeration (sequential numeric path segments)
- Suspicious User-Agent detection (scanner signatures)
- Unusual HTTP methods
- Missing or forged standard headers
- Abnormally large payloads
- Path traversal attempts
- Suspicious file extensions
- Bot traffic classification
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from aisos.brain.base_agent import BaseAgent
from aisos.core.event import AgentReport, AttackCategory, Decision, Severity

if TYPE_CHECKING:
    from aisos.core.event import SecurityEvent

logger = logging.getLogger("aisos.agent.traffic")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCANNER_UA_PATTERNS: list[str] = [
    "sqlmap", "nikto", "nmap", "burpsuite", "burp suite",
    "zgrab", "masscan", "hydra", "metasploit", "dirbuster",
    "gobuster", "wfuzz", "ffuf", "nuclei", "acunetix",
    "nessus", "openvas", "havij", "w3af", "arachni",
]

BOT_UA_PATTERNS: list[str] = [
    "bot", "crawler", "spider", "scraper", "headless",
    "phantomjs", "selenium", "playwright", "puppeteer",
    "python-requests", "go-http-client", "curl/", "wget/",
    "libwww-perl", "java/", "ruby",
]

SUSPICIOUS_EXTENSIONS: set[str] = {
    ".php", ".asp", ".aspx", ".jsp", ".cfm",
    ".cgi", ".pl", ".py", ".rb", ".env",
    ".git", ".svn", ".bak", ".sql", ".htaccess",
}

ALLOWED_METHODS: set[str] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
UNUSUAL_METHODS: set[str] = {"TRACE", "CONNECT", "DEBUG", "MOVE", "COPY", "LOCK", "UNLOCK", "PROPFIND"}

PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.I)
API_ENUM_RE = re.compile(r"/(?:api|v\d+)/[^/]*/(\d+)$")


class _RateWindow:
    """Sliding-window request counter (per IP)."""

    def __init__(self, window_seconds: int = 60, threshold: int = 100) -> None:
        self.window = window_seconds
        self.threshold = threshold
        # ip -> deque of timestamps
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def add(self, ip: str) -> int:
        """Record a request and return current count in the window."""
        now = time.monotonic()
        dq = self._buckets[ip]
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def get_count(self, ip: str) -> int:
        now = time.monotonic()
        dq = self._buckets[ip]
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def is_flooded(self, ip: str) -> bool:
        return self.get_count(ip) >= self.threshold


class TrafficAgent(BaseAgent):
    """Analyses HTTP / API traffic patterns for anomalies."""

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(name="traffic_agent", config=config)
        cfg = self.config
        self._rate_window = _RateWindow(
            window_seconds=cfg.get("rate_window_seconds", 60),
            threshold=cfg.get("rate_threshold", 100),
        )
        self._payload_limit: int = cfg.get("max_payload_bytes", 1_048_576)  # 1 MB default

    # ------------------------------------------------------------------
    async def observe(self, event: "SecurityEvent") -> AgentReport:
        observations: list[str] = []
        indicators: list[str] = []
        risk: float = 0.0
        recommended: Decision | None = None

        # 1. Rate tracking / DDoS
        count = self._rate_window.add(event.source_ip)
        if count >= self._rate_window.threshold:
            ratio = min(count / self._rate_window.threshold, 5.0)
            contribution = min(40.0 * ratio, 80.0)
            risk += contribution
            observations.append(
                f"IP {event.source_ip} sent {count} requests in "
                f"{self._rate_window.window}s (threshold={self._rate_window.threshold})."
            )
            indicators.append(f"high_request_rate:{count}")
            recommended = Decision.RATE_LIMIT

        # 2. User-Agent analysis
        ua: str = event.headers.get("User-Agent", event.headers.get("user-agent", ""))
        ua_lower = ua.lower()

        if not ua:
            risk += 15.0
            observations.append("Missing User-Agent header.")
            indicators.append("missing_user_agent")

        for sig in SCANNER_UA_PATTERNS:
            if sig in ua_lower:
                risk += 50.0
                observations.append(f"Scanner signature detected in User-Agent: '{sig}'.")
                indicators.append(f"scanner_ua:{sig}")
                recommended = Decision.BLOCK
                break

        if recommended != Decision.BLOCK:
            for sig in BOT_UA_PATTERNS:
                if sig in ua_lower:
                    risk += 20.0
                    observations.append(f"Bot/automation signature in User-Agent: '{sig}'.")
                    indicators.append(f"bot_ua:{sig}")
                    if recommended is None:
                        recommended = Decision.MONITOR
                    break

        # 3. Unusual HTTP method
        method = (event.method or "").upper()
        if method in UNUSUAL_METHODS:
            risk += 30.0
            observations.append(f"Unusual HTTP method: {method}.")
            indicators.append(f"unusual_method:{method}")

        # 4. Path traversal
        if PATH_TRAVERSAL_RE.search(event.path):
            risk += 60.0
            observations.append(f"Path traversal pattern detected in: {event.path}")
            indicators.append("path_traversal")
            recommended = Decision.BLOCK

        # 5. API enumeration
        if API_ENUM_RE.search(event.path):
            # Not immediately dangerous, but flag for correlation
            risk += 10.0
            observations.append(f"Possible API enumeration pattern in path: {event.path}")
            indicators.append("api_enumeration_pattern")

        # 6. Suspicious file extension
        path_lower = event.path.lower().split("?")[0]
        for ext in SUSPICIOUS_EXTENSIONS:
            if path_lower.endswith(ext):
                risk += 25.0
                observations.append(f"Request for suspicious file extension: {ext}")
                indicators.append(f"suspicious_extension:{ext}")
                break

        # 7. Large payload
        body = event.body
        payload_size = 0
        if isinstance(body, (str, bytes)):
            payload_size = len(body)
        elif isinstance(body, dict):
            import json
            try:
                payload_size = len(json.dumps(body))
            except Exception:
                pass

        if payload_size > self._payload_limit:
            risk += 20.0
            observations.append(
                f"Abnormally large payload: {payload_size:,} bytes (limit={self._payload_limit:,})."
            )
            indicators.append(f"large_payload:{payload_size}")

        # 8. Missing standard security headers (for responses / proxied requests)
        for header in ["Host"]:
            if header.lower() not in {k.lower() for k in event.headers}:
                risk += 5.0
                observations.append(f"Missing required header: {header}.")
                indicators.append(f"missing_header:{header}")

        # Cap risk at 100
        risk = min(risk, 100.0)
        confidence = min(risk / 100.0, 1.0)

        if not observations:
            observations.append("No traffic anomalies detected.")

        return AgentReport(
            agent_name=self.name,
            observations=observations,
            risk_contribution=risk,
            attack_indicators=indicators,
            recommended_action=recommended,
            confidence=confidence,
            metadata={
                "request_count_in_window": count,
                "user_agent": ua,
                "payload_size": payload_size,
            },
        )
