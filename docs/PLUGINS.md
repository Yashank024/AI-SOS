# AI SOS — Plugin Development Guide

AI SOS features an extensible plugin architecture allowing developers to hook into the pipeline lifecycle, write custom threat detectors, and integrate external SIEM/alerting providers.

---

## 1. Base Plugin Architecture

All custom plugins inherit from `BasePlugin` and implement event lifecycle hooks:

```python
from aisos.plugins import BasePlugin
from aisos.core.event import SecurityEvent, Decision

class CustomRateLimiterPlugin(BasePlugin):
    """Example plugin enforcing custom rate limits on sensitive endpoints."""
    
    name = "custom_rate_limiter"
    version = "1.0.0"

    async def on_event(self, event: SecurityEvent) -> SecurityEvent:
        """Called for every security event passing through Stage 8 of the pipeline."""
        if event.path.startswith("/api/v1/auth/login"):
            # Execute custom plugin logic
            if event.raw_data.get("ip_request_count", 0) > 10:
                event.decision = Decision.BLOCK
                event.add_indicator("CustomPlugin: Login rate limit exceeded")
                
        return event
```

---

## 2. Registering Plugins

Register your custom plugin with `SecurityEngine`:

```python
import aisos

security = aisos.init()

# Instantiate and register custom plugin
plugin = CustomRateLimiterPlugin()
security.register_plugin(plugin)
```

---

## 3. Plugin Lifecycle Hooks

A plugin can implement any of the following async hooks:

| Hook Method | Executed Phase | Use Case |
| :--- | :--- | :--- |
| `async on_init(engine)` | Engine startup | Initialize database connections or external client sockets. |
| `async on_event(event)` | Stage 8 (Policy Evaluation) | Custom threat scoring, rule validation, custom blocking. |
| `async on_decision(event)` | Stage 9 (Defensive Action) | Export alerts to PagerDuty, Slack, Webhooks, Datadog. |
| `async on_shutdown()` | Engine shutdown | Flush connection pools and buffers. |
