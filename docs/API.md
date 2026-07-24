# AI SOS — Complete API Documentation Reference

This document provides a comprehensive technical reference for the **AI SOS** public API surface.

---

## 1. Primary Entry Points

### `aisos.init(config=None, config_path=None) -> SecurityEngine`

Initializes and retrieves the global `SecurityEngine` singleton.

- **Parameters**:
  - `config` (*Optional[Config]*): Programmatic `Config` instance.
  - `config_path` (*Optional[str]*): Path to an `aisos.yaml` configuration file.
- **Returns**: Active `SecurityEngine` instance.

```python
import aisos

security = aisos.init(config_path="aisos.yaml")
```

---

### `aisos.attach(target)`

Attaches AI SOS to a host web application or third-party client library.

- **Supported Targets**:
  - `FastAPI` / `Starlette` app instance
  - `Flask` app instance
  - Strings: `"openai"`, `"anthropic"`, `"httpx"`, `"requests"`, `"mcp"`

```python
# Web Framework
security.attach(app)

# SDK Interception
security.attach("openai")
```

---

### `aisos.enable_ai(provider="OpenAI", api_key="", model="", base_url="")`

Enables optional LLM-powered threat reasoning for the `SecurityBrain`.

```python
security.enable_ai(provider="OpenAI", api_key="sk-...", model="gpt-4o-mini")
```

---

## 2. Core Engine Components

### `SecurityEngine`

Central orchestrator managing pipeline lifecycle, adaptive topology, and capabilities.

#### Key Methods:

- `async process_event(event: SecurityEvent) -> SecurityEvent`: Process a generic security event through the 10-stage pipeline.
- `async process_http_request(method, path, headers, body, source_ip) -> SecurityEvent`: Convenince wrapper for HTTP requests.
- `async process_response(inbound_event, status_code, headers, body) -> SecurityEvent`: Inspects and validates outbound response streams.
- `async process_ai_prompt(prompt, context) -> SecurityEvent`: Intercepts and scores AI agent prompts.
- `async process_tool_call(tool_name, args) -> SecurityEvent`: Inspects MCP/agent tool execution calls.

#### Properties:
- `.topology`: Access `AdaptiveTopologyManager` instance.
- `.capabilities`: Access `CapabilityManager` instance.
- `.metrics`: Dictionary of engine execution stats.

---

## 3. Immune System Topology

### `AdaptiveTopologyManager`

Tracks threat density and automatically shifts execution postures between 5 layers:

```python
layer = engine.topology.current_layer
# SecurityLayer.LAYER_1_NORMAL
# SecurityLayer.LAYER_2_SUSPICIOUS
# SecurityLayer.LAYER_3_ACTIVE_PROTECTION
# SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN
# SecurityLayer.LAYER_5_RECOVERY
```

---

## 4. Security Models

### `SecurityEvent`

Unified event object passing through the security pipeline.

#### Key Attributes:
- `id` (*str*): Unique UUIDv4.
- `event_type` (*str*): `"http_request"`, `"http_response"`, `"ai_prompt"`, `"tool_call"`.
- `severity` (*Severity*): `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `risk_score` (*float*): $0.0 \dots 100.0$.
- `confidence` (*float*): $0.0 \dots 1.0$.
- `decision` (*Decision*): `ALLOW`, `MONITOR`, `CHALLENGE`, `SANITIZE`, `BLOCK`, `LOCKDOWN`.
- `attack_category` (*AttackCategory*): Attack classification enum.
- `attack_indicators` (*list[str]*): List of matched signatures/rules.

#### Methods:
- `.explain() -> dict`: Returns structured explainability dictionary.
- `.to_dict() -> dict`: Serializes event to JSON-safe dictionary.
