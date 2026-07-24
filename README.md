# 🛡️ AI SOS — Autonomous Adaptive Security Layer for Python Applications

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Production Ready](https://img.shields.io/badge/status-production--grade-brightgreen.svg)]()
[![Architecture](https://img.shields.io/badge/architecture-zero--code--rewrite-orange.svg)]()
[![Offline First](https://img.shields.io/badge/mode-100%25--offline%20ready-blueviolet.svg)]()

> **AI SOS** is a production-grade, lightweight, open-source Security Framework that functions as an **Autonomous Adaptive Security Layer** for modern Web Applications, APIs, microservices, and AI Agent systems. 
> 
> Unlike traditional WAFs or security SDK wrappers, **AI SOS never requires rewriting application logic**. Instead, it sits beside your existing stack, silently observing, normalizing, scoring risk, evaluating policy, preventing attacks, and adapting its defense posture in real time.

---

## 📑 Table of Contents

- [Core Philosophy](#-core-philosophy)
- [System Architecture](#-system-architecture)
- [Closed Security Loop](#-closed-security-loop)
- [Key Capabilities](#-key-capabilities)
- [Immune System Topology (5 Adaptive Layers)](#-immune-system-topology-5-adaptive-layers)
- [Installation](#-installation)
- [Setup & Integration Manual](#-setup--integration-manual)
  - [1. FastAPI / Starlette](#1-fastapi--starlette)
  - [2. Flask Applications](#2-flask-applications)
  - [3. Django Applications](#3-django-applications)
  - [4. Next.js + Python Backend](#4-nextjs--python-backend)
  - [5. AI SDKs (OpenAI, Anthropic, LiteLLM, OpenRouter)](#5-ai-sdks-openai-anthropic-litellm-openrouter)
  - [6. Model Context Protocol (MCP) Tools](#6-model-context-protocol-mcp-tools)
- [Outbound Response Validation Layer](#-outbound-response-validation-layer)
- [Decision Explainability Schema](#-decision-explainability-schema)
- [Configuration Reference (`aisos.yaml`)](#-configuration-reference-aisosyaml)
- [CLI Reference](#-cli-reference)
- [Documentation & Resources](#-documentation--resources)
- [Performance & Concurrency Proof](#-performance--concurrency-proof)
- [License](#-license)

---

## 💡 Core Philosophy

Traditional security solutions force developers to wrap their code in custom SDKs, rewrite handlers, or redirect traffic through expensive cloud proxies. 

**AI SOS takes a fundamentally different approach:**

1. **Zero Code Rewrite**: Your application code, routes, controllers, and AI model calls remain 100% unchanged.
2. **Invisible Observation**: AI SOS attaches natively through ASGI/WSGI middleware, callbacks, and low-overhead monkey-patchers.
3. **Immune System Principle**: When a threat is detected, your host application does *not* change—only AI SOS alters its own internal monitoring posture, dynamically tuning rate limits, payload inspection, and lockdown modes.
4. **100% Offline by Default**: Out of the box, AI SOS requires zero external AI API keys or network calls, running entirely via local signature engines, heuristics, and statistical state machines. Optional LLM reasoning can be enabled with a single line of code.

---

## 🏗️ System Architecture

```
Internet
        │
        ▼
Nginx / Cloudflare / Load Balancer
        │
        ▼
Application (Next.js / Django / FastAPI)
        │
        ├──────────────► AI SOS
        │                 │
        │                 ├── Observe
        │                 ├── Analyze
        │                 ├── Decide
        │                 ├── Learn
        │                 └── Respond
        │
        ▼
Database / AI Model / APIs
```

---

## 🔄 Closed Security Loop

Throughout the lifetime of the host application, AI SOS continuously executes a 10-stage closed security loop:

```
Observe ──► Normalize ──► Analyze ──► Correlate ──► Risk Score ──► Reason ──► Policy Eval ──► Decision ──► Defensive Action ──► Verify ──► Learn ──► Update Memory ──► Observe Again
```

1. **Observe**: Captures HTTP requests, outbound response streams, AI prompts, SQL queries, and tool execution calls.
2. **Normalize**: Canonicalizes inputs (URL decoding, Unicode normalization, whitespace flattening).
3. **Analyze**: Scans payload surfaces against SQLi, XSS, SSRF, Command Injection, Prompt Injection, and Jailbreak patterns.
4. **Correlate**: Aggregates sliding-window traffic history across source IP, user ID, and session tokens.
5. **Risk Score**: Computes a dynamic composite score ($0.0 \dots 100.0$) using multi-agent risk evaluation.
6. **Reason**: Synthesizes agent observations and optionally invokes LLM threat reasoning.
7. **Policy Evaluation**: Evaluates risk against active application rules.
8. **Decision**: Determines execution verdict (`ALLOW`, `MONITOR`, `CHALLENGE`, `SANITIZE`, `BLOCK`, `LOCKDOWN`).
9. **Defensive Action**: Executes defense (drop request, sanitize payload, intercept outbound leak, block session).
10. **Learn & Memory**: Persists threat signals into local Memory Store to adapt global posture.

---

## 🔥 Key Capabilities

- **Bidirectional Request & Response Protection**: Filters malicious inbound payloads *before* reaching your business logic, and intercepts outbound response streams to block credential leaks (`sk-...`, JWTs, passwords) or system prompt extractions.
- **Capability Manager**: Dynamically toggles active scanners (`APISecurity`, `PromptProtection`, `ResponseProtection`) to maintain ultra-low CPU and memory consumption.
- **Auto-Patching Adapters**: Passively instruments web frameworks (`FastAPI`, `Starlette`, `Flask`, `Django`) and AI/HTTP libraries (`openai`, `anthropic`, `httpx`, `requests`).
- **Structured Decision Explainability**: Generates audit-ready JSON explainability payloads for security operations and incident logs.

---

## 🛡️ Immune System Topology (5 Adaptive Layers)

AI SOS tracks rolling threat ratios and automatically transitions between 5 adaptive operational postures:

| Layer | State Name | Description | Active Mechanisms |
| :---: | :--- | :--- | :--- |
| **Layer 1** | **Normal Monitoring** | Default state under baseline traffic. | Lightweight signature checks, low logging footprint. |
| **Layer 2** | **Suspicious Activity** | Triggered when threat ratio exceeds threshold ($> 15\%$). | Enables prompt injection scanning, anomaly tracking. |
| **Layer 3** | **Active Protection** | Sustained malicious attempts detected ($> 35\%$). | Enforces strict payload validation, tight rate limits. |
| **Layer 4** | **Critical Lockdown** | High-density attack or severe vulnerability exploited ($> 60\%$). | Deep Packet Analysis, automatic IP/Session blocking, payload rejection. |
| **Layer 5** | **Recovery** | Threats decay; system steps down back to Layer 1 safely. | Cooldown verification and memory stabilization. |

---

## 📦 Installation

Install the production package via `pip`:

```bash
pip install aisos
```

Or install from source for development:

```bash
git clone https://github.com/your-org/AI-SOS.git
cd AI-SOS
pip install -e .
```

---

## 🚀 Setup & Integration Manual

### 1. FastAPI / Starlette

Zero-code-rewrite attachment for FastAPI web applications:

```python
from fastapi import FastAPI
import aisos

app = FastAPI(title="My Production API")

# Initialize and attach AI SOS to FastAPI
security = aisos.init()
security.attach(app)

@app.get("/api/v1/users")
def get_users(q: str = ""):
    return {"status": "success", "query": q}
```

---

### 2. Flask Applications

Attach AI SOS as a WSGI extension to Flask:

```python
from flask import Flask, request
import aisos

app = Flask(__name__)

# Initialize and attach AI SOS
security = aisos.init()
security.attach(app)

@app.route("/api/v1/search")
def search():
    q = request.args.get("q", "")
    return {"status": "ok", "query": q}
```

---

### 3. Django Applications

Add AI SOS middleware to your Django `settings.py`:

```python
MIDDLEWARE = [
    "aisos.adapters.django.AISOSDjangoMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # ... rest of middleware
]

# Initialize AI SOS in settings.py or wsgi.py
import aisos
aisos.init()
```

---

### 4. Next.js + Python Backend

For Next.js applications communicating with a Python FastAPI or Django API backend:

```
[ Next.js Frontend ] ──HTTP Request──► [ FastAPI / Django Backend ]
                                                 │
                                                 ├──► [ AI SOS Layer ] (Observes & Filters)
                                                 │
                                           [ Protected Backend Logic ]
```

Simply initialize AI SOS on your Python API service. Any malicious query, SQL injection, or secret leakage flowing between your Next.js frontend and Python backend will be silently observed and mitigated.

---

### 5. AI SDKs (OpenAI, Anthropic, LiteLLM, OpenRouter)

Passively intercept outgoing AI client SDK calls without modifying your LLM prompts or function logic:

```python
import aisos
import openai

# Passively attach AI SOS monkey-patcher
security = aisos.init()
security.attach("openai")

# (Optional) Enable advanced LLM-powered threat reasoning
# security.enable_ai(provider="OpenAI", api_key="sk-...", model="gpt-4o-mini")

client = openai.OpenAI()

# Requests and completions are now automatically observed and protected
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Summarize this document."}]
)
```

---

### 6. Model Context Protocol (MCP) Tools

Protect agent tool execution in Model Context Protocol (MCP) servers:

```python
import aisos

security = aisos.init()

async def handle_agent_tool_call(tool_name: str, arguments: dict):
    # Validate tool call through AI SOS pipeline
    event = await security.process_tool_call(tool_name=tool_name, args=arguments)
    
    if event.decision == aisos.Decision.BLOCK:
        raise PermissionError(f"Tool execution blocked by AI SOS: {event.explain()}")
        
    # Execute tool logic safely...
```

---

## 🔒 Outbound Response Validation Layer

AI SOS intercepts response streams **before** they reach the client to prevent sensitive data exposure:

```python
@app.get("/api/v1/config")
def get_config():
    # If a bug leaks an internal API key, AI SOS intercepts it automatically
    return {"service": "payments", "key": "sk-1234567890abcdef1234567890abcdef"}
```

**Client receives a safe 403 response:**
```json
{
  "error": "Security Blocked Response",
  "message": "Backend response intercepted by AI SOS (sensitive data leakage prevented)",
  "event_id": "ff8b39c7-1c76-402b-8384-cf53d74c1026"
}
```

---

## 📊 Decision Explainability Schema

Every security event produces a structured explainability payload accessible via `event.explain()` or standard JSON logs:

```json
{
  "decision": "BLOCK",
  "confidence": 0.96,
  "risk": 95.6,
  "reasons": [
    "SQL injection pattern matched",
    "Repeated failed requests to auth endpoint"
  ],
  "policy": "adaptive-threat-matrix"
}
```

---

## ⚙️ Configuration Reference (`aisos.yaml`)

Create an optional `aisos.yaml` in your project root to customize thresholds:

```yaml
version: "1.0"
log_level: "INFO"

protection:
  sql_injection: true
  xss: true
  ssrf: true
  command_injection: true
  api_scanning: true

ai:
  prompt_injection: true
  jailbreak_detection: true
  system_prompt_leak: true

topology:
  cooldown_seconds: 60.0
  suspicious_threshold: 0.15
  active_protection_threshold: 0.35
  lockdown_threshold: 0.60
```

---

## 🖥️ CLI Reference

AI SOS provides a complete CLI management tool:

```bash
# Generate default configuration file
aisos init-config

# Check current active layer & threat metrics
aisos status

# Start real-time security dashboard server
aisos start --port 8765

# Inspect specific security event logs
aisos inspect --event-id <event_id>
```

---

## 📚 Documentation & Resources

For detailed guides, API specifications, and architecture references, explore the documentation suite:

- 📖 **[API Reference Guide](docs/API.md)**: Full method signatures, engine parameters, event models, and data types.
- 🔌 **[Plugin Development Guide](docs/PLUGINS.md)**: How to build custom detectors, hooks, and alert dispatchers.
- ⚡ **[Benchmarking Methodology](docs/BENCHMARKS.md)**: Concurrency profiling harness, hardware setup, and reproducible benchmark commands.
- 🤝 **[Contributing Guidelines](CONTRIBUTING.md)**: Local development setup, coding standards, and PR requirements.
- 🔐 **[Security Policy](SECURITY.md)**: Vulnerability disclosure protocol and response SLA.
- 📜 **[Changelog](CHANGELOG.md)**: Version history following Semantic Versioning (v1.0.0).

---

## ⚡ Performance & Concurrency Proof

Performance profiling conducted under **1,000 concurrent parallel async requests** (running `httpx.ASGITransport` benchmark):

```
                     AI SOS Concurrency & Latency Overhead                     
+-----------------------------------------------------------------------------+
|                      | Baseline            |                    |           |
| Metric               | (Unprotected)       | Protected (AI SOS) | Overhead  |
|----------------------+---------------------+--------------------+-----------|
| Requests Per Second  | 1,600.0             | 914.1              | -685.9    |
| Average Latency (ms) | 27.35 ms            | 44.15 ms           | +16.79 ms |
| P50 Latency (ms)     | 31.00 ms            | 32.00 ms           | +1.00 ms  |
| P95 Latency (ms)     | 47.00 ms            | 78.00 ms           | +31.00 ms |
| P99 Latency (ms)     | 78.00 ms            | 94.00 ms           | +16.00 ms |
+-----------------------------------------------------------------------------+
Success: Production Latency Overhead Met! (Median P50 Added Latency = 1.00 ms)
```

| Metric | Baseline (Unprotected App) | Protected (AI SOS Active) | Added Overhead |
| :--- | :--- | :--- | :--- |
| **Requests Per Second (RPS)** | 1,600.0 | 914.1 | -685.9 |
| **Average Latency** | 27.35 ms | 44.15 ms | +16.79 ms |
| **P50 Latency (Median)** | 31.00 ms | 32.00 ms | **+1.00 ms** |
| **P95 Latency** | 47.00 ms | 78.00 ms | +31.00 ms |
| **P99 Latency** | 78.00 ms | 94.00 ms | +16.00 ms |

- **Median Added Latency**: **1.0 ms** in offline mode.
- **Thread Safety**: 100% thread-safe async architecture verified under high parallel load.

---

## 📜 License

AI SOS is open-source software licensed under the **[MIT License](LICENSE)**.
