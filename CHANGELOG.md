# Changelog — AI SOS

All notable changes to **AI SOS** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-24

### Added
- **Zero-Code-Rewrite Framework Adapters**: Native ASGI/WSGI middleware auto-attachment for FastAPI/Starlette, Flask, and Django.
- **Passively Instrument SDK Patchers**: Monkey-patchers for OpenAI, Anthropic, HTTPX, Requests, and MCP tool servers.
- **Immune System 5-Layer Adaptive Security Topology**: Real-time operational posture manager with rolling threat metrics and automatic recovery step-downs (`Layer 1: Normal` to `Layer 5: Recovery`).
- **Outbound Response Validation Layer**: Stream interceptor preventing secret key leaks (`sk-...`, JWTs, passwords) and system prompt extraction attacks before delivery to client.
- **Capability Manager**: Dynamic capability toggles (`APISecurity`, `PromptProtection`, `ResponseProtection`) to keep CPU/memory footprint minimal during normal baseline operation.
- **Decision Explainability Model**: Structured JSON explainability schema (`event.explain()`) detailing verdict, risk score, confidence, policy rule, and attack indicators.
- **Rich CLI Suite**: Command line interface (`aisos start`, `aisos status`, `aisos inspect`, `aisos init-config`).
- **Benchmarking Suite**: Fully async concurrency benchmark suite profiling latency overhead and RPS stability under 1,000 parallel requests.
