# AI SOS — Benchmark Methodology & Profiling Guide

This document details the performance benchmarking methodology, test harness design, hardware specifications, and latency profiling used to measure the overhead of **AI SOS**.

---

## 1. Benchmarking Goals

The primary goal of AI SOS performance testing is to ensure that:
1. **P50 (Median) Added Latency** remains **<= 5.0 ms** in standard offline mode.
2. **Requests Per Second (RPS)** maintains high throughput under heavy parallel async load.
3. **Thread Safety**: 1,000 concurrent async requests process cleanly with zero race conditions, deadlocks, or state corruption.

---

## 2. Test Harness Architecture

The benchmark harness (`tests/benchmark.py`) runs parallel HTTP requests using `httpx.ASGITransport` targeting two isolated FastAPI instances:

1. **Baseline Application**: A raw FastAPI application returning a JSON payload (`{"status": "ok"}`).
2. **Protected Application**: The identical FastAPI application with `aisos.attach(app)` attached, running full 10-stage inbound and outbound security validation.

```
                    ┌─────────────────────────┐
                    │  Benchmark Test Harness │
                    └────────────┬────────────┘
                                 │
           ┌─────────────────────┴─────────────────────┐
           ▼                                           ▼
[ Baseline FastAPI App ]                 [ Protected FastAPI App ]
(No AI SOS Overhead)                     (AI SOS Middleware Attached)
           │                                           │
           ▼                                           ▼
   Measure Latency                             Measure Latency
   (1,000 requests)                            (1,000 requests)
```

---

## 3. How to Reproduce Benchmarks Locally

Execute the benchmark suite:

```bash
python -m tests.benchmark
```

### Benchmark Execution Flow:
1. **Warm-up**: Fires 50 requests to warm up event loop memory allocations.
2. **Baseline Run**: Fires 1,000 requests to measure raw framework speed.
3. **Protected Run**: Fires 1,000 requests through AI SOS pipeline with `asyncio.gather` and `asyncio.Semaphore(50)`.
4. **Metrics Generation**: Sorts latencies and calculates P50, P95, P99, Average Latency, and RPS delta.

---

## 4. Benchmark Results Matrix

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
