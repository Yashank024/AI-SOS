"""
tests/benchmark.py
~~~~~~~~~~~~~~~~~~~
Performance, Concurrency, and Stability Benchmark for AI SOS.

Simulates concurrent user load (1,000 requests) to measure:
  - Latency difference (with vs. without AI SOS)
  - P50, P95, P99 latency overhead
  - Requests Per Second (RPS)
  - Concurrency stability & thread safety under high parallel async execution.
"""

import asyncio
import time
import httpx
from fastapi import FastAPI
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import aisos
from aisos.core.config import Config

console = Console()


def get_async_client(app, base_url="http://test"):
    """Helper to instantiate HTTPX AsyncClient using ASGITransport."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url=base_url)


async def run_benchmark():
    console.print(
        Panel(
            "[bold green]AI SOS Concurrency & Performance Load Benchmarks[/bold green]\n"
            "[dim]Simulating high parallel loads with silent log level (WARNING) for pure measurement[/dim]",
            title="[bold yellow]Performance Validation[/bold yellow]",
        )
    )

    # Setup base FastAPI application
    app_base = FastAPI()

    @app_base.get("/hello")
    def hello_base():
        return {"status": "ok"}

    # Setup AI SOS protected FastAPI application (Using WARNING log level to prevent loop block)
    app_protected = FastAPI()
    config = Config()
    config.log_level = "warning"
    
    security = aisos.init(config=config)
    security.attach(app_protected)

    @app_protected.get("/hello")
    def hello_protected():
        return {"status": "ok"}

    # --- Benchmark Parameters ---
    total_requests = 1000
    sem = asyncio.Semaphore(50)  # Restrict max parallel loop tasks to avoid event queue starvation

    # 1. Warm-up
    async with get_async_client(app_base) as client_base:
        async with get_async_client(app_protected) as client_prot:
            for _ in range(50):
                await client_base.get("/hello")
                await client_prot.get("/hello")

    # 2. Benchmark Baseline (Without AI SOS)
    console.print(f"Running Baseline: {total_requests} requests (no protection)...")
    
    async def request_baseline(client):
        async with sem:
            req_start = time.monotonic()
            await client.get("/hello")
            return (time.monotonic() - req_start) * 1000.0

    async with get_async_client(app_base) as client_base:
        start_time = time.monotonic()
        tasks = [request_baseline(client_base) for _ in range(total_requests)]
        latencies_base = await asyncio.gather(*tasks)
        duration_base = time.monotonic() - start_time
        rps_base = total_requests / duration_base

    # 3. Benchmark Protected (With AI SOS Enabled)
    console.print(f"Running Protected: {total_requests} requests (AI SOS active)...")
    
    async def request_protected(client):
        async with sem:
            req_start = time.monotonic()
            await client.get("/hello")
            return (time.monotonic() - req_start) * 1000.0

    async with get_async_client(app_protected) as client_prot:
        start_time = time.monotonic()
        tasks = [request_protected(client_prot) for _ in range(total_requests)]
        latencies_protected = await asyncio.gather(*tasks)
        duration_protected = time.monotonic() - start_time
        rps_protected = total_requests / duration_protected

    # --- Metrics Calculation ---
    latencies_base.sort()
    latencies_protected.sort()

    def get_percentile(arr, pct):
        idx = int(len(arr) * (pct / 100.0))
        return arr[min(idx, len(arr) - 1)]

    p50_base, p50_prot = get_percentile(latencies_base, 50), get_percentile(latencies_protected, 50)
    p95_base, p95_prot = get_percentile(latencies_base, 95), get_percentile(latencies_protected, 95)
    p99_base, p99_prot = get_percentile(latencies_base, 99), get_percentile(latencies_protected, 99)

    avg_base = sum(latencies_base) / len(latencies_base)
    avg_prot = sum(latencies_protected) / len(latencies_protected)
    added_latency = avg_prot - avg_base

    # --- Print Benchmark Matrix ---
    table = Table(title="[bold cyan]AI SOS Concurrency & Latency Overhead[/bold cyan]")
    table.add_column("Metric", style="bold white")
    table.add_column("Baseline (Unprotected)", style="yellow")
    table.add_column("Protected (AI SOS)", style="green")
    table.add_column("Overhead", style="bold red")

    table.add_row("Requests Per Second (RPS)", f"{rps_base:.1f}", f"{rps_protected:.1f}", f"{rps_base - rps_protected:.1f}")
    table.add_row("Average Latency (ms)", f"{avg_base:.2f} ms", f"{avg_prot:.2f} ms", f"+{added_latency:.2f} ms")
    table.add_row("P50 Latency (ms)", f"{p50_base:.2f} ms", f"{p50_prot:.2f} ms", f"+{p50_prot - p50_base:.2f} ms")
    table.add_row("P95 Latency (ms)", f"{p95_base:.2f} ms", f"{p95_prot:.2f} ms", f"+{p95_prot - p95_base:.2f} ms")
    table.add_row("P99 Latency (ms)", f"{p99_base:.2f} ms", f"{p99_prot:.2f} ms", f"+{p99_prot - p99_base:.2f} ms")

    console.print("\n")
    console.print(table)

    # Validate target thresholds
    median_overhead = p50_prot - p50_base
    if median_overhead <= 5.0:
        console.print(f"[bold green]Success: Production Latency Overhead Met! (Median P50 Added Latency = {median_overhead:.2f} ms)[/bold green]")
    else:
        console.print(f"[bold yellow]Notice: Median P50 Added Latency = {median_overhead:.2f} ms[/bold yellow]")


if __name__ == "__main__":
    asyncio.run(run_benchmark())
