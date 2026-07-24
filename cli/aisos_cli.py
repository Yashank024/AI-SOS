"""
cli/aisos_cli.py
~~~~~~~~~~~~~~~~~
Production Command Line Interface for AI SOS.

Usage:
  aisos start [--port PORT] [--config PATH]
  aisos status [--config PATH]
  aisos inspect [--ip IP] [--limit N]
  aisos init-config [--output PATH]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import aisos
from aisos.core.config import Config, load_config

console = Console()


@click.group()
@click.version_option(version=aisos.__version__, prog_name="aisos")
def main() -> None:
    """AI SOS — Adaptive Security Layer Framework CLI."""
    pass


@main.command()
@click.option("--port", default=8765, help="Port for the real-time security dashboard.")
@click.option("--host", default="127.0.0.1", help="Host address to bind.")
@click.option("--config", "config_path", default=None, help="Path to custom aisos.yaml.")
def start(port: int, host: str, config_path: str | None) -> None:
    """Start the AI SOS live monitoring engine & dashboard server."""
    console.print(
        Panel(
            f"[bold green]AI SOS Adaptive Security Layer Engine v{aisos.__version__}[/bold green]\n"
            f"[dim]Starting dashboard server on http://{host}:{port}[/dim]\n"
            "[bold cyan]Immune System Active: Passive observation enabled.[/bold cyan]",
            title="[bold yellow]AI SOS Engine[/bold yellow]",
        )
    )

    try:
        from aisos.dashboard.server import start_dashboard_server

        config = load_config(config_path)
        config.dashboard.port = port
        config.dashboard.host = host

        start_dashboard_server(config)
    except KeyboardInterrupt:
        console.print("[yellow]AI SOS Engine stopped by operator.[/yellow]")
    except Exception as exc:
        console.print(f"[bold red]Failed to start AI SOS Engine: {exc}[/bold red]")
        sys.exit(1)


@main.command()
@click.option("--config", "config_path", default=None, help="Path to custom aisos.yaml.")
def status(config_path: str | None) -> None:
    """Display real-time framework health, active topology layer, and metrics."""
    engine = aisos.init(config_path=config_path)
    stat = engine.get_status()
    topology_info = stat.get("topology", {})

    table = Table(title="[bold cyan]AI SOS Framework Status[/bold cyan]")
    table.add_column("Property", style="bold white")
    table.add_column("Value", style="green")

    table.add_row("Version", stat.get("version", aisos.__version__))
    table.add_row("Running", str(stat.get("running", False)))
    table.add_row("Active Topology Layer", topology_info.get("current_layer", "Layer 1: Normal Monitoring"))
    table.add_row("Layer Level", str(topology_info.get("layer_level", 1)))
    table.add_row("AI Provider", stat.get("ai_provider", "DummyOfflineAIProvider"))
    table.add_row("Total Events Processed", str(stat.get("engine_counters", {}).get("total_events", 0)))
    table.add_row("Threats Detected", str(stat.get("engine_counters", {}).get("threats_detected", 0)))
    table.add_row("Blocks Issued", str(stat.get("engine_counters", {}).get("blocks_issued", 0)))

    console.print(table)


@main.command(name="init-config")
@click.option("--output", default="aisos.yaml", help="Target output file path.")
def init_config(output: str) -> None:
    """Generate a default aisos.yaml configuration file."""
    target_path = Path(output).resolve()
    if target_path.exists():
        console.print(f"[bold yellow]Config file already exists at '{target_path}'. Aborting to prevent overwrite.[/bold yellow]")
        return

    sample_yaml = """# AI SOS Configuration File
security:
  monitoring: true
  log_level: "info"
  log_file: "aisos.log"

  ai:
    provider: "openai"
    api_key: ""
    model: "gpt-4o-mini"
    prompt_injection: true
    jailbreak_detection: true
    system_prompt_leak: true

  protection:
    sql_injection: true
    xss: true
    csrf: true
    ssrf: true
    api_scanning: true

  rate_limits:
    requests_per_minute: 120

  dashboard:
    enabled: true
    port: 8765
    host: "127.0.0.1"

policies: []
"""
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(sample_yaml)

    console.print(f"[bold green]Successfully initialized default AI SOS configuration at '{target_path}'.[/bold green]")


@main.command()
@click.option("--ip", default=None, help="Specific IP address to inspect.")
def inspect(ip: str | None) -> None:
    """Inspect current threat memory and reputation scores."""
    engine = aisos.get_engine()
    memory = engine._memory

    if ip:
        risk = memory.get_ip_risk(ip)
        req_count = memory.get_request_count(ip)
        is_blocked = memory.is_blocked(ip)

        table = Table(title=f"[bold cyan]IP Inspection: {ip}[/bold cyan]")
        table.add_column("Metric", style="bold white")
        table.add_column("Value", style="yellow")

        table.add_row("Historical Risk Score", f"{risk:.2f}")
        table.add_row("Total Request Count", str(req_count))
        table.add_row("Is Blocked", str(is_blocked))

        console.print(table)
    else:
        console.print("[dim]Use --ip <IP_ADDRESS> to inspect specific IP metrics.[/dim]")


if __name__ == "__main__":
    main()
