import asyncio
import json
import urllib.parse
from fastapi import FastAPI
from fastapi.testclient import TestClient
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import aisos
from aisos.core.event import AttackCategory, Decision
from aisos.core.topology import SecurityLayer

console = Console()


async def run_diagnostics():
    console.print(
        Panel(
            "[bold green]Starting AI SOS Adaptive Security Layer Diagnostics[/bold green]\n"
            "[dim]Testing Inbound/Outbound Rules, Adaptive Topology Transitions & Middleware Adapters[/dim]",
            title="[bold yellow]AI SOS Diagnostics[/bold yellow]",
        )
    )

    # 1. Initialize global security engine
    security = aisos.init()
    engine = security

    # 2. Setup FastAPI host application
    app = FastAPI()
    security.attach(app)

    @app.get("/api/v1/health")
    def health():
        return {"status": "healthy", "service": "application-backend"}

    @app.get("/api/users")
    def get_users(q: str = ""):
        return {"users": ["alice", "bob"], "query": q}

    @app.get("/api/leak-key")
    def leak_key():
        # Backend attempting to return a leaked API key
        return {"api_key": "sk-1234567890abcdef1234567890abcdef"}

    client = TestClient(app)

    # --- TEST CASES ---
    test_results = []

    # Test Case 1: Normal Clean Traffic
    console.print("\n[bold cyan]1. Simulating Normal Clean Traffic...[/bold cyan]")
    response = client.get("/api/v1/health")
    status = engine.topology.current_layer
    console.print(f"Status: [green]HTTP {response.status_code}[/green] | Active Layer: [yellow]{status.value}[/yellow]")
    test_results.append(("Normal Traffic Allowed", response.status_code == 200 and status == SecurityLayer.LAYER_1_NORMAL))

    # Test Case 2: Inbound Threat - SQL Injection Block
    console.print("\n[bold cyan]2. Simulating Inbound Attack: SQL Injection...[/bold cyan]")
    payload = "SELECT * FROM users WHERE admin=1 OR '1'='1' --"
    encoded_payload = urllib.parse.quote(payload)
    response = client.get(f"/api/users?q={encoded_payload}")
    status = engine.topology.current_layer
    console.print(f"Status: [red]HTTP {response.status_code}[/red] | Active Layer: [yellow]{status.value}[/yellow]")
    console.print(f"Response Body: [dim]{response.text}[/dim]")
    test_results.append(("Inbound Attack Blocked", response.status_code == 403 and status == SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN))

    # Test Case 3: Outbound Response Validation Layer - Secret Leakage Prevention
    console.print("\n[bold cyan]3. Simulating Outbound Response Secret Leakage...[/bold cyan]")
    # Clear critical lockdown state to isolate response validation test
    engine.topology.force_layer(SecurityLayer.LAYER_1_NORMAL, "resetting for next test")
    
    response = client.get("/api/leak-key")
    status = engine.topology.current_layer
    console.print(f"Status: [red]HTTP {response.status_code}[/red] | Active Layer: [yellow]{status.value}[/yellow]")
    console.print(f"Response Body: [dim]{response.text}[/dim]")
    test_results.append(("Secret Leakage Intercepted", response.status_code == 403 and "sensitive data leakage prevented" in response.text))

    # Test Case 4: Cooldown & Automatic Recovery
    console.print("\n[bold cyan]4. Simulating Topology Cooldown and Recovery...[/bold cyan]")
    # Trigger Lockdown mode again
    engine.topology.force_layer(SecurityLayer.LAYER_4_CRITICAL_LOCKDOWN, "manual trigger")
    console.print(f"Current Layer: [yellow]{engine.topology.current_layer.value}[/yellow]")
    
    # Configure temporary short cooldown for diagnostic speed
    engine.topology._cooldown_seconds = 0.05
    await asyncio.sleep(0.06)
    
    # Send a clean request to trigger decay evaluation
    response = client.get("/api/v1/health")
    status = engine.topology.current_layer
    console.print(f"Transition after cooldown: [yellow]{status.value}[/yellow]")
    test_results.append(("Lockdown Cooldown to Recovery", status == SecurityLayer.LAYER_5_RECOVERY))

    # 3. Print test results matrix
    console.print("\n")
    table = Table(title="[bold yellow]AI SOS Diagnostic Matrix[/bold yellow]")
    table.add_column("Diagnostic Scenario", style="bold white")
    table.add_column("Result Status", style="bold green")

    for scenario, passed in test_results:
        result_text = "[bold green]PASSED[/bold green]" if passed else "[bold red]FAILED[/bold red]"
        table.add_row(scenario, result_text)

    console.print(table)


if __name__ == "__main__":
    asyncio.run(run_diagnostics())
