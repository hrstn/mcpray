"""Module 7 REPL commands: toolpoison (7.2), chain (7.3)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from ..state import REPLState


async def cmd_toolpoison(state: "REPLState", args: list[str], console: Console) -> None:
    """Detect tool-description poisoning + MCP-Apps UI spoofing (Module 7.2).

    Usage:
      toolpoison
    """
    from ...scanners.tool_poison import ToolPoisonScanner

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    scanner = ToolPoisonScanner(state.mcp_client, {})
    findings = await scanner.scan(state.scan_result.server_inventory)
    if not findings:
        console.print("[green]✓ No tool-poisoning / UI-spoofing indicators.[/]")
        return

    tbl = Table(box=box.SIMPLE, padding=(0, 1))
    tbl.add_column("Severity", width=10)
    tbl.add_column("Title")
    for f in findings:
        tbl.add_row(f.severity.value, f.title[:70])
    console.print(tbl)
    for f in findings[:5]:
        console.print(Panel(f.evidence, title=f"[bold]{f.title}[/]", border_style="yellow", padding=(0, 1)))


async def cmd_chain(state: "REPLState", args: list[str], console: Console) -> None:
    """Execute a chain of MCP tool calls — chat → root (Module 7.3).

    Usage:
      chain <steps.json> --unsafe
    """
    from ...client import MCPClient
    from ...scanners.chain_exec import ChainExecutor

    files = [a for a in args if not a.startswith("-")]
    if not files:
        console.print("[yellow]Usage: chain <steps.json> --unsafe[/]")
        return
    if "--unsafe" not in args:
        console.print("[yellow]chain executes REAL tool calls. Add [bold]--unsafe[/] to confirm authorization.[/]")
        return
    try:
        steps = json.loads(Path(files[0]).read_text())
    except Exception as e:
        console.print(f"[red]Could not read steps file: {e}[/]")
        return

    async with MCPClient(state.target, headers=state.mcp_client.headers,
                         timeout=state.mcp_client.timeout) as client:
        executor = ChainExecutor(client)
        with console.status("[cyan]Executing tool chain...[/]"):
            executed = await executor.run(steps)
        result = executor.to_scan_result(state.target)

    for s in executed:
        status = "[green]OK[/]" if s["success"] else "[red]FAIL[/]"
        console.print(f"  [{s['step']}] {status} [bold]{s['tool']}[/] {s['arguments']}")
        if s["output"]:
            console.print(f"      [dim]{s['output'][:200]}[/]")
    console.print(Panel(f"[bold red]{result.findings[0].title}[/]", border_style="red"))


COMMANDS: dict[str, tuple] = {
    "toolpoison": (cmd_toolpoison, "Detect tool-description poisoning + UI spoofing (7.2)"),
    "chain":      (cmd_chain,      "Execute a tool-call chain — chat to root (7.3)"),
}
