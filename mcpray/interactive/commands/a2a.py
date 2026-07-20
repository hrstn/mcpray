"""A2A / multi-agent REPL command (Module 4)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from ..state import REPLState


async def cmd_a2a(state: "REPLState", args: list[str], console: Console) -> None:
    """A2A multi-agent attacks (Module 4).

    Usage:
      a2a discover <target>
      a2a rogue <registry_url> --unsafe
      a2a poison <ingest_url> <trigger_url> --unsafe
      a2a attack <task_url> --unsafe
    """
    from ...a2a.attacks import data_poison, rogue_register, workflow_probe
    from ...a2a.core import A2ASession, classify, discover

    if not args:
        console.print("[yellow]Usage: a2a discover|rogue|poison|attack ...[/]")
        return
    sub = args[0]
    rest = [a for a in args[1:] if not a.startswith("-")]
    unsafe = "--unsafe" in args

    async with A2ASession() as session:
        if sub == "discover":
            target = rest[0] if rest else state.target
            result = await discover(session, target)
            c = classify(result)
            console.print(f"[dim]cards={len(result.cards)} agents={len(result.registry_agents)} "
                          f"endpoints={len(result.endpoints)}[/]")
            for card in result.cards:
                console.print(f"  [cyan]{card.name}[/] [dim]{card.url}[/]")
            for a in result.registry_agents:
                console.print(f"  - {a['name']} [dim]{a['url']}[/]")
            console.print(f"[bold]{c['system_type']} / {c['coordination_pattern']}[/]  framework={c['framework']}")
        elif sub == "rogue":
            if not rest or not unsafe:
                console.print("[yellow]a2a rogue <registry_url> --unsafe[/]")
                return
            f = await rogue_register(session, rest[0])
            console.print(f"[red]{f.title}[/]\n{f.evidence}")
        elif sub == "poison":
            if len(rest) < 2 or not unsafe:
                console.print("[yellow]a2a poison <ingest_url> <trigger_url> --unsafe[/]")
                return
            f = await data_poison(session, rest[0], "content", rest[1], "query")
            console.print(f"[red]{f.title}[/]\n{f.evidence}")
        elif sub == "attack":
            if not rest or not unsafe:
                console.print("[yellow]a2a attack <task_url> --unsafe[/]")
                return
            fs = await workflow_probe(session, rest[0])
            if not fs:
                console.print("[green]No workflow-integrity issues detected.[/]")
            for f in fs:
                console.print(f"[red]{f.title}[/]")
        else:
            console.print("[yellow]Unknown a2a subcommand. Try: discover|rogue|poison|attack[/]")


COMMANDS: dict[str, tuple] = {
    "a2a": (cmd_a2a, "A2A multi-agent attacks (Module 4): discover|rogue|poison|attack"),
}
