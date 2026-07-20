"""Output generation REPL command handlers: nuclei, poc."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from ..state import REPLState


# ─── nuclei ───────────────────────────────────────────────────────────────────

async def cmd_nuclei(state: "REPLState", args: list[str], console: Console) -> None:
    """Generate Nuclei templates from current scan results.

    Usage:
      nuclei
      nuclei --output-dir ./nuclei_out
      nuclei --min-severity HIGH
    """
    from ...reporters.nuclei_reporter import generate_nuclei_templates
    from ...findings import Severity

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    output_dir = "."
    min_sev = Severity.MEDIUM
    for i, a in enumerate(args):
        if a == "--output-dir" and i + 1 < len(args):
            output_dir = args[i + 1]
        elif a == "--min-severity" and i + 1 < len(args):
            try:
                min_sev = Severity(args[i + 1].upper())
            except ValueError:
                pass

    paths = generate_nuclei_templates(state.scan_result, output_dir, min_severity=min_sev)
    if paths:
        console.print(f"[green]✓[/] {len(paths)} Nuclei template(s) → {output_dir}/nuclei_templates/")
    else:
        console.print("[yellow]No qualifying findings for Nuclei templates.[/]")


# ─── poc ──────────────────────────────────────────────────────────────────────

async def cmd_poc(state: "REPLState", args: list[str], console: Console) -> None:
    """Generate runnable Python PoC exploit scripts from current scan results.

    Usage:
      poc
      poc --output-dir ./pocs --min-severity CRITICAL
    """
    from ...reporters.poc_generator import generate_all_pocs
    from ...findings import Severity

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    output_dir = "."
    min_sev = Severity.HIGH
    for i, a in enumerate(args):
        if a == "--output-dir" and i + 1 < len(args):
            output_dir = args[i + 1]
        elif a == "--min-severity" and i + 1 < len(args):
            try:
                min_sev = Severity(args[i + 1].upper())
            except ValueError:
                pass

    paths = generate_all_pocs(state.scan_result, output_dir, min_severity=min_sev)
    if paths:
        console.print(f"[green]✓[/] {len(paths)} PoC script(s) → {output_dir}/pocs/")
    else:
        console.print("[yellow]No qualifying findings for PoC generation.[/]")


# ─── bundle ───────────────────────────────────────────────────────────────────

async def cmd_bundle(state: "REPLState", args: list[str], console: Console) -> None:
    """Write an ATLAS-tagged Markdown report bundle (findings + verbatim wire log).

    Usage:
      bundle
      bundle report.md
      bundle --output ./out/mcp_report.md
    """
    from ...reporters import bundle_reporter

    if not state.require_scan():
        console.print("[yellow]Run: scan[/]")
        return

    out = "mcpray_report.md"
    for i, a in enumerate(args):
        if a in ("--output", "-o") and i + 1 < len(args):
            out = args[i + 1]
            break
    else:
        if args and not args[0].startswith("-"):
            out = args[0]

    bundle_reporter.write(state.scan_result, out)
    wl = len(getattr(state.scan_result, "wire_log", []) or [])
    console.print(f"[green]✓[/] Report bundle → {out}  [dim]({wl} wire-log entries)[/]")


# ─── Command registry ─────────────────────────────────────────────────────────

COMMANDS: dict[str, tuple] = {
    "nuclei": (cmd_nuclei, "Generate Nuclei templates from scan results"),
    "poc":    (cmd_poc,    "Generate PoC exploit scripts from scan results"),
    "bundle": (cmd_bundle, "Write ATLAS-tagged report bundle + verbatim wire log"),
}
