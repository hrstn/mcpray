"""Connection preflight — report the negotiated MCP protocol version and the
fastmcp/server versions, so a protocol mismatch surfaces explicitly instead of
failing silently mid-scan (Module 7 transport hardening)."""
from __future__ import annotations

from .client import MCPClient

# Protocol revisions this build of fastmcp is known-good against. Update as the
# MCP spec evolves; a server outside this set gets a soft warning.
KNOWN_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}


async def preflight(target: str, headers: dict | None = None, timeout: int = 30) -> dict:
    """Connect, read the negotiated protocol/version info, and disconnect."""
    info: dict = {"target": target, "reachable": False, "warning": None}
    try:
        async with MCPClient(target, headers=headers, timeout=timeout) as client:
            info.update(client.protocol_info())
            info["transport"] = client.transport
            info["reachable"] = True
    except Exception as e:  # connection / handshake failure
        info["error"] = f"{type(e).__name__}: {e}"
        return info

    pv = info.get("protocol_version")
    if pv and pv not in KNOWN_PROTOCOLS:
        info["warning"] = (f"Server protocol '{pv}' is outside this fastmcp build's known set "
                           f"{sorted(KNOWN_PROTOCOLS)} — enumeration may be partial.")
    return info
