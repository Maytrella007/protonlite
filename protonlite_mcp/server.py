"""An MCP server that exposes protonlite to any MCP client (Cursor, Claude Code,
Claude Desktop).

Sign in once with the CLI, then point an MCP client at this server:

    protonlite login --user you@proton.me
    PROTONLITE_SESSION=~/.protonlite/session.json python -m protonlite_mcp

The server never takes a password: it reuses the session the CLI saved. Message,
calendar, contact and file content is returned wrapped as untrusted data.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from protonlite import ProtonMail

from . import tools

mcp = FastMCP("protonlite")

_client: ProtonMail | None = None


def _get() -> ProtonMail:
    global _client
    if _client is None:
        _client = tools.open_client()
    return _client


@mcp.tool()
def list_messages(folder: str = "inbox", unread_only: bool = False, limit: int = 20) -> str:
    """List messages in a Proton Mail folder (inbox, sent, archive, spam, trash, starred...)."""
    return tools.list_messages(_get(), folder=folder, unread_only=unread_only, limit=limit)


@mcp.tool()
def read_message(message_id: str) -> str:
    """Read one Proton Mail message by id, decrypted, with HTML flattened to prose."""
    return tools.read_message(_get(), message_id=message_id)


@mcp.tool()
def search_messages(query: str, limit: int = 20) -> str:
    """Find messages whose sender or subject contains the query."""
    return tools.search(_get(), query=query, limit=limit)


@mcp.tool()
def send_message(to: list[str], subject: str, body: str, html: bool = False) -> str:
    """Send an email. Plain text by default; set html=true to send the body as HTML."""
    return tools.send(_get(), to=to, subject=subject, body=body, html=html)


@mcp.tool()
def calendar(days: int = 7) -> str:
    """Show the Proton Calendar agenda for the next N days."""
    return tools.calendar(_get(), days=days)


@mcp.tool()
def contacts(query: str = "") -> str:
    """List Proton contacts (name and email), optionally filtered by a query."""
    return tools.contacts(_get(), query=query)


@mcp.tool()
def drive_list(path: str = "") -> str:
    """List a Proton Drive folder by path (folders first); empty path is the root."""
    return tools.drive_list(_get(), path=path)


@mcp.tool()
def drive_download(path: str, dest_dir: str = ".") -> str:
    """Download and decrypt a Proton Drive file to a local directory."""
    return tools.drive_download(_get(), path=path, dest_dir=dest_dir)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
