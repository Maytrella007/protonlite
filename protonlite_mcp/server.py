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
def send_message(to: list[str], subject: str, body: str, html: bool = False,
                 attachments: list[str] | None = None, confirm: bool = False) -> str:
    """Send an email. Plain text by default; set html=true to send the body as HTML.
    attachments is a list of local file paths to attach, e.g. a file you just fetched
    with drive_download. A send is refused if a recipient is not on the allowlist
    (see email_policy_status / email_allow). When the confirm-before-sending rule is
    on, the first call sends nothing and returns a confirmation request; call again
    with confirm=true once the person has approved."""
    return tools.send(_get(), to=to, subject=subject, body=body, html=html,
                      attachments=attachments, confirm=confirm)


@mcp.tool()
def email_policy_status() -> str:
    """Show the send policy: which recipients the allowlist permits (or that it is open),
    any hard ceiling set by the PROTON_ALLOWED_RECIPIENTS env var, and whether a send
    needs confirmation."""
    return tools.email_policy_status()


@mcp.tool()
def email_allow(recipients: list[str]) -> str:
    """Set the recipient allowlist for send_message. Pass specific addresses or globs
    (e.g. *@company.com) to restrict sending to them, ["*"] to allow anyone, or [] to
    block all sending. A hard ceiling from PROTON_ALLOWED_RECIPIENTS still applies on
    top and cannot be loosened here."""
    return tools.email_allow(recipients)


@mcp.tool()
def set_send_confirmation(required: bool) -> str:
    """Turn the 'confirm before sending' rule on or off. When on, send_message sends
    nothing until it is called again with confirm=true, so a person can approve first.
    If PROTON_REQUIRE_SEND_CONFIRMATION is set, the rule is forced on and cannot be
    turned off here."""
    return tools.set_send_confirmation(required)


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


@mcp.tool()
def drive_upload(local_path: str, dest_folder: str = "", name: str = "",
                 mime_type: str = "application/octet-stream") -> str:
    """Encrypt and upload a local file into a Proton Drive folder (empty dest_folder is the root)."""
    return tools.drive_upload(_get(), local_path=local_path, dest_folder=dest_folder,
                              name=name, mime_type=mime_type)


@mcp.tool()
def drive_mkdir(name: str, parent_folder: str = "") -> str:
    """Create a new Proton Drive folder (empty parent_folder is the root)."""
    return tools.drive_mkdir(_get(), name=name, parent_folder=parent_folder)


@mcp.tool()
def drive_move(path: str, dest_folder: str) -> str:
    """Move a Proton Drive file or folder into another folder (empty dest_folder is the root)."""
    return tools.drive_move(_get(), path=path, dest_folder=dest_folder)


@mcp.tool()
def drive_rename(path: str, new_name: str) -> str:
    """Rename a Proton Drive file or folder in place."""
    return tools.drive_rename(_get(), path=path, new_name=new_name)


@mcp.tool()
def drive_trash(path: str) -> str:
    """Move a Proton Drive file or folder to the trash (recoverable in Proton Drive)."""
    return tools.drive_trash(_get(), path=path)


@mcp.tool()
def drive_share_link(path: str) -> str:
    """Create a public share link for a Proton Drive file or folder. The returned URL is
    the whole secret (its fragment holds the password) and lets anyone open the file, so
    only share it when the person asked to make this file public."""
    return tools.drive_share_link(_get(), path=path)


@mcp.tool()
def drive_unshare_link(path: str) -> str:
    """Revoke a Proton Drive file or folder's public share link."""
    return tools.drive_unshare_link(_get(), path=path)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
