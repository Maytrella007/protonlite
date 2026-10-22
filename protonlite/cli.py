"""Command line entry point: ``python -m protonlite <command>``.

The login prompts for the password here, in the terminal, so it never travels
through a shell history, an environment variable or someone else's transcript.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import json
import sys
from typing import Any

from .client import DEFAULT_SESSION_PATH, SYSTEM_LABELS, ProtonMail
from .errors import HumanVerificationRequired, ProtonError, TwoFactorRequired
from .htmltext import render_body


def _stamp(epoch: int) -> str:
    return _dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


def _cmd_login(args: argparse.Namespace) -> int:
    username = args.user or input("Proton address: ").strip()
    password = getpass.getpass("Proton password (not shown): ")
    if not password:
        print("no password given", file=sys.stderr)
        return 2
    token = getattr(args, "verification_token", "") or ""
    code = getattr(args, "totp_code", "") or ""
    try:
        client = ProtonMail.login(
            username,
            password.encode(),
            session_path=args.session,
            verification_token=token,
            totp_code=code,
        )
    except TwoFactorRequired as needed:
        print(f"\n{needed}")
        if code or not sys.stdin.isatty():
            return 1
        code = input("Six-digit code: ").strip()
        if not code:
            return 2
        client = ProtonMail.login(
            username,
            password.encode(),
            session_path=args.session,
            verification_token=token,
            totp_code=code,
        )
    except HumanVerificationRequired as challenge:
        # Proton points at a page where a person completes the check, then the
        # same token is what gets the login through. Interactively we can wait
        # right here; otherwise print it and let the caller come back with it.
        print(f"\nProton wants verification before this login ({', '.join(challenge.methods)}).")
        print(f"Open this and complete it:\n\n  {challenge.web_url}\n")
        if not sys.stdin.isatty():
            print("Then run the login again with:")
            print(f"  --verification-token {challenge.token}")
            return 1
        input("Press Enter once it is done... ")
        client = ProtonMail.login(
            username,
            password.encode(),
            session_path=args.session,
            verification_token=challenge.token,
            totp_code=code,
        )

    addresses = [a["Email"] for a in client.addresses()]
    print(f"logged in as {username}")
    print(f"addresses: {', '.join(addresses)}")
    print(f"session saved to {args.session} (0600)")
    return 0


def _cmd_logout(args: argparse.Namespace) -> int:
    client = ProtonMail.from_session(session_path=args.session)
    client.api.logout()
    print("session revoked on Proton's side and cleared locally")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    client = ProtonMail.from_session(session_path=args.session)
    messages = client.list_messages(
        label=args.label, unread_only=args.unread, limit=args.limit
    )
    if args.json:
        print(json.dumps([_summary_dict(m) for m in messages], indent=2))
        return 0
    if not messages:
        print("nothing to show")
        return 0
    for message in messages:
        mark = "*" if message.unread else " "
        clip = (message.subject or "(no subject)")[:60]
        print(f"{mark} {_stamp(message.time)}  {str(message.sender)[:38]:38}  {clip}")
        print(f"    id: {message.id}")
    return 0


def _cmd_read(args: argparse.Namespace) -> int:
    client = ProtonMail.from_session(session_path=args.session)
    message = client.read_message(args.id)
    if args.mark_read:
        client.mark_read([message.id])
    if args.json:
        print(json.dumps({**_summary_dict(message), "body": message.text}, indent=2))
        return 0
    print(f"From:    {message.sender}")
    print(f"To:      {', '.join(str(c) for c in message.to)}")
    print(f"Date:    {_stamp(message.time)}")
    print(f"Subject: {message.subject}")
    if message.attachments:
        names = ", ".join(a.get("Name", "?") for a in message.attachments)
        print(f"Files:   {names}")
    print()
    print(message.text)
    return 0


def _cmd_send(args: argparse.Namespace) -> int:
    client = ProtonMail.from_session(session_path=args.session)
    body = args.body if args.body is not None else sys.stdin.read()
    rendered, mime_type = render_body(body, args.format)
    sent = client.send(
        to=args.to,
        subject=args.subject,
        body=rendered,
        cc=args.cc or [],
        from_address=args.sender,
        mime_type=mime_type,
    )
    print(f"sent, id {sent.id}")
    return 0


def _summary_dict(message: Any) -> dict[str, Any]:
    return {
        "id": message.id,
        "subject": message.subject,
        "from": str(message.sender),
        "date": _stamp(message.time),
        "unread": message.unread,
        "attachments": message.num_attachments,
    }


def _cmd_mcp(args: argparse.Namespace) -> int:
    # The MCP server lives behind the optional [mcp] extra so the base install
    # stays light. Import it only when this runs, and point at the extra if it
    # is missing instead of surfacing a bare ImportError.
    try:
        from protonlite_mcp.server import main as mcp_main
    except ModuleNotFoundError:
        print('the MCP server needs the extra: pip install "protonlite[mcp]"', file=sys.stderr)
        return 1
    mcp_main()
    return 0


def _print_policy() -> int:
    # Reuse the same status text the MCP server shows, so the CLI and the agent
    # describe the policy identically. Neither import needs the [mcp] extra.
    from protonlite_mcp import tools as _mcp_tools

    print(_mcp_tools.email_policy_status())
    return 0


def _cmd_policy_show(args: argparse.Namespace) -> int:
    return _print_policy()


def _cmd_policy_allow(args: argparse.Namespace) -> int:
    from protonlite_mcp import policy

    policy.set_allowed(args.recipients)
    return _print_policy()


def _cmd_policy_ceiling(args: argparse.Namespace) -> int:
    from protonlite_mcp import policy

    if args.clear:
        policy.set_locked(ceiling=None)
    elif args.recipients:
        policy.set_locked(ceiling=args.recipients)
    else:
        print("give one or more addresses/globs, or --clear to remove the ceiling", file=sys.stderr)
        return 1
    return _print_policy()


def _cmd_policy_require_confirm(args: argparse.Namespace) -> int:
    from protonlite_mcp import policy

    policy.set_locked(require_confirmation=(args.state == "on"))
    return _print_policy()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protonlite", description="Read and send Proton Mail from the command line."
    )
    parser.add_argument(
        "--session",
        default=str(DEFAULT_SESSION_PATH),
        help=f"where the session file lives (default: {DEFAULT_SESSION_PATH})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="log in and save a session")
    login.add_argument("--user", help="the Proton address to log in as")
    login.add_argument(
        "--verification-token",
        default="",
        help="a verification token you already completed on Proton's page",
    )
    login.add_argument(
        "--totp-code",
        default="",
        help="six-digit code from your authenticator app, if the account has one",
    )
    login.set_defaults(func=_cmd_login)

    logout = sub.add_parser("logout", help="revoke the saved session")
    logout.set_defaults(func=_cmd_logout)

    listing = sub.add_parser("list", help="list messages in a folder")
    listing.add_argument("--label", default="inbox", choices=sorted(SYSTEM_LABELS))
    listing.add_argument("--unread", action="store_true", help="only unread messages")
    listing.add_argument("--limit", type=int, default=20)
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(func=_cmd_list)

    unread = sub.add_parser("unread", help="shorthand for: list --unread")
    unread.add_argument("--limit", type=int, default=20)
    unread.add_argument("--json", action="store_true")
    unread.set_defaults(func=_cmd_list, label="inbox", unread=True)

    read = sub.add_parser("read", help="read one message by id")
    read.add_argument("id")
    read.add_argument("--mark-read", action="store_true")
    read.add_argument("--json", action="store_true")
    read.set_defaults(func=_cmd_read)

    send = sub.add_parser("send", help="send a message")
    send.add_argument("--to", action="append", required=True, help="repeatable")
    send.add_argument("--cc", action="append")
    send.add_argument("--subject", required=True)
    send.add_argument("--body", help="message text; read from stdin when omitted")
    send.add_argument(
        "--format",
        choices=["auto", "html", "text"],
        default="auto",
        help="auto: plain text rendered to HTML (default); html: body is HTML; text: plain",
    )
    send.add_argument("--sender", help="which of your addresses to send from")
    send.set_defaults(func=_cmd_send)

    mcp_server = sub.add_parser(
        "mcp", help='run the MCP server over stdio (needs the "protonlite[mcp]" extra)'
    )
    mcp_server.set_defaults(func=_cmd_mcp)

    policy_p = sub.add_parser(
        "policy", help="manage the MCP server's send policy (allowlist and confirmation)"
    )
    psub = policy_p.add_subparsers(dest="policy_cmd", required=True)

    p_show = psub.add_parser("show", help="print the current send policy")
    p_show.set_defaults(func=_cmd_policy_show)

    p_allow = psub.add_parser(
        "allow", help="set the recipient allowlist (addresses or globs; '*' opens it, none blocks all)"
    )
    p_allow.add_argument("recipients", nargs="*", help="addresses or globs; omit to block all sends")
    p_allow.set_defaults(func=_cmd_policy_allow)

    p_ceiling = psub.add_parser(
        "ceiling",
        help="set a HARD recipient ceiling the agent cannot loosen (empty + --clear removes it)",
    )
    p_ceiling.add_argument("recipients", nargs="*", help="addresses or globs the agent may never exceed")
    p_ceiling.add_argument("--clear", action="store_true", help="remove the hard ceiling")
    p_ceiling.set_defaults(func=_cmd_policy_ceiling)

    p_rc = psub.add_parser(
        "require-confirm",
        help="on: enforce confirmation so the agent cannot send (a person sends from the CLI); off: lift it",
    )
    p_rc.add_argument("state", choices=["on", "off"])
    p_rc.set_defaults(func=_cmd_policy_require_confirm)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ProtonError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
