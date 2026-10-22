# protonlite

A small, dependency-light Python client for **Proton Mail, Calendar, Contacts and Drive** --
no Proton Mail Bridge, no paid plan.

Proton has no IMAP or SMTP. The official way in is Proton Mail Bridge, which needs a paid
plan. `protonlite` talks to Proton's web API directly, so it works on a free account, and the
end-to-end crypto is ported from **Proton's own MIT-licensed Go libraries**
([go-srp](https://github.com/ProtonMail/go-srp),
[go-proton-api](https://github.com/ProtonMail/go-proton-api)). It stays MIT-licensed and
dependency-light: just OpenPGP (`PGPy13`, a maintained fork of PGPy), `bcrypt` and `requests`. No CAPTCHA solver, no
computer-vision stack -- a person completes Proton's verification page the same way Proton's
own apps do.

> **Unofficial.** This project is not affiliated with, endorsed by, or supported by Proton AG.
> "Proton", "Proton Mail", "Proton Calendar" and "Proton Drive" are trademarks of Proton AG.
> It talks to a private, undocumented API that can change at any time, and using it may be
> subject to Proton's terms of service. Use it at your own risk, on accounts you own.

## What it does

- **Mail** -- read the inbox and any folder, decrypt messages (HTML flattened to text),
  search, send (plain or HTML, attachments, replies in-thread, scheduled), save drafts,
  mark read/unread, trash/delete, labels and folders, empty trash, storage usage.
- **Calendar** -- read the agenda, create / edit / cancel events, send invitations, RSVP.
- **Contacts** -- read, create, edit and delete contacts (signed/encrypted vCards).
- **Drive** -- list, download, upload (encrypted), move, rename, trash, and create public
  share links.

All of it is end-to-end: keys are unlocked locally with the account password and messages,
events, contacts and files are decrypted on your machine.

## Install

```bash
pip install protonlite
```

Requires Python 3.10+.

## Quickstart

```python
import os
import datetime as dt

from protonlite import ProtonMail

# --- Signing in -------------------------------------------------------------
# The recommended way is the CLI `protonlite login`, which reads the password
# with getpass so it never lives in a script. For automation, read it from the
# environment rather than hard-coding it. Proton usually asks a human to
# complete a verification page; login raises HumanVerificationRequired with
# that URL -- open it, then call again passing verification_token (see
# "Signing in" below). Sign in each account once; every login saves its own
# session file.
ProtonMail.login(
    "you@proton.me",
    password=os.environ["PROTON_PASSWORD"].encode(),
    session_path="you@proton.me.json",
)

# --- More than one account --------------------------------------------------
# Reopen each saved session independently -- no password needed. The two
# clients are fully independent mailboxes.
client  = ProtonMail.from_session(session_path="you@proton.me.json")    # personal
client1 = ProtonMail.from_session(session_path="work@proton.me.json")   # work
# (after a CLI `protonlite login`, ProtonMail.for_account("work") finds it by name)
print(client.addresses()[0]["Email"], "/", client1.addresses()[0]["Email"])

# --- Mail -------------------------------------------------------------------
for msg in client.list_messages(unread_only=True):
    print(msg.time, msg.sender.address, msg.subject)
full = client.read_message(msg.id)
print(full.text)                                  # HTML flattened to prose
client.send(to=["friend@example.com"], subject="Hi", body="Hello")
client1.send(to=["teammate@work.com"], subject="Hi from work", body="Hello")

# --- Calendar ---------------------------------------------------------------
cal_id = client.list_calendars()[0]["ID"]
begins = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
event = client.create_event(cal_id, summary="Demo",
                            start=begins, end=begins + dt.timedelta(hours=1))
for ev in client.list_events(cal_id, start=int(begins.timestamp()) - 3600,
                             end=int(begins.timestamp()) + 86400):
    print(dt.datetime.fromtimestamp(ev.start, dt.timezone.utc), ev.title)
client.delete_event(cal_id, event["id"])

# --- Contacts ---------------------------------------------------------------
cid = client.create_contact(name="Ada Lovelace", emails=["ada@example.com"])
for row in client.list_contact_emails():
    print(row["name"], row["email"])
client.delete_contacts([cid])

# --- Drive ------------------------------------------------------------------
drive = client.drive()
with open("report.pdf", "rb") as fh:
    drive.upload("", "report.pdf", fh.read(), "application/pdf")
for entry in drive.list_folder(""):
    print(entry["name"], entry["type"])
link = drive.share_link("report.pdf")
print(link["url"])                                # https://drive.proton.me/urls/...#password
```

### Command line

A small CLI covers the mail basics:

```bash
protonlite login --user you@proton.me
protonlite unread
protonlite read <message-id>
protonlite send --to friend@example.com --subject "Hi" --body "Hello"
```

## Signing in

Proton logins from a server almost always trigger a human-verification page (hCaptcha). The
login flow surfaces that URL so a person can complete it in a browser; `protonlite` never
solves it and never asks for a password over any channel but your own code. The account
password is used only to derive keys locally -- it is never stored; the saved session holds
OAuth-style tokens and the derived key passphrase, nothing more. Two-factor (TOTP) is
supported.

## MCP server

`protonlite` ships an optional [MCP](https://modelcontextprotocol.io) server so any MCP client
(Cursor, Claude Code, Claude Desktop) can use Proton through it. Sign in once with the CLI,
then run the server pointed at that session:

```bash
pip install "protonlite[mcp]"
protonlite login --user you@proton.me          # one-time; saves a session file
PROTONLITE_SESSION=~/you@proton.me.json protonlite-mcp
```

Wire it into an MCP client (e.g. Claude Desktop / Cursor `mcpServers` config):

```json
{
  "mcpServers": {
    "proton": {
      "command": "protonlite-mcp",
      "env": { "PROTONLITE_SESSION": "/home/you/you@proton.me.json" }
    }
  }
}
```

The server never takes a password -- it reuses the saved session. It exposes `list_messages`,
`read_message`, `search_messages`, `send_message`, `calendar`, `contacts`, `drive_list` and
`drive_download`, and returns other people's content wrapped as untrusted data.

## Status and limits

The write paths (Drive upload, calendar event creation, share links) were reverse-engineered
from Proton's Go and web clients and verified against live accounts, but the API is
undocumented and may change. Calendar key generation shells out to `gpg` (Proton requires an
Ed25519 key that `PGPy` cannot generate). Bug reports and PRs welcome.

## Related

`protonlite` is also the engine behind [hermes-proton](https://github.com/Maytrella007/hermes-proton), a Proton plugin for the
[Hermes Agent](https://github.com/NousResearch/hermes-agent) that adds a recipient allowlist
and a human-approval gate on every send.

## License

MIT. See [LICENSE](LICENSE).
