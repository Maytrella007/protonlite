"""Inbox triage: list the unread messages, newest first.

Read-only. Run after `protonlite login` with PROTONLITE_SESSION set.
"""

import datetime as dt

from protonlite import ProtonMail


def main() -> None:
    client = ProtonMail.from_session()
    unread = client.list_messages(unread_only=True, limit=25)
    if not unread:
        print("Inbox is clear -- nothing unread.")
        return
    print(f"{len(unread)} unread:")
    for m in unread:
        when = dt.datetime.fromtimestamp(m.time, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
        flag = "  (attachment)" if m.num_attachments else ""
        print(f"  {when}  {m.sender.address:30.30}  {m.subject}{flag}")


if __name__ == "__main__":
    main()
