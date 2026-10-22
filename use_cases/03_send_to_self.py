"""Send an email to yourself, confirm it arrives, then clean up both copies.

Sending is the one example that leaves the outside world; sending to your own
address keeps it self-contained. It trashes the sent and received copies when
done. Run with PROTONLITE_SESSION set.
"""

import time

from protonlite import ProtonMail

SUBJECT = f"protonlite demo {int(time.time())}"


def main() -> None:
    client = ProtonMail.from_session()
    me = client.api.session.username
    print(f"Sending a note to {me} ...")
    client.send(to=[me], subject=SUBJECT, body="Hello from protonlite.")
    print("  sent.")

    # Give Proton a moment to deliver, then find both copies by the subject.
    time.sleep(3)
    copies = [m for m in client.list_messages(label="all", limit=50) if m.subject == SUBJECT]
    print(f"  found {len(copies)} copy/copies (sent + inbox).")
    if copies:
        client.trash([m.id for m in copies])
        print("  trashed the demo copies -- account clean.")


if __name__ == "__main__":
    main()
