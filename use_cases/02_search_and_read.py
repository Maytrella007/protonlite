"""Find a message by a word in its subject or sender, then read it decrypted.

Read-only. Usage: python 02_search_and_read.py [query]   (default: "proton")
"""

import sys

from protonlite import ProtonMail


def main(query: str = "proton") -> None:
    client = ProtonMail.from_session()
    # There is no server-side full-text search on the free API, so scan a page
    # of "all mail" and match locally on subject or sender.
    candidates = client.list_messages(label="all", limit=100)
    q = query.lower()
    hits = [m for m in candidates if q in m.subject.lower() or q in m.sender.address.lower()]
    if not hits:
        print(f"No message matching {query!r} in the last 100.")
        return
    print(f"{len(hits)} match {query!r}; reading the first:\n")
    full = client.read_message(hits[0].id)
    print(f"From:    {full.sender.address}")
    print(f"Subject: {full.subject}\n")
    body = full.text
    print(body[:800] + (" ..." if len(body) > 800 else ""))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "proton")
