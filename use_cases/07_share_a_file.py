"""Upload a demo file, create a public share link for it, then revoke it.

Creates a file, a public link, and cleans both up. The link's password is the
part after '#' and never reaches Proton's server, so the whole URL is the
secret. Run with PROTONLITE_SESSION set.
"""

import time

from protonlite import ProtonMail

NAME = f"protonlite-share-demo-{int(time.time())}.txt"


def main() -> None:
    client = ProtonMail.from_session()
    drive = client.drive()

    print(f"Uploading {NAME} ...")
    drive.upload("", NAME, b"A file shared by the protonlite example.", "text/plain")

    print("Creating a public share link ...")
    info = drive.share_link(NAME)
    print(f"  URL: {info['url']}")
    print("  (anyone with that URL can view the file -- the password is after '#')")

    print("Revoking the link ...")
    removed = drive.unshare_link(NAME)
    print(f"  revoked: {removed}")

    drive.trash(NAME)
    print("Trashed the demo file -- clean.")


if __name__ == "__main__":
    main()
