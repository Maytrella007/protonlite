"""Back up a local file to Proton Drive, download it again to verify, delete it.

Creates and deletes one Drive file. Run with PROTONLITE_SESSION set.
Usage: python 06_drive_backup.py [local_file]   (default: this script)
"""

import os
import sys

from protonlite import ProtonMail


def main(local_path: str) -> None:
    client = ProtonMail.from_session()
    drive = client.drive()
    name = "protonlite-demo-" + os.path.basename(local_path)

    with open(local_path, "rb") as fh:
        original = fh.read()

    print(f"Uploading {name} ({len(original)} bytes) to the Drive root ...")
    drive.upload("", name, original, "application/octet-stream")
    print("  uploaded.")

    listing = [e["name"] for e in drive.list_folder("")]
    print(f"  root now has {len(listing)} item(s); present: {name in listing}")

    print("Downloading it back to verify the round-trip ...")
    got_name, _mime, data = drive.download(name)
    print(f"  downloaded {got_name} ({len(data)} bytes); identical: {data == original}")

    drive.trash(name)
    print("Moved the demo file to Drive trash -- clean.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else __file__)
