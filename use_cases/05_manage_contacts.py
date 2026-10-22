"""Add a demo contact, look it up, then delete it.

Creates and deletes one contact. Run with PROTONLITE_SESSION set.
"""

from protonlite import ProtonMail

NAME = "protonlite demo contact"
EMAIL = "demo@example.com"


def main() -> None:
    client = ProtonMail.from_session()

    print(f"Creating {NAME!r} ...")
    contact_id = client.create_contact(name=NAME, emails=[EMAIL], phones=["+1 555 0100"], org="protonlite")
    print(f"  created (id {contact_id}).")

    # Look it up two ways: in the address list, and by full detail.
    rows = client.list_contact_emails()
    found = [r for r in rows if r.get("email") == EMAIL]
    print(f"  address book has {len(rows)} contact(s); {len(found)} match {EMAIL}.")
    detail = client.get_contact(contact_id)
    print(f"  detail: name={detail.name!r} emails={detail.emails} phones={detail.phones}")

    client.delete_contacts([contact_id])
    print("Deleted the demo contact -- address book clean.")


if __name__ == "__main__":
    main()
