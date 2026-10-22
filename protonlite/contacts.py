"""Reading Proton Contacts: decrypt the vCards, pull out the useful fields.

A contact is one or more vCard "cards", the same Type/Data/Signature shape as a
calendar event. The cards are encrypted and/or signed to the account's *user*
key (not an address key), so crypto.decrypt_text with the user keyring opens
them. Names, emails and notes are written by whoever the contact was saved from
(often auto-saved from an incoming mail), so a caller treats them as untrusted.
"""

from __future__ import annotations

import os
import uuid
import warnings
from dataclasses import dataclass, field

from . import crypto, send as _send
from .errors import ProtonError

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import pgpy
    from pgpy.constants import CompressionAlgorithm

# Proton's contact card types match the calendar enum.
_CARD_ENCRYPTED = 1
_CARD_ENCRYPTED_SIGNED = 3


@dataclass
class Contact:
    id: str = ""
    name: str = ""
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    org: str = ""
    title: str = ""
    note: str = ""


def _unfold(vcard: str) -> list[str]:
    """Undo vCard line folding (a continuation line starts with a space/tab)."""
    lines: list[str] = []
    for raw in vcard.replace("\r\n", "\n").split("\n"):
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    specials = {"n": "\n", "N": "\n", ",": ",", ";": ";", "\\": "\\"}
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            out.append(specials.get(value[i + 1], value[i + 1]))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def parse_vcard(vcard: str) -> dict:
    """Pull FN, EMAIL(s), TEL(s), ORG, TITLE, NOTE out of a vCard body."""
    found: dict = {"emails": [], "phones": []}
    for line in _unfold(vcard):
        if ":" not in line or line.startswith("BEGIN") or line.startswith("END"):
            continue
        name, value = line.split(":", 1)
        # strip an "itemN." group prefix and any ;parameters
        key = name.split(";", 1)[0].split(".")[-1].upper()
        value = _unescape(value.strip())
        if not value:
            continue
        if key == "FN":
            found["name"] = value
        elif key == "EMAIL":
            if value not in found["emails"]:
                found["emails"].append(value)
        elif key == "TEL":
            if value not in found["phones"]:
                found["phones"].append(value)
        elif key == "ORG":
            found["org"] = value.replace(";", " ").strip()
        elif key == "TITLE":
            found["title"] = value
        elif key == "NOTE":
            found["note"] = value
    return found


def _escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\").replace("\n", "\\n").replace(",", "\\,").replace(";", "\\;")
    )


def build_contact_cards(
    *,
    name: str,
    emails: list[str] | None = None,
    phones: list[str] | None = None,
    org: str = "",
    title: str = "",
    note: str = "",
    uid: str = "",
) -> tuple[str, str | None]:
    """Split a contact into (signed vCard, private vCard or None).

    Proton only allows a few fields (FN, EMAIL, ...) in the cleartext/signed card
    and rejects the rest ("Field not allowed in ... signed vCard"), so TEL, ORG,
    TITLE and NOTE go in a second vCard that is encrypted. Both carry the same UID.
    """
    uid = uid or "protonlite-" + str(uuid.uuid4())
    signed = ["BEGIN:VCARD", "VERSION:4.0", "PRODID:-//protonlite//EN"]
    if name:
        signed.append(f"FN:{_escape(name)}")
    for i, email in enumerate(emails or [], start=1):
        signed.append(f"item{i}.EMAIL;PREF={i}:{email.strip()}")
    signed += [f"UID:{uid}", "END:VCARD"]
    signed_vcard = "\r\n".join(signed) + "\r\n"

    private: list[str] = []
    for phone in phones or []:
        private.append(f"TEL:{phone.strip()}")
    if org:
        private.append(f"ORG:{_escape(org)}")
    if title:
        private.append(f"TITLE:{_escape(title)}")
    if note:
        private.append(f"NOTE:{_escape(note)}")
    private_vcard = None
    if private:
        private_vcard = "\r\n".join(["BEGIN:VCARD", "VERSION:4.0", *private, f"UID:{uid}", "END:VCARD"]) + "\r\n"
    return signed_vcard, private_vcard


def _detached_sig(text: str, bundle) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with crypto.unlocked(bundle) as key:
            return str(key.sign(text))


def _encrypt_to_user(text: str, bundle) -> str:
    """Armored PGP message encrypting *text* to the account's user key."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = pgpy.PGPMessage.new(text, format="u", compression=CompressionAlgorithm.Uncompressed)
        return str(_send._encrypt_with(bundle.armored, message, os.urandom(32)))


def make_cards(signed_vcard: str, private_vcard: str | None, user_bundle) -> list[dict]:
    """The API cards for a contact: a SIGNED card, plus an ENCRYPTED+SIGNED one."""
    cards = [{"Type": 2, "Data": signed_vcard, "Signature": _detached_sig(signed_vcard, user_bundle)}]
    if private_vcard:
        cards.append(
            {
                "Type": 3,
                "Data": _encrypt_to_user(private_vcard, user_bundle),
                "Signature": _detached_sig(private_vcard, user_bundle),
            }
        )
    return cards


def read_contact(raw: dict, user_bundles) -> Contact:
    """Decrypt a contact's cards and merge the vCard fields into one Contact."""
    user_bundles = list(user_bundles)
    contact = Contact(id=raw.get("ID", ""), name=raw.get("Name", ""))
    for card in raw.get("Cards", []):
        data = card.get("Data", "")
        if card.get("Type") in (_CARD_ENCRYPTED, _CARD_ENCRYPTED_SIGNED):
            try:
                data = crypto.decrypt_text(data, user_bundles, textual=True)
            except ProtonError:
                continue
        fields = parse_vcard(data)
        if fields.get("name"):
            contact.name = fields["name"]
        for email in fields["emails"]:
            if email not in contact.emails:
                contact.emails.append(email)
        for phone in fields["phones"]:
            if phone not in contact.phones:
                contact.phones.append(phone)
        for attr in ("org", "title", "note"):
            if fields.get(attr):
                setattr(contact, attr, fields[attr])
    return contact
