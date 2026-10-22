"""Reading a Proton Calendar: unlock the calendar key, decrypt the events.

Proton Calendar is end-to-end encrypted with the same primitives as mail. A
calendar carries a passphrase encrypted to each member's address key (and
signed); opening that unlocks the calendar's own PGP key. Each event then ships
as iCalendar "cards" -- some in the clear, some encrypted to the calendar key
with one shared session key (the event's SharedKeyPacket). That key-packet plus
data-packet shape is exactly an attachment's, so crypto.decrypt_attachment opens
the encrypted cards without anything new.

The sensitive parts (title, location, description, the organizer's name) live in
the encrypted cards and come from whoever sent the invitation, so a caller must
treat them as untrusted data, the same as a mail body.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
import warnings
from dataclasses import dataclass

from . import crypto, send as _send
from .crypto import KeyBundle
from .errors import ProtonError

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import pgpy
    from pgpy.constants import CompressionAlgorithm

# Proton's calendar card types (proton-shared CALENDAR_CARD_TYPE).
_CARD_CLEAR = 0
_CARD_ENCRYPTED = 1
_CARD_SIGNED = 2
_CARD_ENCRYPTED_SIGNED = 3

#: iCalendar content fields worth surfacing from a VEVENT.
_WANTED = ("SUMMARY", "LOCATION", "DESCRIPTION", "ORGANIZER", "RRULE")


@dataclass
class CalendarEvent:
    """One decrypted event. The times are clear on the API; the rest is from
    the encrypted cards and is therefore sender-authored, untrusted text."""

    id: str
    start: int  # epoch seconds
    end: int
    start_tz: str = ""  # the event's own timezone, e.g. "America/New_York"
    full_day: bool = False
    title: str = ""
    location: str = ""
    description: str = ""
    organizer: str = ""
    rrule: str = ""
    num_attendees: int = 0


def _unfold(ical: str) -> list[str]:
    """Undo iCalendar line folding (a continuation line starts with a space)."""
    lines: list[str] = []
    for raw in ical.replace("\r\n", "\n").split("\n"):
        if raw[:1] in (" ", "\t") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _unescape(value: str) -> str:
    """Undo iCalendar TEXT escaping (\\n, \\,, \\;, \\\\)."""
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


def _fields(ical: str) -> dict[str, str]:
    """Pull the content fields out of a VEVENT body (last value wins)."""
    found: dict[str, str] = {}
    for line in _unfold(ical):
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.split(";", 1)[0].upper()
        if key not in _WANTED:
            continue
        if key == "ORGANIZER":
            # Prefer the display name (CN=...) over the mailto: address.
            cn = ""
            for param in name.split(";")[1:]:
                if param.upper().startswith("CN="):
                    cn = param[3:].strip('"')
            found[key] = cn or value.replace("mailto:", "", 1)
        else:
            found[key] = _unescape(value)
    return found


def decrypt_event(raw: dict, calendar_bundle: KeyBundle) -> CalendarEvent:
    """Decrypt one event's cards and read its iCalendar fields."""
    skp = base64.b64decode(raw["SharedKeyPacket"]) if raw.get("SharedKeyPacket") else b""
    fields: dict[str, str] = {}
    for card in raw.get("SharedEvents", []):
        kind = card.get("Type")
        data = card.get("Data") or ""
        if kind in (_CARD_CLEAR, _CARD_SIGNED):
            fields.update(_fields(data))
        elif kind in (_CARD_ENCRYPTED, _CARD_ENCRYPTED_SIGNED) and skp:
            try:
                opened = crypto.decrypt_attachment(
                    skp, base64.b64decode(data), [calendar_bundle]
                )
            except ProtonError:
                continue
            fields.update(_fields(opened.decode("utf-8", "replace")))
    return CalendarEvent(
        id=raw.get("ID", ""),
        start=int(raw.get("StartTime", 0) or 0),
        end=int(raw.get("EndTime", 0) or 0),
        start_tz=raw.get("StartTimezone", "") or "",
        full_day=bool(raw.get("FullDay")),
        title=fields.get("SUMMARY", ""),
        location=fields.get("LOCATION", ""),
        description=fields.get("DESCRIPTION", ""),
        organizer=fields.get("ORGANIZER", ""),
        rrule=fields.get("RRULE", ""),
        num_attendees=len(raw.get("Attendees") or []),
    )


def _escape(value: str) -> str:
    """iCalendar TEXT escaping -- the inverse of _unescape."""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace(",", "\\,")
        .replace(";", "\\;")
    )


def _fold(line: str) -> str:
    """Fold a content line to <=75 octets, continuation lines starting a space."""
    raw = line.encode("utf-8")
    if len(raw) <= 75:
        return line
    chunks: list[bytes] = []
    first = True
    while raw:
        take = 75 if first else 74  # continuation lines lose one octet to the space
        # do not split a multi-byte UTF-8 character across the fold
        cut = take
        while cut > 0 and (raw[cut:cut + 1] and (raw[cut] & 0xC0) == 0x80):
            cut -= 1
        cut = cut or take
        chunk, raw = raw[:cut], raw[cut:]
        chunks.append(chunk if first else b" " + chunk)
        first = False
    return "\r\n".join(c.decode("utf-8") for c in chunks)


def vevent(uid: str, properties: list[tuple[str, str]]) -> str:
    """Wrap a set of iCalendar properties as a VCALENDAR/VEVENT card body.

    Each *property* is a (name_with_params, value) pair; the value is TEXT-escaped
    unless the name already carries its own encoding (DTSTART, ORGANIZER, ATTENDEE,
    which pass a pre-formatted value). UID is always included to tie the cards of
    one event together.
    """
    raw_value_props = ("DTSTART", "DTEND", "DTSTAMP", "ORGANIZER", "ATTENDEE", "SEQUENCE")
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", f"UID:{uid}"]
    for name, value in properties:
        bare = name.split(";", 1)[0].upper()
        text = value if bare in raw_value_props else _escape(value)
        lines.append(_fold(f"{name}:{text}"))
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines)


def encrypt_card(
    ical: str, session_key: bytes, calendar_key_armored: str, signer: KeyBundle | None = None
) -> tuple[str, str]:
    """Encrypt one iCal card under the shared session key, optionally signing it.

    Returns (base64 data packet, armored detached signature or ""). The data
    packet is the card's Data; paired with the SharedKeyPacket (the session key
    wrapped to the calendar key) a reader opens it. The signature, when a signer
    is given, is over the plaintext and is verified later with the address key.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = pgpy.PGPMessage.new(
            ical, format="u", compression=CompressionAlgorithm.Uncompressed
        )
        encrypted = _send._encrypt_with(calendar_key_armored, message, session_key)
        data_packet = _send._take(bytes(encrypted), (_send.TAG_SEIPD, _send.TAG_SED))
        signature = ""
        if signer is not None:
            with crypto.unlocked(signer) as key:
                signature = str(key.sign(ical))
    return base64.b64encode(data_packet).decode(), signature


def wrap_session_key(session_key: bytes, calendar_key_armored: str) -> str:
    """The session key wrapped to the calendar key, base64 -- the SharedKeyPacket."""
    return _send.key_packet_for(session_key, calendar_key_armored)


def recover_session_key(shared_key_packet_b64: str, bundle: KeyBundle) -> bytes:
    """Recover an event's session key by decrypting its SharedKeyPacket.

    Editing needs this: the update API forbids a fresh key packet ("SharedKeyPacket
    is not allowed"), so the new content has to be encrypted under the same session
    key the event already uses.
    """
    from pgpy.packet import Packet

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pkesk = Packet(bytearray(base64.b64decode(shared_key_packet_b64)))
        with crypto.unlocked(bundle) as key:
            for candidate in [key, *key.subkeys.values()]:
                try:
                    _alg, session_key = pkesk.decrypt_sk(candidate._key)
                    return bytes(session_key)
                except Exception:
                    continue
    raise ProtonError("could not recover the event's session key")


def detached_signature(text: str, signer: KeyBundle) -> str:
    """An armored detached signature over the plaintext, by the address key."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with crypto.unlocked(signer) as key:
            return str(key.sign(text))


def attendee_token(uid: str, canonical_email: str) -> str:
    """Proton's attendee token: SHA1(UID + canonical email), lowercase hex.

    The same value the attendee's own client recomputes to match an RSVP, so the
    email must be the server-canonical form.
    """
    return hashlib.sha1(f"{uid}{canonical_email}".encode("utf-8")).hexdigest()


def attendee_property(email: str, token: str) -> tuple[str, str]:
    """One ATTENDEE iCalendar property (name-with-params, value) for a VEVENT."""
    name = (
        "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;RSVP=TRUE;"
        f"PARTSTAT=NEEDS-ACTION;X-PM-TOKEN={token};CN={email}"
    )
    return name, f"mailto:{email}"


def build_invite_ics(
    *,
    uid: str,
    dtstamp: str,
    dtstart: str,
    dtend: str,
    summary: str,
    location: str,
    description: str,
    organizer_email: str,
    attendees: list[tuple[str, str]],
    method: str = "REQUEST",
    sequence: int = 0,
) -> str:
    """The .ics an attendee is emailed: a full VCALENDAR with METHOD:REQUEST.

    dtstart/dtend are pre-formatted iCal date-times (they pass through unescaped),
    the rest is TEXT-escaped. attendees is a list of (email, token).
    """
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Proton AG//protonlite//EN",
        f"METHOD:{method}",
        "CALSCALE:GREGORIAN",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{dtstamp}",
        f"DTSTART:{dtstart}",
        f"DTEND:{dtend}",
        f"SEQUENCE:{sequence}",
        _fold(f"ORGANIZER;CN={organizer_email}:mailto:{organizer_email}"),
    ]
    if summary:
        lines.append(_fold(f"SUMMARY:{_escape(summary)}"))
    if location:
        lines.append(_fold(f"LOCATION:{_escape(location)}"))
    if description:
        lines.append(_fold(f"DESCRIPTION:{_escape(description)}"))
    for email, token in attendees:
        name, value = attendee_property(email, token)
        lines.append(_fold(f"{name}:{value}"))
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines)


#: iCal PARTSTAT and the Proton API status for each answer.
RSVP_ANSWERS = {
    "yes": ("ACCEPTED", 3),
    "accept": ("ACCEPTED", 3),
    "accepted": ("ACCEPTED", 3),
    "no": ("DECLINED", 2),
    "decline": ("DECLINED", 2),
    "declined": ("DECLINED", 2),
    "maybe": ("TENTATIVE", 1),
    "tentative": ("TENTATIVE", 1),
}


def generate_calendar_key(passphrase: str) -> str:
    """An Ed25519+Curve25519 OpenPGP key, armored and locked with *passphrase*.

    Proton requires an ed25519 calendar key, and pgpy cannot generate one the
    server accepts (it answers 500), so this shells out to gpg -- which must be
    installed. pgpy reads and uses the resulting key fine; it is only generation
    that it gets wrong.
    """
    gpg = shutil.which("gpg")
    if not gpg:
        raise ProtonError(
            "provisioning a new calendar needs the 'gpg' command, which is not installed"
        )
    home = tempfile.mkdtemp(prefix="protonlite-cal-")
    try:
        env = {**os.environ, "GNUPGHOME": home}

        def run(*args: str) -> subprocess.CompletedProcess:
            # Pass the passphrase on stdin (--passphrase-fd 0), never on argv,
            # so it is not visible in the process table to other local users.
            result = subprocess.run(
                [gpg, "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0", *args],
                input=passphrase,
                env=env,
                capture_output=True,
                text=True,
            )
            if result.returncode:
                raise ProtonError(f"gpg failed: {result.stderr.strip()[:200]}")
            return result

        run("--quick-generate-key", "Calendar key", "ed25519", "cert,sign", "never")
        listing = subprocess.run(
            [gpg, "--batch", "--with-colons", "--list-keys"], env=env, capture_output=True, text=True
        ).stdout
        fpr = next((l.split(":")[9] for l in listing.splitlines() if l.startswith("fpr")), "")
        if not fpr:
            raise ProtonError("gpg did not report a key fingerprint")
        run("--quick-add-key", fpr, "cv25519", "encr", "never")
        exported = run("--export-secret-keys", "--armor", fpr)
        if not exported.stdout:
            raise ProtonError("gpg produced no key")
        return exported.stdout
    finally:
        shutil.rmtree(home, ignore_errors=True)


def ical_to_datetime(line: str) -> "object":
    """Parse a DTSTART/DTEND property line to an aware datetime.

    Handles a trailing Z (UTC), a TZID parameter (resolved with zoneinfo), or a
    floating time (taken as UTC). An all-day date is returned at midnight UTC.
    """
    import datetime as dt

    name, value = line.split(":", 1)
    params = name.split(";")[1:]
    tzid = next((p[5:] for p in params if p.upper().startswith("TZID=")), "")
    value = value.strip()
    if value.endswith("Z"):
        return dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    if "T" in value:
        naive = dt.datetime.strptime(value, "%Y%m%dT%H%M%S")
    else:
        naive = dt.datetime.strptime(value, "%Y%m%d")
    if tzid:
        try:
            from zoneinfo import ZoneInfo

            return naive.replace(tzinfo=ZoneInfo(tzid))
        except Exception:
            pass
    return naive.replace(tzinfo=dt.timezone.utc)


def parse_invite(ics: str) -> dict:
    """Pull what a REPLY needs out of a received invitation .ics.

    Returns uid, organizer (email), summary, location, the raw DTSTART/DTEND
    property lines (preserved verbatim so the reply echoes the same time), and
    the attendee list [{email, token}].
    """
    out: dict = {"attendees": [], "timing": []}
    for line in _unfold(ics):
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        bare = name.split(";", 1)[0].upper()
        params = name.split(";")[1:]
        if bare == "UID":
            out["uid"] = value
        elif bare == "ORGANIZER":
            out["organizer"] = value.replace("mailto:", "", 1).strip()
        elif bare in ("DTSTART", "DTEND"):
            out["timing"].append(f"{name}:{value}")
        elif bare == "SUMMARY":
            out["summary"] = _unescape(value)
        elif bare == "LOCATION":
            out["location"] = _unescape(value)
        elif bare == "DESCRIPTION":
            out["description"] = _unescape(value)
        elif bare == "ATTENDEE":
            token = ""
            for param in params:
                if param.upper().startswith("X-PM-TOKEN="):
                    token = param.split("=", 1)[1]
            out["attendees"].append(
                {"email": value.replace("mailto:", "", 1).strip(), "token": token}
            )
    return out


def build_reply_ics(
    *,
    uid: str,
    organizer_email: str,
    attendee_email: str,
    token: str,
    partstat: str,
    dtstamp: str,
    timing: list[str],
    summary: str = "",
) -> str:
    """The .ics a person emails the organizer to answer: METHOD:REPLY, one ATTENDEE."""
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Proton AG//protonlite//EN",
        "METHOD:REPLY",
        "CALSCALE:GREGORIAN",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{dtstamp}",
    ]
    lines += [_fold(t) for t in timing]
    lines.append(_fold(f"ORGANIZER:mailto:{organizer_email}"))
    att = f"ATTENDEE;PARTSTAT={partstat}" + (f";X-PM-TOKEN={token}" if token else "")
    lines.append(_fold(f"{att}:mailto:{attendee_email}"))
    if summary:
        lines.append(_fold(f"SUMMARY:{_escape(summary)}"))
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines)


def calendar_keyring(client, calendar_id: str) -> KeyBundle:
    """Bootstrap a calendar and return its unlocked PGP key as a KeyBundle.

    The member passphrase is decrypted to the signed-in address key and its
    signature verified (crypto.decrypt_token), so a tampered passphrase is
    rejected rather than used.
    """
    bootstrap = client.api.get(f"/calendar/v1/{calendar_id}/bootstrap")
    mine = {a["ID"] for a in client.addresses()}
    member = next((m for m in bootstrap.get("Members", []) if m.get("AddressID") in mine), None)
    if member is None:
        raise ProtonError("no member of this calendar matches a signed-in address")
    passphrases = (bootstrap.get("Passphrase") or {}).get("MemberPassphrases", [])
    mp = next((p for p in passphrases if p.get("MemberID") == member["ID"]), None)
    if mp is None:
        raise ProtonError("this calendar has no passphrase for the signed-in member")
    address_bundles = client._keys_for_address(member["AddressID"])
    calendar_pass = crypto.decrypt_token(mp["Passphrase"], mp["Signature"], address_bundles)
    keys = bootstrap.get("Keys") or []
    if not keys:
        raise ProtonError("this calendar has no key to unlock")
    key = keys[0]
    return KeyBundle(id=key["ID"], armored=key["PrivateKey"], passphrase=calendar_pass)
