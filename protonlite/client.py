"""The read side of the client: log in, list the mailbox, decrypt a message."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import (
    calendar as _calendar,
    contacts as _contacts,
    crypto,
    drive as _drive,
    htmltext,
    send as _send,
    srp,
)
from .accounts import Account, AccountStore, default_root
from .api import _CODE_OK, ProtonAPI, Session, read_session, write_session
from .crypto import KeyBundle
from .errors import ProtonError, SessionExpired
from .send import SCHEME_CLEAR, SCHEME_INTERNAL, SESSION_KEY_ALGORITHM

# Proton's system labels, by the names a person would use.
SYSTEM_LABELS = {
    "inbox": "0",
    "all-drafts": "1",
    "all-sent": "2",
    "trash": "3",
    "spam": "4",
    "all": "5",
    "archive": "6",
    "sent": "7",
    "drafts": "8",
    "starred": "10",
}

#: Kept for callers that want one specific file; multi-account code goes
#: through :class:`protonlite.accounts.AccountStore` instead.
DEFAULT_SESSION_PATH = Path(
    os.environ.get("PROTONLITE_SESSION") or default_root() / "session.json"
)


@dataclass
class Contact:
    address: str
    name: str = ""

    def __str__(self) -> str:
        return f"{self.name} <{self.address}>" if self.name else self.address

    @classmethod
    def from_api(cls, raw: dict[str, Any] | None) -> "Contact":
        raw = raw or {}
        return cls(address=raw.get("Address", ""), name=raw.get("Name", ""))


@dataclass
class MessageSummary:
    id: str
    subject: str
    sender: Contact
    time: int
    unread: bool
    address_id: str = ""
    num_attachments: int = 0
    labels: list[str] = field(default_factory=list)
    #: The thread this belongs to; the stable anchor for re-finding it later.
    conversation_id: str = ""

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> "MessageSummary":
        return cls(
            id=raw["ID"],
            subject=raw.get("Subject", ""),
            sender=Contact.from_api(raw.get("Sender")),
            time=raw.get("Time", 0),
            unread=bool(raw.get("Unread")),
            address_id=raw.get("AddressID", ""),
            num_attachments=raw.get("NumAttachments", 0),
            labels=list(raw.get("LabelIDs", [])),
            conversation_id=raw.get("ConversationID", ""),
        )


@dataclass
class Message(MessageSummary):
    body: str = ""
    to: list[Contact] = field(default_factory=list)
    cc: list[Contact] = field(default_factory=list)
    mime_type: str = ""
    attachments: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """The body as prose. Most mail is HTML, and its markup is not worth reading."""
        if htmltext.looks_like_html(self.body, self.mime_type):
            return htmltext.to_text(self.body)
        return htmltext.collapse(self.body)


class ProtonMail:
    """A logged-in mailbox."""

    def __init__(self, api: ProtonAPI, *, session_path: str | os.PathLike[str] | None = None) -> None:
        self.api = api
        self.session_path = Path(session_path) if session_path else None
        self._user: dict[str, Any] | None = None
        self._addresses: list[dict[str, Any]] | None = None
        self._user_bundles: list[KeyBundle] | None = None
        self._address_bundles: dict[str, list[KeyBundle]] = {}
        self._calendar_bundles: dict[str, KeyBundle] = {}

    # -- construction -----------------------------------------------------

    @classmethod
    def login(
        cls,
        username: str,
        password: bytes,
        *,
        session_path: str | os.PathLike[str] | None = DEFAULT_SESSION_PATH,
        verification_token: str = "",
        verification_method: str = "captcha",
        totp_code: str = "",
        **api_kwargs: Any,
    ) -> "ProtonMail":
        path = Path(session_path) if session_path else None

        def persist(session: Session) -> None:
            if path is not None:
                write_session(session, path)

        api = ProtonAPI(on_session_change=persist, **api_kwargs)
        if verification_token:
            api.set_verification_token(verification_token, verification_method)
        api.login(username, password, totp_code=totp_code)

        # One passphrase for every key, derived from the primary user key's salt.
        salts = {s["ID"]: s["KeySalt"] for s in api.get("/core/v4/keys/salts")["KeySalts"]}
        user = api.get("/core/v4/users")["User"]
        primary = _primary_key(user.get("Keys", []))
        salt = salts.get(primary["ID"])
        if not salt:
            raise ProtonError("Proton did not return a salt for the primary key")
        api.session.salted_key_pass = srp.key_passphrase(
            password, base64.b64decode(salt)
        ).decode("latin-1")
        persist(api.session)

        client = cls(api, session_path=path)
        client._user = user
        return client

    @classmethod
    def for_account(
        cls,
        selector: str = "",
        *,
        root: str | os.PathLike[str] | None = None,
        **api_kwargs: Any,
    ) -> "ProtonMail":
        """Open the mailbox of one signed-in account, named or unambiguous."""
        account = AccountStore(root).resolve(selector)
        return cls.from_session(session_path=account.path, **api_kwargs)

    @classmethod
    def from_session(
        cls,
        *,
        session_path: str | os.PathLike[str] = DEFAULT_SESSION_PATH,
        **api_kwargs: Any,
    ) -> "ProtonMail":
        path = Path(session_path)
        if not path.exists():
            raise SessionExpired(f"no session at {path}; run the login first")
        session = read_session(path)

        def persist(updated: Session) -> None:
            write_session(updated, path)

        api = ProtonAPI(session=session, on_session_change=persist, **api_kwargs)
        return cls(api, session_path=path)

    # -- keys -------------------------------------------------------------

    @property
    def _salted_pass(self) -> bytes:
        if not self.api.session.salted_key_pass:
            raise SessionExpired("the session has no key passphrase; log in again")
        return self.api.session.salted_key_pass.encode("latin-1")

    def _user_keys(self) -> list[KeyBundle]:
        if self._user_bundles is None:
            if self._user is None:
                self._user = self.api.get("/core/v4/users")["User"]
            self._user_bundles = [
                KeyBundle(id=key["ID"], armored=key["PrivateKey"], passphrase=self._salted_pass)
                for key in self._user.get("Keys", [])
                if key.get("Active", 1)
            ]
        return self._user_bundles

    def addresses(self) -> list[dict[str, Any]]:
        if self._addresses is None:
            self._addresses = self.api.get("/core/v4/addresses")["Addresses"]
        return self._addresses

    def _keys_for_address(self, address_id: str) -> list[KeyBundle]:
        if address_id in self._address_bundles:
            return self._address_bundles[address_id]

        address = next((a for a in self.addresses() if a["ID"] == address_id), None)
        if address is None:
            raise ProtonError(f"unknown address {address_id}")

        bundles: list[KeyBundle] = []
        for key in address.get("Keys", []):
            if key.get("Token") and key.get("Signature"):
                # Migrated key: its passphrase is a token encrypted to the user key.
                passphrase = crypto.decrypt_token(
                    key["Token"], key["Signature"], self._user_keys()
                )
            else:
                passphrase = self._salted_pass
            bundles.append(
                KeyBundle(id=key["ID"], armored=key["PrivateKey"], passphrase=passphrase)
            )

        self._address_bundles[address_id] = bundles
        return bundles

    def _decryption_keys(self, address_id: str = "") -> list[KeyBundle]:
        bundles: list[KeyBundle] = []
        if address_id:
            bundles.extend(self._keys_for_address(address_id))
        for address in self.addresses():
            if address["ID"] != address_id:
                bundles.extend(self._keys_for_address(address["ID"]))
        bundles.extend(self._user_keys())
        return bundles

    # -- reading ----------------------------------------------------------

    def list_messages(
        self,
        *,
        label: str = "inbox",
        unread_only: bool = False,
        limit: int = 20,
        page: int = 0,
        keyword: str = "",
        sender: str = "",
        recipient: str = "",
        subject: str = "",
        conversation_id: str = "",
        has_attachments: bool = False,
    ) -> list[MessageSummary]:
        label_id = SYSTEM_LABELS.get(label, label)
        params: dict[str, Any] = {
            "Page": max(page, 0),
            "PageSize": min(max(limit, 1), 150),
            "LabelID": label_id,
            "Sort": "Time",
            "Desc": 1,
        }
        if unread_only:
            params["Unread"] = 1
        if keyword:
            params["Keyword"] = keyword
        if sender:
            params["From"] = sender
        if recipient:
            params["To"] = recipient
        if subject:
            params["Subject"] = subject
        if conversation_id:
            params["ConversationID"] = conversation_id
        if has_attachments:
            params["Attachments"] = 1
        payload = self.api.get("/mail/v4/messages", params=params)
        return [MessageSummary.from_api(raw) for raw in payload.get("Messages", [])][:limit]

    def read_message(self, message_id: str, *, decrypt: bool = True) -> Message:
        raw = self.api.get(f"/mail/v4/messages/{message_id}")["Message"]
        message = Message(
            **{
                **MessageSummary.from_api(raw).__dict__,
                "to": [Contact.from_api(c) for c in raw.get("ToList", [])],
                "cc": [Contact.from_api(c) for c in raw.get("CCList", [])],
                "mime_type": raw.get("MIMEType", ""),
                "attachments": raw.get("Attachments", []),
                "headers": raw.get("ParsedHeaders", {}),
            }
        )
        if decrypt and raw.get("Body"):
            message.body = crypto.decrypt_text(
                raw["Body"], self._decryption_keys(raw.get("AddressID", "")), textual=True
            )
        return message

    def mark_read(self, message_ids: Iterable[str]) -> int:
        return self._set_read("/mail/v4/messages/read", message_ids)

    def mark_unread(self, message_ids: Iterable[str]) -> int:
        return self._set_read("/mail/v4/messages/unread", message_ids)

    def _set_read(self, path: str, message_ids: Iterable[str]) -> int:
        # The read/unread endpoints are batch endpoints: they answer Code 1001
        # with a Response per id, so accept_multiple keeps a 1001 from looking
        # like a failure. Return how many ids Proton actually acted on.
        ids = [i for i in message_ids if i]
        if not ids:
            return 0
        payload = self.api.put(path, json_body={"IDs": ids}, accept_multiple=True)
        return self._batch_ok(payload, len(ids))

    @staticmethod
    def _batch_ok(payload: dict[str, Any], fallback: int) -> int:
        # Batch endpoints answer Code 1001 with one Response per id; count the
        # ids Proton actually acted on (Code 1000). A plain 1000 has no list.
        responses = payload.get("Responses")
        if not responses:
            return fallback
        return sum(1 for r in responses if (r.get("Response") or {}).get("Code") == _CODE_OK)

    def list_labels(self) -> list[dict[str, Any]]:
        """The account's own labels and folders (not the system mailboxes).

        Type 1 is a label (a message can carry several); Type 3 is a folder (a
        message lives in one). Type 2 is contact groups, which mail does not use.
        """
        out: list[dict[str, Any]] = []
        for kind in (1, 3):
            payload = self.api.get("/core/v4/labels", params={"Type": kind})
            out.extend(payload.get("Labels", []))
        return out

    def apply_label(self, label_id: str, message_ids: Iterable[str]) -> int:
        """Add one label to messages. A folder id moves them there (folders are
        exclusive, so Proton takes them out of the old one for us)."""
        ids = [i for i in message_ids if i]
        if not ids:
            return 0
        payload = self.api.put(
            "/mail/v4/messages/label",
            json_body={"LabelID": label_id, "IDs": ids},
            accept_multiple=True,
        )
        return self._batch_ok(payload, len(ids))

    def remove_label(self, label_id: str, message_ids: Iterable[str]) -> int:
        """Take one label off messages."""
        ids = [i for i in message_ids if i]
        if not ids:
            return 0
        payload = self.api.put(
            "/mail/v4/messages/unlabel",
            json_body={"LabelID": label_id, "IDs": ids},
            accept_multiple=True,
        )
        return self._batch_ok(payload, len(ids))

    def create_label(self, name: str, *, color: str = "#8080FF", folder: bool = False) -> dict[str, Any]:
        """Create a new label (or a folder with folder=True) and return it.

        The colour must be one Proton's palette accepts, or it answers 422
        ("Invalid color"); #8080FF is a safe default from that set.
        """
        payload = self.api.post(
            "/core/v4/labels",
            json_body={"Name": name, "Color": color, "Type": 3 if folder else 1},
        )
        return payload.get("Label", {})

    def update_label(self, label_id: str, *, name: str | None = None, color: str | None = None) -> dict[str, Any]:
        """Rename a label/folder or change its colour. Only the given fields
        change; Proton keeps the rest."""
        body: dict[str, Any] = {}
        if name is not None:
            body["Name"] = name
        if color is not None:
            body["Color"] = color
        payload = self.api.put(f"/core/v4/labels/{label_id}", json_body=body)
        return payload.get("Label", {})

    def delete_label(self, label_id: str) -> None:
        """Delete a label or folder. Messages are not deleted; they just lose
        the label (or leave the folder)."""
        self.api.delete(f"/core/v4/labels/{label_id}")

    def trash(self, message_ids: Iterable[str]) -> int:
        """Move messages to Trash. Reversible: Proton keeps them until emptied."""
        return self.apply_label(SYSTEM_LABELS["trash"], message_ids)

    def delete_permanently(self, message_ids: Iterable[str]) -> int:
        """Delete messages for good. Nothing is kept once this returns."""
        ids = [i for i in message_ids if i]
        if not ids:
            return 0
        payload = self.api.put(
            "/mail/v4/messages/delete",
            json_body={"IDs": ids},
            accept_multiple=True,
        )
        return self._batch_ok(payload, len(ids))

    def empty_folder(self, label: str) -> None:
        """Permanently delete everything in a system folder (Trash or Spam).

        This is the "Empty trash" button: it clears the whole folder in one
        call and cannot be undone. Proton only allows it for Trash and Spam,
        not for custom folders or the inbox.
        """
        label_id = SYSTEM_LABELS.get(label, label)
        if label_id not in (SYSTEM_LABELS["trash"], SYSTEM_LABELS["spam"]):
            raise ProtonError("only Trash and Spam can be emptied")
        self.api.delete("/mail/v4/messages/empty", params={"LabelID": label_id})

    def storage(self) -> dict[str, Any]:
        """The account's storage usage, in bytes.

        Newer accounts split the quota into Mail and Drive pools; older ones
        share one. Report the split when Proton sends it, and always the total.
        """
        if self._user is None:
            self._user = self.api.get("/core/v4/users")["User"]
        u = self._user
        out: dict[str, Any] = {
            "used": int(u.get("UsedSpace") or 0),
            "max": int(u.get("MaxSpace") or 0),
        }
        if u.get("MaxBaseSpace") or u.get("MaxDriveSpace"):
            out["mail"] = {
                "used": int(u.get("UsedBaseSpace") or 0),
                "max": int(u.get("MaxBaseSpace") or 0),
            }
            out["drive"] = {
                "used": int(u.get("UsedDriveSpace") or 0),
                "max": int(u.get("MaxDriveSpace") or 0),
            }
        return out

    # -- calendar (read) --------------------------------------------------

    def list_calendars(self) -> list[dict[str, Any]]:
        """The account's calendars (each with its members, type and owner)."""
        return self.api.get("/calendar/v1").get("Calendars", [])

    def _calendar_keyring(self, calendar_id: str) -> KeyBundle:
        bundle = self._calendar_bundles.get(calendar_id)
        if bundle is None:
            bundle = _calendar.calendar_keyring(self, calendar_id)
            self._calendar_bundles[calendar_id] = bundle
        return bundle

    def list_events(
        self,
        calendar_id: str,
        *,
        start: int,
        end: int,
        limit: int = 100,
        timezone: str = "UTC",
    ) -> list["_calendar.CalendarEvent"]:
        """Decrypt the events of a calendar that overlap [start, end] (epochs).

        Proton caps a page at 100 events; a window with more is truncated. The
        caller should treat exactly ``limit`` events back as "possibly more" and
        narrow the range rather than report a partial agenda as complete.
        """
        bundle = self._calendar_keyring(calendar_id)
        payload = self.api.get(
            f"/calendar/v1/{calendar_id}/events",
            params={
                "Start": start,
                "End": end,
                "Timezone": timezone,
                "PageSize": min(max(limit, 1), 100),
            },
        )
        events = [_calendar.decrypt_event(e, bundle) for e in payload.get("Events", [])]
        return sorted(events, key=lambda e: e.start)

    def canonical_emails(self, emails: list[str]) -> dict[str, str]:
        """Ask Proton for the canonical form of each address (for attendee tokens)."""
        wanted = [e for e in emails if e]
        if not wanted:
            return {}
        payload = self.api.get(
            "/core/v4/addresses/canonical", params={"Emails[]": wanted}, accept_multiple=True
        )
        out: dict[str, str] = {}
        for item in payload.get("Responses", []):
            resp = item.get("Response") or {}
            out[item.get("Email", "")] = resp.get("CanonicalEmail") or item.get("Email", "")
        return out

    def _recipient_public_key(self, email: str) -> str | None:
        """The address public key of an internal Proton recipient, else None."""
        info = self.api.get("/core/v4/keys", params={"Email": email})
        keys = info.get("Keys") or []
        if info.get("RecipientType") == 1 and keys:
            return keys[0]["PublicKey"]
        return None

    def create_event(
        self,
        calendar_id: str,
        *,
        summary: str,
        start: "datetime.datetime",
        end: "datetime.datetime",
        location: str = "",
        description: str = "",
        attendees: list[str] | None = None,
        notify_minutes: int | None = None,
        from_address: str | None = None,
    ) -> dict[str, Any]:
        """Create an event on a calendar as the organizer.

        Returns {"id", "attendees": [(email, token)], "invite_ics"}. The caller
        sends the invite_ics to the attendees itself (an ordinary gated mail),
        since Proton's backend does not email them on create.
        """
        import datetime as dt
        import uuid

        attendees = [a.strip() for a in (attendees or []) if a.strip()]
        calendar = next((c for c in self.list_calendars() if c["ID"] == calendar_id), None)
        if calendar is None:
            raise ProtonError(f"unknown calendar {calendar_id}")
        member_id = calendar["Members"][0]["ID"]
        mine = {a["ID"] for a in self.addresses()}
        member = next((m for m in calendar["Members"] if m.get("AddressID") in mine), None)
        if member is None:
            raise ProtonError("no member of this calendar matches a signed-in address")
        organizer_email = from_address or member["Email"]
        signer = self._keys_for_address(member["AddressID"])[0]
        cal_key = self._calendar_keyring(calendar_id).armored

        uid = f"{uuid.uuid4()}@proton.me"

        def ical(d: "dt.datetime") -> str:
            return d.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        dtstamp = ical(dt.datetime.now(dt.timezone.utc))
        dtstart, dtend = ical(start), ical(end)
        session_key = os.urandom(32)

        # Shared, signed-but-clear: the timing and organizer anyone may see.
        clear_vcal = _calendar.vevent(
            uid,
            [
                ("DTSTAMP", dtstamp),
                ("DTSTART", dtstart),
                ("DTEND", dtend),
                ("SEQUENCE", "0"),
                (f"ORGANIZER;CN={organizer_email}", f"mailto:{organizer_email}"),
            ],
        )
        clear_sig = _calendar.detached_signature(clear_vcal, signer)

        # Shared, encrypted: the title, place and notes.
        enc_vcal = _calendar.vevent(
            uid,
            [("SUMMARY", summary), ("LOCATION", location), ("DESCRIPTION", description)],
        )
        enc_data, enc_sig = _calendar.encrypt_card(enc_vcal, session_key, cal_key, signer=signer)

        event: dict[str, Any] = {
            "SharedKeyPacket": _calendar.wrap_session_key(session_key, cal_key),
            "SharedEventContent": [
                {"Type": 2, "Data": clear_vcal, "Signature": clear_sig},
                {"Type": 3, "Data": enc_data, "Signature": enc_sig},
            ],
            "Permissions": 3,
            "IsOrganizer": 1,
            "Color": None,
            "Notifications": (
                [{"Type": 1, "Trigger": f"-PT{int(notify_minutes)}M"}]
                if notify_minutes
                else None
            ),
        }

        resolved: list[tuple[str, str]] = []
        if attendees:
            canon = self.canonical_emails(attendees)
            attendee_props: list[tuple[str, str]] = []
            api_attendees: list[dict[str, Any]] = []
            added_proton: list[dict[str, Any]] = []
            for email in attendees:
                token = _calendar.attendee_token(uid, canon.get(email, email))
                resolved.append((email, token))
                attendee_props.append(_calendar.attendee_property(email, token))
                api_attendees.append({"Token": token, "Status": 0, "Comment": None})
                pub = self._recipient_public_key(email)
                if pub:
                    added_proton.append(
                        {"Email": email, "AddressKeyPacket": _send.key_packet_for(session_key, pub)}
                    )
            att_vcal = _calendar.vevent(uid, attendee_props)
            att_data, att_sig = _calendar.encrypt_card(att_vcal, session_key, cal_key, signer=signer)
            event["AttendeesEventContent"] = [{"Type": 3, "Data": att_data, "Signature": att_sig}]
            event["Attendees"] = api_attendees
            if added_proton:
                event["AddedProtonAttendees"] = added_proton

        body = {"MemberID": member_id, "Events": [{"Overwrite": 1, "Event": event}]}
        payload = self.api.put(
            f"/calendar/v1/{calendar_id}/events/sync", json_body=body, accept_multiple=True
        )
        new_id = ""
        for item in payload.get("Responses", []):
            created = (item.get("Response") or {}).get("Event") or {}
            if created.get("ID"):
                new_id = created["ID"]
        if not new_id:
            raise ProtonError(f"the calendar did not accept the event ({payload.get('Code')})")

        invite_ics = _calendar.build_invite_ics(
            uid=uid,
            dtstamp=dtstamp,
            dtstart=dtstart,
            dtend=dtend,
            summary=summary,
            location=location,
            description=description,
            organizer_email=organizer_email,
            attendees=resolved,
        )
        return {"id": new_id, "attendees": resolved, "invite_ics": invite_ics}

    def _raw_event(self, calendar_id: str, event_id: str) -> dict[str, Any]:
        payload = self.api.get(f"/calendar/v1/{calendar_id}/events/{event_id}")
        return payload.get("Event") or payload.get("CalendarEvent") or payload

    def find_event_calendar(self, event_id: str) -> str | None:
        """Which calendar holds an event, by trying each one."""
        for calendar in self.list_calendars():
            try:
                self._raw_event(calendar["ID"], event_id)
                return calendar["ID"]
            except ProtonError:
                continue
        return None

    def update_event(
        self,
        calendar_id: str,
        event_id: str,
        *,
        summary: str | None = None,
        start: "datetime.datetime | None" = None,
        end: "datetime.datetime | None" = None,
        location: str | None = None,
        description: str | None = None,
        notify_minutes: "int | None | str" = "keep",
    ) -> dict[str, Any]:
        """Edit an event's own fields, keeping anything not passed.

        Reuses the event's existing session key (the update API forbids a new key
        packet) and bumps SEQUENCE only when the time changes, matching Proton.
        """
        import datetime as dt
        import re

        raw = self._raw_event(calendar_id, event_id)
        bundle = self._calendar_keyring(calendar_id)
        current = _calendar.decrypt_event(raw, bundle)

        uid, sequence = "", 0
        for card in raw.get("SharedEvents", []):
            if card.get("Type") in (0, 2):
                data = card.get("Data", "")
                m = re.search(r"UID:(.+)", data)
                if m:
                    uid = m.group(1).strip()
                s = re.search(r"SEQUENCE:(\d+)", data)
                if s:
                    sequence = int(s.group(1))
        if not uid or not raw.get("SharedKeyPacket"):
            raise ProtonError("this event cannot be edited (missing UID or key packet)")
        session_key = _calendar.recover_session_key(raw["SharedKeyPacket"], bundle)

        new_summary = current.title if summary is None else summary
        new_location = current.location if location is None else location
        new_description = current.description if description is None else description
        new_start = start or dt.datetime.fromtimestamp(current.start, dt.timezone.utc)
        new_end = end or dt.datetime.fromtimestamp(current.end, dt.timezone.utc)
        if start is not None or end is not None:
            sequence += 1

        calendar = next(c for c in self.list_calendars() if c["ID"] == calendar_id)
        member_id = calendar["Members"][0]["ID"]
        mine = {a["ID"] for a in self.addresses()}
        member = next((m for m in calendar["Members"] if m.get("AddressID") in mine), None)
        if member is None:
            raise ProtonError("no member of this calendar matches a signed-in address")
        organizer_email = member["Email"]
        signer = self._keys_for_address(member["AddressID"])[0]
        cal_key = bundle.armored

        def ical(d: "dt.datetime") -> str:
            return d.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        dtstamp = ical(dt.datetime.now(dt.timezone.utc))
        clear = _calendar.vevent(
            uid,
            [
                ("DTSTAMP", dtstamp),
                ("DTSTART", ical(new_start)),
                ("DTEND", ical(new_end)),
                ("SEQUENCE", str(sequence)),
                (f"ORGANIZER;CN={organizer_email}", f"mailto:{organizer_email}"),
            ],
        )
        clear_sig = _calendar.detached_signature(clear, signer)
        enc = _calendar.vevent(
            uid,
            [("SUMMARY", new_summary), ("LOCATION", new_location), ("DESCRIPTION", new_description)],
        )
        enc_data, enc_sig = _calendar.encrypt_card(enc, session_key, cal_key, signer=signer)
        event: dict[str, Any] = {
            "SharedEventContent": [
                {"Type": 2, "Data": clear, "Signature": clear_sig},
                {"Type": 3, "Data": enc_data, "Signature": enc_sig},
            ],
            "Permissions": 1,
            "Color": None,
        }
        if notify_minutes != "keep":
            event["Notifications"] = (
                [{"Type": 1, "Trigger": f"-PT{int(notify_minutes)}M"}] if notify_minutes else None
            )
        payload = self.api.put(
            f"/calendar/v1/{calendar_id}/events/sync",
            json_body={"MemberID": member_id, "Events": [{"ID": event_id, "Event": event}]},
            accept_multiple=True,
        )
        ok = any(
            (i.get("Response") or {}).get("Code") == _CODE_OK for i in payload.get("Responses", [])
        )
        if not ok:
            raise ProtonError(f"the calendar did not accept the edit ({payload.get('Responses')})")
        return {
            "id": event_id,
            "uid": uid,
            "summary": new_summary,
            "location": new_location,
            "description": new_description,
            "start": new_start,
            "end": new_end,
            "sequence": sequence,
        }

    def provision_default_calendar(self) -> str:
        """Create and key a default calendar for this account; return its id.

        This is what Proton does for you the first time you accept an invitation
        with no calendar of your own: a new calendar whose key is generated and
        whose passphrase is encrypted to your primary address key.
        """
        import base64 as _b64

        address = next(
            (a for a in self.addresses() if a.get("Status") == 1 and a.get("Keys")), None
        )
        if address is None:
            raise ProtonError("no usable address to own a calendar")
        address_id = address["ID"]
        address_pub = address["Keys"][0]["PublicKey"]
        signer = self._keys_for_address(address_id)[0]

        passphrase = _b64.b64encode(os.urandom(32)).decode()
        calendar_key = _calendar.generate_calendar_key(passphrase)
        session_key = os.urandom(32)
        data_packet, _ = _calendar.encrypt_card(passphrase, session_key, address_pub)
        key_packet = _calendar.wrap_session_key(session_key, address_pub)
        signature = _calendar.detached_signature(passphrase, signer)

        created = self.api.post(
            "/calendar/v1",
            json_body={
                "Name": "My calendar",
                "Color": "#8080FF",
                "Description": "",
                "Display": 1,
                "AddressID": address_id,
            },
        )
        calendar_id = created["Calendar"]["ID"]
        self.api.post(
            f"/calendar/v1/{calendar_id}/keys",
            json_body={
                "AddressID": address_id,
                "Signature": signature,
                "PrivateKey": calendar_key,
                "Passphrase": {"DataPacket": data_packet, "KeyPacket": key_packet},
            },
        )
        self._calendar_bundles.pop(calendar_id, None)
        return calendar_id

    def import_invitation(self, calendar_id: str, invite: dict[str, Any], *, status: int) -> str:
        """Store an emailed invitation in a calendar as an attendee, with my status.

        The organizer's copy is encrypted to their calendar key, which we cannot
        read, so we rebuild the event from the invitation's plaintext and encrypt
        it to our own calendar key. IsOrganizer is 0 and our PARTSTAT is baked in.
        """
        import datetime as dt

        bundle = self._calendar_keyring(calendar_id)
        cal_key = bundle.armored
        calendar = next(c for c in self.list_calendars() if c["ID"] == calendar_id)
        member_id = calendar["Members"][0]["ID"]
        mine = {a["ID"] for a in self.addresses()}
        member = next((m for m in calendar["Members"] if m.get("AddressID") in mine), None)
        if member is None:
            raise ProtonError("no member of this calendar matches a signed-in address")
        my_email = member["Email"].lower()
        signer = self._keys_for_address(member["AddressID"])[0]
        uid = invite.get("uid")
        if not uid or not invite.get("timing"):
            raise ProtonError("this invitation is missing a UID or a start time")

        def ical(d: "dt.datetime") -> str:
            return d.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        start = _calendar.ical_to_datetime(invite["timing"][0])
        end = (
            _calendar.ical_to_datetime(invite["timing"][1])
            if len(invite["timing"]) > 1
            else start + dt.timedelta(hours=1)
        )
        dtstamp = ical(dt.datetime.now(dt.timezone.utc))
        organizer = invite.get("organizer", my_email)
        session_key = os.urandom(32)

        clear = _calendar.vevent(
            uid,
            [
                ("DTSTAMP", dtstamp),
                ("DTSTART", ical(start)),
                ("DTEND", ical(end)),
                ("SEQUENCE", "0"),
                (f"ORGANIZER;CN={organizer}", f"mailto:{organizer}"),
            ],
        )
        clear_sig = _calendar.detached_signature(clear, signer)
        enc = _calendar.vevent(
            uid,
            [
                ("SUMMARY", invite.get("summary", "")),
                ("LOCATION", invite.get("location", "")),
                ("DESCRIPTION", invite.get("description", "")),
            ],
        )
        enc_data, enc_sig = _calendar.encrypt_card(enc, session_key, cal_key, signer=signer)

        attendee_props: list[tuple[str, str]] = []
        api_attendees: list[dict[str, Any]] = []
        for att in invite.get("attendees", []):
            token = att.get("token") or _calendar.attendee_token(
                uid, self.canonical_emails([att["email"]]).get(att["email"], att["email"])
            )
            is_me = att["email"].lower() == my_email
            name, value = _calendar.attendee_property(att["email"], token)
            if is_me:
                partstat = {3: "ACCEPTED", 2: "DECLINED", 1: "TENTATIVE"}.get(status, "NEEDS-ACTION")
                name = name.replace("PARTSTAT=NEEDS-ACTION", f"PARTSTAT={partstat}")
            attendee_props.append((name, value))
            api_attendees.append({"Token": token, "Status": status if is_me else 0, "Comment": None})
        att_vcal = _calendar.vevent(uid, attendee_props)
        att_data, att_sig = _calendar.encrypt_card(att_vcal, session_key, cal_key, signer=signer)

        event = {
            "SharedKeyPacket": _calendar.wrap_session_key(session_key, cal_key),
            "SharedEventContent": [
                {"Type": 2, "Data": clear, "Signature": clear_sig},
                {"Type": 3, "Data": enc_data, "Signature": enc_sig},
            ],
            "AttendeesEventContent": [{"Type": 3, "Data": att_data, "Signature": att_sig}],
            "Attendees": api_attendees,
            "Permissions": 1,
            "IsOrganizer": 0,
            "Color": None,
            "Notifications": None,
        }
        payload = self.api.put(
            f"/calendar/v1/{calendar_id}/events/sync",
            json_body={"MemberID": member_id, "Events": [{"Overwrite": 1, "Event": event}]},
            accept_multiple=True,
        )
        for item in payload.get("Responses", []):
            created = (item.get("Response") or {}).get("Event") or {}
            if created.get("ID"):
                return created["ID"]
        raise ProtonError(f"the calendar did not accept the invitation ({payload.get('Responses')})")

    def delete_event(self, calendar_id: str, event_id: str) -> bool:
        """Delete one event. Returns True when the calendar accepted it."""
        calendar = next((c for c in self.list_calendars() if c["ID"] == calendar_id), None)
        if calendar is None:
            raise ProtonError(f"unknown calendar {calendar_id}")
        member_id = calendar["Members"][0]["ID"]
        payload = self.api.put(
            f"/calendar/v1/{calendar_id}/events/sync",
            json_body={"MemberID": member_id, "Events": [{"ID": event_id, "DeletionReason": 0}]},
            accept_multiple=True,
        )
        return payload.get("Code") in (_CODE_OK, 1001)

    # -- drive (read) -----------------------------------------------------

    def drive(self) -> "_drive.DriveReader":
        """A read-only view of this account's Proton Drive."""
        return _drive.DriveReader(self)

    # -- contacts (read) --------------------------------------------------

    def list_contact_emails(self) -> list[dict[str, str]]:
        """The account's name/email/contact-id index -- cheap, no decryption."""
        out: list[dict[str, str]] = []
        page = 0
        while True:
            payload = self.api.get(
                "/contacts/v4/contacts/emails", params={"PageSize": 1000, "Page": page}
            )
            rows = payload.get("ContactEmails") or []
            for row in rows:
                out.append(
                    {
                        "name": row.get("Name", ""),
                        "email": row.get("Email", ""),
                        "contact_id": row.get("ContactID", ""),
                    }
                )
            total = payload.get("Total", len(out))
            if len(rows) < 1000 or len(out) >= total:
                break
            page += 1
        return out

    def get_contact(self, contact_id: str) -> "_contacts.Contact":
        """One contact's full details, with its vCard decrypted and parsed."""
        raw = self.api.get(f"/contacts/v4/contacts/{contact_id}")["Contact"]
        return _contacts.read_contact(raw, self._user_keys())

    def create_contact(
        self,
        *,
        name: str,
        emails: list[str] | None = None,
        phones: list[str] | None = None,
        org: str = "",
        title: str = "",
        note: str = "",
    ) -> str:
        """Create a contact from a signed vCard; return its id.

        The vCard is signed with the account's user key (a single SIGNED card is
        all Proton requires for a name-and-email contact).
        """
        signed_vcard, private_vcard = _contacts.build_contact_cards(
            name=name, emails=emails, phones=phones, org=org, title=title, note=note
        )
        cards = _contacts.make_cards(signed_vcard, private_vcard, self._user_keys()[0])
        payload = self.api.post(
            "/contacts/v4/contacts",
            json_body={"Contacts": [{"Cards": cards}], "Overwrite": 0, "Labels": 0},
            accept_multiple=True,
        )
        for item in payload.get("Responses", []):
            created = (item.get("Response") or {}).get("Contact") or {}
            if created.get("ID"):
                return created["ID"]
        raise ProtonError(f"the contact was not created ({payload.get('Responses')})")

    def update_contact(
        self,
        contact_id: str,
        *,
        name: str | None = None,
        emails: list[str] | None = None,
        phones: list[str] | None = None,
        org: str | None = None,
        title: str | None = None,
        note: str | None = None,
    ) -> str:
        """Edit a contact, keeping fields that are not passed."""
        current = self.get_contact(contact_id)
        signed_vcard, private_vcard = _contacts.build_contact_cards(
            name=current.name if name is None else name,
            emails=current.emails if emails is None else emails,
            phones=current.phones if phones is None else phones,
            org=current.org if org is None else org,
            title=current.title if title is None else title,
            note=current.note if note is None else note,
        )
        cards = _contacts.make_cards(signed_vcard, private_vcard, self._user_keys()[0])
        self.api.put(f"/contacts/v4/contacts/{contact_id}", json_body={"Cards": cards})
        return contact_id

    def delete_contacts(self, contact_ids: Iterable[str]) -> int:
        """Delete contacts for good. Proton keeps no trash for contacts."""
        ids = [i for i in contact_ids if i]
        if not ids:
            return 0
        payload = self.api.put(
            "/contacts/v4/contacts/delete", json_body={"IDs": ids}, accept_multiple=True
        )
        return self._batch_ok(payload, len(ids))

    # -- attachments ------------------------------------------------------

    def list_attachments(self, message_id: str) -> list[dict[str, Any]]:
        raw = self.api.get(f"/mail/v4/messages/{message_id}")["Message"]
        return raw.get("Attachments") or []

    def get_attachment(
        self,
        message_id: str,
        *,
        name: str | None = None,
        attachment_id: str | None = None,
        index: int | None = None,
    ) -> tuple[str, str, bytes]:
        """Download and decrypt one attachment. Returns (name, mime, bytes)."""
        raw = self.api.get(f"/mail/v4/messages/{message_id}")["Message"]
        atts = raw.get("Attachments") or []
        if not atts:
            raise ProtonError("that message has no attachments")
        chosen: dict[str, Any] | None = None
        if attachment_id:
            chosen = next((a for a in atts if a.get("ID") == attachment_id), None)
        elif name:
            matches = [a for a in atts if (a.get("Name") or "") == name]
            if len(matches) > 1:
                raise ProtonError(f"more than one attachment is named {name!r}; pass an index")
            chosen = matches[0] if matches else None
        elif index is not None:
            if 1 <= index <= len(atts):
                chosen = atts[index - 1]
            else:
                raise ProtonError(f"index {index} is out of range (1..{len(atts)})")
        if chosen is None:
            raise ProtonError("no attachment matched")
        enc = self.api.get_bytes(f"/mail/v4/attachments/{chosen['ID']}")
        key_packets = base64.b64decode(chosen["KeyPackets"])
        data = crypto.decrypt_attachment(
            key_packets, enc, self._decryption_keys(raw.get("AddressID", ""))
        )
        name_out = chosen.get("Name") or chosen["ID"]
        mime = chosen.get("MIMEType") or "application/octet-stream"
        return name_out, mime, data

    # -- sending ----------------------------------------------------------

    def sending_address(self, email: str | None = None) -> dict[str, Any]:
        """Pick which of the account's addresses to send from."""
        usable = [
            a
            for a in self.addresses()
            if a.get("Status") == 1 and a.get("Send") == 1 and a.get("Keys")
        ]
        if not usable:
            raise ProtonError("no address on this account can send mail")
        if email:
            for address in usable:
                if address["Email"].lower() == email.lower():
                    return address
            raise ProtonError(f"{email} is not a sending address on this account")
        return min(usable, key=lambda a: a.get("Order", 0))

    def _recipient_entries(
        self,
        material: "_send.SendMaterial",
        recipients: list[str],
        uploaded: list[tuple[str, bytes]] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        uploaded = uploaded or []
        internal: dict[str, Any] = {}
        external: dict[str, Any] = {}
        for recipient in recipients:
            info = self.api.get("/core/v4/keys", params={"Email": recipient})
            keys = info.get("Keys") or []
            if info.get("RecipientType") == 1 and keys:
                # Inside Proton: end-to-end, the session key wrapped to their key.
                entry = {
                    "Type": SCHEME_INTERNAL,
                    "Signature": 0,
                    "BodyKeyPacket": _send.key_packet_for(
                        material.session_key, keys[0]["PublicKey"]
                    ),
                }
                if uploaded:
                    entry["AttachmentKeyPackets"] = {
                        att_id: _send.key_packet_for(session_key, keys[0]["PublicKey"])
                        for att_id, session_key in uploaded
                    }
                internal[recipient] = entry
            else:
                # Outside Proton: Proton's servers need the session key to be able
                # to deliver ordinary mail. This is what the web client does too.
                external[recipient] = {"Type": SCHEME_CLEAR, "Signature": 0}
        return internal, external

    def send(
        self,
        *,
        to: list[str],
        subject: str,
        body: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        from_address: str | None = None,
        mime_type: str = "text/plain",
        parent_id: str = "",
        reply_all: bool = False,
        delivery_time: int = 0,
    ) -> MessageSummary:
        """Create a draft, address it to everyone, and send it.

        When *parent_id* is a message in a thread, the draft is created as a
        reply to it: Proton files the draft in the parent's conversation and
        stamps the outgoing mail with the In-Reply-To and References headers
        (it knows the parent's Message-Id), so the reply threads both inside
        Proton and in an external client like Gmail. We still address the mail
        with the explicit to/cc given here -- the *Action* only tells Proton how
        to build those reference headers (reply vs. reply-all), never who gets
        it.
        """
        cc = cc or []
        bcc = bcc or []
        recipients = [r.strip() for r in [*to, *cc, *bcc] if r.strip()]
        if not recipients:
            raise ProtonError("there is nobody to send this to")

        address = self.sending_address(from_address)
        # Sign with the sending address's own key: Proton rejects an unsigned
        # body when it has to deliver the mail outside Proton itself.
        signer = self._keys_for_address(address["ID"])[0]
        material = _send.build(body, address["Keys"][0]["PrivateKey"], signer=signer)

        draft_body: dict[str, Any] = {
            "Message": {
                "Subject": subject,
                "Sender": {
                    "Address": address["Email"],
                    "Name": address.get("DisplayName") or "",
                },
                "ToList": [{"Address": a, "Name": ""} for a in to],
                "CCList": [{"Address": a, "Name": ""} for a in cc],
                "BCCList": [{"Address": a, "Name": ""} for a in bcc],
                "Body": material.armored_body,
                "MIMEType": mime_type,
                "Unread": 0,
            },
            "AttachmentKeyPackets": [],
        }
        if parent_id:
            # ParentID + Action turn this draft into a reply: Proton links it to
            # the parent's conversation and adds the reference headers. Action
            # is Proton's draft enum -- 0 reply, 1 reply-all (2 is forward).
            draft_body["ParentID"] = parent_id
            draft_body["Action"] = 1 if reply_all else 0
        draft = self.api.post("/mail/v4/messages", json_body=draft_body)["Message"]

        uploaded: list[tuple[str, bytes]] = []
        for att in attachments or []:
            amat = _send.build_attachment(
                att["data"], address["Keys"][0]["PrivateKey"], signer=signer
            )
            info = self.api.post_multipart(
                "/mail/v4/attachments",
                data={
                    "Filename": att["name"],
                    "MessageID": draft["ID"],
                    "MIMEType": att.get("mime") or "application/octet-stream",
                    # An inline image carries a Content-ID the HTML body points
                    # at with <img src="cid:...">; a plain file has neither.
                    "ContentID": att.get("content_id") or "",
                    "Disposition": "inline" if att.get("inline") else "attachment",
                },
                files={
                    "KeyPackets": ("keypackets", amat.key_packets, "application/octet-stream"),
                    "DataPacket": ("datapacket", amat.data_packet, "application/octet-stream"),
                    "Signature": ("signature", amat.signature, "application/octet-stream"),
                },
            )
            uploaded.append((info["Attachment"]["ID"], amat.session_key))

        internal, external = self._recipient_entries(material, recipients, uploaded)
        packages: list[dict[str, Any]] = []
        if internal:
            packages.append(
                {
                    "Addresses": internal,
                    "Type": SCHEME_INTERNAL,
                    "MIMEType": mime_type,
                    "Body": material.b64_data_packet,
                }
            )
        if external:
            packages.append(
                {
                    "Addresses": external,
                    "Type": SCHEME_CLEAR,
                    "MIMEType": mime_type,
                    "Body": material.b64_data_packet,
                    "BodyKey": {
                        "Key": material.b64_session_key,
                        "Algorithm": SESSION_KEY_ALGORITHM,
                    },
                    "AttachmentKeys": {
                        att_id: {
                            "Key": base64.b64encode(session_key).decode(),
                            "Algorithm": SESSION_KEY_ALGORITHM,
                        }
                        for att_id, session_key in uploaded
                    },
                }
            )

        send_body: dict[str, Any] = {"Packages": packages}
        if delivery_time:
            # Schedule the send for a future time instead of delivering now.
            send_body["DeliveryTime"] = int(delivery_time)
        payload = self.api.post(
            f"/mail/v4/messages/{draft['ID']}", json_body=send_body
        )
        sent = payload.get("Sent") or payload.get("Message") or draft
        return MessageSummary.from_api(sent)

    def save_draft(
        self,
        *,
        to: list[str],
        subject: str,
        body: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        from_address: str | None = None,
        mime_type: str = "text/plain",
        parent_id: str = "",
        reply_all: bool = False,
    ) -> MessageSummary:
        """Save a draft in the account's Drafts folder without sending it.

        This is the draft half of send(): the body is encrypted to the account's
        own key and stored, so the person can review, edit and send it later from
        any Proton client. Nothing leaves the mailbox.
        """
        cc = cc or []
        bcc = bcc or []
        address = self.sending_address(from_address)
        signer = self._keys_for_address(address["ID"])[0]
        material = _send.build(body, address["Keys"][0]["PrivateKey"], signer=signer)
        draft_body: dict[str, Any] = {
            "Message": {
                "Subject": subject,
                "Sender": {"Address": address["Email"], "Name": address.get("DisplayName") or ""},
                "ToList": [{"Address": a, "Name": ""} for a in to],
                "CCList": [{"Address": a, "Name": ""} for a in cc],
                "BCCList": [{"Address": a, "Name": ""} for a in bcc],
                "Body": material.armored_body,
                "MIMEType": mime_type,
                "Unread": 0,
            },
            "AttachmentKeyPackets": [],
        }
        if parent_id:
            draft_body["ParentID"] = parent_id
            draft_body["Action"] = 1 if reply_all else 0
        draft = self.api.post("/mail/v4/messages", json_body=draft_body)["Message"]
        return MessageSummary.from_api(draft)

    def unread_count(self, label: str = "inbox") -> int:
        label_id = SYSTEM_LABELS.get(label, label)
        counts = self.api.get("/mail/v4/messages/count").get("Counts", [])
        for entry in counts:
            if entry.get("LabelID") == label_id:
                return int(entry.get("Unread", 0))
        return 0


def _primary_key(keys: list[dict[str, Any]]) -> dict[str, Any]:
    for key in keys:
        if key.get("Primary"):
            return key
    if keys:
        return keys[0]
    raise ProtonError("the account has no keys")
