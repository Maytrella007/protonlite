"""Tests for the MCP server's Proton operations (protonlite_mcp.tools).

These exercise the formatting/fencing with a fake client, so they need neither
the mcp SDK nor a network.
"""

from __future__ import annotations

import types
import unittest

from protonlite_mcp import tools


def _contact(email):
    # Mirror protonlite.client.Contact: the address lives on `.address`, not `.email`.
    return types.SimpleNamespace(address=email)


def _msg(mid, subject, email, time=1_700_000_000, unread=False):
    return types.SimpleNamespace(id=mid, subject=subject, sender=_contact(email), time=time, unread=unread)


class _Client:
    def __init__(self, msgs=None, message=None, calendars=None, events=None, rows=None):
        self._msgs = msgs or []
        self._message = message
        self._calendars = calendars or []
        self._events = events or []
        self._rows = rows or []
        self.sent = None

    def list_messages(self, label="inbox", unread_only=False, limit=20):
        out = [m for m in self._msgs if (not unread_only or m.unread)]
        return out[:limit]

    def read_message(self, mid):
        return self._message

    def send(self, *, to, subject, body, mime_type):
        self.sent = {"to": to, "subject": subject, "body": body, "mime": mime_type}
        return types.SimpleNamespace(id="SENT1")

    def list_calendars(self):
        return self._calendars

    def list_events(self, cid, *, start, end):
        return self._events

    def list_contact_emails(self):
        return self._rows


class ListAndFence(unittest.TestCase):
    def test_list_fences_and_shows_ids(self):
        c = _Client(msgs=[_msg("M1", "Hello", "a@b.com", unread=True)])
        out = tools.list_messages(c, unread_only=True)
        self.assertIn("begin content", out)  # untrusted fence
        self.assertIn("a@b.com", out)
        self.assertIn("[M1]", out)

    def test_empty_list(self):
        self.assertIn("No unread", tools.list_messages(_Client(), unread_only=True))

    def test_read_fences_body(self):
        msg = types.SimpleNamespace(sender=_contact("x@y.com"), subject="S", text="the body")
        out = tools.read_message(_Client(message=msg), message_id="M1")
        self.assertIn("the body", out)
        self.assertIn("begin content", out)

    def test_search_matches_subject_or_sender(self):
        c = _Client(msgs=[_msg("M1", "Invoice", "boss@acme.com"), _msg("M2", "Lunch", "pal@x.com")])
        self.assertIn("Invoice", tools.search(c, query="acme"))
        self.assertIn("No messages matching", tools.search(c, query="zzz"))


class SendCalendarContactsDrive(unittest.TestCase):
    def test_send_plain_and_html(self):
        c = _Client()
        tools.send(c, to=["a@b.com"], subject="s", body="b")
        self.assertEqual(c.sent["mime"], "text/plain")
        tools.send(c, to=["a@b.com"], subject="s", body="<p>b</p>", html=True)
        self.assertEqual(c.sent["mime"], "text/html")

    def test_calendar(self):
        ev = types.SimpleNamespace(start=1_700_000_000, title="Standup")
        c = _Client(calendars=[{"ID": "C1"}], events=[ev])
        out = tools.calendar(c, days=7)
        self.assertIn("Standup", out)
        self.assertIn("begin content", out)

    def test_calendar_empty(self):
        self.assertIn("No events", tools.calendar(_Client(), days=3))

    def test_contacts_filter(self):
        c = _Client(rows=[{"name": "Ana", "email": "ana@x.com"}, {"name": "Bob", "email": "bob@y.com"}])
        out = tools.contacts(c, query="ana")
        self.assertIn("ana@x.com", out)
        self.assertNotIn("bob@y.com", out)


class Drive(unittest.TestCase):
    class _Drive:
        def __init__(self, entries=None, download=None):
            self._entries = entries or []
            self._download = download

        def list_folder(self, path):
            return self._entries

        def download(self, path):
            return self._download

    class _DriveClient:
        def __init__(self, drive):
            self._drive = drive

        def drive(self):
            return self._drive

    def test_list_folders_first(self):
        d = self._Drive(entries=[
            {"name": "report.pdf", "type": "file", "size": 10},
            {"name": "Work", "type": "folder"},
        ])
        out = tools.drive_list(self._DriveClient(d), path="")
        self.assertIn("[folder] Work/", out)
        self.assertIn("report.pdf", out)

    def test_download_writes_file(self):
        import tempfile, os
        d = self._Drive(download=("notes.txt", "text/plain", b"hola"))
        with tempfile.TemporaryDirectory() as tmp:
            out = tools.drive_download(self._DriveClient(d), path="notes.txt", dest_dir=tmp)
            self.assertIn("Downloaded notes.txt", out)
            self.assertEqual(open(os.path.join(tmp, "notes.txt"), "rb").read(), b"hola")


if __name__ == "__main__":
    unittest.main()
