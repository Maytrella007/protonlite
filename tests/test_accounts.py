"""Tests for keeping several accounts apart."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from protonlite.accounts import AccountStore
from protonlite.errors import ProtonError, SessionExpired


def _write(path: Path, address: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "uid": "u",
                "access_token": "a",
                "refresh_token": "r",
                "username": address,
                "salted_key_pass": "p",
            }
        )
    )


class Resolution(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.store = AccountStore(self._dir.name)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _add(self, address: str) -> None:
        _write(self.store.path_for(address), address)

    def test_nothing_signed_in(self) -> None:
        with self.assertRaises(SessionExpired):
            self.store.resolve()

    def test_one_account_needs_no_selector(self) -> None:
        self._add("solo@proton.me")
        self.assertEqual(self.store.resolve().address, "solo@proton.me")

    def test_two_accounts_refuse_to_be_guessed(self) -> None:
        self._add("work@proton.me")
        self._add("home@proton.me")
        with self.assertRaises(ProtonError) as caught:
            self.store.resolve()
        self.assertIn("say which one", str(caught.exception))
        self.assertIn("work@proton.me", str(caught.exception))

    def test_exact_address(self) -> None:
        self._add("work@proton.me")
        self._add("home@proton.me")
        self.assertEqual(self.store.resolve("home@proton.me").address, "home@proton.me")

    def test_case_insensitive(self) -> None:
        self._add("Work@Proton.me")
        self.assertEqual(self.store.resolve("work@proton.me").address, "Work@Proton.me")

    def test_a_distinctive_fragment_is_enough(self) -> None:
        self._add("william.work@proton.me")
        self._add("personal@proton.me")
        self.assertEqual(
            self.store.resolve("william").address, "william.work@proton.me"
        )

    def test_an_ambiguous_fragment_is_an_error(self) -> None:
        self._add("one@proton.me")
        self._add("two@proton.me")
        with self.assertRaises(ProtonError) as caught:
            self.store.resolve("proton.me")
        self.assertIn("be exact", str(caught.exception))

    def test_an_unknown_selector_lists_what_exists(self) -> None:
        self._add("one@proton.me")
        with self.assertRaises(ProtonError) as caught:
            self.store.resolve("nope@proton.me")
        self.assertIn("one@proton.me", str(caught.exception))

    def test_separate_files_per_account(self) -> None:
        self._add("one@proton.me")
        self._add("two@proton.me")
        paths = {a.path for a in self.store.list()}
        self.assertEqual(len(paths), 2)

    def test_a_corrupt_file_is_not_an_account(self) -> None:
        self._add("fine@proton.me")
        (self.store.sessions_dir / "broken.json").write_text("{ not json")
        self.assertEqual([a.address for a in self.store.list()], ["fine@proton.me"])


class LegacyMigration(unittest.TestCase):
    """Early versions kept a single session.json; it is moved in, once."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.store = AccountStore(self._dir.name)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_moves_the_old_file_into_the_new_layout(self) -> None:
        _write(self.store.legacy_session, "old@proton.me")
        accounts = self.store.list()
        self.assertEqual([a.address for a in accounts], ["old@proton.me"])
        self.assertFalse(self.store.legacy_session.exists())
        self.assertTrue(self.store.path_for("old@proton.me").exists())

    def test_without_a_username_it_still_becomes_an_account(self) -> None:
        self.store.legacy_session.parent.mkdir(parents=True, exist_ok=True)
        self.store.legacy_session.write_text(
            json.dumps({"version": 1, "uid": "u", "access_token": "a", "refresh_token": "r"})
        )
        self.assertEqual(len(self.store.list()), 1)

    def test_a_newer_session_is_not_overwritten(self) -> None:
        _write(self.store.path_for("same@proton.me"), "same@proton.me")
        _write(self.store.legacy_session, "same@proton.me")
        self.store.list()
        # The legacy file stays put rather than clobbering the live session.
        self.assertTrue(self.store.legacy_session.exists())
        self.assertEqual(len(self.store.list()), 1)


if __name__ == "__main__":
    unittest.main()
