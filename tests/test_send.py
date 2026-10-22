"""Tests for the send-side encryption: one body, many recipients."""

from __future__ import annotations

import base64
import unittest
from unittest import mock
import warnings

from protonlite import crypto, send
from protonlite.crypto import KeyBundle
from protonlite.errors import ProtonError

warnings.simplefilter("ignore")

import pgpy  # noqa: E402
from pgpy.constants import (  # noqa: E402
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

BODY = "Subject matter.\n\nSecond paragraph."


def _make_key(email: str) -> "pgpy.PGPKey":
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        pgpy.PGPUID.new("Test", email=email),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    return key


class PacketSplitting(unittest.TestCase):
    def test_splits_an_encrypted_message_into_key_and_body(self) -> None:
        key = _make_key("me@proton.me")
        material = send.build(BODY, str(key.pubkey))
        tags = [tag for tag, _ in send.split_packets(bytes(pgpy.PGPMessage.from_blob(material.armored_body)))]
        self.assertEqual(tags, [send.TAG_PKESK, send.TAG_SEIPD])

    def test_rejects_garbage(self) -> None:
        with self.assertRaises(ProtonError):
            send.split_packets(b"not a packet stream")

    def test_rejects_a_truncated_packet(self) -> None:
        key = _make_key("me@proton.me")
        blob = bytes(pgpy.PGPMessage.from_blob(send.build(BODY, str(key.pubkey)).armored_body))
        with self.assertRaises(ProtonError):
            send.split_packets(blob[:-5])


class KeysWithAnEncryptionSubkey(unittest.TestCase):
    """The shape Proton actually issues: signing primary, encryption subkey.

    A single-key fixture hid a real bug -- picking the subkey by hand off a
    ``pubkey`` copy loses its link to the primary and pgpy dies reading flags.
    """

    @classmethod
    def setUpClass(cls) -> None:
        primary = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        primary.add_uid(
            pgpy.PGPUID.new("Proton Shaped", email="shaped@proton.me"),
            usage={KeyFlags.Sign, KeyFlags.Certify},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.Uncompressed],
        )
        subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        primary.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})
        cls.key = primary

    def test_build_finds_the_encryption_subkey(self) -> None:
        material = send.build(BODY, str(self.key.pubkey))
        self.assertEqual(len(material.data_packet) > 0, True)
        message = pgpy.PGPMessage.from_blob(material.armored_body)
        self.assertEqual(str(self.key.decrypt(message).message), BODY)

    def test_key_packet_finds_it_too(self) -> None:
        material = send.build(BODY, str(self.key.pubkey))
        packet = base64.b64decode(
            send.key_packet_for(material.session_key, str(self.key.pubkey))
        )
        reassembled = pgpy.PGPMessage.from_blob(packet + material.data_packet)
        self.assertEqual(str(self.key.decrypt(reassembled).message), BODY)

    def test_a_key_that_cannot_encrypt_is_reported(self) -> None:
        signing_only = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        signing_only.add_uid(
            pgpy.PGPUID.new("Sign Only", email="sign@proton.me"),
            usage={KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.Uncompressed],
        )
        with self.assertRaises(ProtonError):
            send.build(BODY, str(signing_only.pubkey))


class OneBodyManyRecipients(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mine = _make_key("me@proton.me")
        cls.theirs = _make_key("you@proton.me")
        cls.material = send.build(BODY, str(cls.mine.pubkey))

    def test_session_key_is_32_bytes(self) -> None:
        self.assertEqual(len(self.material.session_key), send.SESSION_KEY_BYTES)

    def test_draft_body_decrypts_with_our_own_key(self) -> None:
        message = pgpy.PGPMessage.from_blob(self.material.armored_body)
        self.assertEqual(str(self.mine.decrypt(message).message), BODY)

    def test_recipient_key_packet_opens_the_same_body(self) -> None:
        packet = base64.b64decode(
            send.key_packet_for(self.material.session_key, str(self.theirs.pubkey))
        )
        reassembled = pgpy.PGPMessage.from_blob(packet + self.material.data_packet)
        self.assertEqual(str(self.theirs.decrypt(reassembled).message), BODY)

    def test_signing_produces_a_verifiable_signature(self) -> None:
        """Proton refuses an unsigned body when it must deliver mail outside."""
        bundle = KeyBundle(id="test", armored=str(self.mine), passphrase=b"")
        material = send.build(BODY, str(self.mine.pubkey), signer=bundle)
        decrypted = self.mine.decrypt(pgpy.PGPMessage.from_blob(material.armored_body))
        self.assertTrue(decrypted.signatures)
        self.assertTrue(self.mine.pubkey.verify(decrypted))

    def test_unsigned_by_default(self) -> None:
        decrypted = self.mine.decrypt(
            pgpy.PGPMessage.from_blob(self.material.armored_body)
        )
        self.assertFalse(decrypted.signatures)

    def test_a_stranger_cannot_open_it(self) -> None:
        stranger = _make_key("nope@proton.me")
        packet = base64.b64decode(
            send.key_packet_for(self.material.session_key, str(self.theirs.pubkey))
        )
        reassembled = pgpy.PGPMessage.from_blob(packet + self.material.data_packet)
        with self.assertRaises(Exception):
            stranger.decrypt(reassembled)


class _RecordingApi:
    """A fake API that records the draft body and returns canned ids."""

    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []

    def post(self, path, json_body=None, **_kw):
        self.posts.append((path, json_body or {}))
        if path == "/mail/v4/messages":  # draft creation
            return {"Message": {"ID": "DRAFT1"}}
        return {"Sent": {"ID": "SENT1", "ConversationID": "CONV1"}}  # the send

    def get(self, path, params=None, **_kw):
        return {"Keys": [{"PublicKey": "k"}], "RecipientType": 1}


class DraftThreading(unittest.TestCase):
    """send(parent_id=...) carries ParentID + Action into the draft request."""

    def _send(self, **extra):
        from protonlite.client import ProtonMail

        client = ProtonMail.__new__(ProtonMail)
        client.api = _RecordingApi()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with mock.patch.object(
                ProtonMail, "sending_address",
                return_value={"ID": "A", "Email": "me@proton.me", "DisplayName": "",
                              "Keys": [{"PrivateKey": str(_make_key("me@proton.me"))}]},
            ), mock.patch.object(
                ProtonMail, "_keys_for_address",
                return_value=[KeyBundle(id="A", armored=str(_make_key("me@proton.me")), passphrase=b"")],
            ), mock.patch.object(
                ProtonMail, "_recipient_entries", return_value=({}, {"you@acme.com": {}}),
            ):
                client.send(to=["you@acme.com"], subject="Re: hi", body="b", **extra)
        draft = next(b for p, b in client.api.posts if p == "/mail/v4/messages")
        return draft

    def test_a_reply_sets_parent_and_reply_action(self) -> None:
        draft = self._send(parent_id="MSG42")
        self.assertEqual(draft["ParentID"], "MSG42")
        self.assertEqual(draft["Action"], 0)

    def test_reply_all_uses_action_one(self) -> None:
        draft = self._send(parent_id="MSG42", reply_all=True)
        self.assertEqual(draft["Action"], 1)

    def test_a_fresh_send_has_no_parent_or_action(self) -> None:
        draft = self._send()
        self.assertNotIn("ParentID", draft)
        self.assertNotIn("Action", draft)


BODY_UTF = "Café en Perú: piña, señor, ñandú. 日本語 y un emoji 😀."


class Utf8Body(unittest.TestCase):
    """A body with accents, CJK and an emoji survives the send/read round trip."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.key = _make_key("utf@proton.me")
        cls.bundle = KeyBundle(id="utf", armored=str(cls.key), passphrase=b"")

    def _encrypt(self, fmt: str) -> str:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            msg = pgpy.PGPMessage.new(
                BODY_UTF, format=fmt, compression=CompressionAlgorithm.Uncompressed
            )
            return str(self.key.pubkey.encrypt(msg))

    def test_build_tags_the_literal_utf8(self) -> None:
        material = send.build(BODY_UTF, str(self.key.pubkey))
        message = pgpy.PGPMessage.from_blob(material.armored_body)
        self.assertEqual(str(self.key.decrypt(message).message), BODY_UTF)

    def test_decrypt_text_repairs_a_latin1_tagged_body(self) -> None:
        # A sender that tags a UTF-8 body as format "t" (what some clients do).
        armored = self._encrypt("t")
        self.assertEqual(
            crypto.decrypt_text(armored, [self.bundle], textual=True), BODY_UTF
        )

    def test_decrypt_text_leaves_a_proper_utf8_body(self) -> None:
        armored = self._encrypt("u")
        self.assertEqual(
            crypto.decrypt_text(armored, [self.bundle], textual=True), BODY_UTF
        )


if __name__ == "__main__":
    unittest.main()
