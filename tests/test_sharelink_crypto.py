"""Offline tests for the share-link crypto primitives: the password session-key
packet (SKESK) round-trips, and the SRP verifier is g^x mod N."""

from __future__ import annotations

import base64
import unittest
from unittest import mock

import pgpy
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.packet import Packet

from protonlite import crypto, srp


class PasswordKeyPacket(unittest.TestCase):
    """crypto.password_key_packet must emit a standalone, passphrase-openable
    session-key packet encoding the exact session key given to it."""

    def test_round_trips_the_session_key(self):
        algo = SymmetricKeyAlgorithm.AES256
        sk = algo.gen_key()
        passphrase = "a-bcrypt-derived-passphrase"
        packet_b64 = crypto.password_key_packet(sk, passphrase)
        raw = base64.b64decode(packet_b64)

        # It is a single tag-3 (SKESK) packet.
        pkt = Packet(bytearray(raw))
        self.assertEqual(int(pkt.header.tag), 3)

        # Splice it into a different message that used the same session key; it
        # must open -- proving the packet encodes THIS session key.
        other = pgpy.PGPMessage.new(b"payload").encrypt(passphrase, sessionkey=sk, cipher=algo)
        blob = bytes(other.__bytes__())
        buf = bytearray(blob)
        span = None
        off = 0
        while buf:
            before = len(buf)
            p = Packet(buf)
            consumed = before - len(buf)
            if int(p.header.tag) == 3:
                span = (off, off + consumed)
            off += consumed
        spliced = blob[: span[0]] + raw + blob[span[1] :]
        opened = pgpy.PGPMessage.from_blob(spliced).decrypt(passphrase)
        m = opened.message
        self.assertEqual(m.encode() if isinstance(m, str) else bytes(m), b"payload")


class SrpVerifier(unittest.TestCase):
    def test_verifier_is_generator_to_the_x(self):
        # A small stand-in modulus so the math is checkable; patch the signed
        # modulus reader so we do not need a real signed blob.
        modulus = (1 << 2048) - 1559  # odd, 2048-bit-ish; only the math matters here
        mod_bytes = srp._from_int(modulus)
        with mock.patch.object(srp, "read_signed_modulus", return_value=mod_bytes):
            salt_b64, verifier_b64 = srp.random_verifier(b"hunter2", "SIGNED-IGNORED")

        salt = base64.b64decode(salt_b64)
        self.assertEqual(len(salt), 10)  # Proton uses a 10-byte SRP salt
        x = srp._to_int(srp.hash_password(b"hunter2", salt, mod_bytes))
        expected = srp._from_int(pow(srp._GENERATOR, x, modulus))
        self.assertEqual(base64.b64decode(verifier_b64), expected)

    def test_salt_is_random_each_call(self):
        modulus = (1 << 2048) - 1559
        with mock.patch.object(srp, "read_signed_modulus", return_value=srp._from_int(modulus)):
            a, _ = srp.random_verifier(b"pw", "x")
            b, _ = srp.random_verifier(b"pw", "x")
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
