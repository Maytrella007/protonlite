"""Tests for the login math. No account and no network needed."""

from __future__ import annotations

import base64
import hashlib
import pathlib
import unittest

from protonlite import srp

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SIGNED_MODULUS = (FIXTURES / "signed_modulus.txt").read_text()


class ExpandHash(unittest.TestCase):
    def test_shape(self) -> None:
        digest = srp.expand_hash(b"anything")
        self.assertEqual(len(digest), 256)

    def test_matches_its_definition(self) -> None:
        data = b"proton"
        expected = b"".join(
            hashlib.sha512(data + bytes((i,))).digest() for i in range(4)
        )
        self.assertEqual(srp.expand_hash(data), expected)

    def test_suffixes_are_distinct(self) -> None:
        # A port that appended the same byte four times would still be 256 bytes.
        quarters = {srp.expand_hash(b"x")[i * 64 : (i + 1) * 64] for i in range(4)}
        self.assertEqual(len(quarters), 4)


class Derivations(unittest.TestCase):
    def test_bcrypt_salt_uses_bcrypts_alphabet(self) -> None:
        encoded = srp._bcrypt_salt(bytes(range(16)))
        self.assertEqual(len(encoded), 22)
        self.assertNotIn(b"+", encoded)
        self.assertNotIn(b"=", encoded)

    def test_key_passphrase_is_31_bytes(self) -> None:
        # The last 31 bytes of the bcrypt hash, as Proton's clients do it.
        passphrase = srp.key_passphrase(b"a password", bytes(range(16)))
        self.assertEqual(len(passphrase), 31)

    def test_key_passphrase_is_deterministic_and_salt_bound(self) -> None:
        first = srp.key_passphrase(b"pw", bytes(16))
        again = srp.key_passphrase(b"pw", bytes(16))
        other_salt = srp.key_passphrase(b"pw", bytes([1] * 16))
        self.assertEqual(first, again)
        self.assertNotEqual(first, other_salt)

    def test_password_hash_is_256_bytes_and_modulus_bound(self) -> None:
        modulus = bytes(256)
        hashed = srp.hash_password(b"pw", bytes(16), modulus)
        self.assertEqual(len(hashed), 256)
        other = srp.hash_password(b"pw", bytes(16), bytes([7] * 256))
        self.assertNotEqual(hashed, other)

    def test_login_and_key_derivations_differ(self) -> None:
        """The whole reason a leaked session file cannot log in."""
        salt = bytes(range(16))
        login = srp.hash_password(b"pw", salt, bytes(256))
        keys = srp.key_passphrase(b"pw", salt)
        self.assertNotIn(keys, login)


class Endianness(unittest.TestCase):
    def test_round_trip(self) -> None:
        value = 1234567890123456789
        self.assertEqual(srp._to_int(srp._from_int(value)), value)

    def test_is_little_endian(self) -> None:
        self.assertEqual(srp._from_int(1)[0], 1)
        self.assertEqual(srp._from_int(1)[-1], 0)


class SignedModulus(unittest.TestCase):
    def test_accepts_protons_signature(self) -> None:
        modulus = srp.read_signed_modulus(SIGNED_MODULUS)
        self.assertEqual(len(modulus), 256)

    def test_rejects_a_tampered_modulus(self) -> None:
        lines = SIGNED_MODULUS.splitlines()
        for index, line in enumerate(lines):
            if len(line) > 40 and not line.startswith("-----") and ":" not in line:
                swapped = "B" if line[0] != "B" else "C"
                lines[index] = swapped + line[1:]
                break
        else:  # pragma: no cover
            self.fail("could not find a body line to tamper with")

        with self.assertRaises(srp.SRPError):
            srp.read_signed_modulus("\n".join(lines))


class Parameters(unittest.TestCase):
    def setUp(self) -> None:
        self.modulus = srp._to_int(srp.read_signed_modulus(SIGNED_MODULUS))

    def test_real_modulus_passes(self) -> None:
        srp._check_params(self.modulus, 12345)

    def test_rejects_wrong_size(self) -> None:
        with self.assertRaises(srp.SRPError):
            srp._check_params(self.modulus >> 8, 12345)

    def test_rejects_ephemeral_out_of_bounds(self) -> None:
        for bad in (0, 1, self.modulus - 1, self.modulus):
            with self.assertRaises(srp.SRPError):
                srp._check_params(self.modulus, bad)

    def test_rejects_a_non_prime_modulus(self) -> None:
        composite = self.modulus + 8  # keeps 3 mod 8 and the bit length
        with self.assertRaises(srp.SRPError):
            srp._check_params(composite, 12345)


class Proofs(unittest.TestCase):
    def test_generates_the_expected_sizes(self) -> None:
        ephemeral = base64.b64encode(bytes([2] + [0] * 255)).decode()
        proofs = srp.generate_proofs(
            version=4,
            password=b"a password",
            b64_salt=base64.b64encode(bytes(range(16))).decode(),
            signed_modulus=SIGNED_MODULUS,
            b64_server_ephemeral=ephemeral,
        )
        self.assertEqual(len(proofs.client_ephemeral), 256)
        self.assertEqual(len(proofs.client_proof), 256)
        self.assertEqual(len(proofs.expected_server_proof), 256)
        self.assertFalse(proofs.server_proof_matches(base64.b64encode(bytes(256)).decode()))

    def test_refuses_old_auth_versions(self) -> None:
        for version in (0, 1, 2):
            with self.assertRaises(srp.SRPError):
                srp.generate_proofs(
                    version=version,
                    password=b"pw",
                    b64_salt=base64.b64encode(bytes(16)).decode(),
                    signed_modulus=SIGNED_MODULUS,
                    b64_server_ephemeral=base64.b64encode(bytes(256)).decode(),
                )


if __name__ == "__main__":
    unittest.main()


class BcryptCompatibility(unittest.TestCase):
    """The salt handling that only ProtonMail's bcrypt fork gets right."""

    def test_echoes_protons_22_characters(self) -> None:
        salt = bytes(range(16))
        over_long = srp._bcrypt_salt(salt + b"proton")
        self.assertEqual(len(over_long), 30)
        result = srp._bcrypt(b"pw", over_long)
        self.assertEqual(result[:7], b"$2y$10$")
        self.assertEqual(result[7:29], over_long[:22])

    def test_the_echoed_salt_changes_the_hash(self) -> None:
        """If the echo were normalised, version 3 hashing would be wrong."""
        salt = bytes(range(16))
        with_proton = srp._bcrypt(b"pw", srp._bcrypt_salt(salt + b"proton"))
        plain = srp._bcrypt(b"pw", srp._bcrypt_salt(salt))
        self.assertNotEqual(with_proton, plain)
        # ...but only in the salt field: the same 16 bytes go into Blowfish.
        self.assertEqual(with_proton[29:], plain[29:])

    def test_decode_round_trip(self) -> None:
        salt = bytes(range(16))
        self.assertEqual(srp._bcrypt_unsalt(srp._bcrypt_salt(salt)), salt)

    def test_rejects_a_short_salt(self) -> None:
        with self.assertRaises(srp.SRPError):
            srp._bcrypt(b"pw", b"tooshort")

    def test_rejects_a_password_over_bcrypts_limit(self) -> None:
        # bcrypt>=4 raises ValueError past 72 bytes; we want our own SRPError
        # so the login path reports it instead of crashing.
        salt = srp._bcrypt_salt(bytes(range(16)))
        with self.assertRaises(srp.SRPError):
            srp._bcrypt(b"x" * 73, salt)
