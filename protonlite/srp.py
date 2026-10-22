"""Proton's SRP-6a login math.

Python port of Proton's own MIT-licensed Go implementation (ProtonMail/go-srp,
``srp.go`` and ``hash.go``, Copyright (c) 2019 Proton Technologies AG; see
THIRD-PARTY-NOTICES.md).

Two things make this flow unlike textbook SRP, and both are where a naive port
breaks: every big integer travels **little-endian**, and the hash is not a bare
SHA-512 but ``expand_hash``, four SHA-512 digests concatenated into 256 bytes.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass

import bcrypt

from ._modulus_key import MODULUS_SIGNING_KEY

BIT_LENGTH = 2048
_LEN_BYTES = BIT_LENGTH // 8
_GENERATOR = 2

# bcrypt's base64 alphabet: './' first, and no padding.
_STD_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCRYPT_B64 = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_TO_BCRYPT_B64 = bytes.maketrans(_STD_B64, _BCRYPT_B64)
_FROM_BCRYPT_B64 = bytes.maketrans(_BCRYPT_B64, _STD_B64)

SUPPORTED_AUTH_VERSIONS = (3, 4)


class SRPError(Exception):
    """The login handshake could not be completed safely."""


def _bcrypt_salt(raw: bytes) -> bytes:
    return base64.b64encode(raw).translate(_TO_BCRYPT_B64).rstrip(b"=")


def _bcrypt_unsalt(encoded: bytes) -> bytes:
    """The 16 salt bytes that 22 encoded characters stand for."""
    return base64.b64decode(encoded[:22].translate(_FROM_BCRYPT_B64) + b"==")


def _bcrypt(password: bytes, encoded_salt: bytes) -> bytes:
    """Hash like ProtonMail/bcrypt does, returning the whole modular-crypt string.

    Proton's fork reads only the **first 22 characters** of the encoded salt,
    hashes with the 16 bytes they decode to, and then echoes those same 22
    characters back in its output. That echo matters: the full string is what
    gets fed to ``expand_hash`` next, and version 3 hashing deliberately passes
    an over-long salt (``salt + b"proton"``) whose 22nd character therefore
    carries four bits of "proton" in it.

    Python's bcrypt refuses a salt whose trailing padding bits are not zero, so
    we hash with the canonical spelling of the same 16 bytes -- the Blowfish
    setup only ever sees those bytes -- and then restore Proton's spelling.
    """
    # bcrypt hashes at most 72 bytes, and bcrypt>=4 raises instead of silently
    # truncating. A longer password is not a valid Proton password, so I turn
    # it into our own error rather than let a raw ValueError escape the login.
    if len(password) > 72:
        raise SRPError("the password is longer than bcrypt's 72-byte limit")
    echoed = encoded_salt[:22]
    if len(echoed) != 22:
        raise SRPError(f"a bcrypt salt is 22 characters, got {len(echoed)}")
    canonical = _bcrypt_salt(_bcrypt_unsalt(echoed))
    digest = bcrypt.hashpw(password, b"$2y$10$" + canonical)
    return b"$2y$10$" + echoed + digest[29:]


def expand_hash(data: bytes) -> bytes:
    """SHA-512 of the data with each of four one-byte suffixes, concatenated."""
    return b"".join(hashlib.sha512(data + bytes((i,))).digest() for i in range(4))


def hash_password(password: bytes, salt: bytes, modulus: bytes) -> bytes:
    """Auth version 3/4 password hash. Versions 0-2 are pre-2016 accounts."""
    return expand_hash(_bcrypt(password, _bcrypt_salt(salt + b"proton")) + modulus)


def key_passphrase(password: bytes, key_salt: bytes) -> bytes:
    """Passphrase that unlocks the PGP private keys: last 31 bytes of the bcrypt hash."""
    return _bcrypt(password, _bcrypt_salt(key_salt))[-31:]


def _to_int(raw: bytes) -> int:
    return int.from_bytes(raw, "little")


def _from_int(value: int) -> bytes:
    return value.to_bytes(_LEN_BYTES, "little")


def read_signed_modulus(signed_modulus: str) -> bytes:
    """Verify the clear-signed modulus against Proton's key and return its bytes.

    Skipping this check would let whoever answers the request choose the group,
    which is the whole point of the signature.
    """
    import pgpy  # imported lazily: the math above is useful without a keyring

    try:
        key, _ = pgpy.PGPKey.from_blob(MODULUS_SIGNING_KEY)
        message = pgpy.PGPMessage.from_blob(signed_modulus)
    except Exception as exc:  # pgpy raises a zoo of exception types
        raise SRPError(f"could not parse the signed modulus: {exc}") from exc

    if not message.is_signed:
        raise SRPError("the modulus is not signed")
    if not key.verify(message):
        raise SRPError("the modulus signature is not Proton's")

    return base64.b64decode(str(message.message).strip())


def _is_probably_prime(n: int, rounds: int = 10) -> bool:
    """Miller-Rabin, standing in for Go's big.Int.ProbablyPrime."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _check_params(modulus: int, server_ephemeral: int) -> None:
    if modulus.bit_length() != BIT_LENGTH:
        raise SRPError("the modulus has the wrong size")
    # N must be 3 mod 8 so that 2 generates the whole group rather than a subgroup.
    if modulus % 8 != 3:
        raise SRPError("the modulus is not 3 mod 8")
    if not 1 < server_ephemeral < modulus - 1:
        raise SRPError("the server ephemeral is out of bounds")
    half = modulus >> 1
    if not _is_probably_prime(half):
        raise SRPError("the modulus is not a safe prime")
    # Lucas test base 2: proves primality in one exponentiation given (N-1)/2 prime.
    if pow(_GENERATOR, half, modulus) != modulus - 1:
        raise SRPError("the modulus is not prime")


@dataclass(frozen=True)
class Proofs:
    client_ephemeral: bytes
    client_proof: bytes
    expected_server_proof: bytes

    @property
    def b64_client_ephemeral(self) -> str:
        return base64.b64encode(self.client_ephemeral).decode()

    @property
    def b64_client_proof(self) -> str:
        return base64.b64encode(self.client_proof).decode()

    def server_proof_matches(self, b64_server_proof: str) -> bool:
        return secrets.compare_digest(
            self.expected_server_proof, base64.b64decode(b64_server_proof)
        )


def generate_proofs(
    *,
    version: int,
    password: bytes,
    b64_salt: str,
    signed_modulus: str,
    b64_server_ephemeral: str,
) -> Proofs:
    """Run the client half of the handshake and return what the server expects."""
    if version not in SUPPORTED_AUTH_VERSIONS:
        raise SRPError(
            f"auth version {version} is not supported (only {SUPPORTED_AUTH_VERSIONS}); "
            "change the account password once in the web client to upgrade it"
        )

    modulus_bytes = read_signed_modulus(signed_modulus)
    server_ephemeral_bytes = base64.b64decode(b64_server_ephemeral)
    hashed_password = hash_password(password, base64.b64decode(b64_salt), modulus_bytes)

    modulus = _to_int(modulus_bytes)
    server_ephemeral = _to_int(server_ephemeral_bytes)
    _check_params(modulus, server_ephemeral)

    x = _to_int(hashed_password)
    multiplier = _to_int(expand_hash(_from_int(_GENERATOR) + _from_int(modulus))) % modulus
    if not 1 < multiplier < modulus - 1:
        raise SRPError("the SRP multiplier is out of bounds")

    while True:
        secret = secrets.randbelow(modulus - 1)
        if not BIT_LENGTH * 2 < secret < modulus - 1:
            continue
        client_ephemeral = pow(_GENERATOR, secret, modulus)
        client_ephemeral_bytes = _from_int(client_ephemeral)
        scrambler = _to_int(expand_hash(client_ephemeral_bytes + server_ephemeral_bytes))
        if scrambler != 0:
            break

    base = (server_ephemeral - multiplier * pow(_GENERATOR, x, modulus)) % modulus
    exponent = (scrambler * x + secret) % (modulus - 1)
    shared_secret = _from_int(pow(base, exponent, modulus))

    client_proof = expand_hash(
        client_ephemeral_bytes + server_ephemeral_bytes + shared_secret
    )
    server_proof = expand_hash(client_ephemeral_bytes + client_proof + shared_secret)
    return Proofs(client_ephemeral_bytes, client_proof, server_proof)


def random_verifier(password: bytes, signed_modulus: str) -> tuple[str, str]:
    """A fresh SRP verifier for a new password, as Proton's share-link flow needs.

    Returns ``(salt_b64, verifier_b64)``. The salt is 10 random bytes; the
    verifier is ``g^x mod N`` where ``x`` is the Proton password hash over that
    salt and the signed server modulus. The caller supplies the modulus (and
    sends its ``ModulusID`` alongside these two values).
    """
    modulus = read_signed_modulus(signed_modulus)
    modulus_int = _to_int(modulus)
    salt = secrets.token_bytes(10)
    x = _to_int(hash_password(password, salt, modulus))
    verifier = _from_int(pow(_GENERATOR, x, modulus_int))
    return base64.b64encode(salt).decode(), base64.b64encode(verifier).decode()
