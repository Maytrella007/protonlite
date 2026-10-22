"""Key unlocking and message decryption.

Mirrors the unlock rules of Proton's own MIT Go client (ProtonMail/go-proton-api,
``keyring.go``): a key is unlocked with the salted passphrase derived from the
account password, unless it is a *migrated* key carrying ``Token``/``Signature``,
in which case the passphrase is the token decrypted with the user keyring -- and
the token's signature has to check out before it is trusted.
"""

from __future__ import annotations

import contextlib
import warnings
from dataclasses import dataclass
from typing import Iterable, Iterator

from .errors import ProtonError

with warnings.catch_warnings():
    # pgpy warns once at import that key-flag checks are unimplemented.
    warnings.simplefilter("ignore")
    import pgpy


@dataclass(frozen=True)
class KeyBundle:
    """An armored private key plus the passphrase that opens it."""

    id: str
    armored: str
    passphrase: bytes

    @property
    def _passphrase_text(self) -> str:
        # bcrypt output is ASCII; decrypted tokens can be arbitrary bytes.
        return self.passphrase.decode("latin-1")


@contextlib.contextmanager
def unlocked(bundle: KeyBundle) -> Iterator["pgpy.PGPKey"]:
    """Yield the key decrypted, and let pgpy re-protect it on the way out.

    pgpy only keeps a key open inside this block by design, so every operation
    pays the key-derivation cost again instead of leaving secrets in memory.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        key, _ = pgpy.PGPKey.from_blob(bundle.armored)
        if not key.is_protected:
            yield key
            return
        with key.unlock(bundle._passphrase_text):
            yield key


def decrypt_text(
    armored_message: str, bundles: Iterable[KeyBundle], *, textual: bool = False
) -> str:
    """Decrypt an armored message with the first key that can open it.

    With *textual* set, repair a UTF-8 body that pgpy handed back as latin-1,
    which is what it does for a format "t" literal. The token path leaves it
    off so its raw bytes still round-trip through latin-1 untouched.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = pgpy.PGPMessage.from_blob(armored_message)

    failures: list[str] = []
    for bundle in bundles:
        try:
            with unlocked(bundle) as key:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    decrypted = key.decrypt(message)
        except Exception as exc:  # pgpy raises PGPError, KeyError, ValueError...
            failures.append(f"{bundle.id}: {exc}")
            continue
        body = decrypted.message
        if isinstance(body, (bytes, bytearray)):
            return bytes(body).decode("utf-8", "replace")
        if textual:
            # pgpy latin-1-decodes a format "t" literal, so a UTF-8 body comes
            # back as mojibake. Re-read those same bytes as UTF-8, and leave a
            # genuine format "u" body alone when it does not round-trip latin-1.
            try:
                return body.encode("latin-1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                return body
        return str(body)

    detail = "; ".join(failures) if failures else "no keys were available"
    raise ProtonError(f"could not decrypt the message ({detail})")


def decrypt_attachment(
    key_packets: bytes, data_packet: bytes, bundles: Iterable[KeyBundle]
) -> bytes:
    """Decrypt one attachment: the key packet wraps its session key, the data
    packet is the file. The two together are a complete PGP message.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = pgpy.PGPMessage.from_blob(key_packets + data_packet)
    failures: list[str] = []
    for bundle in bundles:
        try:
            with unlocked(bundle) as key:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    decrypted = key.decrypt(message)
        except Exception as exc:
            failures.append(f"{bundle.id}: {exc}")
            continue
        body = decrypted.message
        if isinstance(body, (bytes, bytearray)):
            return bytes(body)
        # A text-format literal comes back as a latin-1 string; its bytes are
        # recovered 1:1 through latin-1.
        return body.encode("latin-1")
    detail = "; ".join(failures) if failures else "no keys were available"
    raise ProtonError(f"could not decrypt the attachment ({detail})")


def decrypt_token(
    token_armored: str, signature_armored: str, user_bundles: Iterable[KeyBundle]
) -> bytes:
    """Decrypt a migrated key's token and verify its signature before returning it.

    Skipping the signature check would let a tampered API response hand us a
    passphrase of its choosing.
    """
    user_bundles = list(user_bundles)
    token = decrypt_text(token_armored, user_bundles).encode("latin-1")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        signature = pgpy.PGPSignature.from_blob(signature_armored)
        for bundle in user_bundles:
            try:
                with unlocked(bundle) as key:
                    if key.verify(token.decode("latin-1"), signature):
                        return token
            except Exception:
                continue

    raise ProtonError("the key token's signature could not be verified")


def password_key_packet(session_key: bytes, passphrase: str) -> str:
    """A standalone password-encrypted session-key packet (OpenPGP SKESK, tag 3).

    Proton's "share via link" wraps a share's session key under a passphrase so
    a visitor who knows the URL password can recover it. pgpy has no direct call
    for a lone SKESK, so encrypt a throwaway message with the passphrase and the
    exact session key, then keep only the SKESK packet it emits. Returns base64.
    """
    from pgpy.constants import SymmetricKeyAlgorithm
    from pgpy.packet import Packet

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = pgpy.PGPMessage.new(b"x")
        encrypted = message.encrypt(
            passphrase, sessionkey=session_key, cipher=SymmetricKeyAlgorithm.AES256
        )
    blob = bytes(encrypted.__bytes__())
    buf = bytearray(blob)
    while buf:
        before = len(buf)
        packet = Packet(buf)
        consumed = before - len(buf)
        if consumed <= 0:
            break
        if int(packet.header.tag) == 3:  # Symmetric-Key Encrypted Session Key
            start = len(blob) - before
            import base64

            return base64.b64encode(blob[start:start + consumed]).decode()
    raise ProtonError("pgpy did not produce a password session-key packet")
