"""Encrypting a message the way Proton's send API expects it.

Proton does not take a finished PGP message per recipient. It takes the body
once, encrypted with a session key (the *data packet*), plus that session key
wrapped for each recipient (a *key packet*) -- and, for recipients outside
Proton, the session key in the clear so their servers can deliver normal mail.
That shape comes from Proton's own MIT Go client (``message_send_types.go``).

So we encrypt once and then take the resulting packet stream apart, which is
what ``split_packets`` is for.
"""

from __future__ import annotations

import base64
import os
import warnings
from dataclasses import dataclass

from .crypto import KeyBundle, unlocked
from .errors import ProtonError

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import pgpy
    from pgpy.constants import CompressionAlgorithm, SymmetricKeyAlgorithm

SESSION_KEY_ALGORITHM = "aes256"
SESSION_KEY_BYTES = 32

TAG_PKESK = 1  # public-key encrypted session key
TAG_SED = 9  # symmetrically encrypted data (legacy)
TAG_SEIPD = 18  # symmetrically encrypted and integrity protected data

# Proton's encryption schemes, as sent in a package's Type field.
SCHEME_INTERNAL = 1
SCHEME_CLEAR = 4


def split_packets(blob: bytes) -> list[tuple[int, bytes]]:
    """Split an OpenPGP packet stream into (tag, whole packet) pairs."""
    packets: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(blob):
        start = offset
        header = blob[offset]
        if not header & 0x80:
            raise ProtonError("this is not an OpenPGP packet stream")
        offset += 1

        if header & 0x40:  # new-format header
            tag = header & 0x3F
            first = blob[offset]
            offset += 1
            if first < 192:
                length = first
            elif first < 224:
                length = ((first - 192) << 8) + blob[offset] + 192
                offset += 1
            elif first == 255:
                length = int.from_bytes(blob[offset : offset + 4], "big")
                offset += 4
            else:
                raise ProtonError("partial packet lengths are not supported")
        else:  # old-format header
            tag = (header >> 2) & 0x0F
            length_type = header & 0x03
            if length_type == 0:
                length = blob[offset]
                offset += 1
            elif length_type == 1:
                length = int.from_bytes(blob[offset : offset + 2], "big")
                offset += 2
            elif length_type == 2:
                length = int.from_bytes(blob[offset : offset + 4], "big")
                offset += 4
            else:
                raise ProtonError("indeterminate packet lengths are not supported")

        offset += length
        if offset > len(blob):
            raise ProtonError("truncated OpenPGP packet")
        packets.append((tag, blob[start:offset]))
    return packets


def _take(blob: bytes, wanted: tuple[int, ...]) -> bytes:
    for tag, packet in split_packets(blob):
        if tag in wanted:
            return packet
    raise ProtonError(f"no packet with tag {wanted} in the encrypted message")


@dataclass
class SendMaterial:
    """One encrypted body, ready to be addressed to anyone."""

    armored_body: str  # what the draft stores, encrypted to our own key
    data_packet: bytes  # the body alone, for the send packages
    session_key: bytes

    @property
    def b64_data_packet(self) -> str:
        return base64.b64encode(self.data_packet).decode()

    @property
    def b64_session_key(self) -> str:
        return base64.b64encode(self.session_key).decode()


def _encrypt_with(
    armored_key: str, message: "pgpy.PGPMessage", session_key: bytes
) -> "pgpy.PGPMessage":
    """Encrypt to a key, letting pgpy choose which part of it can encrypt.

    Proton keys carry a separate encryption subkey. Picking one by hand looks
    tempting and fails: a subkey taken off a ``pubkey`` copy has lost its link
    to the primary key, and pgpy then raises ``'NoneType' has no attribute
    'fingerprint'`` while reading its flags. So ask the primary key first and
    only fall back to subkeys of the key as loaded.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        loaded, _ = pgpy.PGPKey.from_blob(armored_key)
        public = loaded if loaded.is_public else loaded.pubkey
        attempts: list[Exception] = []
        for candidate in (public, *public.subkeys.values()):
            try:
                return candidate.encrypt(
                    message, sessionkey=session_key, cipher=SymmetricKeyAlgorithm.AES256
                )
            except Exception as exc:
                attempts.append(exc)

    detail = "; ".join(str(exc) for exc in attempts) or "no usable key"
    raise ProtonError(f"could not encrypt to this key ({detail})")


def build(
    body: str, own_key_armored: str, *, signer: "KeyBundle | None" = None
) -> SendMaterial:
    """Encrypt the body once, to ourselves, and keep the pieces Proton needs.

    The body is signed first when a *signer* is given, and it has to be: for a
    recipient outside Proton the server decrypts the body itself to deliver
    ordinary mail, and it refuses an unsigned one ("message signature is
    invalid or empty"). Proton's own client signs and encrypts in a single
    keyring call, which is easy to miss when porting.
    """
    session_key = os.urandom(SESSION_KEY_BYTES)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # Mark the literal UTF-8. With format "t" pgpy reads the body back as
        # latin-1 and mangles every non-ASCII character.
        message = pgpy.PGPMessage.new(
            body, format="u", compression=CompressionAlgorithm.Uncompressed
        )
        if signer is not None:
            with unlocked(signer) as key:
                message |= key.sign(message)
    encrypted = _encrypt_with(own_key_armored, message, session_key)
    blob = bytes(encrypted)
    return SendMaterial(
        armored_body=str(encrypted),
        data_packet=_take(blob, (TAG_SEIPD, TAG_SED)),
        session_key=session_key,
    )


@dataclass
class AttachmentMaterial:
    """One encrypted attachment, ready to upload and then address to anyone."""

    session_key: bytes
    data_packet: bytes  # the file, encrypted under the session key
    key_packets: bytes  # the session key wrapped to the sender, for the upload
    signature: bytes  # detached signature of the plaintext, by the sender


def build_attachment(
    data: bytes, own_key_armored: str, *, signer: "KeyBundle"
) -> AttachmentMaterial:
    """Encrypt and sign one attachment the way Proton's upload expects."""
    session_key = os.urandom(SESSION_KEY_BYTES)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = pgpy.PGPMessage.new(
            data, format="b", compression=CompressionAlgorithm.Uncompressed
        )
        with unlocked(signer) as key:
            signature = bytes(key.sign(data))
    encrypted = _encrypt_with(own_key_armored, message, session_key)
    blob = bytes(encrypted)
    return AttachmentMaterial(
        session_key=session_key,
        data_packet=_take(blob, (TAG_SEIPD, TAG_SED)),
        key_packets=_take(blob, (TAG_PKESK,)),
        signature=signature,
    )


def key_packet_for(session_key: bytes, recipient_key_armored: str) -> str:
    """Wrap the session key for one recipient and return the key packet, base64.

    The stub body is throwaway: a key packet only ever encodes the session key
    and who may open it, so encrypting an empty message is the cheapest way to
    mint one without touching the real body again.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        stub = pgpy.PGPMessage.new("", format="t")
    encrypted = _encrypt_with(recipient_key_armored, stub, session_key)
    return base64.b64encode(_take(bytes(encrypted), (TAG_PKESK,))).decode()
