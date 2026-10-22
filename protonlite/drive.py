"""Reading Proton Drive: walk the encrypted tree, list folders, download files.

Drive is a crypto tree. A Share carries a passphrase encrypted to the account's
address key; unlocking it opens the Share key. The share points at a root Link
(a folder). Every Link carries its own NodeKey, whose passphrase is encrypted to
its parent's key (the share key for the root, the parent folder's node key
otherwise) and whose Name is encrypted to the parent too. A file Link also has a
ContentKeyPacket -- the content session key wrapped to the file's node key -- and
its bytes are stored as encrypted blocks on a CDN, each a bare data packet under
that one session key.

This reads only. Names and file bytes may come from things other people shared
into the drive, so a caller treats them as untrusted, like a mail body.

Mirrors the read chain of Proton's own MIT Go client (ProtonMail/go-proton-api:
share.go, link.go, link_file.go, block.go).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import warnings

import secrets
import string
import requests

from . import calendar as _calendar, crypto, send as _send, srp as _srp
from .api import _CODE_OK
from .crypto import KeyBundle
from .errors import ProtonError

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import pgpy
    from pgpy.constants import CompressionAlgorithm

LINK_FOLDER = 1
LINK_FILE = 2
_LINK_ACTIVE = 1
_PAGE = 100  # the children endpoint rejects PageSize >= 150
_BLOCK_PAGE = 50
_BLOCK_SIZE = 4 * 1024 * 1024  # Proton's default block size


class DriveReader:
    """A read-only view of one account's Proton Drive, resolved by path."""

    def __init__(self, client) -> None:
        self.client = client
        self.api = client.api
        self._share: dict | None = None

    # -- the crypto chain -------------------------------------------------

    def _main_share(self) -> dict:
        if self._share is None:
            shares = self.api.get("/drive/shares").get("Shares", [])
            meta = next((s for s in shares if s.get("Type") == 1), None)
            if meta is None:
                raise ProtonError("this account has no Proton Drive")
            self._share = self.api.get(f"/drive/shares/{meta['ShareID']}")
        return self._share

    def _share_keyring(self, share: dict) -> KeyBundle:
        passphrase = crypto.decrypt_text(
            share["Passphrase"], self.client._keys_for_address(share["AddressID"])
        ).encode("latin-1")
        return KeyBundle(id="share", armored=share["Key"], passphrase=passphrase)

    def _link(self, share_id: str, link_id: str) -> dict:
        return self.api.get(f"/drive/shares/{share_id}/links/{link_id}")["Link"]

    def _node_keyring(self, link: dict, parent: KeyBundle) -> KeyBundle:
        passphrase = crypto.decrypt_text(link["NodePassphrase"], [parent]).encode("latin-1")
        return KeyBundle(id=link["LinkID"], armored=link["NodeKey"], passphrase=passphrase)

    def _children(self, share_id: str, folder_id: str) -> list[dict]:
        out: list[dict] = []
        page = 0
        while True:
            payload = self.api.get(
                f"/drive/shares/{share_id}/folders/{folder_id}/children",
                params={"Page": page, "PageSize": _PAGE},
            )
            links = payload.get("Links", [])
            out.extend(links)
            if len(links) < _PAGE:
                break
            page += 1
        return out

    # -- write helpers ----------------------------------------------------

    def _address(self) -> tuple[KeyBundle, str]:
        share = self._main_share()
        bundle = self.client._keys_for_address(share["AddressID"])[0]
        email = next(
            a["Email"] for a in self.client.addresses() if a["ID"] == share["AddressID"]
        )
        return bundle, email

    def _encrypt_to(self, key_armored: str, data, sign_bundle: KeyBundle | None = None, binary: bool = False) -> str:
        """Encrypt *data* to a key (armored result), optionally inline-signed."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            message = pgpy.PGPMessage.new(
                data, format=("b" if binary else "u"), compression=CompressionAlgorithm.Uncompressed
            )
            if sign_bundle is not None:
                with crypto.unlocked(sign_bundle) as key:
                    message |= key.sign(message)
            return str(_send._encrypt_with(key_armored, message, os.urandom(32)))

    def _detached(self, data, bundle: KeyBundle) -> str:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with crypto.unlocked(bundle) as key:
                return str(key.sign(data))

    def _decrypt_binary(self, armored: str, bundle: KeyBundle) -> bytes:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with crypto.unlocked(bundle) as key:
                opened = key.decrypt(pgpy.PGPMessage.from_blob(armored)).message
        return opened if isinstance(opened, (bytes, bytearray)) else opened.encode("latin-1")

    def _hash_key(self, folder_link: dict, node: KeyBundle) -> bytes:
        return self._decrypt_binary(folder_link["FolderProperties"]["NodeHashKey"], node)

    @staticmethod
    def _name_hash(name: str, hash_key: bytes) -> str:
        return hmac.new(hash_key, name.encode("utf-8"), hashlib.sha256).hexdigest()

    def _resolve_parent_child(self, path: str) -> tuple[str, dict, KeyBundle, dict]:
        """Resolve a path to (share_id, parent folder link, parent node keyring, child link)."""
        segments = [s for s in path.strip("/").split("/") if s]
        if not segments:
            raise ProtonError("a path to an item is required")
        share_id, parent_link, parent_node = self._resolve("/".join(segments[:-1]))
        child = None
        for ch in self._children(share_id, parent_link["LinkID"]):
            if ch.get("State") != _LINK_ACTIVE:
                continue
            if crypto.decrypt_text(ch["Name"], [parent_node], textual=True) == segments[-1]:
                child = ch
                break
        if child is None:
            raise ProtonError(f"not found in Drive: {segments[-1]!r}")
        return share_id, parent_link, parent_node, child

    # -- write operations -------------------------------------------------

    def create_folder(self, parent_path: str, name: str) -> str:
        share_id, parent_link, parent_node = self._resolve(parent_path)
        if parent_link["Type"] != LINK_FOLDER:
            raise ProtonError(f"{parent_path!r} is not a folder")
        addr, email = self._address()
        parent_hash_key = self._hash_key(parent_link, parent_node)
        passphrase = base64.b64encode(os.urandom(32)).decode()
        node_key = _calendar.generate_calendar_key(passphrase)
        node = KeyBundle(id="node", armored=node_key, passphrase=passphrase.encode("latin-1"))
        new_hash_key = base64.b64encode(os.urandom(32)).decode()
        req = {
            "ParentLinkID": parent_link["LinkID"],
            "Name": self._encrypt_to(parent_link["NodeKey"], name, sign_bundle=addr),
            "Hash": self._name_hash(name, parent_hash_key),
            "NodeKey": node_key,
            "NodeHashKey": self._encrypt_to(node_key, new_hash_key, sign_bundle=node),
            "NodePassphrase": self._encrypt_to(parent_link["NodeKey"], passphrase),
            "NodePassphraseSignature": self._detached(passphrase, addr),
            "SignatureAddress": email,
        }
        return self.api.post(f"/drive/shares/{share_id}/folders", json_body=req)["Folder"]["ID"]

    def trash(self, path: str) -> str:
        """Move a file or folder to Drive's trash (recoverable). Returns its name."""
        share_id, parent_link, _node, child = self._resolve_parent_child(path)
        payload = self.api.post(
            f"/drive/shares/{share_id}/folders/{parent_link['LinkID']}/trash_multiple",
            json_body={"LinkIDs": [child["LinkID"]]},
            accept_multiple=True,
        )
        if not any(
            (i.get("Response") or {}).get("Code") == _CODE_OK for i in payload.get("Responses", [])
        ):
            raise ProtonError(f"the item was not trashed ({payload.get('Responses')})")
        return path.strip("/").split("/")[-1]

    def _rewrap_passphrase(self, old_armored: str, old_parent: KeyBundle, new_parent_key_armored: str) -> str:
        """Re-wrap a node passphrase to a new parent, reusing its session key.

        Proton's move keeps the passphrase's data packet and only re-wraps the
        session key to the new parent; a full fresh re-encryption with a new
        session key is mishandled (the stored passphrase then cannot be opened).
        """
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            raw = bytes(pgpy.PGPMessage.from_blob(old_armored))
        key_packet = _send._take(raw, (_send.TAG_PKESK,))
        data_packet = _send._take(raw, (_send.TAG_SEIPD, _send.TAG_SED))
        session_key = _calendar.recover_session_key(base64.b64encode(key_packet).decode(), old_parent)
        new_key_packet = base64.b64decode(_send.key_packet_for(session_key, new_parent_key_armored))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return str(pgpy.PGPMessage.from_blob(new_key_packet + data_packet))

    def move(self, src_path: str, dest_folder_path: str) -> str:
        share_id, _src_parent, src_parent_node, child = self._resolve_parent_child(src_path)
        name = src_path.strip("/").split("/")[-1]
        _sid2, dest_link, dest_node = self._resolve(dest_folder_path)
        if dest_link["Type"] != LINK_FOLDER:
            raise ProtonError(f"{dest_folder_path!r} is not a folder")
        addr, email = self._address()
        dest_hash_key = self._hash_key(dest_link, dest_node)
        req = {
            "Name": self._encrypt_to(dest_link["NodeKey"], name, sign_bundle=addr),
            "Hash": self._name_hash(name, dest_hash_key),
            "ParentLinkID": dest_link["LinkID"],
            "NodePassphrase": self._rewrap_passphrase(
                child["NodePassphrase"], src_parent_node, dest_link["NodeKey"]
            ),
            "NameSignatureEmail": email,
        }
        self.api.put(
            f"/drive/shares/{share_id}/links/{child['LinkID']}/move", json_body=req, accept_multiple=True
        )
        return child["LinkID"]

    def rename(self, path: str, new_name: str) -> str:
        """Rename a file or folder in place (same parent)."""
        share_id, parent_link, parent_node, child = self._resolve_parent_child(path)
        addr, email = self._address()
        parent_hash_key = self._hash_key(parent_link, parent_node)
        req = {
            "Name": self._encrypt_to(parent_link["NodeKey"], new_name, sign_bundle=addr),
            "Hash": self._name_hash(new_name, parent_hash_key),
            "NameSignatureEmail": email,
            "OriginalHash": child.get("Hash", ""),
        }
        self.api.put(
            f"/drive/shares/{share_id}/links/{child['LinkID']}/rename", json_body=req, accept_multiple=True
        )
        return child["LinkID"]

    def _data_packet(self, plaintext: bytes, session_key: bytes, recipient_armored: str) -> bytes:
        """Encrypt *plaintext* under the session key, return the bare data packet bytes."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            message = pgpy.PGPMessage.new(
                plaintext, format="b", compression=CompressionAlgorithm.Uncompressed
            )
            encrypted = _send._encrypt_with(recipient_armored, message, session_key)
            return _send._take(bytes(encrypted), (_send.TAG_SEIPD, _send.TAG_SED))

    def upload(self, dest_folder_path: str, name: str, data: bytes, mime_type: str = "application/octet-stream") -> str:
        """Upload a file into a Drive folder. Encrypts it into blocks and commits a revision."""
        share_id, folder_link, folder_node = self._resolve(dest_folder_path)
        if folder_link["Type"] != LINK_FOLDER:
            raise ProtonError(f"{dest_folder_path!r} is not a folder")
        addr, email = self._address()
        folder_hash_key = self._hash_key(folder_link, folder_node)

        passphrase = base64.b64encode(os.urandom(32)).decode()
        node_key = _calendar.generate_calendar_key(passphrase)
        node = KeyBundle(id="node", armored=node_key, passphrase=passphrase.encode("latin-1"))
        session_key = os.urandom(32)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with crypto.unlocked(node) as nkey:
                content_key_sig = str(nkey.sign(session_key))

        draft = self.api.post(
            f"/drive/shares/{share_id}/files",
            json_body={
                "ParentLinkID": folder_link["LinkID"],
                "Name": self._encrypt_to(folder_link["NodeKey"], name, sign_bundle=addr),
                "Hash": self._name_hash(name, folder_hash_key),
                "MIMEType": mime_type or "application/octet-stream",
                "ContentKeyPacket": _send.key_packet_for(session_key, node_key),
                "ContentKeyPacketSignature": content_key_sig,
                "NodeKey": node_key,
                "NodePassphrase": self._encrypt_to(folder_link["NodeKey"], passphrase),
                "NodePassphraseSignature": self._detached(passphrase, addr),
                "SignatureAddress": email,
            },
        )["File"]
        link_id, revision_id = draft["ID"], draft["RevisionID"]

        verification = self.api.get(
            f"/drive/shares/{share_id}/links/{link_id}/revisions/{revision_id}/verification"
        )
        code = base64.b64decode(verification["VerificationCode"])

        # Encrypt the content into blocks (one shared session key for all of them).
        chunks = [data[i : i + _BLOCK_SIZE] for i in range(0, len(data), _BLOCK_SIZE)] or [b""]
        block_infos: list[dict] = []
        encrypted_blocks: list[bytes] = []
        for index, chunk in enumerate(chunks, start=1):
            block = self._data_packet(chunk, session_key, node_key)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with crypto.unlocked(addr) as akey:
                    signature = bytes(akey.sign(chunk))
            enc_signature = self._encrypt_to(node_key, signature, binary=True)
            digest = hashlib.sha256(block).digest()
            verifier = bytes(code[i] ^ (block[i] if i < len(block) else 0) for i in range(len(code)))
            encrypted_blocks.append(block)
            block_infos.append(
                {
                    "Index": index,
                    "Size": len(block),
                    "EncSignature": enc_signature,
                    "Hash": base64.b64encode(digest).decode(),
                    "Verifier": {"Token": base64.b64encode(verifier).decode()},
                    "_digest": digest,
                }
            )

        upload = self.api.post(
            "/drive/blocks",
            json_body={
                "AddressID": self._main_share()["AddressID"],
                "ShareID": share_id,
                "LinkID": link_id,
                "RevisionID": revision_id,
                "BlockList": [{k: v for k, v in b.items() if not k.startswith("_")} for b in block_infos],
            },
            accept_multiple=True,
        )
        links = upload.get("UploadLinks") or []
        if len(links) < len(block_infos):
            raise ProtonError("the server did not return an upload link for every block")

        block_tokens: list[dict] = []
        for info, upload_link in zip(block_infos, links):
            resp = requests.post(
                upload_link["BareURL"],
                files={"Block": ("blob", encrypted_blocks[info["Index"] - 1], "application/octet-stream")},
                headers={"pm-storage-token": upload_link["Token"]},
                timeout=300,
            )
            if resp.status_code >= 400:
                raise ProtonError(f"block {info['Index']} upload failed (HTTP {resp.status_code})")
            block_tokens.append({"Index": info["Index"], "Token": upload_link["Token"]})

        manifest = b"".join(info["_digest"] for info in block_infos)
        self.api.put(
            f"/drive/shares/{share_id}/files/{link_id}/revisions/{revision_id}",
            json_body={
                "BlockList": block_tokens,
                "State": 1,
                "ManifestSignature": self._detached(manifest, addr),
                "SignatureAddress": email,
            },
            accept_multiple=True,
        )
        return link_id

    def _resolve(self, path: str) -> tuple[str, dict, KeyBundle]:
        """Walk from the root to *path*. Returns (share_id, target link, its node keyring).

        The returned keyring is the target's OWN node keyring: for a folder it
        opens the folder's children, for a file it opens the content session key.
        """
        share = self._main_share()
        share_id = share["ShareID"]
        node = self._share_keyring(share)
        link = self._link(share_id, share["LinkID"])
        node = self._node_keyring(link, node)  # root folder's node keyring
        for segment in [s for s in path.strip("/").split("/") if s]:
            match = None
            for child in self._children(share_id, link["LinkID"]):
                if child.get("State") != _LINK_ACTIVE:
                    continue
                if crypto.decrypt_text(child["Name"], [node], textual=True) == segment:
                    match = child
                    break
            if match is None:
                raise ProtonError(f"not found in Drive: {segment!r}")
            link = match
            node = self._node_keyring(link, node)
        return share_id, link, node

    # -- public read operations ------------------------------------------

    def list_folder(self, path: str = "") -> list[dict]:
        share_id, link, node = self._resolve(path)
        if link["Type"] != LINK_FOLDER:
            raise ProtonError(f"{path!r} is a file, not a folder")
        entries: list[dict] = []
        for child in self._children(share_id, link["LinkID"]):
            if child.get("State") != _LINK_ACTIVE:
                continue
            entries.append(
                {
                    "name": crypto.decrypt_text(child["Name"], [node], textual=True),
                    "type": "folder" if child["Type"] == LINK_FOLDER else "file",
                    "size": int(child.get("Size", 0) or 0),
                    "mime": child.get("MIMEType", ""),
                }
            )
        entries.sort(key=lambda e: (e["type"] != "folder", e["name"].lower()))
        return entries

    def download(self, path: str, *, size_limit: int = 0) -> tuple[str, str, bytes]:
        """Download and decrypt a file. Returns (name, mime, bytes)."""
        share_id, link, node = self._resolve(path)
        if link["Type"] != LINK_FILE:
            raise ProtonError(f"{path!r} is a folder, not a file")
        if size_limit and int(link.get("Size", 0) or 0) > size_limit:
            raise ProtonError(
                f"that file is {link.get('Size')} bytes; over the {size_limit}-byte download limit"
            )
        props = link["FileProperties"]
        content_key = base64.b64decode(props["ContentKeyPacket"])
        revision_id = props["ActiveRevision"]["ID"]
        name = path.strip("/").split("/")[-1] or link["LinkID"]

        data = bytearray()
        from_index = 1
        while True:
            revision = self.api.get(
                f"/drive/shares/{share_id}/files/{link['LinkID']}/revisions/{revision_id}",
                params={"FromBlockIndex": from_index, "PageSize": _BLOCK_PAGE},
            )
            blocks = sorted(
                (revision.get("Revision") or revision).get("Blocks", []),
                key=lambda b: b["Index"],
            )
            if not blocks:
                break
            for block in blocks:
                encrypted = requests.get(
                    block["BareURL"], headers={"pm-storage-token": block["Token"]}, timeout=120
                ).content
                data += crypto.decrypt_attachment(content_key, encrypted, [node])
            if len(blocks) < _BLOCK_PAGE:
                break
            from_index = blocks[-1]["Index"] + 1
        return name, link.get("MIMEType", ""), bytes(data)

    # -- public share links -----------------------------------------------

    _SHARE_PASSWORD_LEN = 12
    _VIEWER = 4
    _FLAG_GENERATED_PASSWORD = 2

    def _key_packet_of(self, armored: str) -> str:
        """The base64 PKESK key packet inside an armored PGP message."""
        blob = bytes(pgpy.PGPMessage.from_blob(armored))
        return base64.b64encode(_send._take(blob, (_send.TAG_PKESK,))).decode()

    def _create_link_share(self, share_id: str, parent_node: KeyBundle, link: dict) -> tuple[str, bytes]:
        """Create a Share on a link so it can be shared. Returns (shareID, shareSessionKey).

        The new share re-wraps the link's own passphrase and name session keys
        to a fresh share key, so the link stays reachable through the share.
        """
        addr, _email = self._address()
        link_pass_sk = _calendar.recover_session_key(self._key_packet_of(link["NodePassphrase"]), parent_node)
        name_sk = _calendar.recover_session_key(self._key_packet_of(link["Name"]), parent_node)

        raw_pass = base64.b64encode(os.urandom(32)).decode()
        share_key = _calendar.generate_calendar_key(raw_pass)
        share_sk = os.urandom(32)
        # SharePassphrase: raw_pass encrypted to [the link's node key, our address],
        # unsigned, with a detached signature alongside (the NodePassphrase pattern).
        enc = _send._encrypt_with(link["NodeKey"], pgpy.PGPMessage.new(raw_pass, format="t"), share_sk)
        blob = bytes(enc)
        assembled = (
            _send._take(blob, (_send.TAG_PKESK,))
            + base64.b64decode(_send.key_packet_for(share_sk, addr.armored))
            + _send._take(blob, (_send.TAG_SEIPD, _send.TAG_SED))
        )
        volume_id = self._main_share()["VolumeID"]
        body = {
            "AddressID": self._main_share()["AddressID"],
            "RootLinkID": link["LinkID"],
            "ShareKey": share_key,
            "SharePassphrase": str(pgpy.PGPMessage.from_blob(assembled)),
            "SharePassphraseSignature": _calendar.detached_signature(raw_pass, addr),
            "PassphraseKeyPacket": _send.key_packet_for(link_pass_sk, share_key),
            "NameKeyPacket": _send.key_packet_for(name_sk, share_key),
        }
        resp = self.api.post(f"/drive/volumes/{volume_id}/shares", json_body=body)
        return resp["Share"]["ID"], share_sk

    def share_link(self, path: str) -> dict:
        """Create a public "share via link" for a file or folder.

        Returns ``{"url", "token", "password", "share_id", "share_url_id"}``.
        The URL fragment after ``#`` is the password: it never reaches Proton's
        server, so the returned ``url`` is the whole secret -- hand it out
        carefully. The link is view-only with no expiry.
        """
        share_id, parent_link, parent_node, link = self._resolve_parent_child(path)
        if self._link_share_id(link):
            raise ProtonError(
                f"{path!r} is already shared; revoke the existing link with unshare first"
            )
        addr, email = self._address()

        # Everything from the share creation through the URL POST is one unit: if
        # any step fails after the share exists, roll the share back so the link
        # is not left with a dangling, URL-less share.
        link_share_id = None
        try:
            link_share_id, share_sk = self._create_link_share(share_id, parent_node, link)
            alphabet = string.ascii_letters + string.digits
            password = "".join(secrets.choice(alphabet) for _ in range(self._SHARE_PASSWORD_LEN))
            salt16 = os.urandom(16)
            url_passphrase = _srp.key_passphrase(password.encode(), salt16).decode()
            modulus = self.api.get("/core/v4/auth/modulus")
            url_salt, verifier = _srp.random_verifier(password.encode(), modulus["Modulus"])
            body = {
                "CreatorEmail": email,
                "ExpirationDuration": None,
                "Flags": self._FLAG_GENERATED_PASSWORD,
                "MaxAccesses": 0,
                "Password": self._encrypt_to(addr.armored, password),
                "Permissions": self._VIEWER,
                "SharePassphraseKeyPacket": crypto.password_key_packet(share_sk, url_passphrase),
                "SharePasswordSalt": base64.b64encode(salt16).decode(),
                "SRPModulusID": modulus["ModulusID"],
                "SRPVerifier": verifier,
                "UrlPasswordSalt": url_salt,
            }
            resp = self.api.post(f"/drive/shares/{link_share_id}/urls", json_body=body)
        except Exception:
            if link_share_id:
                try:
                    self.api.delete(f"/drive/shares/{link_share_id}", params={"Force": 0})
                except Exception:
                    pass
            raise
        su = resp["ShareURL"]
        return {
            "url": f"https://drive.proton.me/urls/{su['Token']}#{password}",
            "token": su["Token"],
            "password": password,
            "share_id": link_share_id,
            "share_url_id": su["ShareURLID"],
        }

    def _link_share_id(self, link: dict) -> str:
        """The id of the share that a shared link carries, or '' if not shared."""
        details = link.get("SharingDetails") or {}
        return details.get("ShareID") or (details.get("ShareUrl") or {}).get("ShareID") or ""

    def unshare_link(self, path: str) -> bool:
        """Revoke a file or folder's public link and delete its share.

        Returns True if a link was removed, False if it was not shared.
        """
        share_id, _parent_link, _parent_node, link = self._resolve_parent_child(path)
        link_share_id = self._link_share_id(link)
        if not link_share_id:
            return False
        urls = self.api.get(f"/drive/shares/{link_share_id}/urls", params={"Page": 0, "PageSize": 10})
        for su in urls.get("ShareURLs", []):
            self.api.delete(f"/drive/shares/{link_share_id}/urls/{su['ShareURLID']}")
        self.api.delete(f"/drive/shares/{link_share_id}", params={"Force": 0})
        return True
