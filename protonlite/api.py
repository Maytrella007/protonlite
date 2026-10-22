"""HTTP transport and session handling for the Proton API.

Endpoint paths, payload shapes and the refresh dance follow Proton's own
MIT-licensed Go client (ProtonMail/go-proton-api); see THIRD-PARTY-NOTICES.md.

What a saved session holds is a deliberate choice: the access and refresh
tokens, and the *salted key passphrases* -- never the account password. The
passphrase derivation for keys uses a different salt than the one the login
handshake uses, so a leaked session file decrypts mail but cannot log in or
change the password.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from . import srp
from .errors import (
    APIError,
    AuthError,
    HumanVerificationRequired,
    SessionExpired,
    TwoFactorRequired,
)

DEFAULT_HOST = "https://mail.proton.me/api"
# Proton rejects a request with no app version (HTTP 400). "Other" is the
# value reserved for clients that are not one of Proton's own apps.
DEFAULT_APP_VERSION = "Other"
DEFAULT_USER_AGENT = "protonlite/0.1 (+https://github.com/Maytrella007/protonlite)"

#: ``2FA.Enabled`` is a bitfield: a code from an app, a security key, or both.
_TOTP = 1
_FIDO2 = 2

_CODE_OK = 1000
_CODE_HUMAN_VERIFICATION = 9001
_CODE_BAD_CREDENTIALS = 8002
_CODE_INVALID_TOKEN = 10013
_CODE_MULTIPLE = 1001  # batch endpoints: see per-item Responses


@dataclass
class Session:
    """Everything needed to keep talking to the API after a login."""

    uid: str = ""
    access_token: str = ""
    refresh_token: str = ""
    username: str = ""
    # One passphrase unlocks every key: it is derived from the primary user
    # key's salt, exactly as Proton's own clients do it.
    salted_key_pass: str = ""

    @property
    def authenticated(self) -> bool:
        return bool(self.uid and self.access_token)

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": 1,
                "uid": self.uid,
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "username": self.username,
                "salted_key_pass": self.salted_key_pass,
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, raw: str) -> "Session":
        data = json.loads(raw)
        if data.get("version") != 1:
            raise SessionExpired("unrecognised session file version; log in again")
        return cls(
            uid=data["uid"],
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            username=data.get("username", ""),
            salted_key_pass=data.get("salted_key_pass", ""),
        )


def write_session(session: Session, path: str | os.PathLike[str]) -> None:
    """Write the session with 0600 permissions, replacing any previous file atomically."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(session.to_json())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, target)
    os.chmod(target, 0o600)


def read_session(path: str | os.PathLike[str]) -> Session:
    return Session.from_json(Path(path).read_text())


class ProtonAPI:
    """A thin, synchronous Proton API client."""

    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        app_version: str = DEFAULT_APP_VERSION,
        user_agent: str = DEFAULT_USER_AGENT,
        session: Session | None = None,
        timeout: int = 30,
        on_session_change: Any = None,
    ) -> None:
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.session = session or Session()
        self._on_session_change = on_session_change
        self._http = requests.Session()
        self._http.headers.update(
            {
                "x-pm-appversion": app_version,
                "User-Agent": user_agent,
                "Accept": "application/vnd.protonmail.v1+json",
                "Content-Type": "application/json",
            }
        )

    # -- plumbing ---------------------------------------------------------

    def set_verification_token(self, token: str, method: str = "captcha") -> None:
        """Carry a verification token a person already completed into later requests.

        Header names are Proton's own (``manager_auth.go``). The token comes
        from the page Proton points at in :class:`HumanVerificationRequired`.
        """
        self._http.headers["x-pm-human-verification-token"] = token
        self._http.headers["x-pm-human-verification-token-type"] = method

    def _auth_headers(self) -> dict[str, str]:
        if not self.session.authenticated:
            return {}
        return {
            "x-pm-uid": self.session.uid,
            "Authorization": f"Bearer {self.session.access_token}",
        }

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: dict[str, Any] | None = None,
        authenticated: bool = True,
        accept_multiple: bool = False,
        _retry: bool = True,
    ) -> dict[str, Any]:
        headers = self._auth_headers() if authenticated else {}
        response = self._http.request(
            method,
            f"{self.host}{path}",
            json=json_body,
            params=params,
            headers=headers,
            timeout=self.timeout,
        )

        if response.status_code == 429:
            delay = int(response.headers.get("Retry-After", "5"))
            if _retry and delay <= 30:
                time.sleep(delay)
                return self.request(
                    method,
                    path,
                    json_body=json_body,
                    params=params,
                    authenticated=authenticated,
                    accept_multiple=accept_multiple,
                    _retry=False,
                )
            raise APIError(429, None, f"rate limited; retry in {delay}s")

        try:
            payload = response.json()
        except ValueError:
            raise APIError(response.status_code, None, response.text[:200]) from None

        code = payload.get("Code")
        message = payload.get("Error", "")

        if code == _CODE_HUMAN_VERIFICATION:
            details = payload.get("Details") or {}
            raise HumanVerificationRequired(
                message or "Proton is asking for verification before this login",
                token=details.get("HumanVerificationToken", ""),
                methods=list(details.get("HumanVerificationMethods") or []),
                web_url=details.get("WebUrl", ""),
                expires_at=details.get("ExpiresAt"),
            )
        if code == _CODE_BAD_CREDENTIALS:
            raise AuthError("Proton rejected the username or password.")
        if response.status_code == 401 and authenticated:
            # The access token lasts a day; the refresh token outlives it.
            if _retry and self.session.refresh_token:
                self.refresh()
                return self.request(
                    method,
                    path,
                    json_body=json_body,
                    params=params,
                    authenticated=authenticated,
                    accept_multiple=accept_multiple,
                    _retry=False,
                )
            raise SessionExpired("the session is no longer valid; log in again")
        if code == _CODE_INVALID_TOKEN:
            raise SessionExpired("the stored token was revoked; log in again")
        ok_codes = {_CODE_OK, _CODE_MULTIPLE} if accept_multiple else {_CODE_OK}
        if not response.ok or (code is not None and code not in ok_codes):
            raise APIError(response.status_code, code, message or response.text[:200])

        return payload

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self.request("GET", path, **kwargs)

    def get_bytes(self, path: str, params: dict[str, Any] | None = None, *, _retry: bool = True) -> bytes:
        """Fetch a raw, non-JSON body such as an attachment's encrypted data."""
        response = self._http.request(
            "GET",
            f"{self.host}{path}",
            params=params,
            headers=self._auth_headers(),
            timeout=self.timeout,
        )
        if response.status_code == 401 and _retry and self.session.refresh_token:
            self.refresh()
            return self.get_bytes(path, params, _retry=False)
        if not response.ok:
            raise APIError(response.status_code, None, response.text[:200])
        return response.content

    def post_multipart(
        self, path: str, data: dict[str, Any], files: dict[str, Any], *, _retry: bool = True
    ) -> dict[str, Any]:
        """POST a multipart form (an attachment upload), returning the JSON body."""
        # Drop the session's default JSON Content-Type so requests sets the
        # multipart/form-data boundary; otherwise Proton tries to parse the
        # body as JSON and rejects it.
        headers = {**self._auth_headers(), "Content-Type": None}
        response = self._http.request(
            "POST",
            f"{self.host}{path}",
            data=data,
            files=files,
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code == 401 and _retry and self.session.refresh_token:
            self.refresh()
            return self.post_multipart(path, data, files, _retry=False)
        try:
            payload = response.json()
        except ValueError:
            raise APIError(response.status_code, None, response.text[:200]) from None
        code = payload.get("Code")
        if not response.ok or (code is not None and code != _CODE_OK):
            raise APIError(response.status_code, code, payload.get("Error") or response.text[:200])
        return payload

    def post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self.request("DELETE", path, **kwargs)

    def _session_changed(self) -> None:
        if self._on_session_change is not None:
            self._on_session_change(self.session)

    # -- authentication ---------------------------------------------------

    def login(
        self, username: str, password: bytes, *, totp_code: str = ""
    ) -> dict[str, Any]:
        """Run the SRP handshake. Returns the auth payload (scopes, password mode...).

        *totp_code* is the six-digit code from an authenticator app, needed only
        by accounts that have one. It cannot be supplied in advance usefully --
        codes last about thirty seconds -- so a caller without one gets
        :class:`TwoFactorRequired` and asks for it then.
        """
        info = self.post(
            "/auth/v4/info", json_body={"Username": username}, authenticated=False
        )
        proofs = srp.generate_proofs(
            version=info["Version"],
            password=password,
            b64_salt=info["Salt"],
            signed_modulus=info["Modulus"],
            b64_server_ephemeral=info["ServerEphemeral"],
        )
        auth = self.post(
            "/auth/v4",
            json_body={
                "Username": username,
                "ClientEphemeral": proofs.b64_client_ephemeral,
                "ClientProof": proofs.b64_client_proof,
                "SRPSession": info["SRPSession"],
            },
            authenticated=False,
        )

        # Authenticating the server too is the point of SRP: a wrong proof here
        # means we are not talking to Proton, even though the password matched.
        if not proofs.server_proof_matches(auth["ServerProof"]):
            raise AuthError("the server proof did not match; aborting the login")

        # The second factor is submitted *against the session this login just
        # created*, so the tokens have to be in place before it is settled --
        # but nothing is persisted until the account is fully open.
        self.session.uid = auth["UID"]
        self.session.access_token = auth["AccessToken"]
        self.session.refresh_token = auth["RefreshToken"]
        self.session.username = username

        enabled = int((auth.get("2FA") or {}).get("Enabled") or 0)
        if enabled:
            self._settle_second_factor(enabled, totp_code)

        self._session_changed()
        return auth

    def _settle_second_factor(self, enabled: int, code: str) -> None:
        """Submit a one-time code, or explain exactly what is missing."""
        if not enabled & _TOTP:
            self._abandon_partial_session()
            raise TwoFactorRequired(
                "this account's second factor is a security key (FIDO2/U2F), which this "
                "client cannot do — a code from an authenticator app can be added in "
                "Proton's settings as an alternative"
            )
        if not code.strip():
            self._abandon_partial_session()
            raise TwoFactorRequired(
                "this account needs the six-digit code from your authenticator app; "
                "sign in again and pass the code that is showing now"
            )

        try:
            self.post(
                "/auth/v4/2fa",
                json_body={"TwoFactorCode": code.strip().replace(" ", "")},
                _retry=False,
            )
        except APIError as exc:
            self._abandon_partial_session()
            raise TwoFactorRequired(
                f"Proton rejected that code ({exc.message or 'invalid'}). They last about "
                "thirty seconds, so use the one showing now — and check the server clock "
                "if it keeps failing"
            ) from exc

    def _abandon_partial_session(self) -> None:
        """Throw away a session that never got past the second factor.

        Leaving it would list a half-open session as a signed-in device on the
        account, which is confusing and pointless.
        """
        try:
            self.request("DELETE", "/auth/v4", _retry=False)
        except Exception:
            pass  # best effort: the session is useless to us either way
        self.session = Session()

    def refresh(self) -> None:
        payload = self.post(
            "/auth/v4/refresh",
            json_body={
                "UID": self.session.uid,
                "RefreshToken": self.session.refresh_token,
                "ResponseType": "token",
                "GrantType": "refresh_token",
                "RedirectURI": "https://protonmail.ch",
                "State": secrets.token_hex(16),
            },
            authenticated=True,
            _retry=False,
        )
        self.session.access_token = payload["AccessToken"]
        self.session.refresh_token = payload["RefreshToken"]
        self._session_changed()

    def logout(self) -> None:
        """Revoke this session server-side. Proton counts it as a signed-in device."""
        if self.session.authenticated:
            self.request("DELETE", "/auth/v4", _retry=False)
        self.session = Session()
        self._session_changed()
