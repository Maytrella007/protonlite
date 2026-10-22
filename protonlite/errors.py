"""Errors worth telling apart, because each one needs a different fix."""

from __future__ import annotations


class ProtonError(Exception):
    """Base class for everything this package raises."""


class AuthError(ProtonError):
    """The credentials were rejected."""


class HumanVerificationRequired(ProtonError):
    """Proton wants verification before it will let this login through.

    Expect it when logging in from a datacenter address. Proton hands over a
    verification token and the address of a page where **a person** completes
    the check; sending that same token back with the login is what gets
    through. Nothing here attempts the check itself -- there is deliberately no
    solver in this package, which is also what keeps a computer-vision stack
    out of a mail client's dependencies.
    """

    def __init__(
        self,
        message: str,
        *,
        token: str = "",
        methods: list[str] | None = None,
        web_url: str = "",
        expires_at: int | None = None,
    ) -> None:
        super().__init__(message)
        self.token = token
        self.methods = methods or []
        self.web_url = web_url
        self.expires_at = expires_at


class TwoFactorRequired(ProtonError):
    """The account has 2FA enabled and a code is needed."""


class SessionExpired(ProtonError):
    """The stored tokens are no longer valid; log in again."""


class APIError(ProtonError):
    """The API answered with an error payload."""

    def __init__(self, status: int, code: int | None, message: str) -> None:
        super().__init__(f"HTTP {status} (code {code}): {message}")
        self.status = status
        self.code = code
        self.message = message
