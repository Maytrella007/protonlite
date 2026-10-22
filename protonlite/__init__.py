"""A small, unofficial Python client for Proton Mail, Calendar, Contacts and Drive.

The protocol work is a port of Proton's own MIT Go libraries; see
THIRD-PARTY-NOTICES.md. Nothing here is derived from GPL sources.

This project is not affiliated with Proton AG. It talks to a private, undocumented
API and is provided as-is, for use on accounts you own.
"""

from .client import Contact, Message, MessageSummary, ProtonMail
from .errors import (
    APIError,
    AuthError,
    HumanVerificationRequired,
    ProtonError,
    SessionExpired,
    TwoFactorRequired,
)

__version__ = "0.1.1"

__all__ = [
    "ProtonMail",
    "Message",
    "MessageSummary",
    "Contact",
    "APIError",
    "AuthError",
    "HumanVerificationRequired",
    "ProtonError",
    "SessionExpired",
    "TwoFactorRequired",
    "__version__",
]
