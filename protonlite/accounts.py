"""Several Proton accounts side by side.

One session file per account, in a directory, with the address recorded inside
each one. Which account a request means is resolved by that address, never
guessed: with more than one signed in and nothing said, the tools ask instead
of picking. Mailing the wrong person from the wrong account is not a mistake
worth being convenient about.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ProtonError, SessionExpired

#: Where the sessions live, overridable for tests and odd layouts.
ROOT_ENV = "PROTONLITE_HOME"

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def default_root() -> Path:
    return Path(os.environ.get(ROOT_ENV) or Path.home() / ".config" / "protonlite")


def _slug(address: str) -> str:
    """A filename for an address. Cosmetic: the address itself lives in the file."""
    return _SAFE.sub("-", address.strip().lower()).strip("-") or "account"


@dataclass(frozen=True)
class Account:
    address: str
    path: Path

    @property
    def label(self) -> str:
        return self.address or self.path.stem


class AccountStore:
    """The set of accounts signed in on this machine."""

    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        self.root = Path(root) if root else default_root()

    # -- layout -----------------------------------------------------------

    @property
    def sessions_dir(self) -> Path:
        return self.root / "sessions"

    @property
    def legacy_session(self) -> Path:
        return self.root / "session.json"

    def path_for(self, address: str) -> Path:
        return self.sessions_dir / f"{_slug(address)}.json"

    def migrate_legacy(self) -> Account | None:
        """Move a single-account session into the per-account layout, once.

        Early versions kept one ``session.json``. Rather than carry two code
        paths forever, the file is moved the first time the store is read.
        """
        if not self.legacy_session.exists():
            return None
        try:
            address = json.loads(self.legacy_session.read_text()).get("username", "")
        except (OSError, ValueError):
            address = ""
        target = self.path_for(address or "default")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():  # a newer session wins; leave the old file alone
            return None
        os.replace(self.legacy_session, target)
        return Account(address=address, path=target)

    # -- reading ----------------------------------------------------------

    def list(self) -> list[Account]:
        self.migrate_legacy()
        if not self.sessions_dir.is_dir():
            return []
        accounts: list[Account] = []
        for path in sorted(self.sessions_dir.glob("*.json")):
            try:
                address = json.loads(path.read_text()).get("username", "")
            except (OSError, ValueError):
                continue  # a half-written file is not an account
            accounts.append(Account(address=address, path=path))
        return accounts

    def resolve(self, selector: str = "") -> Account:
        """Find the account a request means, or explain why it cannot.

        An empty selector is fine with exactly one account signed in and an
        error with several -- that ambiguity is the caller's to settle.
        """
        accounts = self.list()
        if not accounts:
            raise SessionExpired(
                "no Proton account is signed in yet; sign in before reading mail"
            )

        selector = selector.strip().lower()
        if not selector:
            if len(accounts) == 1:
                return accounts[0]
            names = ", ".join(a.label for a in accounts)
            raise ProtonError(
                f"there are {len(accounts)} accounts signed in ({names}); say which one"
            )

        exact = [a for a in accounts if a.address.lower() == selector]
        if exact:
            return exact[0]

        # A local part or any distinctive fragment is enough when it picks out
        # exactly one account; anything vaguer is reported rather than guessed.
        partial = [a for a in accounts if selector in a.address.lower()]
        if len(partial) == 1:
            return partial[0]
        if partial:
            names = ", ".join(a.label for a in partial)
            raise ProtonError(f"{selector!r} matches several accounts ({names}); be exact")

        names = ", ".join(a.label for a in accounts)
        raise ProtonError(f"no account matches {selector!r}; signed in: {names}")
