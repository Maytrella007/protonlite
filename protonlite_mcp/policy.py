"""The send policy the MCP server enforces: a recipient allowlist and a
"confirm before sending" rule.

The policy is kept in a small JSON file so it survives across runs. Two
environment variables act as a hard ceiling a human sets out of band, which the
tools cannot loosen:

- ``PROTON_ALLOWED_RECIPIENTS`` -- comma-separated addresses or globs. When set,
  a send is refused unless every recipient matches, no matter what the mutable
  allowlist says, and the allowlist tool cannot open sending to everyone.
- ``PROTON_REQUIRE_SEND_CONFIRMATION`` -- when truthy, confirmation is forced on
  and the tool cannot turn it off.

Without those env vars the tools are freely mutable: convenient, but an agent
can change them, so they are advisory rather than a hard boundary. The env vars
are what make the boundary hard.
"""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path

_DEFAULT_PATH = Path.home() / ".config" / "protonlite" / "mcp_policy.json"
_TRUTHY = {"1", "true", "yes", "on"}
_UNSET = object()


def _path() -> Path:
    return Path(os.environ.get("PROTONLITE_MCP_POLICY") or _DEFAULT_PATH)


def env_ceiling() -> list[str] | None:
    """The hard recipient ceiling from the env, or None when unset."""
    raw = os.environ.get("PROTON_ALLOWED_RECIPIENTS", "").strip()
    if not raw:
        return None
    return [p.strip() for p in raw.split(",") if p.strip()]


def env_forces_confirmation() -> bool:
    return os.environ.get("PROTON_REQUIRE_SEND_CONFIRMATION", "").strip().lower() in _TRUTHY


def load() -> dict:
    """Load the policy, filling defaults from the env on first use."""
    path = _path()
    data: dict = {}
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except (ValueError, OSError):
            data = {}
    if "allowed" not in data:
        ceiling = env_ceiling()
        # Default to open so send keeps working when no policy is set; the env
        # ceiling, if any, still applies on top at send time.
        data["allowed"] = list(ceiling) if ceiling is not None else ["*"]
    if "require_confirmation" not in data:
        data["require_confirmation"] = env_forces_confirmation()
    return data


def save(data: dict) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _matches(addr: str, patterns: list[str]) -> bool:
    a = addr.strip().lower()
    return any(fnmatch.fnmatch(a, pat.strip().lower()) for pat in patterns if pat.strip())


def is_open(allowed: list[str]) -> bool:
    return "*" in [p.strip() for p in allowed]


def locked_ceiling(data: dict) -> list[str] | None:
    """The hard recipient ceiling set from the CLI (the `locked` section), or None."""
    ceiling = (data.get("locked") or {}).get("ceiling")
    return ceiling or None


def locked_requires_confirmation(data: dict) -> bool:
    return bool((data.get("locked") or {}).get("require_confirmation"))


def classify_blocked(recipients: list[str], data: dict) -> tuple[list[str], list[str]]:
    """Split the blocked recipients by why they are blocked: those outside a hard
    ceiling (the env var or the CLI-set `locked` ceiling, which no tool can lift)
    and those only off the mutable allowlist (which `email_allow` can permit)."""
    env_c = env_ceiling()
    lock_c = locked_ceiling(data)
    allowed = data.get("allowed", ["*"])
    ceiling_blocked, allow_blocked = [], []
    for r in recipients:
        if not r.strip():
            continue
        if env_c is not None and not _matches(r, env_c):
            ceiling_blocked.append(r)
        elif lock_c is not None and not _matches(r, lock_c):
            ceiling_blocked.append(r)
        elif not _matches(r, allowed):
            allow_blocked.append(r)
    return ceiling_blocked, allow_blocked


def disallowed(recipients: list[str], data: dict) -> list[str]:
    """Every recipient that may NOT be emailed (ceiling or allowlist), as one list."""
    ceiling_blocked, allow_blocked = classify_blocked(recipients, data)
    return ceiling_blocked + allow_blocked


def soft_confirmation(data: dict) -> bool:
    """The mutable confirm rule an agent can toggle (two-step send)."""
    return bool(data.get("require_confirmation"))


def hard_confirmation(data: dict) -> bool:
    """Confirmation enforced out of band (env var or the CLI-set `locked`
    section). When this is on, the agent cannot send at all: a person sends from
    the CLI. An agent cannot bypass it with the `confirm` argument."""
    return env_forces_confirmation() or locked_requires_confirmation(data)


# -- setters the CLI uses to write the human-only parts of the policy ----------


def set_allowed(recipients: list[str]) -> dict:
    data = load()
    data["allowed"] = [r.strip() for r in recipients if r.strip()]
    save(data)
    return data


def set_soft_confirmation(required: bool) -> dict:
    data = load()
    data["require_confirmation"] = bool(required)
    save(data)
    return data


def set_locked(*, ceiling=_UNSET, require_confirmation=_UNSET) -> dict:
    data = load()
    locked = data.setdefault("locked", {})
    if ceiling is not _UNSET:
        locked["ceiling"] = [c.strip() for c in ceiling if c.strip()] if ceiling else None
    if require_confirmation is not _UNSET:
        locked["require_confirmation"] = bool(require_confirmation)
    save(data)
    return data
