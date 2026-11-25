"""Version-pin check shared by the LiteLLM gates.

Each gate is validated against one pinned release (or a small set) and refuses
any other installed version. That stays the default. A release watcher needs to
run the same gate, unchanged, against whatever release it just installed, so
there is one explicit
opt-in: ``ST_ALLOW_ANY_VERSION=1`` in the environment. Under it the gate records
the installed version and runs anyway; the saved run says the pin was overridden.

The opt-in changes nothing about what a gate tests or how it grades.

Standard library only (the gates import this before their own dependencies).
"""

import os
from typing import Dict, Iterable, Mapping, Optional

ALLOW_ENV = "ST_ALLOW_ANY_VERSION"
_TRUE = ("1", "true", "yes", "on")


def allow_any_version(environ: Optional[Mapping[str, str]] = None) -> bool:
    """True only when the opt-in is set to an explicit yes."""
    environ = os.environ if environ is None else environ
    return str(environ.get(ALLOW_ENV, "")).strip().lower() in _TRUE


def check_version_pin(installed: str, accepted: Iterable[str], refusal: str,
                      environ: Optional[Mapping[str, str]] = None) -> Dict[str, object]:
    """Enforce the pin, or record that it was overridden.

    ``accepted`` is the version (or versions) the gate is validated for. If
    ``installed`` is one of them, nothing changes. Otherwise the gate stops with
    ``refusal`` (``SystemExit``) unless the opt-in is set. Returns the record the
    gate saves with its run.
    """
    accepted = sorted(set(accepted))
    matches = installed in accepted
    override = (not matches) and allow_any_version(environ)
    if not matches and not override:
        raise SystemExit(refusal)
    return {"validated_versions": accepted, "installed": installed,
            "matches_pin": matches,
            "override": ALLOW_ENV + "=1" if override else None}
