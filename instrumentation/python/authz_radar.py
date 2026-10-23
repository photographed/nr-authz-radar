"""nr-authz-radar stage S2 for Python (newrelic agent 14.x API).

Sends resource.owner_match and authz.decision (shared/attribute-spec.md) and an HMAC-pseudonymized
enduser.id. Call check_ownership() right after loading a resource by a client-supplied ID.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


class OwnershipError(PermissionError):
    """Raised on a mismatch in enforce mode. Map it to HTTP 403 (or 404)."""


@dataclass
class RequestState:
    """One per request. Keeps owner_match sticky and lets deny win over allow."""
    mismatch: bool = False
    denied: bool = False


def _agent(agent):
    if agent is not None:
        return agent
    import newrelic.agent  # imported lazily so the module works without the agent installed
    return newrelic.agent


def pseudonym(user_id, key: bytes) -> str | None:
    """'u_' + 16 hex chars. Without a key, nothing is sent (a plain hash can be brute-forced)."""
    if not key or user_id is None:
        return None
    return "u_" + hmac.new(key, str(user_id).encode(), hashlib.sha256).hexdigest()[:16]


def set_user(user_id, key: bytes, agent=None) -> None:
    value = pseudonym(user_id, key)
    if value:
        _agent(agent).set_user_id(value)


def check_ownership(owner_id, current_user_id, state: RequestState, *, enforce: bool = True,
                    bypass_scope: str | None = None, agent=None) -> bool:
    """Records the check and returns whether the current user owns the resource.

    enforce=False (observe) lets mismatches through so detection D01 can show real IDORs.
    bypass_scope marks legitimate cross-owner access (e.g. 'admin:read') so D01 excludes it.
    """
    nr = _agent(agent)
    match = current_user_id is not None and str(owner_id) == str(current_user_id)
    if not match:
        state.mismatch = True
    nr.add_custom_attribute("resource.owner_match", not state.mismatch)
    if not match and bypass_scope:
        nr.add_custom_attribute("authz.required_scope", bypass_scope)
    elif not match and enforce:
        state.denied = True
        nr.add_custom_attribute("authz.decision", "deny")
        try:
            raise OwnershipError("ownership check failed")
        except OwnershipError:
            nr.notice_error(expected=True)  # grouped in Errors Inbox, not counted in error rate
            raise
    if not state.denied:
        nr.add_custom_attribute("authz.decision", "allow")
    return match
