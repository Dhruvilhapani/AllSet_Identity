"""Who a token belongs to, and the payload /v1/introspect and /v1/auth/me return.

The roster in the snapshot wins over the token's claims, which is what makes a
role change or deactivation take effect in about a minute rather than when the
7-day token expires. The claims are used only for a user created after the
snapshot was loaded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core import security
from app.permissions.compat import legacy_flags
from app.permissions.snapshot import NO_ACCESS, Snapshot


@dataclass(frozen=True)
class Identity:
    user_id: str
    email: str
    roles: list[str]
    is_active: bool
    full_name: str
    phone: str
    attributes: dict[str, dict[str, str]] = field(default_factory=dict)


def identity_from_claims(snapshot: Snapshot, claims: dict) -> Identity:
    user_id, email, token_roles, token_active, full_name, phone = security.claims_to_identity(claims)
    entry, deleted = snapshot.roster_entry(user_id, token_issued_at=claims.get('iat'))

    if entry is not None:
        return Identity(
            user_id=user_id,
            email=str(entry.get('email') or email),
            roles=snapshot.known_roles(entry.get('roles') or []),
            is_active=bool(entry.get('is_active')),
            full_name=entry.get('full_name') or '',
            phone=entry.get('phone') or '',
            attributes=entry.get('attributes') or {},
        )
    if deleted:
        return Identity(user_id=user_id, email=email, roles=[], is_active=False,
                        full_name=full_name, phone=phone)
    return Identity(
        user_id=user_id, email=email, roles=snapshot.known_roles(token_roles),
        is_active=token_active, full_name=full_name, phone=phone,
    )


def build_apps(snapshot: Snapshot, roles: list[str], *, is_active: bool,
               attributes: dict[str, dict[str, str]] | None = None) -> dict:
    """Per-service blocks: access, primary_role, permissions, attributes, plus
    the legacy flags for the services that had them."""
    resolved = snapshot.resolve(roles) if is_active else {}
    apps = {}
    for key in snapshot.services:
        app = resolved.get(key, NO_ACCESS)
        apps[key] = {
            'access': app.access,
            'primary_role': app.primary_role,
            'permissions': app.permissions,
            'attributes': dict((attributes or {}).get(key, {})) if is_active else {},
            **legacy_flags(key, resolved),
        }
    return apps


def build_payload(snapshot: Snapshot, identity: Identity) -> dict:
    """The shape shared by /v1/introspect and /v1/auth/me, so a consumer's
    server-side checks and its UI gating can never drift apart."""
    roles = identity.roles
    return {
        'active': bool(identity.is_active),
        'user_id': identity.user_id,
        'email': identity.email,
        'full_name': identity.full_name,
        # As stored on the profile, not normalised. Consultation Agent matches
        # it against its brokers' phones on the last 10 digits.
        'phone': identity.phone,
        'roles': roles,
        'role_labels': [snapshot.roles[r].label for r in roles],
        'is_active': bool(identity.is_active),
        'apps': build_apps(snapshot, roles, is_active=identity.is_active, attributes=identity.attributes),
    }


def inactive_apps(snapshot: Snapshot) -> dict:
    return build_apps(snapshot, [], is_active=False)
