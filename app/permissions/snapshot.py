"""The policy snapshot: everything introspect needs, held in memory.

Built from identity_policy_snapshot() (db/004_permissions.sql). Resolution here
is pure CPU: a role set goes in, per-service access, primary role and granted
scopes come out, memoised per role set because there are only a handful.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.permissions.catalogue import ALL_SCOPE, APP_RESOURCE, USE_ACTION

# A user missing from a snapshot that started loading this long after their
# token was issued has been deleted. The margin absorbs clock differences
# between this instance and Supabase, which stamps iat.
DELETED_USER_GRACE_SECONDS = 60


class InvalidRoles(ValueError):
    """A role set identity_set_user_roles would refuse."""


@dataclass(frozen=True)
class Role:
    key: str
    label: str
    description: str
    priority: int
    is_superuser: bool
    exclusive_group: str | None


@dataclass(frozen=True)
class Resource:
    key: str
    label: str
    retired: bool
    actions: tuple[str, ...]          # live actions only, in manifest order
    scopes: tuple[str, ...]           # live scopes only, 'all' first


@dataclass(frozen=True)
class Service:
    key: str
    name: str
    is_system: bool
    is_active: bool
    grants_version: int
    resources: dict[str, Resource]    # live resources only
    attributes: dict[str, dict]       # live attributes only: key -> {label, kind, options}


@dataclass(frozen=True)
class ResolvedApp:
    """One service's answer for one role set."""

    access: bool
    primary_role: str | None
    # resource -> action -> scopes as granted, before collapsing to ['all'].
    # Kept because the legacy flags need to know which named scopes a role set
    # was granted even when another role also grants 'all'.
    raw: dict[str, dict[str, frozenset[str]]]

    @property
    def permissions(self) -> dict[str, dict[str, list[str]]]:
        """What consumers read: an absent action is denied; 'all' wins."""
        return {
            resource: {
                action: [ALL_SCOPE] if ALL_SCOPE in scopes else sorted(scopes)
                for action, scopes in sorted(actions.items())
            }
            for resource, actions in sorted(self.raw.items())
            if resource != APP_RESOURCE
        }

    def has(self, resource: str, action: str) -> bool:
        return bool(self.raw.get(resource, {}).get(action))

    def scopes(self, resource: str, action: str) -> frozenset[str]:
        return self.raw.get(resource, {}).get(action, frozenset())


NO_ACCESS = ResolvedApp(access=False, primary_role=None, raw={})


@dataclass
class Snapshot:
    services: dict[str, Service]
    roles: dict[str, Role]
    # role -> service -> [(resource, action, scope)], live items only
    grants: dict[str, dict[str, list[tuple[str, str, str]]]]
    users: dict[str, dict]
    service_key_hashes: dict[str, str]       # sha256 hex -> service key
    # time.time() when the load STARTED, compared with token iat
    loaded_at: float = 0.0
    # time.monotonic() when it finished, for the cache's TTL
    fetched_at: float = field(default_factory=time.monotonic)
    # The document as loaded, retired items included, for the admin views.
    raw: dict = field(default_factory=dict, repr=False)
    _memo: dict = field(default_factory=dict, repr=False)

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_json(cls, data: dict, *, loaded_at: float = 0.0) -> Snapshot:
        services: dict[str, Service] = {}
        live: set[tuple[str, str, str, str]] = set()   # service, resource, action, scope
        for svc in data.get('services') or []:
            resources = {}
            for res in svc.get('resources') or []:
                if res.get('retired'):
                    continue
                actions = tuple(a['key'] for a in res.get('actions') or [] if not a.get('retired'))
                scopes = tuple(s['key'] for s in res.get('scopes') or [] if not s.get('retired'))
                resources[res['key']] = Resource(
                    key=res['key'], label=res.get('label', res['key']), retired=False,
                    actions=actions, scopes=scopes,
                )
                for action in actions:
                    for scope in scopes:
                        live.add((svc['key'], res['key'], action, scope))
            services[svc['key']] = Service(
                key=svc['key'],
                name=svc.get('name', svc['key']),
                is_system=bool(svc.get('is_system')),
                is_active=bool(svc.get('is_active', True)),
                grants_version=int(svc.get('grants_version') or 0),
                resources=resources,
                attributes={
                    a['key']: {'label': a.get('label', a['key']), 'kind': a.get('kind', 'enum'),
                               'options': list(a.get('options') or [])}
                    for a in svc.get('attributes') or [] if not a.get('retired')
                },
            )

        roles = {
            r['key']: Role(
                key=r['key'], label=r.get('label', r['key']), description=r.get('description', ''),
                priority=int(r.get('priority', 100)), is_superuser=bool(r.get('is_superuser')),
                exclusive_group=r.get('exclusive_group'),
            )
            for r in data.get('roles') or []
        }

        grants: dict[str, dict[str, list[tuple[str, str, str]]]] = {}
        for g in data.get('grants') or []:
            if (g['service'], g['resource'], g['action'], g['scope']) not in live:
                continue    # on a retired item, or one this snapshot does not know
            grants.setdefault(g['role'], {}).setdefault(g['service'], []).append(
                (g['resource'], g['action'], g['scope'])
            )

        users = {str(u['user_id']): u for u in data.get('users') or []}
        keys = {k['key_hash']: k['service'] for k in data.get('service_keys') or []}
        return cls(services=services, roles=roles, grants=grants, users=users,
                   service_key_hashes=keys, loaded_at=loaded_at, raw=data)

    # ── Resolution ───────────────────────────────────────────────────────────

    def known_roles(self, roles: Iterable[str]) -> list[str]:
        """Roles this snapshot knows, sorted. Unknown names grant nothing."""
        return sorted({r for r in roles if r in self.roles})

    def validate_roles(self, roles: object) -> list[str]:
        """Normalise a role set, or raise InvalidRoles with the same message
        identity_set_user_roles would give. Lets the API refuse before it
        creates anything; the database enforces the same rules regardless."""
        if not isinstance(roles, (list, tuple, set, frozenset)):
            raise InvalidRoles('roles must be a list')
        keys: list[str] = []
        for role in roles:
            if not isinstance(role, str):
                raise InvalidRoles(f'role must be a string, got {type(role).__name__}')
            key = role.strip().lower()
            if key and key not in keys:
                keys.append(key)
        unknown = sorted(k for k in keys if k not in self.roles)
        if unknown:
            raise InvalidRoles('unknown role: ' + ', '.join(unknown))
        groups: dict[str, list[str]] = {}
        for key in keys:
            group = self.roles[key].exclusive_group
            if group:
                groups.setdefault(group, []).append(key)
        for group, held in sorted(groups.items()):
            if len(held) > 1:
                members = '/'.join(sorted(r.key for r in self.roles.values() if r.exclusive_group == group))
                got = ', '.join(sorted(held))
                raise InvalidRoles(f'a user may hold at most one of {members}, got: {got}')
        return sorted(keys)

    def exclusive_groups(self) -> list[list[str]]:
        groups: dict[str, list[str]] = {}
        for role in self.roles.values():
            if role.exclusive_group:
                groups.setdefault(role.exclusive_group, []).append(role.key)
        return [sorted(members) for _, members in sorted(groups.items())]

    def resolve(self, roles: Iterable[str]) -> dict[str, ResolvedApp]:
        held = frozenset(r for r in roles if r in self.roles)
        cached = self._memo.get(held)
        if cached is not None:
            return cached

        superusers = {r for r in held if self.roles[r].is_superuser}
        result: dict[str, ResolvedApp] = {}
        for svc in self.services.values():
            if not svc.is_active:
                result[svc.key] = NO_ACCESS
                continue

            raw: dict[str, dict[str, set[str]]] = {}
            users_app: set[str] = set(superusers)
            if superusers:
                for res in svc.resources.values():
                    for action in res.actions:
                        raw.setdefault(res.key, {}).setdefault(action, set()).add(ALL_SCOPE)
            for role in held:
                for resource, action, scope in self.grants.get(role, {}).get(svc.key, ()):
                    raw.setdefault(resource, {}).setdefault(action, set()).add(scope)
                    if resource == APP_RESOURCE and action == USE_ACTION:
                        users_app.add(role)

            primary = min(users_app, key=lambda r: (self.roles[r].priority, r)) if users_app else None
            result[svc.key] = ResolvedApp(
                access=bool(raw.get(APP_RESOURCE, {}).get(USE_ACTION)),
                primary_role=primary,
                raw={res: {a: frozenset(s) for a, s in acts.items()} for res, acts in raw.items()},
            )

        self._memo[held] = result
        return result

    # ── Roster ───────────────────────────────────────────────────────────────

    def roster_entry(self, user_id: str, *, token_issued_at: float | None) -> tuple[dict | None, bool]:
        """(entry, deleted). `deleted` is true when this snapshot started loading
        well after the token was issued and still has no such user."""
        entry = self.users.get(user_id)
        if entry is not None:
            return entry, False
        deleted = bool(
            self.loaded_at and token_issued_at
            and self.loaded_at > token_issued_at + DELETED_USER_GRACE_SECONDS
        )
        return None, deleted

    # ── Service keys ─────────────────────────────────────────────────────────

    def service_for_key(self, presented: str) -> str | None:
        """The service a database-held key belongs to, or None."""
        return self.service_key_hashes.get(hashlib.sha256(presented.encode()).hexdigest())
