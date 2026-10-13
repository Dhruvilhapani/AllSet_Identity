"""The seeded policy reproduces app/capabilities.py exactly.

This is the gate that protects production when the engine ships: if any legal
role set resolved to different legacy flags than before, somebody's access
would change on deploy. Every subset of the eight roles is checked, except the
ones holding both presales and sales, which were never legal.
"""

from __future__ import annotations

from itertools import combinations

import pytest

from app import capabilities
from app.permissions.catalogue import seed_snapshot
from app.permissions.payload import build_apps
from app.permissions.snapshot import Snapshot

LEGACY_SERVICES = ('cms', 'broker_tools', 'consultation_agent')


def legal_role_sets():
    for size in range(len(capabilities.ALL_ROLES) + 1):
        for combo in combinations(capabilities.ALL_ROLES, size):
            if {capabilities.PRESALES, capabilities.SALES} <= set(combo):
                continue
            yield sorted(combo)


def legacy_view(apps: dict) -> dict:
    return {
        service: {k: v for k, v in apps[service].items() if k not in ('permissions', 'attributes')}
        for service in LEGACY_SERVICES
    }


@pytest.fixture(scope='module')
def snapshot():
    return Snapshot.from_json(seed_snapshot())


def test_every_legal_role_set_resolves_to_the_old_flags(snapshot):
    role_sets = list(legal_role_sets())
    assert len(role_sets) == 2 ** 8 - 2 ** 6   # 192

    mismatches = []
    for roles in role_sets:
        new = legacy_view(build_apps(snapshot, roles, is_active=True))
        old = capabilities.build_capabilities(roles)
        if new != old:
            mismatches.append((roles, old, new))
    assert not mismatches, mismatches[:3]


def test_a_deactivated_user_resolves_to_the_old_no_access_flags(snapshot):
    for roles in (['admin'], ['tech', 'presales'], []):
        new = legacy_view(build_apps(snapshot, roles, is_active=False))
        assert new == capabilities.build_capabilities(roles, is_active=False)


def test_unknown_roles_grant_nothing(snapshot):
    apps = build_apps(snapshot, ['not_a_role'], is_active=True)
    assert all(not app['access'] for app in apps.values())
