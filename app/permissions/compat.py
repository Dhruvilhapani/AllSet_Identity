"""The pre-engine capability flags, derived from resolved permissions.

Consumers still read apps.cms.can_* and apps.broker_tools.unrestricted_leads /
own_* until their own migration PRs ship. These flags are derived from
`permissions` so that both shapes always agree; tests/
test_permissions_equivalence.py proves they equal what app/capabilities.py
returned, for every legal role set. Delete this module in the cleanup PR, once
no consumer reads the flags (docs/ARCHITECTURE_ADMIN.md, Rollout).
"""

from __future__ import annotations

from app.permissions.catalogue import ALL_SCOPE
from app.permissions.snapshot import NO_ACCESS, ResolvedApp


def _cms(cms: ResolvedApp, identity: ResolvedApp) -> dict:
    return {
        'can_add_property': cms.has('property', 'create'),
        'can_edit_property': cms.has('property', 'update'),
        'can_publish': cms.has('property', 'publish'),
        'can_upload_media': cms.has('media', 'create'),
        'can_edit_seo': cms.has('property', 'update_seo'),
        'can_delete_property': cms.has('property', 'delete'),
        # User management moved to the Identity console.
        'can_manage_users': identity.has('console', 'use'),
    }


def _broker_tools(bt: ResolvedApp) -> dict:
    lead_read = bt.scopes('lead', 'read')
    return {
        'unrestricted_leads': ALL_SCOPE in lead_read,
        # Named scopes as granted, even alongside 'all': the old flags were
        # "holds the presales role", independent of being unrestricted.
        'own_presales': 'own_presales' in lead_read,
        'own_sales': 'own_sales' in lead_read,
    }


def legacy_flags(service: str, resolved: dict[str, ResolvedApp]) -> dict:
    """The extra keys a legacy app block carried, or {} for newer services."""
    if service == 'cms':
        return _cms(resolved.get('cms', NO_ACCESS), resolved.get('identity', NO_ACCESS))
    if service == 'broker_tools':
        return _broker_tools(resolved.get('broker_tools', NO_ACCESS))
    return {}
