"""The seed catalogue, and the manifest rules shared with the database.

app/permissions/seed/ holds the initial roles, one manifest per service (the
same format a service pushes as its identity-manifest.json), and the grants that
reproduce what each service enforced before this engine existed.
db/005_seed_permissions.sql is generated from these files by
scripts/build_seed_sql.py, and the tests build their snapshot from them, so the
SQL, the tests and the equivalence check all read one source.

The implicit parts of a manifest (every service's `app.use`, every resource's
`all` scope) are added here exactly as identity_apply_manifest adds them in SQL.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SEED_DIR = Path(__file__).parent / 'seed'

APP_RESOURCE = 'app'
USE_ACTION = 'use'
ALL_SCOPE = 'all'

_KEY = re.compile(r'^[a-z][a-z0-9_]{0,62}$')
_SERVICE_KEY = re.compile(r'^[a-z][a-z0-9_]{1,39}$')


class ManifestInvalid(ValueError):
    """A manifest that identity_apply_manifest would refuse."""


def _label(key: str) -> str:
    # Matches SQL's initcap(replace(key, '_', ' ')) for the keys we use.
    return ' '.join(word.capitalize() for word in key.split('_'))


def load_roles() -> list[dict]:
    return json.loads((SEED_DIR / 'roles.json').read_text(encoding='utf-8'))


def load_manifests() -> dict[str, dict]:
    manifests = {}
    for path in sorted((SEED_DIR / 'services').glob('*.json')):
        manifest = json.loads(path.read_text(encoding='utf-8'))
        validate_manifest(manifest)
        manifests[manifest['service']] = manifest
    return manifests


def load_grants() -> dict[str, dict]:
    grants = json.loads((SEED_DIR / 'grants.json').read_text(encoding='utf-8'))
    grants.pop('_comment', None)
    return grants


def validate_manifest(manifest: object) -> None:
    """The checks identity_apply_manifest makes, run before a round trip."""
    if not isinstance(manifest, dict):
        raise ManifestInvalid('manifest must be an object')
    service = manifest.get('service')
    if not isinstance(service, str) or not _SERVICE_KEY.match(service):
        raise ManifestInvalid('manifest.service must be a lowercase key')
    resources = manifest.get('resources', {})
    if not isinstance(resources, dict):
        raise ManifestInvalid('manifest.resources must be an object')
    if APP_RESOURCE in resources:
        raise ManifestInvalid('app is implicit; do not declare it')
    for key, resource in resources.items():
        if not _KEY.match(key):
            raise ManifestInvalid(f'resource key {key!r} must be lowercase letters, digits and _')
        if not isinstance(resource, dict):
            raise ManifestInvalid(f'resource {key} must be an object')
        actions = resource.get('actions')
        if not isinstance(actions, list) or not actions:
            raise ManifestInvalid(f'resource {key} needs a non-empty actions list')
        for action in actions:
            if not isinstance(action, str) or not _KEY.match(action):
                raise ManifestInvalid(f'resource {key}: action {action!r} is not a valid key')
        scopes = resource.get('scopes', {})
        if not isinstance(scopes, dict):
            raise ManifestInvalid(f'resource {key}: scopes must be an object')
        if ALL_SCOPE in scopes:
            raise ManifestInvalid(f'resource {key}: the all scope is implicit')
        for scope in scopes:
            if not _KEY.match(scope):
                raise ManifestInvalid(f'resource {key}: scope {scope!r} is not a valid key')
    attributes = manifest.get('attributes', {})
    if not isinstance(attributes, dict):
        raise ManifestInvalid('manifest.attributes must be an object')
    for key, attribute in attributes.items():
        if not _KEY.match(key):
            raise ManifestInvalid(f'attribute key {key!r} is not a valid key')
        if not isinstance(attribute, dict) or attribute.get('kind', 'enum') != 'enum':
            raise ManifestInvalid(f'attribute {key} must be an enum')
        options = attribute.get('options')
        if not isinstance(options, list) or not options or not all(isinstance(o, str) for o in options):
            raise ManifestInvalid(f'attribute {key} needs a non-empty list of string options')


def catalogue_from_manifest(manifest: dict) -> dict:
    """A manifest as identity_policy_snapshot() reports the service, before any
    grant: implicit app.use first, an all scope on every resource."""
    resources = {APP_RESOURCE: {'label': 'The app', 'actions': [USE_ACTION]}}
    resources.update(manifest.get('resources', {}))
    return {
        'key': manifest['service'],
        'name': manifest.get('name', manifest['service']),
        'description': manifest.get('description', ''),
        'is_system': bool(manifest.get('is_system', False)),
        'is_active': True,
        'grants_version': 0,
        'resources': [
            {
                'key': key,
                'label': resource.get('label', _label(key)),
                'description': resource.get('description', ''),
                'retired': False,
                'actions': [
                    {'key': action, 'label': _label(action), 'retired': False}
                    for action in resource['actions']
                ],
                'scopes': [{'key': ALL_SCOPE, 'label': 'All', 'is_all': True, 'retired': False}] + [
                    {'key': scope, 'label': label, 'is_all': False, 'retired': False}
                    for scope, label in resource.get('scopes', {}).items()
                ],
            }
            for key, resource in resources.items()
        ],
        'attributes': [
            {'key': key, 'label': attribute.get('label', _label(key)), 'kind': 'enum',
             'options': list(attribute['options']), 'retired': False}
            for key, attribute in manifest.get('attributes', {}).items()
        ],
    }


def expand_grants(service_grants: dict, catalogue: dict) -> dict[str, dict[str, dict[str, list[str]]]]:
    """Expand "*" actions and check every name against the catalogue.

    Returns role -> resource -> action -> [scopes], the shape
    identity_set_service_grants takes.
    """
    resources = {r['key']: r for r in catalogue['resources']}
    expanded: dict[str, dict[str, dict[str, list[str]]]] = {}
    for role, by_resource in service_grants.items():
        for resource_key, by_action in by_resource.items():
            resource = resources.get(resource_key)
            if resource is None:
                raise ValueError(f'{catalogue["key"]}: {role} names unknown resource {resource_key}')
            actions = [a['key'] for a in resource['actions']]
            scopes = {s['key'] for s in resource['scopes']}
            for action, granted in by_action.items():
                targets = actions if action == '*' else [action]
                if action != '*' and action not in actions:
                    raise ValueError(f'{catalogue["key"]}: {resource_key} has no action {action}')
                unknown = set(granted) - scopes
                if unknown:
                    raise ValueError(f'{catalogue["key"]}: {resource_key} has no scope {sorted(unknown)}')
                for target in targets:
                    slot = expanded.setdefault(role, {}).setdefault(resource_key, {}).setdefault(target, [])
                    for scope in granted:
                        if scope not in slot:
                            slot.append(scope)
    return expanded


def seed_snapshot(users: list[dict] | None = None) -> dict:
    """The seed as identity_policy_snapshot() would return it after
    db/004 and db/005, with the given roster."""
    manifests = load_manifests()
    grants = load_grants()
    services = [catalogue_from_manifest(m) for m in manifests.values()]
    flat = []
    for service in services:
        for role, by_resource in expand_grants(grants.get(service['key'], {}), service).items():
            for resource, by_action in by_resource.items():
                for action, scopes in by_action.items():
                    for scope in scopes:
                        flat.append({'role': role, 'service': service['key'], 'resource': resource,
                                     'action': action, 'scope': scope})
    return {
        'services': services,
        'roles': [
            {'key': r['key'], 'label': r['label'], 'description': r.get('description', ''),
             'priority': r['priority'], 'is_superuser': bool(r.get('is_superuser', False)),
             'exclusive_group': r.get('exclusive_group')}
            for r in load_roles()
        ],
        'grants': flat,
        'users': users or [],
        'service_keys': [],
    }
