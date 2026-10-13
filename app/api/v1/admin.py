"""Administration: users, roles, services, permissions, keys, audit.

Restricted to holders of identity.console.use (admin, as superuser, and tech).
These are the operations that need the service-role key, which is the reason
this service exists as a separate deployable: the key can mint a session for any
user, so it must live in exactly one place and never in a browser bundle. The
admin console at /admin is the main client; scripts/manage_users.py is the other.

Writes go through the SQL functions in db/004 (app/policy_db.py), so each change
and its audit row commit together. After every write this instance reloads its
policy snapshot at once; other instances pick it up within
POLICY_CACHE_TTL_SECONDS. Reads that an admin acts on reload first, so the
console never shows a stale matrix.
"""

from __future__ import annotations

import hashlib
import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, EmailStr, Field

from app import policy_db, profiles, supabase_client
from app.api.deps import Caller, require_global_admin
from app.permissions import cache
from app.permissions.catalogue import APP_RESOURCE
from app.permissions.payload import build_apps
from app.permissions.snapshot import InvalidRoles, Snapshot

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix='/admin',
    tags=['admin'],
    dependencies=[Depends(require_global_admin)],
)


# ── Request bodies ───────────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(default='', max_length=200)
    phone: str = Field(default='', max_length=32)
    roles: list[str] = Field(default_factory=list)


class UpdateProfileRequest(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, max_length=32)


class UpdateRolesRequest(BaseModel):
    roles: list[str]


class UpdateStatusRequest(BaseModel):
    is_active: bool


class SetPasswordRequest(BaseModel):
    # Same floor as /v1/auth/password/change, so an admin-set password cannot be
    # weaker than one the owner would be allowed to choose themselves.
    new_password: str = Field(min_length=10, max_length=256)


class SetAttributesRequest(BaseModel):
    # An empty string clears an attribute.
    attributes: dict[str, str]


class CreateRoleRequest(BaseModel):
    key: str = Field(pattern=r'^[a-z][a-z0-9_]{1,39}$')
    label: str = Field(min_length=1, max_length=80)
    description: str = Field(default='', max_length=500)
    priority: int = Field(default=100, ge=0, le=10000)
    exclusive_group: str | None = Field(default=None, pattern=r'^[a-z][a-z0-9_]{0,39}$')


class UpdateRoleRequest(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    priority: int | None = Field(default=None, ge=0, le=10000)
    # Send "" to take the role out of its group.
    exclusive_group: str | None = Field(default=None, pattern=r'^([a-z][a-z0-9_]{0,39})?$')


class CreateServiceRequest(BaseModel):
    key: str = Field(pattern=r'^[a-z][a-z0-9_]{1,39}$')
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default='', max_length=500)


class UpdateServiceRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    is_active: bool | None = None


class SetGrantsRequest(BaseModel):
    # role -> resource -> action -> [scopes], for this service only.
    grants: dict[str, dict[str, dict[str, list[str]]]]


class CreateKeyRequest(BaseModel):
    label: str = Field(default='', max_length=120)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _fresh() -> Snapshot:
    """A snapshot reloaded now: what an admin is about to act on must not be
    up to 30 s stale."""
    return cache.refresh()


def _validated(snapshot: Snapshot, roles: list[str]) -> list[str]:
    try:
        return snapshot.validate_roles(roles)
    except InvalidRoles as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


def _roster_roles(snapshot: Snapshot, profile: dict) -> list[str]:
    entry = snapshot.users.get(str(profile['user_id']))
    roles = entry['roles'] if entry is not None else (profile.get('roles') or [])
    return snapshot.known_roles(roles)


def _profile_response(snapshot: Snapshot, profile: dict) -> dict:
    roles = _roster_roles(snapshot, profile)
    entry = snapshot.users.get(str(profile['user_id'])) or {}
    attributes = entry.get('attributes') or {}
    is_active = profile.get('is_active', True)
    return {
        'user_id': profile['user_id'],
        'email': profile['email'],
        'full_name': profile.get('full_name', ''),
        'phone': profile.get('phone', ''),
        'roles': roles,
        'role_labels': [snapshot.roles[role].label for role in roles],
        'attributes': attributes,
        'is_active': is_active,
        'legacy_migrated_at': profile.get('legacy_migrated_at'),
        'created_at': profile.get('created_at'),
        'apps': build_apps(snapshot, roles, is_active=is_active, attributes=attributes),
    }


def _get_profile(user_id: str) -> dict:
    profile = profiles.get_by_user_id(user_id)
    if profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'user not found')
    return profile


def _active_superusers(snapshot: Snapshot) -> set[str]:
    return {
        user_id for user_id, entry in snapshot.users.items()
        if entry.get('is_active') and any(
            snapshot.roles[r].is_superuser for r in entry.get('roles') or [] if r in snapshot.roles
        )
    }


def _service(snapshot: Snapshot, key: str) -> dict:
    for service in snapshot.raw.get('services') or []:
        if service['key'] == key:
            return service
    raise HTTPException(status.HTTP_404_NOT_FOUND, 'service not found')


def _grants_of(snapshot: Snapshot, service_key: str) -> dict:
    """role -> resource -> action -> [scopes] on live items, as the console edits it."""
    grants: dict[str, dict[str, dict[str, list[str]]]] = {}
    for role, by_service in snapshot.grants.items():
        for resource, action, scope in by_service.get(service_key, ()):
            slot = grants.setdefault(role, {}).setdefault(resource, {}).setdefault(action, [])
            slot.append(scope)
    for by_resource in grants.values():
        for by_action in by_resource.values():
            for action, scopes in by_action.items():
                by_action[action] = sorted(scopes)
    return grants


# ── Users ────────────────────────────────────────────────────────────────────

@router.get('/users')
def list_users(
    role: str | None = Query(default=None, description='only users holding this role'),
    service: str | None = Query(default=None, description='only users with access to this service'),
    active: bool | None = Query(default=None),
) -> dict:
    snapshot = _fresh()
    users = [_profile_response(snapshot, profile) for profile in profiles.list_all()]
    if role:
        users = [u for u in users if role in u['roles']]
    if service:
        users = [u for u in users if u['apps'].get(service, {}).get('access')]
    if active is not None:
        users = [u for u in users if u['is_active'] is active]
    return {'users': users}


@router.post('/users', status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest, caller: Caller = Depends(require_global_admin)
) -> dict:
    """Provision an account and email a set-password link.

    No password is set here: the invitee chooses their own via the recovery
    email. This replaces the CMS's invite flow, which generated a random
    password and then never emailed or returned it, leaving invited users unable
    to log in at all.
    """
    email = payload.email.strip().lower()
    snapshot = _fresh()
    roles = _validated(snapshot, payload.roles)

    if profiles.get_by_email(email) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, 'a user with that email already exists')

    existing = supabase_client.admin_get_user_by_email(email)
    if existing is not None:
        user_id = existing['id']
    else:
        created = supabase_client.admin_create_user(
            email, password=None, full_name=payload.full_name
        )
        user_id = created['id']

    profile = profiles.upsert(
        user_id=user_id,
        email=email,
        full_name=payload.full_name,
        phone=payload.phone,
        is_active=True,
    )
    policy_db.set_user_roles(user_id, roles, actor=caller.user_id)
    supabase_client.send_recovery_email(email)

    snapshot = _fresh()
    return _profile_response(snapshot, {**profile, 'roles': roles})


@router.get('/users/{user_id}')
def get_user(user_id: str) -> dict:
    """One user, with what they can do in every service (effective access)."""
    return _profile_response(_fresh(), _get_profile(user_id))


@router.patch('/users/{user_id}')
def update_profile(
    user_id: str, payload: UpdateProfileRequest, caller: Caller = Depends(require_global_admin)
) -> dict:
    """Change a user's name or phone.

    Consumers see the change within a minute: introspect reads both from the
    roster in its policy snapshot. Phone matters more than it looks, because
    Consultation Agent finds a user's broker profile by it.
    """
    changes = {field: value.strip() for field, value in payload.model_dump(exclude_none=True).items()}
    if not changes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'nothing to update')

    _get_profile(user_id)
    profile = profiles.update(user_id, changes)
    logger.info('%s updated for %s by %s', ', '.join(sorted(changes)), user_id, caller.user_id)
    return _profile_response(_fresh(), profile)


@router.patch('/users/{user_id}/roles')
def update_roles(
    user_id: str, payload: UpdateRolesRequest, caller: Caller = Depends(require_global_admin)
) -> dict:
    """Replace a user's role set.

    Revokes the user's sessions afterwards, so they must sign in again; the new
    roles reach consumers within a minute either way, because introspect reads
    roles from the roster rather than the token.
    """
    snapshot = _fresh()
    roles = _validated(snapshot, payload.roles)
    profile = _get_profile(user_id)

    if user_id == caller.user_id and not snapshot.resolve(roles)['identity'].has('console', 'use'):
        # Changing your own roles must not lock you out of the console.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            'you cannot remove your own console access; ask another admin to do it',
        )

    policy_db.set_user_roles(user_id, roles, actor=caller.user_id)
    supabase_client.admin_sign_out_everywhere(user_id)
    logger.info('roles updated for %s by %s', user_id, caller.user_id)
    return _profile_response(_fresh(), profile)


@router.put('/users/{user_id}/attributes/{service}')
def set_attributes(
    user_id: str, service: str, payload: SetAttributesRequest,
    caller: Caller = Depends(require_global_admin),
) -> dict:
    """Replace a user's attributes in one service, e.g. Broker Tools' desk.

    The console warns when a desk and the presales/sales role disagree; it does
    not stop an admin choosing them separately.
    """
    _get_profile(user_id)
    policy_db.set_user_attributes(user_id, service, payload.attributes, actor=caller.user_id)
    return _profile_response(_fresh(), _get_profile(user_id))


@router.patch('/users/{user_id}/status')
def update_status(
    user_id: str, payload: UpdateStatusRequest, caller: Caller = Depends(require_global_admin)
) -> dict:
    """Activate or deactivate an account.

    Deactivation blocks login outright, which is distinct from clearing a user's
    roles — that leaves the account usable but with no app access.
    """
    if user_id == caller.user_id and not payload.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'you cannot deactivate yourself')

    _get_profile(user_id)
    if not payload.is_active:
        snapshot = _fresh()
        if _active_superusers(snapshot) == {user_id}:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                'cannot deactivate the last active admin; give another active user the admin role first',
            )

    profile = profiles.update(user_id, {'is_active': payload.is_active})
    if not payload.is_active:
        supabase_client.admin_sign_out_everywhere(user_id)
    logger.info('status for %s set to active=%s by %s', user_id, payload.is_active, caller.user_id)
    return _profile_response(_fresh(), profile)


@router.post('/users/{user_id}/reset-password', status_code=status.HTTP_202_ACCEPTED)
def admin_reset_password(user_id: str) -> dict:
    """Send a set-password email on a user's behalf.

    The admin never sees or chooses the password, which makes this the better of
    the two recovery paths where it works. It needs the emailed link to land
    somewhere, and today it does not — see the note on set_password below.
    """
    profile = _get_profile(user_id)
    supabase_client.send_recovery_email(profile['email'])
    return {'detail': 'password reset email sent'}


@router.post('/users/{user_id}/set-password', status_code=status.HTTP_204_NO_CONTENT)
def set_password(
    user_id: str,
    payload: SetPasswordRequest,
    caller: Caller = Depends(require_global_admin),
) -> None:
    """Set a user's password outright, without their current one.

    The counterpart to /v1/auth/password/change: that endpoint is how people
    change their own password and requires the old one, which is no help to
    somebody who has forgotten it. reset-password above is the path that avoids
    an admin ever knowing the password, but the emailed link has nowhere to land
    yet and Supabase's built-in mailer is rate-limited to a few messages an hour
    and silently stops delivering. So this exists for real lockouts.

    Unlike scripts/set_password.py, which reaches Supabase directly with the
    service-role key, this runs as an authenticated admin. That is the point:
    the reset is attributable, and helping someone back in does not require
    handing out the key that can act as any user in the project.

    Sessions are revoked afterwards — whoever knew the old password may still
    hold a live session, and a reset that leaves them signed in has not actually
    recovered the account. Resetting your own password therefore signs you out
    too, including the session making this request.
    """
    _get_profile(user_id)
    supabase_client.admin_set_password(user_id, payload.new_password)
    # Raises if revocation fails, rather than reporting a success that left the
    # old sessions alive. See admin_sign_out_everywhere.
    supabase_client.admin_sign_out_everywhere(user_id)
    logger.info('password set for %s by %s', user_id, caller.user_id)


# ── Roles ────────────────────────────────────────────────────────────────────

def _role_response(snapshot: Snapshot, key: str) -> dict:
    role = snapshot.roles[key]
    members = sum(1 for entry in snapshot.users.values() if key in (entry.get('roles') or []))
    apps = build_apps(snapshot, [key], is_active=True)
    return {
        'key': role.key,
        'label': role.label,
        'description': role.description,
        'priority': role.priority,
        'is_superuser': role.is_superuser,
        'exclusive_group': role.exclusive_group,
        'members': members,
        'apps': [service for service, block in apps.items() if block['access']],
    }


@router.get('/roles')
def list_roles() -> dict:
    snapshot = _fresh()
    roles = sorted(snapshot.roles.values(), key=lambda r: (r.priority, r.key))
    return {
        'roles': [_role_response(snapshot, role.key) for role in roles],
        'exclusive_groups': snapshot.exclusive_groups(),
    }


@router.post('/roles', status_code=status.HTTP_201_CREATED)
def create_role(payload: CreateRoleRequest, caller: Caller = Depends(require_global_admin)) -> dict:
    """A new role, with no grants until an admin ticks the matrix."""
    if payload.key in _fresh().roles:
        raise HTTPException(status.HTTP_409_CONFLICT, 'a role with that key already exists')
    policy_db.upsert_role(payload.key, payload.label, payload.description, payload.priority,
                          payload.exclusive_group, actor=caller.user_id)
    return _role_response(_fresh(), payload.key)


@router.patch('/roles/{key}')
def update_role(key: str, payload: UpdateRoleRequest, caller: Caller = Depends(require_global_admin)) -> dict:
    """Relabel, reprioritise or regroup a role. Its key never changes."""
    snapshot = _fresh()
    role = snapshot.roles.get(key)
    if role is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'role not found')
    group = role.exclusive_group if payload.exclusive_group is None else (payload.exclusive_group or None)
    policy_db.upsert_role(
        key,
        payload.label if payload.label is not None else role.label,
        payload.description if payload.description is not None else role.description,
        payload.priority if payload.priority is not None else role.priority,
        group,
        actor=caller.user_id,
    )
    return _role_response(_fresh(), key)


@router.delete('/roles/{key}', status_code=status.HTTP_204_NO_CONTENT)
def delete_role(key: str, caller: Caller = Depends(require_global_admin)) -> None:
    """Refused while anyone holds the role, and for the superuser role."""
    policy_db.delete_role(key, actor=caller.user_id)
    cache.refresh_quietly()


# ── Services ─────────────────────────────────────────────────────────────────

@router.get('/services')
def list_services() -> dict:
    snapshot = _fresh()
    return {
        'services': [
            {
                'key': s['key'],
                'name': s['name'],
                'description': s.get('description', ''),
                'is_system': s['is_system'],
                'is_active': s['is_active'],
                'grants_version': s['grants_version'],
                'manifest_pushed_at': s.get('manifest_pushed_at'),
                'resources': sum(1 for r in s['resources'] if not r['retired'] and r['key'] != APP_RESOURCE),
                'retired_resources': sum(1 for r in s['resources'] if r['retired']),
            }
            for s in snapshot.raw.get('services') or []
        ],
    }


@router.post('/services', status_code=status.HTTP_201_CREATED)
def create_service(payload: CreateServiceRequest, caller: Caller = Depends(require_global_admin)) -> dict:
    """Register a service. It gets the implicit app.use at once; the rest of its
    catalogue arrives with its first manifest push."""
    policy_db.register_service(payload.key, payload.name, payload.description, actor=caller.user_id)
    return _service(_fresh(), payload.key)


@router.get('/services/{key}')
def get_service(key: str) -> dict:
    """The catalogue, retired items included, and the service's keys."""
    service = _service(_fresh(), key)
    return {**service, 'keys': policy_db.list_service_keys(key)}


@router.patch('/services/{key}')
def update_service(
    key: str, payload: UpdateServiceRequest, caller: Caller = Depends(require_global_admin)
) -> dict:
    policy_db.update_service(key, name=payload.name, description=payload.description,
                             is_active=payload.is_active, actor=caller.user_id)
    return _service(_fresh(), key)


@router.delete('/services/{key}/resources/{resource}', status_code=status.HTTP_204_NO_CONTENT)
def delete_retired_resource(key: str, resource: str, caller: Caller = Depends(require_global_admin)) -> None:
    """Only a resource the latest manifest no longer lists; its grants go too."""
    policy_db.delete_retired_resource(key, resource, actor=caller.user_id)
    cache.refresh_quietly()


@router.get('/services/{key}/grants')
def get_grants(key: str, response: Response) -> dict:
    """One service's whole matrix. The version goes back in If-Match on PUT."""
    snapshot = _fresh()
    service = _service(snapshot, key)
    response.headers['ETag'] = f'"{service["grants_version"]}"'
    return {
        'service': key,
        'version': service['grants_version'],
        'editable': not service['is_system'],
        'grants': _grants_of(snapshot, key),
        'roles': [
            {'key': r.key, 'label': r.label, 'is_superuser': r.is_superuser}
            for r in sorted(snapshot.roles.values(), key=lambda r: (r.priority, r.key))
        ],
    }


@router.put('/services/{key}/grants')
def set_grants(
    key: str,
    payload: SetGrantsRequest,
    response: Response,
    if_match: str | None = Header(default=None, alias='If-Match'),
    caller: Caller = Depends(require_global_admin),
) -> dict:
    """Replace one service's matrix. Needs If-Match with the version the admin
    edited, so two admins cannot silently overwrite each other (409)."""
    if not if_match or not if_match.strip('"').isdigit():
        raise HTTPException(
            status.HTTP_428_PRECONDITION_REQUIRED, 'If-Match with the grants version is required'
        )
    version = policy_db.set_service_grants(key, payload.grants, expected_version=int(if_match.strip('"')),
                                           actor=caller.user_id)
    cache.refresh_quietly()
    response.headers['ETag'] = f'"{version}"'
    return {'service': key, 'version': version}


@router.post('/services/{key}/keys', status_code=status.HTTP_201_CREATED)
def create_key(key: str, payload: CreateKeyRequest, caller: Caller = Depends(require_global_admin)) -> dict:
    """A new key for a service. The plaintext is in this response only; only
    its SHA-256 is stored."""
    plaintext = secrets.token_urlsafe(32)
    key_id = policy_db.create_service_key(
        key, hashlib.sha256(plaintext.encode()).hexdigest(), plaintext[:6], payload.label,
        actor=caller.user_id,
    )
    cache.refresh_quietly()
    return {'id': key_id, 'service': key, 'key': plaintext, 'prefix': plaintext[:6], 'label': payload.label}


@router.delete('/services/{key}/keys/{key_id}', status_code=status.HTTP_204_NO_CONTENT)
def revoke_key(key: str, key_id: str, caller: Caller = Depends(require_global_admin)) -> None:
    """Stops working at once here, and within POLICY_CACHE_TTL_SECONDS elsewhere."""
    policy_db.revoke_service_key(key, key_id, actor=caller.user_id)
    cache.refresh_quietly()


# ── Audit ────────────────────────────────────────────────────────────────────

@router.get('/audit')
def list_audit(
    target_type: str | None = Query(default=None, description='user, role or service'),
    target_key: str | None = Query(default=None),
    actor_email: str | None = Query(default=None),
    before_id: int | None = Query(default=None, description='for the next page: the last id you saw'),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    entries = policy_db.list_audit(target_type=target_type, target_key=target_key,
                                   actor_email=actor_email, before_id=before_id, limit=limit)
    return {'entries': entries}
