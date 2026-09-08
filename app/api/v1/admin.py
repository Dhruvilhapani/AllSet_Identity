"""User and role administration. Restricted to admin and tech.

These are the operations that need the service-role key, which is the reason
this service exists as a separate deployable: the key can mint a session for any
user, so it must live in exactly one place and never in a browser bundle. The
CMS's and Broker Tools' own admin screens proxy through here.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app import capabilities, profiles, supabase_client
from app.api.deps import Caller, require_global_admin

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix='/admin',
    tags=['admin'],
    dependencies=[Depends(require_global_admin)],
)


class CreateUserRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(default='', max_length=200)
    phone: str = Field(default='', max_length=32)
    roles: list[str] = Field(default_factory=list)


class UpdateRolesRequest(BaseModel):
    roles: list[str]


class UpdateStatusRequest(BaseModel):
    is_active: bool


def _validated(roles: list[str]) -> list[str]:
    try:
        return capabilities.validate_roles(roles)
    except capabilities.InvalidRoles as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


def _profile_response(profile: dict) -> dict:
    roles = profile.get('roles') or []
    return {
        'user_id': profile['user_id'],
        'email': profile['email'],
        'full_name': profile.get('full_name', ''),
        'phone': profile.get('phone', ''),
        'roles': roles,
        'role_labels': [capabilities.ROLE_LABELS[role] for role in roles],
        'is_active': profile.get('is_active', True),
        'legacy_migrated_at': profile.get('legacy_migrated_at'),
        'created_at': profile.get('created_at'),
        'apps': capabilities.build_capabilities(
            roles, is_active=profile.get('is_active', True)
        ),
    }


@router.get('/users')
def list_users() -> dict:
    return {'users': [_profile_response(profile) for profile in profiles.list_all()]}


@router.post('/users', status_code=status.HTTP_201_CREATED)
def create_user(payload: CreateUserRequest) -> dict:
    """Provision an account and email a set-password link.

    No password is set here: the invitee chooses their own via the recovery
    email. This replaces the CMS's invite flow, which generated a random
    password and then never emailed or returned it, leaving invited users unable
    to log in at all.
    """
    email = payload.email.strip().lower()
    roles = _validated(payload.roles)

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
        roles=roles,
        full_name=payload.full_name,
        phone=payload.phone,
        is_active=True,
    )
    supabase_client.send_recovery_email(email)

    return _profile_response(profile)


@router.patch('/users/{user_id}/roles')
def update_roles(
    user_id: str, payload: UpdateRolesRequest, caller: Caller = Depends(require_global_admin)
) -> dict:
    """Replace a user's role set.

    Signs the user out globally afterwards. Roles ride in the JWT and consumers
    cache for 60s, so without this a removed role would keep working until the
    access token expired.
    """
    roles = _validated(payload.roles)
    target = profiles.get_by_user_id(user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'user not found')

    if user_id == caller.user_id and not set(roles) & {capabilities.ADMIN, capabilities.TECH}:
        # Removing your own last admin role can leave the org with no way in.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            'you cannot remove your own admin/tech role; ask another admin to do it',
        )

    profile = profiles.update(user_id, {'roles': roles})
    supabase_client.admin_sign_out_everywhere(user_id)
    logger.info('roles updated for %s by %s', user_id, caller.user_id)
    return _profile_response(profile)


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

    if profiles.get_by_user_id(user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'user not found')

    profile = profiles.update(user_id, {'is_active': payload.is_active})
    if not payload.is_active:
        supabase_client.admin_sign_out_everywhere(user_id)
    logger.info('status for %s set to active=%s by %s', user_id, payload.is_active, caller.user_id)
    return _profile_response(profile)


@router.post('/users/{user_id}/reset-password', status_code=status.HTTP_202_ACCEPTED)
def admin_reset_password(user_id: str) -> dict:
    """Send a set-password email on a user's behalf.

    The admin never sees or chooses the password — this is the supported way to
    help someone who is locked out, rather than setting a temporary password and
    sending it over chat.
    """
    profile = profiles.get_by_user_id(user_id)
    if profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'user not found')

    supabase_client.send_recovery_email(profile['email'])
    return {'detail': 'password reset email sent'}
