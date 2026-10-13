"""Writes to the permission tables, through the SQL functions in db/004.

Every multi-row write is one function call so it runs in one transaction with
its audit row; PostgREST cannot hold a transaction across calls. The functions
signal refusals with SQLSTATEs that map straight onto HTTP:

    22023  invalid request              -> 400
    P0002  not found                    -> 404
    40001  someone else changed it      -> 409
    23505  would break a unique rule    -> 409 (e.g. two roles of one group)
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core import config

logger = logging.getLogger(__name__)

_STATUS_BY_SQLSTATE = {
    '22023': 400,
    '23514': 400,
    'P0002': 404,
    '40001': 409,
    '23505': 409,
}


class PolicyError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _headers() -> dict[str, str]:
    return {
        'apikey': config.SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': f'Bearer {config.SUPABASE_SERVICE_ROLE_KEY}',
        'Content-Type': 'application/json',
    }


def _client() -> httpx.Client:
    return httpx.Client(base_url=f'{config.SUPABASE_URL}/rest/v1', timeout=config.HTTP_TIMEOUT_SECONDS)


def _raise(response: httpx.Response, what: str) -> None:
    try:
        body = response.json()
    except ValueError:
        body = {}
    code = body.get('code') if isinstance(body, dict) else None
    message = body.get('message') if isinstance(body, dict) else None

    if code in _STATUS_BY_SQLSTATE:
        if code == '23505':
            message = 'that change would give a user two roles from the same group'
        raise PolicyError(message or f'{what} was refused', _STATUS_BY_SQLSTATE[code])
    if code in ('PGRST202', '42883') or response.status_code == 404:
        logger.error('%s is missing; apply db/004_permissions.sql', what)
        raise PolicyError('the permission tables are not installed', 500)
    logger.warning('%s failed: HTTP %s (code=%s)', what, response.status_code, code)
    raise PolicyError(f'{what} failed')


def rpc(function: str, **arguments: Any) -> Any:
    with _client() as client:
        response = client.post(f'/rpc/{function}', headers=_headers(), json=arguments)
    if not response.is_success:
        _raise(response, function)
    return response.json() if response.content else None


def select(table: str, params: dict[str, str]) -> list[dict]:
    with _client() as client:
        response = client.get(f'/{table}', headers=_headers(), params=params)
    if not response.is_success:
        _raise(response, f'read {table}')
    return response.json()


# ── The calls the API makes ──────────────────────────────────────────────────

def set_user_roles(user_id: str, roles: list[str], *, actor: str | None) -> list[str]:
    return rpc('identity_set_user_roles', p_user_id=user_id, p_role_keys=roles, p_actor=actor)


def set_user_attributes(user_id: str, service: str, values: dict[str, str], *, actor: str | None) -> dict:
    return rpc('identity_set_user_attributes', p_user_id=user_id, p_service=service,
               p_values=values, p_actor=actor)


def upsert_role(key: str, label: str, description: str, priority: int,
                exclusive_group: str | None, *, actor: str | None) -> dict:
    return rpc('identity_upsert_role', p_key=key, p_label=label, p_description=description,
               p_priority=priority, p_exclusive_group=exclusive_group, p_actor=actor)


def delete_role(key: str, *, actor: str | None) -> None:
    rpc('identity_delete_role', p_key=key, p_actor=actor)


def set_service_grants(service: str, grants: dict, *, expected_version: int, actor: str | None) -> int:
    return rpc('identity_set_service_grants', p_service=service, p_grants=grants,
               p_expected_version=expected_version, p_actor=actor, p_allow_system=False)


def register_service(key: str, name: str, description: str, *, actor: str | None) -> None:
    rpc('identity_register_service', p_key=key, p_name=name, p_description=description, p_actor=actor)


def update_service(key: str, *, name: str | None, description: str | None,
                   is_active: bool | None, actor: str | None) -> None:
    rpc('identity_update_service', p_key=key, p_name=name, p_description=description,
        p_is_active=is_active, p_actor=actor)


def apply_manifest(service: str, manifest: dict, *, actor: str | None) -> dict:
    return rpc('identity_apply_manifest', p_service=service, p_manifest=manifest, p_actor=actor, p_audit=True)


def delete_retired_resource(service: str, resource: str, *, actor: str | None) -> None:
    rpc('identity_delete_retired_resource', p_service=service, p_resource=resource, p_actor=actor)


def create_service_key(service: str, key_hash: str, prefix: str, label: str, *, actor: str | None) -> str:
    return rpc('identity_create_service_key', p_service=service, p_key_hash=key_hash,
               p_key_prefix=prefix, p_label=label, p_actor=actor)


def revoke_service_key(service: str, key_id: str, *, actor: str | None) -> None:
    rpc('identity_revoke_service_key', p_service=service, p_key_id=key_id, p_actor=actor)


def list_service_keys(service: str) -> list[dict]:
    return select('identity_service_keys', {
        'select': 'id,key_prefix,label,created_at,created_by,revoked_at,identity_services!inner(key)',
        'identity_services.key': f'eq.{service}',
        'order': 'created_at.desc',
    })


def list_audit(*, target_type: str | None = None, target_key: str | None = None,
               actor_email: str | None = None, before_id: int | None = None, limit: int = 100) -> list[dict]:
    params = {'select': '*', 'order': 'id.desc', 'limit': str(min(max(limit, 1), 500))}
    if target_type:
        params['target_type'] = f'eq.{target_type}'
    if target_key:
        params['target_key'] = f'eq.{target_key}'
    if actor_email:
        params['actor_email'] = f'ilike.{actor_email}'
    if before_id:
        params['id'] = f'lt.{before_id}'
    return select('identity_audit_log', params)
