"""The hot path.

Every authenticated request in every consuming service lands here. It is
therefore built to do no I/O per request: the token's signature is checked
against in-memory JWKS, and the caller's roles, status and permissions come from
the in-memory policy snapshot (app/permissions/cache.py), refreshed in the
background. No Supabase call, no database query.

Consumers cache the response for 60 seconds keyed on a hash of the token, so in
steady state most requests do not even reach this service.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.api.deps import require_service_key
from app.core import security
from app.permissions import cache
from app.permissions.payload import build_payload, identity_from_claims, inactive_apps

router = APIRouter(tags=['introspect'])


class IntrospectRequest(BaseModel):
    token: str = Field(min_length=1, description='A Supabase access token')


@router.post('/introspect', dependencies=[Depends(require_service_key)])
def introspect(payload: IntrospectRequest) -> dict:
    """Resolve a token into identity and per-app capabilities.

    Always returns HTTP 200. An invalid, expired or deactivated token comes back
    as `{"active": false}` rather than an error status, so a consumer can tell
    "this token is no good" apart from "the identity service is broken" — the
    latter must fail closed, the former is a routine 401 for the end user.

    A snapshot that cannot be loaded at all is a 5xx (PolicyUnavailable,
    handled in app/main.py), never `active: false`.
    """
    snapshot = cache.current()
    try:
        claims = security.verify_access_token(payload.token)
    except security.TokenInvalid as exc:
        return {
            'active': False,
            'reason': str(exc),
            'roles': [],
            'apps': inactive_apps(snapshot),
        }

    return build_payload(snapshot, identity_from_claims(snapshot, claims))


@router.get('/introspect/health', status_code=status.HTTP_200_OK)
def introspect_health(service: str | None = Depends(require_service_key)) -> dict:
    """Lets a consumer verify its service key is correct without a user token,
    and see whether this instance has a policy snapshot to answer from."""
    age = cache.age_seconds()
    return {
        'status': 'ok',
        'service': service,
        'policy_loaded': age is not None,
        'policy_age_seconds': None if age is None else round(age, 1),
    }
