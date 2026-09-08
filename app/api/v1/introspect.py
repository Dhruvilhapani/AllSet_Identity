"""The hot path.

Every authenticated request in both Django backends and Broker Tools' FastAPI
service lands here. It is therefore built to do no I/O at all: the token's
signature is checked against in-memory JWKS and the role set is read from the
`app_metadata` claim written by the Custom Access Token Hook. No Supabase call,
no database query.

Consumers cache the response for 60 seconds keyed on a hash of the token, so in
steady state most requests do not even reach this service.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app import capabilities
from app.api.deps import require_service_key
from app.core import security

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
    """
    try:
        claims = security.verify_access_token(payload.token)
    except security.TokenInvalid as exc:
        return {
            'active': False,
            'reason': str(exc),
            'roles': [],
            'apps': capabilities.build_capabilities([], is_active=False),
        }

    user_id, email, roles, is_active, full_name = security.claims_to_identity(claims)

    return capabilities.build_payload(
        user_id=user_id,
        email=email,
        roles=roles,
        is_active=is_active,
        full_name=full_name,
    )


@router.get('/introspect/health', status_code=status.HTTP_200_OK)
def introspect_health(_: None = Depends(require_service_key)) -> dict:
    """Lets a consumer verify its service key is correct without a user token."""
    return {'status': 'ok'}
