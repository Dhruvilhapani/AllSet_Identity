"""Service-facing catalogue updates: a service pushes its manifest on deploy.

Authenticated by the calling service's own key, which also says which service
it is. The shared ALLSET_SERVICE_KEY identifies nobody, so it cannot push. A
push can add, relabel or retire resources, actions, scopes and attributes, but
never grants anything (identity_apply_manifest in db/004).
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, status

from app import policy_db
from app.api.deps import require_service_key
from app.permissions import cache
from app.permissions.catalogue import ManifestInvalid, validate_manifest

router = APIRouter(prefix='/services', tags=['services'])


@router.put('/manifest')
def push_manifest(
    manifest: dict = Body(..., description="The service's identity-manifest.json"),
    service: str | None = Depends(require_service_key),
) -> dict:
    if service is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            'the shared service key identifies no service; push with the key issued for yours',
        )
    try:
        validate_manifest(manifest)
    except ManifestInvalid as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if manifest['service'] != service:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f'this key belongs to {service}, not {manifest["service"]}',
        )

    body = {k: manifest[k] for k in ('resources', 'attributes') if k in manifest}
    result = policy_db.apply_manifest(service, body, actor=None)
    cache.refresh_quietly()
    resources = (result or {}).get('resources') or []
    return {
        'service': service,
        'resources': sorted(r['key'] for r in resources if not r['retired']),
        'retired': sorted(r['key'] for r in resources if r['retired']),
    }
