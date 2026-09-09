"""AllSet Identity — the shared auth gateway for AllSet_CMS and AllSet_Broker_Tools.

Serves three audiences:
  * the two admin UIs, for login / refresh / me / password management
  * the consuming backends, via POST /v1/introspect on every request
  * admins, via /v1/admin/* for provisioning and role changes

Token verification is local (cached JWKS) and roles arrive inside the JWT via a
Supabase Custom Access Token Hook, so introspection performs no I/O.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import admin, auth, introspect
from app.core import config
from app.profiles import ProfileError
from app.supabase_client import SupabaseError

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
)
logger = logging.getLogger(__name__)

config.validate()

app = FastAPI(
    title='AllSet Identity',
    version='1.0.0',
    description=(
        'Unified authentication and role-based access control for AllSet CMS '
        'and AllSet Broker Tools.'
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    # Tokens travel in the Authorization header, not cookies. Both admin UIs are
    # same-origin under dev.allset.in in production, so there is no need to
    # allow credentials — and not allowing them keeps CSRF off the table.
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'PATCH', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type', 'X-Allset-Service-Key'],
)

v1 = APIRouter(prefix='/v1')
v1.include_router(auth.router)
v1.include_router(introspect.router)
v1.include_router(admin.router)
app.include_router(v1)

# Firebase Hosting's `run` rewrite for /identity/** forwards the request path
# unchanged (it does not strip the matched prefix, unlike a dev-server proxy
# rewrite), so the same routes must also answer under /identity/v1/... for
# browser calls made through that same-origin path in production.
app.include_router(v1, prefix='/identity')


@app.get('/health', tags=['health'])
def health() -> dict:
    """Liveness only — deliberately does not reach out to Supabase, so a
    dependency blip cannot make Cloud Run cycle the instance."""
    return {'status': 'ok', 'service': 'allset-identity'}


@app.exception_handler(SupabaseError)
def handle_supabase_error(_: Request, exc: SupabaseError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})


@app.exception_handler(ProfileError)
def handle_profile_error(_: Request, exc: ProfileError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})


@app.exception_handler(Exception)
def handle_unexpected(_: Request, exc: Exception) -> JSONResponse:
    """Never leak an internal message to a caller of an auth service."""
    logger.exception('unhandled error', exc_info=exc)
    return JSONResponse(status_code=500, content={'detail': 'internal error'})
