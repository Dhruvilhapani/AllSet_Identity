"""Serve the admin console (admin/, built into admin/dist) at /admin.

Same origin as the API, so the console needs no CORS entry, and it is also
reachable at /identity/admin through the Firebase Hosting rewrite that forwards
/identity/** unchanged. The console routes with URL hashes, so the server only
ever returns index.html and its assets.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

CONSOLE_DIR = Path(__file__).resolve().parent.parent / 'admin' / 'dist'
PREFIXES = ('/admin', '/identity/admin')

# The console loads nothing from anywhere else and must never be framed.
CONSOLE_HEADERS = {
    'Content-Security-Policy': (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    ),
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
}


def mount(app: FastAPI, directory: Path = CONSOLE_DIR) -> bool:
    """Serve the built console, if there is one. Returns whether it was mounted."""
    if not (directory / 'index.html').is_file():
        logger.info('admin console not built (%s); /admin is not served', directory)
        return False

    for prefix in PREFIXES:
        # /admin -> /admin/, so the bundle's relative asset paths resolve.
        app.add_api_route(prefix, _redirect_to(prefix + '/'), include_in_schema=False)
        app.mount(prefix + '/', StaticFiles(directory=directory, html=True), name=f'console{prefix}')

    @app.middleware('http')
    async def console_headers(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(PREFIXES):
            response.headers.update(CONSOLE_HEADERS)
        return response

    return True


def _redirect_to(target: str):
    def redirect() -> RedirectResponse:
        return RedirectResponse(target, status_code=308)
    return redirect
