"""The in-memory policy snapshot, refreshed stale-while-revalidate.

Introspect must not touch the database per request, so every instance holds the
whole policy and roster and refreshes it in the background once it is older
than POLICY_CACHE_TTL_SECONDS. The refresh is started by a request rather than
a timer, because Cloud Run throttles CPU between requests. A failed refresh
keeps the last good snapshot. Only an instance that has never loaded one fails,
with PolicyUnavailable, which callers turn into a 503.
"""

from __future__ import annotations

import logging
import threading
import time

import httpx

from app.core import config
from app.permissions.snapshot import Snapshot

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_snapshot: Snapshot | None = None
_refreshing = False


class PolicyUnavailable(Exception):
    """No snapshot could be loaded. Fail closed."""


def _fetch() -> Snapshot:
    started = time.time()
    try:
        with httpx.Client(
            base_url=f'{config.SUPABASE_URL}/rest/v1', timeout=config.HTTP_TIMEOUT_SECONDS
        ) as client:
            response = client.post(
                '/rpc/identity_policy_snapshot',
                headers={
                    'apikey': config.SUPABASE_SERVICE_ROLE_KEY,
                    'Authorization': f'Bearer {config.SUPABASE_SERVICE_ROLE_KEY}',
                    'Content-Type': 'application/json',
                },
                json={},
            )
    except httpx.HTTPError as exc:
        raise PolicyUnavailable('policy snapshot unreachable') from exc

    if response.status_code == 404:
        logger.error('identity_policy_snapshot is missing; apply db/004_permissions.sql')
        raise PolicyUnavailable('policy tables are not installed')
    if not response.is_success:
        logger.error('policy snapshot failed: HTTP %s', response.status_code)
        raise PolicyUnavailable('policy snapshot failed')
    try:
        data = response.json()
    except ValueError as exc:
        raise PolicyUnavailable('policy snapshot was not JSON') from exc
    return Snapshot.from_json(data, loaded_at=started)


def refresh() -> Snapshot:
    """Load now and install it. Raises PolicyUnavailable on failure."""
    global _snapshot
    snapshot = _fetch()
    with _lock:
        _snapshot = snapshot
    return snapshot


def refresh_quietly() -> None:
    """After an admin write: pick the change up on this instance at once, but a
    failure must not fail a write that has already committed."""
    try:
        refresh()
    except PolicyUnavailable:
        logger.warning('policy refresh after a write failed; the next request will retry', exc_info=True)


def _background_refresh() -> None:
    global _refreshing
    try:
        refresh()
    except PolicyUnavailable:
        logger.warning('background policy refresh failed; serving the previous snapshot', exc_info=True)
    finally:
        with _lock:
            _refreshing = False


def current() -> Snapshot:
    """The snapshot to answer this request from."""
    global _refreshing
    snapshot = _snapshot
    if snapshot is None:
        return refresh()

    if time.monotonic() - snapshot.fetched_at > config.POLICY_CACHE_TTL_SECONDS:
        with _lock:
            start = not _refreshing
            _refreshing = True
        if start:
            threading.Thread(target=_background_refresh, name='policy-refresh', daemon=True).start()
    return snapshot


def age_seconds() -> float | None:
    snapshot = _snapshot
    return None if snapshot is None else time.monotonic() - snapshot.fetched_at


def install(snapshot: Snapshot | None) -> None:
    """Replace the cached snapshot. For tests and for dev seeding."""
    global _snapshot, _refreshing
    with _lock:
        _snapshot = snapshot
        _refreshing = False
