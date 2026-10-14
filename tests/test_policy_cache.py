"""The policy snapshot cache: stale-while-revalidate, and keep the last good one."""

from __future__ import annotations

import threading

import pytest
import respx
from httpx import Response

from app.core import config
from app.permissions import cache
from app.permissions.catalogue import seed_snapshot
from app.permissions.snapshot import Snapshot
from tests.conftest import SUPABASE_URL

SNAPSHOT_RPC = f'{SUPABASE_URL}/rest/v1/rpc/identity_policy_snapshot'


# Taken at import, before the conftest fixture swaps _fetch out for each test.
_original_fetch = cache._fetch


@respx.mock
def test_a_cold_instance_loads_synchronously(monkeypatch):
    route = respx.post(SNAPSHOT_RPC).mock(return_value=Response(200, json=seed_snapshot()))
    monkeypatch.setattr(cache, '_fetch', _original_fetch)
    cache.install(None)

    snapshot = cache.current()
    assert route.called
    assert 'broker_tools' in snapshot.services
    assert snapshot.loaded_at > 0


@respx.mock
def test_a_missing_function_is_policy_unavailable(monkeypatch):
    respx.post(SNAPSHOT_RPC).mock(return_value=Response(404, json={'code': 'PGRST202'}))
    monkeypatch.setattr(cache, '_fetch', _original_fetch)
    cache.install(None)
    with pytest.raises(cache.PolicyUnavailable):
        cache.current()


def test_a_stale_snapshot_is_served_while_one_background_refresh_runs(monkeypatch):
    old = Snapshot.from_json(seed_snapshot())
    old.fetched_at -= config.POLICY_CACHE_TTL_SECONDS + 1
    cache.install(old)

    started = threading.Event()
    release = threading.Event()
    calls = []

    def slow_fetch():
        calls.append(1)
        started.set()
        release.wait(5)
        return Snapshot.from_json(seed_snapshot())

    monkeypatch.setattr(cache, '_fetch', slow_fetch)
    assert cache.current() is old          # answered from the stale copy at once
    assert started.wait(5)
    assert cache.current() is old          # a second request does not start another
    release.set()
    for _ in range(50):
        if cache.current() is not old:
            break
        threading.Event().wait(0.02)
    assert cache.current() is not old
    assert len(calls) == 1


def test_a_failed_background_refresh_keeps_the_last_good_snapshot(monkeypatch):
    old = Snapshot.from_json(seed_snapshot())
    old.fetched_at -= config.POLICY_CACHE_TTL_SECONDS + 1
    cache.install(old)
    done = threading.Event()

    def failing_fetch():
        try:
            raise cache.PolicyUnavailable('down')
        finally:
            done.set()

    monkeypatch.setattr(cache, '_fetch', failing_fetch)
    assert cache.current() is old
    assert done.wait(5)
    threading.Event().wait(0.05)
    assert cache.current() is old


def test_a_write_refreshes_quietly_even_when_the_reload_fails(monkeypatch):
    def failing_fetch():
        raise cache.PolicyUnavailable('down')

    monkeypatch.setattr(cache, '_fetch', failing_fetch)
    cache.refresh_quietly()   # must not raise: the write already committed

