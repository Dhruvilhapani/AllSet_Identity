"""The admin console is served same-origin at /admin and /identity/admin."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import console


@pytest.fixture
def built(tmp_path):
    (tmp_path / 'index.html').write_text('<!doctype html><title>console</title>', encoding='utf-8')
    (tmp_path / 'assets').mkdir()
    (tmp_path / 'assets' / 'app.js').write_text('console.log(1)', encoding='utf-8')
    return tmp_path


@pytest.mark.parametrize('prefix', ['/admin', '/identity/admin'])
def test_the_console_and_its_assets_are_served_with_strict_headers(built, prefix):
    app = FastAPI()
    assert console.mount(app, built)
    client = TestClient(app)

    page = client.get(prefix + '/')
    assert page.status_code == 200 and '<title>console</title>' in page.text
    assert "frame-ancestors 'none'" in page.headers['Content-Security-Policy']
    assert page.headers['X-Frame-Options'] == 'DENY'
    assert client.get(prefix + '/assets/app.js').status_code == 200

    redirect = client.get(prefix, follow_redirects=False)
    assert (redirect.status_code, redirect.headers['location']) == (308, prefix + '/')


def test_nothing_is_mounted_without_a_build(tmp_path):
    app = FastAPI()
    assert console.mount(app, tmp_path) is False
    assert TestClient(app).get('/admin/').status_code == 404


def test_api_responses_do_not_get_the_console_headers(client):
    assert 'Content-Security-Policy' not in client.get('/health').headers
