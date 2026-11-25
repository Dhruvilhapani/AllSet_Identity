"""Personal data never reaches a log line: emails, phones, PAN, Aadhaar are masked."""

from __future__ import annotations

import io
import logging

import pytest

from app import redact


@pytest.fixture
def streams():
    """One handler on root, one on uvicorn.error wired the way gunicorn's
    UvicornWorker does it (its own handlers, no propagation)."""
    root_stream, worker_stream = io.StringIO(), io.StringIO()
    root_handler, worker_handler = logging.StreamHandler(root_stream), logging.StreamHandler(worker_stream)
    root = logging.getLogger()
    worker = logging.getLogger('uvicorn.error')
    saved = (root.level, worker.handlers, worker.propagate, worker.level)
    root.addHandler(root_handler)
    root.setLevel(logging.INFO)
    worker.handlers = [worker_handler]
    worker.propagate = False
    worker.setLevel(logging.INFO)
    redact.install()
    yield root_stream, worker_stream
    root.removeHandler(root_handler)
    root.setLevel(saved[0])
    worker.handlers, worker.propagate, worker.level = saved[1], saved[2], saved[3]


def test_every_kind_of_pii_is_masked(streams):
    root_stream, worker_stream = streams
    logger = logging.getLogger('app.anything')
    logger.info('login for %s', 'john.doe@example.com')
    logger.info('HTTP Request: GET %s', 'https://x.supabase.co/auth/v1/admin/users?filter=john.doe%40example.com')
    logger.info('call %s and %s', '9876543210', '+91 9123456780')
    logger.info('pan %s aadhaar %s', 'ABCDE1234F', '2345 6789 0123')
    try:
        raise ValueError('no profile for jane@example.org')
    except ValueError:
        logger.exception('lookup failed')
    logging.getLogger('uvicorn.error').error('worker saw %s', 'jane@example.org')

    out = root_stream.getvalue()
    for raw in ('john.doe@example.com', 'john.doe%40example.com', '9876543210', '9123456780',
                'ABCDE1234F', '2345 6789 0123', 'jane@example.org'):
        assert raw not in out
    for masked in ('j***@example.com', 'filter=j***%40example.com', '******3210', '******6780',
                   '******234F', '********0123', 'j***@example.org'):
        assert masked in out
    assert 'j***@example.org' in worker_stream.getvalue()
    assert 'jane@example.org' not in worker_stream.getvalue()


def test_masks():
    assert redact.mask_phone('9876543210') == '******3210'
    assert redact.mask_email('john@example.com') == 'j***@example.com'
    assert redact.redact_text('user 3f9a6e12-0b1c-4d2e-9f3a-1b2c3d4e5f60 did it') == \
        'user 3f9a6e12-0b1c-4d2e-9f3a-1b2c3d4e5f60 did it'


def test_httpx_request_urls_are_not_logged():
    import app.main  # noqa: F401  (configures logging on import)

    assert logging.getLogger('httpx').level >= logging.WARNING
    assert logging.getLogger('httpcore').level >= logging.WARNING


def test_aadhaar_pattern_skips_uuid_digit_groups():
    uuid = '123e4567-1234-5678-9012-123456789012'
    assert redact.redact_text(f'id {uuid} done') == f'id {uuid} done'
    assert redact.redact_text('aadhaar 1234 5678 9012') == 'aadhaar ********9012'
    assert redact.redact_text('aadhaar 1234-5678-9012') == 'aadhaar ********9012'
