"""Masks personal data (phones, Aadhaar, PAN, emails) before a log line is written.

The same rules, in the same order, run in every AllSet service, so a log line
looks the same whichever service wrote it.
"""

from __future__ import annotations

import logging
import re

_PHONE = re.compile(r'(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)')
_AADHAAR = re.compile(r'(?<![\w-])\d{4}[\s-]?\d{4}[\s-]?\d{4}(?![\w-])')
_PAN = re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')
_EMAIL = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')
# Emails in URLs arrive percent-encoded.
_EMAIL_ENCODED = re.compile(r'[\w.+-]+%40[\w-]+(?:\.[\w-]+)+')


def mask_phone(phone: str) -> str:
    return '******' + re.sub(r'\D', '', phone)[-4:]


def mask_email(email: str) -> str:
    for at in ('@', '%40'):
        local, sep, domain = email.partition(at)
        if sep:
            return f'{local[:1]}***{at}{domain}'
    return email


def redact_text(text: str) -> str:
    text = _PHONE.sub(lambda m: mask_phone(m.group()), text)
    text = _AADHAAR.sub(lambda m: '********' + re.sub(r'\D', '', m.group())[-4:], text)
    text = _PAN.sub(lambda m: '******' + m.group()[-4:], text)
    text = _EMAIL.sub(lambda m: mask_email(m.group()), text)
    return _EMAIL_ENCODED.sub(lambda m: mask_email(m.group()), text)


class PiiRedactionFilter(logging.Filter):
    """Rewrites the record in place, so every handler after it sees only masked text."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_text(record.stack_info)
        return True


_FILTER = PiiRedactionFilter()

# Root (basicConfig), and the handlers gunicorn's UvicornWorker hands to
# uvicorn.error (they do not propagate to root). uvicorn.access is left out: it
# has no handler under gunicorn, and uvicorn's AccessFormatter needs its args.
_LOGGERS = ('', 'gunicorn.error', 'uvicorn', 'uvicorn.error')


def install() -> None:
    """Attach the filter to every handler that writes this service's logs."""
    for name in _LOGGERS:
        for handler in logging.getLogger(name).handlers:
            handler.addFilter(_FILTER)
