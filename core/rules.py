"""S2: free-provider own rules (Gmail strict; Outlook/Yahoo basic)."""
from __future__ import annotations

import re
from typing import Optional

GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
OUTLOOK_DOMAINS = {"outlook.com", "hotmail.com", "live.com", "msn.com"}
YAHOO_DOMAINS = {"yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es",
                 "yahoo.it", "ymail.com", "rocketmail.com"}

_GMAIL_LOCAL = re.compile(r"^[a-z0-9.]+$")
_OUTLOOK_LOCAL = re.compile(r"^[a-z0-9._-]+$")
_YAHOO_LOCAL = re.compile(r"^[a-z0-9._-]+$")


def _stop(code: str, message: str):
    from .models import make_stop_cause

    return make_stop_cause(code, message=message)


def check_rules(email: str) -> Optional[object]:
    """Return a StopCause (E201) when the provider's own rules are violated."""
    local, domain = email.rsplit("@", 1)
    local_l = local.lower()

    if domain in GMAIL_DOMAINS:
        # Length window 6-30 evaluated on the full local part (sub-addressing
        # like user+tag counts toward the window; base part must be clean).
        if not (6 <= len(local_l) <= 30):
            return _stop("E201", "Gmail local part must be 6-30 characters")
        base = local_l.split("+", 1)[0]
        if not base or not _GMAIL_LOCAL.match(base):
            return _stop("E201", "Gmail local part may only contain a-z 0-9 and dots")
        if base.startswith(".") or base.endswith(".") or ".." in base:
            return _stop("E201", "Gmail local part dot placement invalid")
        return None

    if domain in OUTLOOK_DOMAINS:
        if len(local_l) < 5 or len(local_l) > 64:
            return _stop("E201", "Outlook local part must be 5-64 characters")
        base = local_l.split("+", 1)[0]
        if not _OUTLOOK_LOCAL.match(base):
            return _stop("E201", "Outlook local part has illegal characters")
        if base.startswith(".") or base.endswith("."):
            return _stop("E201", "Outlook local part dot placement invalid")
        return None

    if domain in YAHOO_DOMAINS:
        if len(local_l) < 4 or len(local_l) > 64:
            return _stop("E201", "Yahoo local part must be 4-64 characters")
        base = local_l.split("+", 1)[0]
        if not _YAHOO_LOCAL.match(base):
            return _stop("E201", "Yahoo local part has illegal characters")
        return None

    return None
