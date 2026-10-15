"""S1: syntax validation (offline, RFC-style, PRD 4 / 5.1)."""
from __future__ import annotations

import re
from typing import Optional, Tuple

MAX_TOTAL = 254
MAX_LOCAL = 64
MAX_LABEL = 63

# RFC 5322 atext + dot (quoted local parts are treated invalid per PRD 14.3).
_ATEXT = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&'*+-/=?^_`{|}~."
)

_ANGLE_RE = re.compile(r"<([^<>]+)>")


def _stop(code: str, message: Optional[str] = None):
    from .models import make_stop_cause

    return make_stop_cause(code, message=message)


def check_syntax(raw) -> Tuple[Optional[str], Optional[object]]:
    """Return (normalized_email, None) on success or (None, StopCause)."""
    if raw is None:
        return None, _stop("E101", "empty address")
    s = str(raw).strip()
    # Display-name form: Some One <a@b.com> -> a@b.com (parseaddr-equivalent).
    m = _ANGLE_RE.search(s)
    if m:
        s = m.group(1).strip()
    if not s:
        return None, _stop("E101", "empty or whitespace address")
    if len(s) > MAX_TOTAL:
        return None, _stop("E102", "address longer than 254 characters")
    if s.startswith('"'):
        return None, _stop("E104", "quoted local parts are not supported")
    at_count = s.count("@")
    if at_count == 0:
        return None, _stop("E103", "missing @")
    if at_count > 1:
        return None, _stop("E103", "multiple unquoted @")
    local, domain = s.split("@", 1)
    if not local or not domain:
        return None, _stop("E103", "missing local part or domain")
    if len(local) > MAX_LOCAL:
        return None, _stop("E102", "local part longer than 64 characters")
    # E104: illegal local part.
    if local.startswith(".") or local.endswith("."):
        return None, _stop("E104", "local part starts or ends with a dot")
    if ".." in local:
        return None, _stop("E104", "consecutive dots in local part")
    for ch in local:
        if ch not in _ATEXT:
            return None, _stop("E104", f"illegal character in local part: {ch!r}")
    # E105: illegal domain.
    dom = domain
    if any(ord(ch) > 127 for ch in dom):
        try:
            dom = ".".join(
                lbl.encode("idna").decode("ascii") for lbl in dom.split(".")
            )
        except (UnicodeError, UnicodeDecodeError):
            return None, _stop("E105", "IDN domain cannot be punycode-encoded")
    dom = dom.lower()
    if len(dom) > 253:
        return None, _stop("E102", "domain longer than 253 characters")
    labels = dom.split(".")
    if len(labels) < 2:
        return None, _stop("E105", "domain must have at least two labels")
    for lbl in labels:
        if not lbl or len(lbl) > MAX_LABEL:
            return None, _stop("E105", "bad domain label length")
        if lbl.startswith("-") or lbl.endswith("-"):
            return None, _stop("E105", "domain label starts or ends with hyphen")
        if not re.fullmatch(r"[a-z0-9-]+", lbl):
            return None, _stop("E105", f"illegal domain label: {lbl!r}")
    tld = labels[-1]
    if not re.search(r"[a-z]", tld):
        # Numeric/symbol-only TLD: covers numeric TLDs and IPv4 literals.
        return None, _stop("E105", "numeric or invalid TLD (IP literals not allowed)")
    if len(tld) < 2:
        return None, _stop("E105", "TLD shorter than 2 characters")
    return f"{local}@{dom}", None
