"""S3: disposable/role/typo/blocklist checks + free-provider flag (PRD 4)."""
from __future__ import annotations

import os
import threading
import time
from typing import List, Optional, Set, Tuple

from . import config

ROLE_LOCALS = {
    "info", "admin", "administrator", "abuse", "postmaster", "webmaster",
    "hostmaster", "support", "sales", "contact", "contactus", "billing",
    "help", "helpdesk", "security", "noc", "root", "sysadmin", "marketing",
    "team", "hr", "legal", "office", "press", "jobs", "careers", "noreply",
    "no-reply", "donotreply", "mailer-daemon", "bounce", "privacy", "registrar",
}

# Small static typo table (PRD 11): common misspellings of big free providers.
TYPO_DOMAINS = {
    "gmial.com": "gmail.com",
    "gmai.com": "gmail.com",
    "gmal.com": "gmail.com",
    "gmial.co": "gmail.com",
    "gmailm.com": "gmail.com",
    "gamil.com": "gmail.com",
    "yaho.com": "yahoo.com",
    "yahooo.com": "yahoo.com",
    "yaho.co": "yahoo.com",
    "hotmial.com": "hotmail.com",
    "hotmai.com": "hotmail.com",
    "hotmal.com": "hotmail.com",
    "homail.com": "hotmail.com",
    "outlok.com": "outlook.com",
    "outloo.com": "outlook.com",
    "outllok.com": "outlook.com",
    "icloudd.com": "icloud.com",
    "iclod.com": "icloud.com",
    "icoud.com": "icloud.com",
    "protonmai.com": "proton.me",
    "protonmil.com": "proton.me",
    "protonmai.com.br": "proton.me",
}

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "icloud.com", "me.com", "aol.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.de", "mail.com",
    "zoho.com", "yandex.com", "fastmail.com", "tutanota.com", "tutamail.com",
}

_BUNDLED = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "disposed_email.conf")
_BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "blocklist.conf")


class ListsDB:
    """Disposable/role/typo/blocklist data with 24 h TTL and thread safety."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.disposable: Set[str] = set()
        self.blocklist: Set[str] = set()
        self.loaded_at: float = 0.0
        self.ok: bool = False

    def load(self, force: bool = False) -> bool:
        with self._lock:
            if (self.ok and not force
                    and time.time() - self.loaded_at < config.LISTS_CACHE_TTL_S):
                return True
            domains: Set[str] = set()
            try:
                if os.path.exists(_BUNDLED):
                    with open(_BUNDLED, "r", encoding="utf-8", errors="ignore") as f:
                        domains = {ln.strip().lower() for ln in f if ln.strip()
                                   and not ln.startswith("#")}
            except OSError:
                domains = set()
            if config.DISPOSABLE_FETCH_ENABLED:
                try:
                    import requests

                    resp = requests.get(config.DISPOSABLE_LIST_URL, timeout=5)
                    if resp.status_code == 200 and resp.text.strip():
                        domains |= {ln.strip().lower() for ln in resp.text.splitlines()
                                    if ln.strip()}
                except Exception:
                    pass  # keep bundled snapshot
            self.disposable = domains
            self.blocklist = set()
            try:
                if os.path.exists(_BLOCKLIST_FILE):
                    with open(_BLOCKLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
                        self.blocklist = {ln.strip().lower() for ln in f
                                          if ln.strip() and not ln.startswith("#")}
            except OSError:
                pass
            self.loaded_at = time.time()
            self.ok = bool(self.disposable)
            return self.ok


_DB = ListsDB()


def get_db() -> ListsDB:
    if not _DB.ok:
        _DB.load()
    return _DB


def reset_db() -> None:
    """Test hook: drop cached lists."""
    _DB.__init__()


def check_lists(email: str, db: Optional[ListsDB] = None
                ) -> Tuple[Optional[object], List[str], Optional[str], Optional[str]]:
    """Return (stop_cause_or_None, flags, did_you_mean, advice).

    Order: blocklist (always halts) -> disposable -> role -> typo.
    """
    from .models import make_stop_cause

    db = db or get_db()
    if not db.ok:
        return make_stop_cause("E305"), [], None, None
    local, domain = email.rsplit("@", 1)
    local_l = local.lower()
    flags: List[str] = []

    if email.lower() in db.blocklist or domain in db.blocklist:
        return make_stop_cause("E302"), flags, None, None

    # Typo wins over disposable: misspellings of major providers are often
    # listed by disposable feeds too, but the useful answer is the fix.
    if domain in TYPO_DOMAINS:
        fixed = TYPO_DOMAINS[domain]
        return (make_stop_cause("E304", f"probable typo: did you mean {fixed}?"),
                flags, fixed, f"Did you mean {local_l}@{fixed}? Verify the "
                "source of this address before sending.")

    if domain in db.disposable:
        return (make_stop_cause("E301", "disposable email domain"), flags, None,
                "Disposable addresses rarely receive long-term mail; "
                "request a permanent address if this contact matters.")

    if local_l in ROLE_LOCALS:
        return (make_stop_cause("E303", f"role account ({local_l}@)"), flags, None,
                "Role accounts are shared inboxes; engagement is usually low "
                "and complaints are high. Mail to humans, not roles.")

    if domain in FREE_PROVIDERS:
        flags.append("free_provider")
    return None, flags, None, None
