"""Env-driven settings with sane defaults (all free, no keys required)."""
import os

VALID_MODES = ("fast", "standard", "deep")


def get_mode() -> str:
    m = os.environ.get("MODE", "standard")
    return m if m in VALID_MODES else "standard"


def deadline_ms() -> int:
    """Per-email wall-clock budget. deep=7000, otherwise 3000 (PRD 15.1)."""
    override = os.environ.get("DEADLINE_MS")
    if override:
        try:
            return int(override)
        except ValueError:
            pass
    return 7000 if get_mode() == "deep" else 3000


# Networking knobs (PRD 15.2)
DOH_TIMEOUT_MS = int(os.environ.get("DOH_TIMEOUT_MS", "1000"))
SMTP_CONNECT_TIMEOUT_MS = int(os.environ.get("SMTP_CONNECT_TIMEOUT_MS", "2000"))
SMTP_REPLY_TIMEOUT_MS = int(os.environ.get("SMTP_REPLY_TIMEOUT_MS", "1500"))
# If remaining budget before S6 is below this, skip SMTP and return E618.
DEADLINE_GUARD_MS = int(os.environ.get("DEADLINE_GUARD_MS", "250"))

# S0 request limits
MAX_BULK = int(os.environ.get("MAX_BULK", "100"))
MAX_INPUT_BYTES = int(os.environ.get("MAX_INPUT_BYTES", str(1024 * 1024)))

# Behavior
def get_halt_policy() -> str:
    p = os.environ.get("HALT_POLICY", "strict")
    return p if p in ("strict", "soft") else "strict"


MAIL_FROM = os.environ.get("MAIL_FROM", "verify-probe@example.org")

# Auth / delegation
API_KEY = os.environ.get("API_KEY", "")
SMTP_PROBE_URL = os.environ.get("SMTP_PROBE_URL", "")
SMTP_PROBE_KEY = os.environ.get("SMTP_PROBE_KEY", "")

# Optional third-party adapter (off unless both are set)
TV_API_URL = os.environ.get("TV_API_URL", "")
TV_API_KEY = os.environ.get("TV_API_KEY", "")

# Live-test gating for probe/integration tests
RUN_LIVE = os.environ.get("RUN_LIVE", "") == "1"

# Free disposable list sources: bundled snapshot first, optional live fetch.
DISPOSABLE_LIST_URL = os.environ.get(
    "DISPOSABLE_LIST_URL",
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains"
    "/master/disposable_email_domains.txt",
)
DISPOSABLE_FETCH_ENABLED = os.environ.get("DISPOSABLE_FETCH", "0") == "1"

# Cache TTLs (seconds), PRD 15.4
DOH_CACHE_TTL_S = int(os.environ.get("DOH_CACHE_TTL_S", str(60 * 60)))
CATCHALL_CACHE_TTL_S = int(os.environ.get("CATCHALL_CACHE_TTL_S", str(24 * 60 * 60)))
RESULT_CACHE_TTL_S = int(os.environ.get("RESULT_CACHE_TTL_S", str(6 * 60 * 60)))
LISTS_CACHE_TTL_S = int(os.environ.get("LISTS_CACHE_TTL_S", str(24 * 60 * 60)))

# Bulk throughput (PRD 15.5)
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "8"))
