"""S6: SMTP probe (direct smtplib or external probe service).

Hard rules: never send mail (stop at RCPT TO, then RSET/QUIT); connection and
IP problems are S-class -> unknown, never undeliverable; catch-all domains are
risky (E615), never valid. Catch-all verdicts are cached per domain (24 h).
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import config

_CATCHALL_TTL = 24 * 60 * 60
_CATCHALL_CACHE: Dict[str, Tuple[bool, float]] = {}
_RECENT_ACCEPT: Dict[str, float] = {}
_POOL: Dict[str, Tuple[object, object]] = {}  # domain -> (factory, session)
_LOCK = threading.Lock()


def reset_caches() -> None:
    """Test hook: drop catch-all cache and session pool."""
    with _LOCK:
        _CATCHALL_CACHE.clear()
        _RECENT_ACCEPT.clear()
    close_pool()  # acquires _LOCK itself; must be called without it held


def close_pool() -> None:
    with _LOCK:
        sessions = list(_POOL.values())
        _POOL.clear()
    for _factory, session in sessions:
        try:
            session.quit()
        except Exception:  # noqa: BLE001
            pass


class SmtpConnectError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class SmtpVerdict:
    stop_code: Optional[str]  # None => deliverable (SMTP-proven)
    message: str
    catchall: bool = False
    smtp_code: Optional[int] = None
    flags: List[str] = field(default_factory=list)


# Sender-side policy rejections. These refuse OUR connection, not the address,
# so they must never fall through to E610 ("mailbox rejected" -> Invalid): a
# live mailbox would be reported unreachable purely because this host's outbound
# IP is listed. Matched BEFORE the bare 550/551/553 check below, which is what
# separates a truthful "unknown, retry later" from a false negative.
#
# The literal "5.7." test alone was insufficient: Barracuda answers
#     550 JunkMail rejected - host ([127.0.0.1]) [34.127.0.121]:3968 is in an RBL
# with no enhanced-status token at all, so it landed in E610 and got scored
# as "Invalid". The keyword set below catches that shape too.
_POLICY_MARKERS = (
    "5.7.",           # enhanced status class 5.7 (security / policy)
    "5.7 ",           # "550 5.7" truncated at end of line
    "rbl",            # "[1.2.3.4]:3968 is in an RBL"
    "blocklist",
    "blacklist",
    "spamhaus",
    "barracuda",
    "spamtrap",
    "junkmail",
    "sender reputation",
)


def is_sender_policy(message: str) -> bool:
    """True when the reply rejects our sender, not the recipient address."""
    msg = (message or "").lower()
    return any(marker in msg for marker in _POLICY_MARKERS)


def classify_rcpt(code: int, message: str) -> str:
    """Map an SMTP RCPT reply to a registry code (PRD S6 table)."""
    msg = (message or "").lower()
    if code in (250, 251):
        return "OK"
    if is_sender_policy(msg):
        return "E614"
    if code == 552 or "5.2.2" in msg:
        return "E611"
    if code in (550, 551, 553):
        return "E610"
    if code in (421, 450):
        return "E613"
    if 400 <= code < 500:
        return "E612"
    return "E617"


def classify_mail_from(code: int) -> str:
    if code == 250:
        return "OK"
    if code == 421:
        return "E613"
    return "E608"


class SmtpSession:
    """smtplib-backed session; the only place raw sockets are opened."""

    def __init__(self, host: str, timeout_s: float, port: int = 25):
        import socket
        import smtplib

        self.host = host
        client = smtplib.SMTP(timeout=timeout_s)
        try:
            client.connect(host, port)
        except socket.timeout as exc:
            raise SmtpConnectError("E604", f"connect timeout to {host}") from exc
        except smtplib.SMTPConnectError as exc:
            raise SmtpConnectError("E606", f"bad greeting from {host}: {exc}") from exc
        except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            raise SmtpConnectError("E605", f"connection failed to {host}: {exc}") from exc
        try:
            client.ehlo_or_helo_if_needed()
        except (smtplib.SMTPException, OSError) as exc:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
            raise SmtpConnectError("E606", f"EHLO/HELO failed: {exc}") from exc
        self.client = client

    def peer_ip(self) -> Optional[str]:
        try:
            return self.client.sock.getpeername()[0]
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _text(msg) -> str:
        if isinstance(msg, (bytes, bytearray)):
            return msg.decode("utf-8", "ignore")
        return str(msg)

    def mail_from(self, sender: str) -> Tuple[int, str]:
        code, msg = self.client.docmd("MAIL", f"FROM:<{sender}>")
        return code, self._text(msg)

    def rcpt(self, address: str) -> Tuple[int, str]:
        code, msg = self.client.docmd("RCPT", f"TO:<{address}>")
        return code, self._text(msg)

    def rset(self) -> None:
        try:
            self.client.docmd("RSET", "")
        except Exception:  # noqa: BLE001
            pass

    def quit(self) -> None:
        try:
            self.client.quit()
        except Exception:  # noqa: BLE001
            try:
                self.client.close()
            except Exception:  # noqa: BLE001
                pass


def _default_factory(host: str, timeout_s: float):
    return SmtpSession(host, timeout_s)

def _get_session(domain: str, mx_hosts: List[str], factory: Callable,
                 timeout_s: float):
    """One SMTP session per domain, reused across emails (PRD 15.5)."""
    with _LOCK:
        entry = _POOL.get(domain)
    if entry is not None and entry[0] is factory:
        return entry[1]
    errors: List[str] = []
    for host in mx_hosts:
        try:
            session = factory(host, timeout_s)
        except SmtpConnectError as exc:
            errors.append(f"{host}: {exc.message}")
            continue
        except Exception as exc:  # noqa: BLE001 - fake factories may raise
            errors.append(f"{host}: {exc}")
            continue
        with _LOCK:
            _POOL[domain] = (factory, session)
        return session
    raise SmtpConnectError("E617", "all MX hosts failed: " + "; ".join(errors))


def _drop_session(domain: str, session) -> None:
    with _LOCK:
        entry = _POOL.get(domain)
        if entry is not None and entry[1] is session:
            _POOL.pop(domain, None)
    try:
        session.quit()
    except Exception:  # noqa: BLE001
        pass


def _catchall_cached(domain: str) -> Optional[bool]:
    with _LOCK:
        hit = _CATCHALL_CACHE.get(domain)
        if hit and time.time() - hit[1] < _CATCHALL_TTL:
            return hit[0]
        return None


def _catchall_store(domain: str, is_catchall: bool) -> None:
    with _LOCK:
        _CATCHALL_CACHE[domain] = (is_catchall, time.time())
        if is_catchall:
            _RECENT_ACCEPT[domain] = time.time()


def _recently_accepting(domain: str) -> bool:
    with _LOCK:
        ts = _RECENT_ACCEPT.get(domain)
    return bool(ts and time.time() - ts < _CATCHALL_TTL)


def random_probe_address(domain: str) -> str:
    """High-entropy address no human typed (never a dictionary word)."""
    return f"zq7{secrets.token_hex(10)}@{domain}"


def _unsafe_peer(session) -> bool:
    ip = session.peer_ip()
    if not ip:
        return False
    from .dns_check import _is_unsafe_ip

    return _is_unsafe_ip(ip)



def probe_email(email: str, mx_hosts: List[str], opts: Optional[dict] = None,
                remaining_fn: Optional[Callable] = None) -> SmtpVerdict:
    """Direct SMTP probe for one address against the domain's MX hosts."""
    opts = opts or {}
    sender = opts.get("sender") or config.MAIL_FROM
    domain = email.rsplit("@", 1)[1]
    factory = opts.get("smtp_factory") or _default_factory

    budget_ms = config.SMTP_CONNECT_TIMEOUT_MS
    if remaining_fn is not None:
        budget_ms = min(budget_ms, max(50, int(remaining_fn())))
    timeout_s = budget_ms / 1000.0

    try:
        session = _get_session(domain, mx_hosts, factory, timeout_s)
    except SmtpConnectError as exc:
        return SmtpVerdict(stop_code=exc.code, message=exc.message)

    try:
        if _unsafe_peer(session):
            _drop_session(domain, session)
            return SmtpVerdict(stop_code="E616",
                               message="SSRF guard: MX peer IP is unsafe")
        code, msg = session.mail_from(sender)
        mapped = classify_mail_from(code)
        if mapped != "OK":
            _drop_session(domain, session)
            return SmtpVerdict(stop_code=mapped,
                               message=f"MAIL FROM rejected: {code} {msg}",
                               smtp_code=code)
        code, msg = session.rcpt(email)
        verdict = classify_rcpt(code, msg)
        if verdict == "E610":
            session.rset()
            return SmtpVerdict(stop_code="E610",
                               message=f"mailbox rejected: {code} {msg}",
                               smtp_code=code)
        if verdict != "OK":
            session.rset()
            return SmtpVerdict(
                stop_code=verdict,
                message=f"RCPT reply {code} {msg}",
                smtp_code=code,
                # E614 blames our outbound IP/PTR, not the address. Carry a flag
                # so the UI and any CSV export can say so instead of the row
                # reading like a verdict about the recipient.
                flags=["sender_blocked"] if verdict == "E614" else [],
            )
        # Real address accepted: prove it is not a catch-all domain.
        cached = _catchall_cached(domain)
        if cached is False:
            session.rset()
            return SmtpVerdict(stop_code=None, smtp_code=code,
                               message="mailbox accepted; random probe rejected")
        if cached is True:
            session.rset()
            return SmtpVerdict(stop_code="E615", catchall=True,
                               message="catch-all domain (cached verdict)",
                               flags=["catchall_domain"])
        rcode, rmsg = session.rcpt(random_probe_address(domain))
        rverdict = classify_rcpt(rcode, rmsg)
        if rverdict == "OK":
            _catchall_store(domain, True)
            session.rset()
            return SmtpVerdict(
                stop_code="E615", catchall=True, smtp_code=rcode,
                flags=["catchall_domain"],
                message="catch-all domain: random address accepted too")
        if rverdict in ("E612", "E613", "E614"):
            session.rset()
            return SmtpVerdict(
                stop_code=rverdict, smtp_code=rcode,
                message=f"random probe reply {rcode} {rmsg}",
                flags=["sender_blocked"] if rverdict == "E614" else [],
            )
        # Random rejected; lazy wildcard servers may accept the second random
        # address - re-probe once only if recently seen accepting (PRD 6).
        if _recently_accepting(domain):
            rcode2, rmsg2 = session.rcpt(random_probe_address(domain))
            if classify_rcpt(rcode2, rmsg2) == "OK":
                _catchall_store(domain, True)
                session.rset()
                return SmtpVerdict(
                    stop_code="E615", catchall=True, smtp_code=rcode2,
                    flags=["catchall_domain"],
                    message="catch-all domain: second random address accepted")
        _catchall_store(domain, False)
        session.rset()
        return SmtpVerdict(stop_code=None, smtp_code=code,
                           message="mailbox accepted; random probe rejected")
    except (BrokenPipeError, ConnectionResetError, EOFError, OSError) as exc:
        _drop_session(domain, session)
        return SmtpVerdict(stop_code="E609",
                           message=f"session dropped mid-conversation: {exc}")


def probe_via_service(email: str, opts: Optional[dict] = None) -> SmtpVerdict:
    """Delegate S6 to the external smtp-probe service (PRD 10)."""
    from .models import ERROR_CODES

    opts = opts or {}
    url = (opts.get("probe_url") or config.SMTP_PROBE_URL).rstrip("/")
    key = opts.get("probe_key") or config.SMTP_PROBE_KEY
    import requests

    try:
        resp = requests.post(
            url + "/probe",
            json={"email": email,
                  "sender": opts.get("sender") or config.MAIL_FROM,
                  "timeout_s": opts.get("probe_timeout_s", 7),
                  "check_catchall": True},
            headers={"X-Probe-Key": key} if key else {},
            timeout=float(opts.get("probe_http_timeout_s", 10)),
        )
    except Exception as exc:  # noqa: BLE001 - network failure is S-class
        return SmtpVerdict(stop_code="E602", message=f"probe unreachable: {exc}")
    if resp.status_code == 401:
        return SmtpVerdict(stop_code="E603", message="probe auth failed")
    if resp.status_code != 200:
        return SmtpVerdict(stop_code="E602",
                           message=f"probe HTTP {resp.status_code}")
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return SmtpVerdict(stop_code="E602", message="probe returned invalid JSON")
    code = str(data.get("code", "E602"))
    message = str(data.get("message", ""))[:300]
    catchall = bool(data.get("catchall"))
    if code == "OK" and not catchall:
        return SmtpVerdict(stop_code=None, catchall=False,
                           smtp_code=data.get("smtp_code"),
                           message=message or "mailbox accepted (external probe)")
    if code == "OK" and catchall:
        code = "E615"
    if code not in ERROR_CODES:
        code = "E602"
    return SmtpVerdict(stop_code=code, catchall=catchall,
                       smtp_code=data.get("smtp_code"), message=message,
                       flags=["catchall_domain"] if catchall else [])
