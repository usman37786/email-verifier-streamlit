#!/usr/bin/env python3
"""SMTP probe microservice (PRD section 10).

Python stdlib only -- no pip installs. Exposes:

    POST /probe   {"email", "sender", "timeout_s", "check_catchall"}
                  -> {"code", "smtp_code", "message", "catchall", "level"}
    GET  /health  -> {"ok": true, "port25": true}

Reply code -> verdict mapping is identical to core/smtp_check.py, so a caller
that already runs the pipeline gets the same reason_codes whether S6 is done
locally or delegated here. MX resolution order: dnspython (if installed) ->
free DoH JSON -> the domain's own A record (RFC 5321 fallback). No mail is
ever sent: the conversation stops after RCPT TO, then RSET/QUIT.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import smtplib
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional, Tuple

MAIL_FROM = os.environ.get("MAIL_FROM", "verify-probe@example.org")
PROBE_TIMEOUT_S = float(os.environ.get("PROBE_TIMEOUT_S", "7"))
CONNECT_TIMEOUT_S = float(os.environ.get("PROBE_CONNECT_TIMEOUT_S", "3"))
# SMTP port to dial. 25 is normal; set e.g. 2525 for submissions/testing so the
# service is usable and testable on hosts where port 25 is blocked.
SMTP_PORT = int(os.environ.get("PROBE_SMTP_PORT", "25"))
MX_CACHE_TTL_S = float(os.environ.get("MX_CACHE_TTL_S", "3600"))
CATCHALL_TTL_S = float(os.environ.get("CATCHALL_TTL_S", str(24 * 3600)))
HOST = os.environ.get("PROBE_HOST", "0.0.0.0")
PORT = int(os.environ.get("PROBE_PORT", "8787"))
# Set PROBE_API_KEY to require the X-Probe-Key header. Unset => open (dev).
PROBE_API_KEY = os.environ.get("PROBE_API_KEY", "")
# Dev/test escape hatch. Never set this in production.
ALLOW_INSECURE = os.environ.get("PROBE_ALLOW_INSECURE", "") == "1"

_LOCK = threading.Lock()
_MX_CACHE: dict = {}
_CATCHALL_CACHE: dict = {}


def classify_rcpt(code: int, message: str) -> str:
    """Map an SMTP RCPT reply to a registry code (PRD S6 table)."""
    msg = (message or "").lower()
    if code in (250, 251):
        return "OK"
    if "5.7." in msg:
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


def random_probe_address(domain: str) -> str:
    """High-entropy address no human typed (never a dictionary word)."""
    return f"zq7{secrets.token_hex(10)}@{domain}"


def is_unsafe_ip(ip_text: str) -> bool:
    """Private/loopback/link-local/reserved/multicast/unspecified == unsafe."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _strip_dot(name: str) -> str:
    return str(name).rstrip(".")


def _hosts_from_doh(domain: str, timeout_s: float) -> List[str]:
    """Free DoH JSON query for MX. No API key required."""
    for endpoint in ("https://cloudflare-dns.com/dns-query",
                     "https://dns.google/resolve"):
        try:
            req = urllib.request.Request(
                endpoint,
                headers={"accept": "application/dns-json",
                         "user-agent": "email-verify-probe/1.0"})
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            if int(data.get("Status", -1)) not in (0, 3):
                continue
            records = [a for a in data.get("Answer", [])
                       if isinstance(a, dict) and a.get("type") == 15]
            if not records:
                continue
            if {_strip_dot(a.get("data", "")) for a in records} == {"."}:
                return []  # RFC 7505 null MX -> caller falls back to A record
            records.sort(key=lambda a: int(a.get("preference", 0)))
            return [_strip_dot(a["data"]) for a in records]
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            continue
    return []


def resolve_mx(domain: str, timeout_s: Optional[float] = None
               ) -> Tuple[Optional[List[str]], Optional[str]]:
    """Return (mx_hosts, error_code); mx_hosts is None on failure."""
    timeout_s = CONNECT_TIMEOUT_S if timeout_s is None else timeout_s
    domain = _strip_dot((domain or "").lower())
    if not domain:
        return None, "E617"
    with _LOCK:
        hit = _MX_CACHE.get(domain)
        if hit and time.time() - hit[2] < MX_CACHE_TTL_S:
            return hit[0], hit[1]

    hosts: List[str] = []
    # 1) dnspython, when present (honours system resolver config).
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout_s)
        hosts = [_strip_dot(a.exchange.text)
                 for a in sorted(answers, key=lambda a: a.preference)]
        if hosts == ["."]:
            hosts = []
    except Exception:  # noqa: BLE001 - not installed or lookup failed
        hosts = []
    if not hosts:
        hosts = _hosts_from_doh(domain, timeout_s)
    # 2) RFC 5321: no usable MX -> use the domain's own A record.
    if not hosts:
        try:
            infos = socket.getaddrinfo(
                domain, SMTP_PORT, type=socket.SOCK_STREAM)
            hosts = sorted({_strip_dot(i[4][0]) for i in infos if i[4][0]})
        except OSError:
            hosts = []
    if not hosts:
        with _LOCK:
            _MX_CACHE[domain] = (None, "E617", time.time())
        return None, "E617"
    with _LOCK:
        _MX_CACHE[domain] = (hosts, None, time.time())
    return hosts, None


def _resolve_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, SMTP_PORT, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos if i[4][0]})


def _text(msg) -> str:
    if isinstance(msg, (bytes, bytearray)):
        return msg.decode("utf-8", "ignore")
    return str(msg)


class ConnectError(Exception):
    """Raised when a session cannot be established; carries a registry code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ProbeSession:
    """smtplib-backed session; the only place a raw socket is opened."""

    def __init__(self, host: str, timeout_s: float):
        self.host = host
        client = smtplib.SMTP(timeout=timeout_s)
        try:
            client.connect(host, SMTP_PORT)
        except socket.timeout as exc:
            raise ConnectError("E604", f"connect timeout to {host}") from exc
        except smtplib.SMTPConnectError as exc:
            raise ConnectError("E606",
                               f"bad greeting from {host}: {exc}") from exc
        except (ConnectionRefusedError, ConnectionResetError,
                OSError) as exc:
            raise ConnectError("E605",
                               f"connection failed to {host}: {exc}") from exc
        try:
            client.ehlo_or_helo_if_needed()
        except (smtplib.SMTPException, OSError) as exc:
            client.close()
            raise ConnectError("E606", f"EHLO/HELO failed: {exc}") from exc
        self.client = client

    def peer_ip(self) -> Optional[str]:
        try:
            return self.client.sock.getpeername()[0]
        except Exception:  # noqa: BLE001
            return None

    def mail_from(self, sender: str) -> Tuple[int, str]:
        code, msg = self.client.docmd("MAIL", f"FROM:<{sender}>")
        return code, _text(msg)

    def rcpt(self, address: str) -> Tuple[int, str]:
        code, msg = self.client.docmd("RCPT", f"TO:<{address}>")
        return code, _text(msg)

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


_RECENT_ACCEPT: dict = {}


def _catchall_cached(domain: str) -> Optional[bool]:
    with _LOCK:
        hit = _CATCHALL_CACHE.get(domain)
        if hit and time.time() - hit[1] < CATCHALL_TTL_S:
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
    return bool(ts and time.time() - ts < CATCHALL_TTL_S)


def probe_email(email: str, sender: str, timeout_s: float,
                check_catchall: bool = True) -> dict:
    """Probe one address. Returns the JSON payload for POST /probe."""
    out = {"code": "OK", "smtp_code": None, "message": "",
           "catchall": False, "level": "smtp"}
    domain = _strip_dot(email.rsplit("@", 1)[1].lower())
    hosts, err = resolve_mx(domain, timeout_s)
    if not hosts:
        out["code"] = err or "E617"
        out["message"] = f"no usable MX or A record for {domain}"
        return out

    errors: List[str] = []
    for host in hosts:
        if host.lower().endswith(".local"):
            errors.append(f"{host}: unsafe hostname")
            continue
        ips = _resolve_ips(host)
        if not ips:
            errors.append(f"{host}: does not resolve")
            continue
        if all(is_unsafe_ip(ip) for ip in ips):
            errors.append(f"{host}: resolves to unsafe IP {ips[0]}")
            continue
        try:
            session = ProbeSession(host, timeout_s)
        except ConnectError as exc:
            errors.append(f"{host}: {exc.message}")
            continue
        return _conversation(session, email, domain, sender,
                             timeout_s, check_catchall)
    out["code"] = "E617"
    out["message"] = "all MX hosts failed: " + "; ".join(errors)
    return out


def _conversation(session, email, domain, sender, timeout_s,
                  check_catchall) -> dict:
    """Run MAIL FROM + RCPT TO (+ random RCPT) and map the replies."""
    out = {"code": "OK", "smtp_code": None, "message": "",
           "catchall": False, "level": "smtp"}
    try:
        if not ALLOW_INSECURE:
            peer = session.peer_ip()
            if peer and is_unsafe_ip(peer):
                session.quit()
                out["code"] = "E616"
                out["message"] = "SSRF guard: MX peer IP is unsafe"
                return out
        code, msg = session.mail_from(sender)
        mapped = classify_mail_from(code)
        if mapped != "OK":
            session.rset()
            session.quit()
            out["code"] = mapped
            out["smtp_code"] = code
            out["message"] = f"MAIL FROM rejected: {code} {msg}"
            return out
        code, msg = session.rcpt(email)
        verdict = classify_rcpt(code, msg)
        out["smtp_code"] = code
        if verdict != "OK":
            session.rset()
            session.quit()
            out["code"] = verdict
            out["message"] = (f"mailbox rejected: {code} {msg}"
                              if verdict == "E610"
                              else f"RCPT reply {code} {msg}")
            return out
        if not check_catchall:
            session.rset()
            session.quit()
            out["message"] = "mailbox accepted (catch-all check skipped)"
            return out

        cached = _catchall_cached(domain)
        if cached is False:
            session.rset()
            session.quit()
            out["message"] = "mailbox accepted; random probe rejected"
            return out
        if cached is True:
            session.rset()
            session.quit()
            out["code"] = "E615"
            out["catchall"] = True
            out["message"] = "catch-all domain (cached verdict)"
            return out
        rcode, rmsg = session.rcpt(random_probe_address(domain))
        rverdict = classify_rcpt(rcode, rmsg)
        if rverdict == "OK":
            _catchall_store(domain, True)
            session.rset()
            session.quit()
            out["code"] = "E615"
            out["catchall"] = True
            out["smtp_code"] = rcode
            out["message"] = "catch-all domain: random address accepted too"
            return out
        if rverdict in ("E612", "E613", "E614"):
            session.rset()
            session.quit()
            out["code"] = rverdict
            out["smtp_code"] = rcode
            out["message"] = f"random probe reply {rcode} {rmsg}"
            return out
        # Lazy wildcard servers may accept the second random address; re-probe
        # once only if this domain was recently seen accepting (PRD 6).
        if _recently_accepting(domain):
            rcode2, rmsg2 = session.rcpt(random_probe_address(domain))
            if classify_rcpt(rcode2, rmsg2) == "OK":
                _catchall_store(domain, True)
                session.rset()
                session.quit()
                out["code"] = "E615"
                out["catchall"] = True
                out["smtp_code"] = rcode2
                out["message"] = ("catch-all domain: second random "
                                  "address accepted")
                return out
        _catchall_store(domain, False)
        session.rset()
        session.quit()
        out["message"] = "mailbox accepted; random probe rejected"
        return out
    except (BrokenPipeError, ConnectionResetError, EOFError,
            OSError) as exc:
        session.quit()
        out["code"] = "E609"
        out["message"] = f"session dropped mid-conversation: {exc}"
        return out


def _port25_open() -> bool:
    """3 s TCP connect test to a well-known MX (PRD 10)."""
    try:
        with socket.create_connection(("aspmx.l.google.com", 25), timeout=3):
            return True
    except OSError:
        return False


class Handler(BaseHTTPRequestHandler):
    """POST /probe, GET /health. Stdlib only."""

    server_version = "smtp-probe/1.0"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("probe %s - %s\n" % (self.address_string(),
                                              fmt % args))

    def do_GET(self) -> None:
        if self.path.rstrip("/") != "/health":
            self._send(404, {"ok": False, "error": "not found"})
            return
        self._send(200, {"ok": True, "port25": _port25_open()})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/probe":
            self._send(404, {"ok": False, "error": "not found"})
            return
        if PROBE_API_KEY:
            if self.headers.get("X-Probe-Key") != PROBE_API_KEY:
                self._send(401, {"ok": False, "error": "bad probe key"})
                return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 1_048_576:  # PRD 12: 1 MB cap
            self._send(400, {"ok": False, "error": "bad body size"})
            return
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"ok": False, "error": "invalid JSON"})
            return
        if not isinstance(data, dict):
            self._send(400, {"ok": False, "error": "expected a JSON object"})
            return

        email = str(data.get("email") or "").strip()
        if not email or "@" not in email or len(email) > 320:
            self._send(400, {"ok": False, "code": "E103",
                             "message": "invalid or missing email"})
            return
        sender = str(data.get("sender") or MAIL_FROM).strip() or MAIL_FROM
        try:
            timeout_s = float(data.get("timeout_s") or PROBE_TIMEOUT_S)
        except (TypeError, ValueError):
            timeout_s = PROBE_TIMEOUT_S
        timeout_s = min(max(timeout_s, 0.5), 30.0)
        check_catchall = bool(data.get("check_catchall", True))

        result = probe_email(email, sender, timeout_s, check_catchall)
        result = {"code": result["code"], "smtp_code": result.get("smtp_code"),
                  "message": result.get("message", "")[:300],
                  "catchall": bool(result.get("catchall")),
                  "level": "smtp"}
        self._send(200, result)


def main() -> None:
    sys.stderr.write(
        "smtp-probe listening on %s:%d (smtp_port=%d, api_key=%s, "
        "allow_insecure=%s)\n"
        % (HOST, PORT, SMTP_PORT, "set" if PROBE_API_KEY else "OPEN",
           ALLOW_INSECURE))
    sys.stderr.flush()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

