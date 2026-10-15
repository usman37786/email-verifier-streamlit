"""Tests for smtp-probe/probe.py.

Loads probe.py by path (the directory name has a dash, so it is not a normal
package), runs a minimal in-process SMTP server, and points ProbeSession at it
so no network access is needed. Also asserts the reply->code mapping is
identical to core/smtp_check.py, which is the whole point of the probe.
"""
from __future__ import annotations

import importlib.util
import json
import re
import socket
import threading
from pathlib import Path
from typing import Callable, Dict, Tuple

import pytest

from core import smtp_check


HERE = Path(__file__).resolve().parent
PROBE_PATH = HERE.parent / "smtp-probe" / "probe.py"


def _load_probe():
    spec = importlib.util.spec_from_file_location("probe_mod", PROBE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def probe():
    mod = _load_probe()
    # Loopback is "unsafe" by design; the escape hatch exists exactly for this.
    mod.ALLOW_INSECURE = True
    yield mod
    mod._MX_CACHE.clear()
    mod._CATCHALL_CACHE.clear()
    mod._RECENT_ACCEPT.clear()


def _accept_loop(sock: socket.socket, stop: threading.Event,
                 handle: Callable[[socket.socket], None]) -> None:
    """Accept loop for the fake SMTP server.

    Note: a subclass of threading.Thread that overrode run() did not work here,
    and catching OSError before socket.timeout killed the loop (socket.timeout
    is a subclass of OSError).
    """
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


class FakeSMTP:
    """Minimal SMTP server. reply_for(local_part) -> (code, text)."""

    def __init__(self, reply_for: Callable[[str], Tuple[int, str]]):
        self.reply_for = reply_for
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    def start(self) -> None:
        threading.Thread(target=_accept_loop,
                         args=(self.sock, self._stop, self._handle),
                         daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    @staticmethod
    def _send(conn, text: str) -> None:
        conn.sendall((text + "\r\n").encode("utf-8"))

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(3)
        try:
            lines = conn.makefile("rb")
            self._send(conn, "220 fake.local ESMTP FakeSMTP")
            while True:
                raw = lines.readline()
                if not raw:
                    break
                cmd = raw.decode("utf-8", "ignore").strip()
                if not cmd:
                    continue
                verb = cmd.split(" ", 1)[0].upper()
                if verb == "EHLO":
                    self._send(conn, "250-fake.local")
                    self._send(conn, "250 OK")
                elif verb == "HELO":
                    self._send(conn, "250 OK")
                elif verb == "MAIL":
                    self._send(conn, "250 OK")
                elif verb == "RCPT":
                    local = cmd.split("<", 1)[-1].rstrip(">").strip()
                    local = local.split("@", 1)[0]
                    code, text = self.reply_for(local)
                    self._send(conn, f"{code} {text}")
                elif verb == "RSET":
                    self._send(conn, "250 OK")
                elif verb == "QUIT":
                    self._send(conn, "221 Bye")
                    break
                else:
                    self._send(conn, "502 Not implemented")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _aim(probe, port: int) -> None:
    """Route the probe at a local fake SMTP server.

    The SSRF guard (correctly, in production) rejects loopback, so _resolve_ips
    reports a public IP to get past the guard, while the real connect still
    targets loopback. ALLOW_INSECURE covers the post-connect peer check.
    """
    def fake_init(self, h: str, timeout_s: float):
        import smtplib

        self.host = h
        client = smtplib.SMTP(timeout=timeout_s)
        client.connect("127.0.0.1", port)
        client.ehlo_or_helo_if_needed()
        self.client = client

    probe.ProbeSession.__init__ = fake_init  # type: ignore
    probe.resolve_mx = lambda domain, timeout_s=None: (["mx.example.test"], None)
    probe._resolve_ips = lambda host: ["93.184.216.34"]  # public -> guard OK


@pytest.fixture()
def live(probe):
    """Start a fake SMTP server accepting every address; return (probe, srv)."""
    srv = FakeSMTP(lambda local: (250, "OK"))
    srv.start()
    _aim(probe, srv.port)
    yield probe, srv
    srv.stop()


# ---------------------------------------------------------------------------
# Mapping parity with core/smtp_check.py -- the contract the pipeline relies on.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code,msg,expected", [
    (250, "OK", "OK"),
    (251, "user accepted", "OK"),
    (550, "User unknown", "E610"),
    (551, "not our customer", "E610"),
    (553, "invalid mailbox", "E610"),
    (552, "mailbox full", "E611"),
    (552, "5.2.2 over quota", "E611"),
    (451, "4.7.1 greylisted, retry later", "E612"),
    (450, "5.7.1 policy block", "E614"),  # 5.7.x wins over the code class
    (421, "rate limited", "E613"),
    (450, "try again later", "E613"),
    (500, "unrecognized command", "E617"),
])
def test_classify_rcpt_matches_core(probe, code, msg, expected):
    assert probe.classify_rcpt(code, msg) == expected
    assert probe.classify_rcpt(code, msg) == smtp_check.classify_rcpt(code, msg)


@pytest.mark.parametrize("code,expected", [(250, "OK"), (421, "E613"),
                                           (550, "E608"), (504, "E608")])
def test_classify_mail_from_matches_core(probe, code, expected):
    assert probe.classify_mail_from(code) == expected
    assert probe.classify_mail_from(code) == smtp_check.classify_mail_from(code)


def test_is_unsafe_ip_matches_core_logic(probe):
    for bad in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1",
                "172.16.0.1", "172.31.255.255", "0.0.0.0", "::1",
                "224.0.0.1", "255.255.255.255"):
        assert probe.is_unsafe_ip(bad), bad
    assert not probe.is_unsafe_ip("93.184.216.34")
    assert not probe.is_unsafe_ip("::ffff:93.184.216.34")
    assert probe.is_unsafe_ip("not-an-ip")  # unparsable is treated as unsafe


def test_random_probe_address_is_high_entropy(probe):
    addrs = {probe.random_probe_address("example.com") for _ in range(200)}
    assert len(addrs) == 200
    local = probe.random_probe_address("example.com").split("@")[0]
    assert local.startswith("zq7") and len(local) == 23


def test_no_mail_is_ever_sent():
    """The probe stops after RCPT TO -- there is no DATA/SEND/SENDMAIL."""
    text = PROBE_PATH.read_text(encoding="utf-8")
    for banned in ('docmd("DATA"', 'docmd("SEND"', 'docmd("SMTPUTF8"',
                   'docmd("VRFY"', 'docmd("EXPN"'):
        assert banned not in text
    # Only three SMTP verbs are ever issued, plus RSET and QUIT on teardown.
    issued = re.findall(r'docmd\("([A-Z]+)"', text)
    assert set(issued) == {"MAIL", "RCPT", "RSET"}, issued
    assert "self.client.quit()" in text


def test_deliverable_real_accepted_random_rejected(live):
    probe, _srv = live

    def replies(local):
        if local.startswith("zq7"):
            return 550, "5.1.1 User unknown"
        return 250, "OK"

    srv = FakeSMTP(replies)
    srv.start()
    try:
        _aim(probe, srv.port)
        out = probe.probe_email("user@example.com", probe.MAIL_FROM, 5.0)
    finally:
        srv.stop()
    assert out["code"] == "OK", out
    assert out["catchall"] is False
    assert out["level"] == "smtp"
    assert out["smtp_code"] == 250
    assert "random probe rejected" in out["message"]


def test_catchall_domain_is_risky_never_valid(live):
    probe, _srv = live
    srv = FakeSMTP(lambda local: (250, "OK"))
    srv.start()
    try:
        _aim(probe, srv.port)
        out = probe.probe_email("user@example.com", probe.MAIL_FROM, 5.0)
    finally:
        srv.stop()
    assert out["code"] == "E615", out
    assert out["catchall"] is True
    assert "catch-all" in out["message"]


def test_rejected_mailbox_is_E610(live):
    probe, _srv = live
    srv = FakeSMTP(lambda local: (550, "5.1.1 User unknown"))
    srv.start()
    try:
        _aim(probe, srv.port)
        out = probe.probe_email("user@example.com", probe.MAIL_FROM, 5.0)
    finally:
        srv.stop()
    assert out["code"] == "E610", out
    assert out["catchall"] is False
    assert out["smtp_code"] == 550


def test_greylisting_is_E612_unknown_not_undeliverable(live):
    probe, _srv = live
    srv = FakeSMTP(lambda local: (451, "4.7.1 Greylisted, retry in 60s"))
    srv.start()
    try:
        _aim(probe, srv.port)
        out = probe.probe_email("user@example.com", probe.MAIL_FROM, 5.0)
    finally:
        srv.stop()
    assert out["code"] == "E612", out
    assert out["smtp_code"] == 451
    from core.models import ERROR_CODES
    assert ERROR_CODES["E612"]["status"] == "unknown"


def test_no_mx_record_is_E617(live):
    probe, _srv = live
    probe.resolve_mx = lambda domain, timeout_s=None: (None, "E617")
    out = probe.probe_email("user@nowhere.invalid", probe.MAIL_FROM, 5.0)
    assert out["code"] == "E617", out
    assert "no usable MX" in out["message"]


def test_all_mx_hosts_failed_is_E617(live):
    probe, _srv = live
    probe.resolve_mx = lambda domain, timeout_s=None: (["bad.example"], None)
    probe._resolve_ips = lambda host: ["93.184.216.34"]  # public, so the
                                                         # SSRF guard passes

    def explode(host, timeout_s):
        raise probe.ConnectError("E605", "connection failed")

    probe.ProbeSession = explode  # type: ignore
    out = probe.probe_email("user@example.com", probe.MAIL_FROM, 5.0)
    assert out["code"] == "E617", out
    assert "all MX hosts failed" in out["message"]


def test_full_pipeline_delegates_s6_to_probe(live):
    """The whole point: core.pipeline -> probe_via_service -> real HTTP -> SMTP."""
    from core.pipeline import verify
    from core.models import ERROR_CODES

    probe, _srv = live
    probe._port25_open = lambda: True  # don't burn 3s on the TCP test
    httpd, _thr = _start_http_server(probe)
    try:
        def doh(name, rtype, timeout_ms):
            # Deterministic fake DNS so S1-S5 pass and we reach S6.
            if rtype == "MX":
                return {"Status": 0, "Answer": [
                    {"name": name, "type": 15,
                     "data": "10 mx.example.test."}]}
            if rtype == "A":
                return {"Status": 0, "Answer": [
                    {"name": "mx.example.test", "type": 1,
                     "data": "93.184.216.34"}]}
            return {"Status": 0, "Answer": []}

        result = verify("user@example.com", {
            "doh_query": doh, "smtp": True, "use_cache": False,
            "probe_url": "http://127.0.0.1:%d" % httpd.server_port,
            "deadline_ms": 15000,
        })
        d = result.to_dict()
    finally:
        httpd.shutdown()

    # The fake server accepts every address, so this is a catch-all domain.
    assert d["status"] == "risky", d
    assert d["reason_code"] == "E615", d
    assert d["halted"] is True
    assert "catchall_domain" in d["flags"], d["flags"]
    assert d["stop_cause"]["stage"] == "S6_smtp", d["stop_cause"]
    assert ERROR_CODES["E615"]["status"] == "risky"
    assert "S6" in d["stages_completed"], d["stages_completed"]


def test_pipeline_stays_unknown_when_probe_is_down(live):
    """A dead probe must never be reported as an invalid address."""
    from core.pipeline import verify
    from core.models import ERROR_CODES

    probe, _srv = live
    def doh(name, rtype, timeout_ms):
        if rtype == "MX":
            return {"Status": 0, "Answer": [
                {"name": name, "type": 15, "data": "10 mx.example.test."}]}
        if rtype == "A":
            return {"Status": 0, "Answer": [
                {"name": "mx.example.test", "type": 1,
                 "data": "93.184.216.34"}]}
        return {"Status": 0, "Answer": []}

    d = verify("user@example.com", {
        "doh_query": doh, "smtp": True, "use_cache": False,
        # Nothing is listening on this port.
        "probe_url": "http://127.0.0.1:1", "deadline_ms": 15000,
    }).to_dict()
    assert d["status"] == "unknown", d
    assert d["reason_code"] == "E602", d
    assert ERROR_CODES["E602"]["status"] == "unknown"


# ---------------------------------------------------------------------------
# HTTP layer: the real ThreadingHTTPServer + Handler, driven over a socket.
# ---------------------------------------------------------------------------

def _start_http_server(probe, probe_key: str = ""):
    import http.server
    import threading as _t

    probe.PROBE_API_KEY = probe_key
    handler = type("H", (probe.Handler,), {})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thr = _t.Thread(target=httpd.serve_forever, daemon=True)
    thr.start()
    return httpd, thr


def _post(httpd, path: str, body: dict, key: str = "") -> Tuple[int, dict]:
    import urllib.error
    import urllib.request

    data = json.dumps(body).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (httpd.server_port, path),
        data=data, method="POST",
        headers={"Content-Type": "application/json",
                 **({"X-Probe-Key": key} if key else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.getcode(), json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def test_http_health_and_probe_end_to_end(live):
    probe, _srv = live
    probe._port25_open = lambda: True  # avoid a real 3s TCP connect
    httpd, _thr = _start_http_server(probe)
    try:
        import urllib.request

        with urllib.request.urlopen(
                "http://127.0.0.1:%d/health" % httpd.server_port,
                timeout=20) as resp:
            health = json.loads(resp.read().decode())
        assert health["ok"] is True
        assert isinstance(health["port25"], bool)

        status, body = _post(httpd, "/probe", {
            "email": "user@example.com",
            "sender": probe.MAIL_FROM,
            "timeout_s": 5,
            "check_catchall": True,
        })
        assert status == 200, body
        assert body["code"] == "E615", body      # accepts everything => catchall
        assert body["catchall"] is True
        assert body["level"] == "smtp"
    finally:
        httpd.shutdown()


def test_http_rejects_unknown_paths(live):
    probe, _srv = live
    httpd, _thr = _start_http_server(probe)
    try:
        status, _body = _post(httpd, "/nope", {"email": "a@b"})
        assert status == 404
    finally:
        httpd.shutdown()


def test_http_rejects_bad_json_and_bad_email(live):
    probe, _srv = live
    httpd, _thr = _start_http_server(probe)
    try:
        import urllib.error
        import urllib.request

        raw = urllib.request.Request(
            "http://127.0.0.1:%d/probe" % httpd.server_port,
            data=b"{not json", method="POST",
            headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(raw, timeout=20)
        assert ei.value.code == 400

        status, body = _post(httpd, "/probe", {"email": "not-an-email"})
        assert status == 400, body
        assert body["code"] == "E103"
    finally:
        httpd.shutdown()


def test_http_enforces_api_key_when_configured(live):
    probe, _srv = live
    httpd, _thr = _start_http_server(probe, probe_key="secret")
    try:
        status, _body = _post(httpd, "/probe", {"email": "a@b"}, key="wrong")
        assert status == 401
        status, body = _post(httpd, "/probe", {"email": "a@b"}, key="secret")
        assert status == 200
        assert "code" in body
    finally:
        httpd.shutdown()


def test_http_timeout_clamped_to_sane_bounds(live):
    probe, _srv = live
    httpd, _thr = _start_http_server(probe)
    seen = {}

    orig = probe.probe_email

    def spy(email, sender, timeout_s, check_catchall=True):
        seen["timeout_s"] = timeout_s
        return orig(email, sender, timeout_s, check_catchall)

    probe.probe_email = spy
    try:
        _post(httpd, "/probe", {"email": "user@example.com",
                                "timeout_s": 99999})
        assert seen["timeout_s"] == 30.0, seen
        _post(httpd, "/probe", {"email": "user@example.com",
                                "timeout_s": 0.01})
        assert seen["timeout_s"] == 0.5, seen
    finally:
        httpd.shutdown()
