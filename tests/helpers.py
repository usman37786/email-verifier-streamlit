"""Shared fakes for the Python test-suite (no network, no real SMTP)."""
from __future__ import annotations

import json
import os
import threading
import time

FIXDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load_json(name: str) -> dict:
    with open(os.path.join(FIXDIR, name), encoding="utf-8") as f:
        return json.load(f)


def make_doh(mapping: dict, counter: dict | None = None):
    """Build an injectable DoH query from a {name|TYPE: response} mapping."""

    def doh(name: str, rtype: str, timeout_ms: int) -> dict:
        key = f"{name}|{rtype}"
        if counter is not None:
            counter[key] = counter.get(key, 0) + 1
        val = mapping.get(key)
        if val is None:
            return {"Status": 0, "Answer": []}
        return val

    return doh


def make_slow_doh(sleep_s: float):
    """Fake DoH that honors its timeout budget, then times out (requests-like)."""

    def doh(name: str, rtype: str, timeout_ms: int) -> dict:
        time.sleep(min(sleep_s, timeout_ms / 1000.0))
        from core.dns_check import DohTimeout

        raise DohTimeout(f"fake timeout for {name} {rtype}")

    return doh


class FakeSmtpSession:
    """Protocol-compatible stand-in for core.smtp_check.SmtpSession."""

    @staticmethod
    def _pair(spec):
        """Normalize (code, msg) specs; accepts int or str codes."""
        if isinstance(spec, (tuple, list)) and len(spec) == 2:
            return int(spec[0]), str(spec[1])
        text = str(spec)
        return int(text.split(" ", 1)[0]), text

    def __init__(self, real=(250, "2.1.5 Ok"), rnd=(550, "5.1.1 No such user"),
                 peer="93.184.216.50", mail_from=(250, "Ok"),
                 rcpt_delay_s: float = 0.0):
        self.real = real
        self.rnd = rnd
        self._peer = peer
        self._mail = mail_from
        self.rcpt_delay_s = rcpt_delay_s
        self.rcpt_calls: list[str] = []
        self.quit_called = False
        self._lock = threading.Lock()

    def peer_ip(self):
        return self._peer

    def mail_from(self, sender):
        return self._pair(self._mail)

    def rcpt(self, address: str):
        if self.rcpt_delay_s:
            time.sleep(self.rcpt_delay_s)
        with self._lock:
            self.rcpt_calls.append(address)
        if address.lower().startswith("zq7"):
            return self._pair(self.rnd)
        return self._pair(self.real)

    def rset(self):
        pass

    def quit(self):
        self.quit_called = True


class FakeSmtpSessionFactory:
    """Returns one FakeSmtpSession per host; counts connects.

    `behavior` maps host -> session or exception to raise for that host.
    The default session is used for hosts without an entry.
    """

    def __init__(self, default_session=None, behavior: dict | None = None):
        self.default_session = default_session or FakeSmtpSession()
        self.behavior = behavior or {}
        self.connects: list[str] = []
        self._lock = threading.Lock()

    def __call__(self, host: str, timeout_s: float):
        with self._lock:
            self.connects.append(host)
        act = self.behavior.get(host, self.default_session)
        if isinstance(act, BaseException):
            raise act
        return act


def ok_doh(extra: dict | None = None) -> dict:
    """Fixture mapping for good.com plus optional extra entries."""
    mapping = load_json("doh_ok.json")
    if extra:
        mapping.update(extra)
    return mapping
