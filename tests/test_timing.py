"""Latency SLO tests (PRD 15.6): hard deadline, DoH cap, warm cache."""
import time

from core.pipeline import clear_all_caches, verify
from helpers import (FakeSmtpSession, FakeSmtpSessionFactory, load_json,
                     make_doh, make_slow_doh)

OK = load_json("doh_ok.json")


def test_fake_smtp_sleeping_10s_cuts_off_at_deadline():
    """A server that never answers must not blow the 3 s budget (E618)."""
    clear_all_caches()
    session = FakeSmtpSession(real=("250", "ok"), rnd=("550", "no"),
                              rcpt_delay_s=10)
    factory = FakeSmtpSessionFactory(default_session=session)
    opts = {"doh_query": make_doh(OK), "smtp_factory": factory}

    t0 = time.monotonic()
    result = verify("sleeper@good.com", opts)
    wall_s = time.monotonic() - t0

    assert result.status.value == "unknown", result.to_dict()
    assert result.reason_code == "E618"
    assert result.stop_cause.retryable is True
    assert "deadline_exceeded" in result.flags
    assert result.status.value != "undeliverable"
    assert wall_s < 3.5, f"wall clock {wall_s:.2f}s"
    # completed stages preserved so a retry resumes at S6
    assert result.stages_completed == ["S1", "S2", "S3", "S4", "S5"]
    assert "S6" in result.stages_skipped


def test_slow_doh_capped_by_per_query_timeout():
    """Fake DoH sleeps long; capped at DOH_TIMEOUT_MS=1000, S4 <= ~1100 ms."""
    clear_all_caches()
    slow = make_slow_doh(sleep_s=10)
    t0 = time.monotonic()
    result = verify("anyone@good.com", {"doh_query": slow, "smtp": False})
    took_ms = (time.monotonic() - t0) * 1000

    assert result.reason_code == "E406"
    assert result.status.value == "unknown"
    assert result.stop_cause.retryable is True
    # configured budget: 1000 ms per query; generous CI margin added
    assert took_ms <= 1100 + 250, f"S4 took {took_ms:.0f} ms"


def test_warm_cache_under_50ms_zero_network_calls():
    clear_all_caches()
    counter = {}

    def counting_doh(name, rtype, timeout_ms):
        key = f"{name}|{rtype}"
        counter[key] = counter.get(key, 0) + 1
        val = OK.get(key)
        return val if val is not None else {"Status": 0, "Answer": []}

    opts = {"doh_query": counting_doh, "smtp": False}
    first = verify("warm@good.com", opts)
    assert first.reason_code == "E601"
    calls_after_first = dict(counter)

    t0 = time.monotonic()
    second = verify("warm@good.com", opts)
    elapsed_ms = (time.monotonic() - t0) * 1000

    assert second.reason_code == "E601"
    assert counter == calls_after_first, "warm re-lookup must hit the DNS cache"
    assert elapsed_ms < 50, f"warm cache took {elapsed_ms:.1f} ms"


def test_deadline_guard_skips_smtp_when_budget_gone():
    clear_all_caches()

    def slow_but_not_quite(name, rtype, timeout_ms):
        # consumes most of a tiny deadline, then succeeds
        time.sleep(timeout_ms / 1000.0)
        val = OK.get(f"{name}|{rtype}")
        return val if val is not None else {"Status": 0, "Answer": []}

    result = verify("anyone@good.com", {
        "doh_query": slow_but_not_quite,
        "deadline_ms": 400,  # S4 eats ~400 ms -> S6 guard trips
        "smtp": True,
        "smtp_factory": FakeSmtpSessionFactory(),
    })
    assert result.status.value == "unknown"
    assert result.reason_code in ("E618", "E406")
    assert result.stop_cause.retryable is True
    assert result.status.value != "undeliverable"


def test_fast_mode_never_opens_smtp():
    clear_all_caches()
    factory = FakeSmtpSessionFactory()
    result = verify("someone@good.com", {"mode": "fast",
                                         "doh_query": make_doh(OK),
                                         "smtp_factory": factory})
    assert result.reason_code == "E601"
    assert result.level == "dns"
    assert factory.connects == []
    assert "S6" in result.stages_skipped
