"""Catch-all + SMTP reply matrix with mocked SMTP (PRD 13.7, section 6)."""
from core.pipeline import clear_all_caches, verify
from core.smtp_check import (SmtpConnectError, classify_rcpt, probe_email,
                             random_probe_address)
from helpers import FakeSmtpSession, FakeSmtpSessionFactory, load_json, make_doh

OK = load_json("doh_ok.json")
PRIVMX = load_json("doh_privmx.json")


def opts_for(session, doh=None):
    factory = FakeSmtpSessionFactory(default_session=session)
    return {"doh_query": make_doh(doh or OK), "smtp_factory": factory}, factory


def test_classify_rcpt_table():
    assert classify_rcpt(250, "Ok") == "OK"
    assert classify_rcpt(251, "Ok") == "OK"
    assert classify_rcpt(550, "5.1.1 no such user") == "E610"
    assert classify_rcpt(551, "user not local") == "E610"
    assert classify_rcpt(553, "no") == "E610"
    assert classify_rcpt(552, "full") == "E611"
    assert classify_rcpt(550, "5.2.2 mailbox full") == "E611"
    assert classify_rcpt(550, "5.7.1 blocked by policy") == "E614"
    assert classify_rcpt(552, "5.7.1 reputation") == "E614"
    assert classify_rcpt(451, "greylist") == "E612"
    assert classify_rcpt(421, "try later") == "E613"
    assert classify_rcpt(450, "busy") == "E613"
    assert classify_rcpt(554, "no") == "E617"


def test_accept_reject_deliverable():
    clear_all_caches()
    session = FakeSmtpSession(real=("250", "ok"), rnd=("550", "no such user"))
    opts, _ = opts_for(session)
    result = verify("someone@good.com", opts)
    assert result.status.value == "deliverable"
    assert result.reason_code == "OK"
    assert 90 <= result.score <= 100
    assert result.level == "smtp"
    assert "smtp_proven" in result.flags
    assert "S6" in result.stages_completed


def test_accept_accept_catchall_risky():
    clear_all_caches()
    session = FakeSmtpSession(real=("250", "ok"), rnd=("250", "ok"))
    opts, _ = opts_for(session)
    result = verify("someone@good.com", opts)
    assert result.status.value == "risky"
    assert result.reason_code == "E615"
    assert 45 <= result.score <= 55
    assert "catchall_domain" in result.flags
    assert result.advice  # honest reporting guidance
    assert result.status.value != "deliverable"


def test_reject_550_undeliverable():
    clear_all_caches()
    session = FakeSmtpSession(real=("550", "5.1.1 unknown user"))
    opts, _ = opts_for(session)
    result = verify("ghost@good.com", opts)
    assert result.status.value == "undeliverable"
    assert result.reason_code == "E610"
    assert result.score <= 10
    # random probe never needed after a definitive rejection
    assert not any(c.startswith("zq7") for c in session.rcpt_calls)


def test_greylist_unknown_retryable():
    clear_all_caches()
    session = FakeSmtpSession(real=("451", "greylisting, try later"))
    opts, _ = opts_for(session)
    result = verify("slow@good.com", opts)
    assert result.status.value == "unknown"
    assert result.reason_code == "E612"
    assert result.stop_cause.retryable is True


def test_mailbox_full_risky():
    clear_all_caches()
    session = FakeSmtpSession(real=("552", "over quota"))
    opts, _ = opts_for(session)
    result = verify("busy@good.com", opts)
    assert result.status.value == "risky"
    assert result.reason_code == "E611"


def test_policy_block_5_7_1_unknown():
    clear_all_caches()
    session = FakeSmtpSession(real=("550", "5.7.1 blocked by reputation"))
    opts, _ = opts_for(session)
    result = verify("blocked@good.com", opts)
    assert result.status.value == "unknown"
    assert result.reason_code == "E614"
    assert result.stop_cause.retryable is True


def test_all_mx_fail_e617():
    clear_all_caches()
    behavior = {"mx.good.com": SmtpConnectError("E604", "connect timeout")}
    factory = FakeSmtpSessionFactory(behavior=behavior)
    opts = {"doh_query": make_doh(OK), "smtp_factory": factory}
    result = verify("someone@good.com", opts)
    assert result.status.value == "unknown"
    assert result.reason_code == "E617"
    assert result.stop_cause.retryable is True


def test_mx_failover_tries_next_host():
    clear_all_caches()
    mapping = dict(OK)
    mapping["good.com|MX"] = {"Status": 0, "Answer": [
        {"name": "good.com", "type": 15, "data": "10 mx.good.com."},
        {"name": "good.com", "type": 15, "data": "20 mx2.good.com."},
    ]}
    mapping["mx2.good.com|A"] = {"Status": 0, "Answer": [
        {"name": "mx2.good.com", "type": 1, "data": "93.184.216.66"}]}
    mapping["mx2.good.com|AAAA"] = {"Status": 0, "Answer": []}
    good = FakeSmtpSession(real=("250", "ok"), rnd=("550", "no"))
    factory = FakeSmtpSessionFactory(behavior={
        "mx.good.com": SmtpConnectError("E605", "connection refused"),
        "mx2.good.com": good,
    })
    opts = {"doh_query": make_doh(mapping), "smtp_factory": factory}
    result = verify("someone@good.com", opts)
    assert result.status.value == "deliverable"
    assert factory.connects == ["mx.good.com", "mx2.good.com"]


def test_catchall_cache_second_email_skips_random_probe():
    clear_all_caches()
    session = FakeSmtpSession(real=("250", "ok"), rnd=("250", "ok"))
    opts, _ = opts_for(session)
    first = verify("one@good.com", opts)
    assert first.reason_code == "E615"
    rcpt_after_first = len(session.rcpt_calls)
    second = verify("two@good.com", opts)
    assert second.reason_code == "E615"
    assert "cached" in second.reason.lower()
    # second run: only the real RCPT, no new random probe
    assert len(session.rcpt_calls) == rcpt_after_first + 1


def test_session_reused_per_domain():
    clear_all_caches()
    session = FakeSmtpSession(real=("250", "ok"), rnd=("550", "no"))
    opts, factory = opts_for(session)
    verify("one@good.com", opts)
    verify("two@good.com", opts)
    assert factory.connects == ["mx.good.com"]  # one connect for two emails


def test_ssrf_guard_recheck_peer_e616():
    clear_all_caches()
    session = FakeSmtpSession(peer="127.0.0.1")
    opts = {"smtp_factory": FakeSmtpSessionFactory(default_session=session)}
    # Defense in depth: S4 catches private MX (E405); the S6 peer re-check
    # fires when a session connects somewhere unsafe anyway.
    verdict = probe_email("someone@privmx.example", ["mx.internal.example"],
                          opts)
    assert verdict.stop_code == "E616"
    from core.models import ERROR_CODES

    assert ERROR_CODES["E616"]["status"] == "undeliverable"


def test_random_probe_address_high_entropy():
    a = random_probe_address("x.example")
    b = random_probe_address("x.example")
    assert a != b
    local = a.split("@")[0]
    assert local.startswith("zq7")
    assert len(local) == 3 + 20  # token_hex(10) -> 20 hex chars
    assert local[3:].isalnum()

