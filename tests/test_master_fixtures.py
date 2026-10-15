"""Master fixture table (AGENT_PROMPT Step 8) through the full pipeline.

Rows 1-11 are asserted at unit level in test_syntax/test_rules; this file
covers pipeline-level rows with injected DoH/SMTP fakes.
"""
import pytest

from core.pipeline import verify
from helpers import FakeSmtpSessionFactory, load_json, make_doh

OK = load_json("doh_ok.json")
NX = load_json("doh_nxdomain.json")
NULLMX = load_json("doh_nullmx.json")
NOMA = load_json("doh_noma.json")
PRIVMX = load_json("doh_privmx.json")
SHARED = load_json("fixtures.json")
GHOST = SHARED["doh"]["mxhost_nxdomain"]

GMAIL_DOH = {
    "gmail.com|MX": {"Status": 0, "Answer": [
        {"name": "gmail.com", "type": 15, "data": "10 gmail-smtp-in.l.google.com."}]},
    "gmail.com|A": {"Status": 0, "Answer": [
        {"name": "gmail.com", "type": 1, "data": "142.250.0.0"}]},
    "gmail.com|AAAA": {"Status": 0, "Answer": []},
    "gmail-smtp-in.l.google.com|A": {"Status": 0, "Answer": [
        {"name": "gmail-smtp-in.l.google.com", "type": 1, "data": "142.251.0.1"}]},
    "gmail-smtp-in.l.google.com|AAAA": {"Status": 0, "Answer": []},
}
COMPANY_DOH = {
    "company.com|MX": {"Status": 0, "Answer": [
        {"name": "company.com", "type": 15, "data": "10 mail.company.com."}]},
    "company.com|A": {"Status": 0, "Answer": []},
    "company.com|AAAA": {"Status": 0, "Answer": []},
    "mail.company.com|A": {"Status": 0, "Answer": [
        {"name": "mail.company.com", "type": 1, "data": "93.184.216.70"}]},
    "mail.company.com|AAAA": {"Status": 0, "Answer": []},
}
GMIAL_DOH = {
    "gmial.com|MX": {"Status": 0, "Answer": [
        {"name": "gmial.com", "type": 15, "data": "10 mx.gmial.com."}]},
    "gmial.com|A": {"Status": 0, "Answer": []},
    "gmial.com|AAAA": {"Status": 0, "Answer": []},
    "mx.gmial.com|A": {"Status": 0, "Answer": [
        {"name": "mx.gmial.com", "type": 1, "data": "93.184.216.71"}]},
    "mx.gmial.com|AAAA": {"Status": 0, "Answer": []},
}


def test_row12_valid_user_gmail_passes_s1_s2():
    result = verify("valid.user@gmail.com", {"doh_query": make_doh(GMAIL_DOH),
                                             "smtp": False})
    assert result.reason_code == "E601"          # DNS-level stop, no probe
    assert result.stages_completed[:2] == ["S1", "S2"]
    assert "S3" in result.stages_completed
    assert result.status.value == "unknown"
    assert "free_provider" in result.flags


def test_row13_disposable_risky_e301():
    result = verify("x@mailinator.com", {"smtp": False})
    assert result.status.value == "risky"
    assert result.reason_code == "E301"
    assert result.level == "lists"
    assert result.halted is True


def test_row14_role_account_risky_e303_strict_halts():
    result = verify("info@company.com", {"smtp": False,
                                         "doh_query": make_doh(COMPANY_DOH)})
    assert result.status.value == "risky"
    assert result.reason_code == "E303"
    assert result.halted is True
    assert "S4" in result.stages_skipped  # strict stops before DNS


def test_row14_soft_policy_continues_to_dns():
    result = verify("info@company.com", {"smtp": False, "halt_policy": "soft",
                                         "doh_query": make_doh(COMPANY_DOH)})
    assert result.reason_code == "E601"          # ran through S5
    assert "role_account" in result.flags


def test_row15_typo_risky_with_did_you_mean():
    result = verify("user@gmial.com", {"smtp": False,
                                       "doh_query": make_doh(GMIAL_DOH)})
    assert result.status.value == "risky"
    assert result.reason_code == "E304"
    assert result.did_you_mean == "gmail.com"


def test_row16_nxdomain_e401():
    result = verify("a@nonexistent-domain-xyz123.tld",
                    {"doh_query": make_doh(NX), "smtp": False})
    assert result.status.value == "undeliverable"
    assert result.reason_code == "E401"
    assert result.level == "dns"


def test_row17_null_mx_e402():
    result = verify("a@nullmx.example", {"doh_query": make_doh(NULLMX),
                                         "smtp": False})
    assert result.status.value == "undeliverable"
    assert result.reason_code == "E402"


def test_row18_no_mx_no_a_e403():
    result = verify("a@noma.example", {"doh_query": make_doh(NOMA),
                                       "smtp": False})
    assert result.status.value == "undeliverable"
    assert result.reason_code == "E403"


def test_row19_mx_host_unresolvable_e404():
    result = verify("a@ghost.example", {"doh_query": make_doh(GHOST),
                                        "smtp": False})
    assert result.status.value == "undeliverable"
    assert result.reason_code == "E404"


def test_row20_private_mx_e405():
    result = verify("a@privmx.example", {"doh_query": make_doh(PRIVMX),
                                         "smtp": False})
    assert result.status.value == "undeliverable"
    assert result.reason_code == "E405"


def test_row21_doh_timeout_e406_unknown():
    from core.dns_check import DohTimeout

    def raising(name, rtype, timeout_ms):
        raise DohTimeout("fake timeout")

    result = verify("a@good.com", {"doh_query": raising, "smtp": False})
    assert result.status.value == "unknown"
    assert result.reason_code == "E406"
    assert result.stop_cause.retryable is True


def test_row22_doh_http_500_e408_unknown():
    from core.dns_check import DohHttpError

    def raising(name, rtype, timeout_ms):
        raise DohHttpError("HTTP 500")

    result = verify("a@good.com", {"doh_query": raising, "smtp": False})
    assert result.status.value == "unknown"
    assert result.reason_code == "E408"
    assert result.stop_cause.retryable is True


def test_row23_good_domain_no_probe_e601():
    result = verify("someone@good.com", {"doh_query": make_doh(OK),
                                         "smtp": False})
    assert result.status.value == "unknown"
    assert result.reason_code == "E601"
    assert result.reason == "domain_ok_mailbox_unchecked"
    assert result.level == "dns"
    assert result.score == 40


def test_row34_display_name_form_parsed():
    queries = {}

    def spy_doh(name, rtype, timeout_ms):
        queries[f"{name}|{rtype}"] = queries.get(f"{name}|{rtype}", 0) + 1
        val = OK.get(f"{name}|{rtype}")
        return val if val is not None else {"Status": 0, "Answer": []}

    result = verify("Some One <someone@good.com>",
                    {"doh_query": spy_doh, "smtp": False})
    assert "good.com|MX" in queries          # domain extracted via parseaddr
    assert result.reason_code == "E601"
    assert result.email.endswith("someone@good.com")


def test_row35_plus_tag_passes_s2():
    result = verify("user+tag@gmail.com", {"doh_query": make_doh(GMAIL_DOH),
                                           "smtp": False})
    assert result.reason_code == "E601"      # did NOT stop at S2 with E201
    assert result.stages_completed[:2] == ["S1", "S2"]


def test_s_class_never_undeliverable_through_pipeline():
    """End-to-end invariant: system failures stay unknown even mid-SMTP."""
    from core.smtp_check import SmtpConnectError

    factory = FakeSmtpSessionFactory(behavior={
        "mx.good.com": SmtpConnectError("E605", "connection reset"),
    })
    result = verify("someone@good.com", {"doh_query": make_doh(OK),
                                         "smtp_factory": factory})
    assert result.status.value == "unknown"
    assert result.reason_code == "E617"

