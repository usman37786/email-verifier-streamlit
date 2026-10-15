"""S4 DNS suite against recorded DoH fixtures (PRD 13.4)."""
import pytest

from core.dns_check import (DnsOutcome, DohHttpError, DohMalformed, DohTimeout,
                            check_domain)
from helpers import load_json, make_doh

NX = load_json("doh_nxdomain.json")
NULLMX = load_json("doh_nullmx.json")
NOMA = load_json("doh_noma.json")
OK = load_json("doh_ok.json")
PRIVMX = load_json("doh_privmx.json")
SHARED = load_json("fixtures.json")
GHOST = SHARED["doh"]["mxhost_nxdomain"]
SERVFAIL = SHARED["doh"]["servfail"]


def test_ok_domain_returns_mx():
    out = check_domain("good.com", doh=make_doh(OK))
    assert out.stop is None
    assert out.mx == ["mx.good.com"]
    assert out.ips["mx.good.com"] == ["93.184.216.34"]


def test_nxdomain_e401():
    out = check_domain("nonexistent-domain-xyz123.tld", doh=make_doh(NX))
    assert out.stop.code == "E401"


def test_null_mx_e402():
    out = check_domain("nullmx.example", doh=make_doh(NULLMX))
    assert out.stop.code == "E402"


def test_no_mx_no_a_e403():
    out = check_domain("noma.example", doh=make_doh(NOMA))
    assert out.stop.code == "E403"


def test_mx_host_nxdomain_e404():
    out = check_domain("ghost.example", doh=make_doh(GHOST))
    assert out.stop.code == "E404"


def test_private_mx_ip_e405():
    out = check_domain("privmx.example", doh=make_doh(PRIVMX))
    assert out.stop.code == "E405"
    assert "10.0.0.5" in out.stop.message


def test_doh_timeout_e406():
    def raising(name, rtype, timeout_ms):
        raise DohTimeout("boom")

    out = check_domain("good.com", doh=raising)
    assert out.stop.code == "E406"


def test_doh_http_error_e408():
    def raising(name, rtype, timeout_ms):
        raise DohHttpError("HTTP 500")

    out = check_domain("good.com", doh=raising)
    assert out.stop.code == "E408"


def test_doh_unexpected_exception_e408():
    def raising(name, rtype, timeout_ms):
        raise RuntimeError("connector exploded")

    out = check_domain("good.com", doh=raising)
    assert out.stop.code == "E408"


def test_malformed_doh_e409():
    def garbage(name, rtype, timeout_ms):
        return {"Answer": "not-a-list"}

    out = check_domain("good.com", doh=garbage)
    assert out.stop.code == "E409"


def test_servfail_e407():
    out = check_domain("servfail.example", doh=make_doh(SERVFAIL))
    assert out.stop.code == "E407"


def test_implicit_mx_on_a_only():
    mapping = {
        "aonly.example|MX": {"Status": 0, "Answer": []},
        "aonly.example|A": {"Status": 0,
                            "Answer": [{"name": "aonly.example", "type": 1,
                                        "data": "93.184.216.42"}]},
        "aonly.example|AAAA": {"Status": 0, "Answer": []},
    }
    out = check_domain("aonly.example", doh=make_doh(mapping))
    assert out.stop is None
    assert out.mx == ["aonly.example"]
    assert "implicit_mx" in out.flags


def test_implicit_mx_private_ip_e405():
    mapping = {
        "aonly2.example|MX": {"Status": 0, "Answer": []},
        "aonly2.example|A": {"Status": 0,
                             "Answer": [{"name": "aonly2.example", "type": 1,
                                         "data": "192.168.1.10"}]},
        "aonly2.example|AAAA": {"Status": 0, "Answer": []},
    }
    out = check_domain("aonly2.example", doh=make_doh(mapping))
    assert out.stop.code == "E405"


def test_mx_preference_order():
    mapping = dict(OK)
    mapping["good.com|MX"] = {
        "Status": 0,
        "Answer": [
            {"name": "good.com", "type": 15, "data": "20 backup.good.com."},
            {"name": "good.com", "type": 15, "data": "10 primary.good.com."},
        ],
    }
    mapping["backup.good.com|A"] = {"Status": 0, "Answer": [
        {"name": "backup.good.com", "type": 1, "data": "93.184.216.40"}]}
    mapping["backup.good.com|AAAA"] = {"Status": 0, "Answer": []}
    mapping["primary.good.com|A"] = {"Status": 0, "Answer": [
        {"name": "primary.good.com", "type": 1, "data": "93.184.216.41"}]}
    mapping["primary.good.com|AAAA"] = {"Status": 0, "Answer": []}
    out = check_domain("good.com", doh=make_doh(mapping))
    assert out.mx == ["primary.good.com", "backup.good.com"]


@pytest.mark.parametrize("cls", [DnsOutcome])
def test_outcome_defaults(cls):
    o = cls()
    assert o.mx == [] and o.stop is None and o.ips == {}
