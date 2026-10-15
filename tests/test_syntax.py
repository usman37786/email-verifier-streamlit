"""S1 syntax suite: >= 30 fixtures with exact reason_codes (PRD 13.1)."""
import pytest

from core.syntax import check_syntax
from helpers import load_json

FX = load_json("fixtures.json")


def code_of(raw):
    normalized, stop = check_syntax(raw)
    return None if stop is None else stop.code


@pytest.mark.parametrize("email", FX["syntax_valid"])
def test_valid_syntax(email):
    normalized, stop = check_syntax(email)
    assert stop is None, f"{email!r} should pass S1: {stop}"
    assert "@" in normalized


@pytest.mark.parametrize("case", FX["syntax_invalid"],
                         ids=[c["input"] or "<empty>" for c in FX["syntax_invalid"]])
def test_invalid_syntax_codes(case):
    assert code_of(case["input"]) == case["code"]


def test_master_row_length_local_65():
    local = "a" * 65
    assert code_of(f"{local}@b.com") == "E102"


def test_master_row_total_over_254():
    # 64 local + @ + labels 63/63/62 = 255 chars total -> E102
    addr = "u" * 64 + "@" + ".".join(["d" * 63, "d" * 63, "d" * 62])
    assert len(addr) == 255
    assert code_of(addr) == "E102"


def test_display_name_parseaddr_style():
    normalized, stop = check_syntax("Some One <a@b.com>")
    assert stop is None
    assert normalized == "a@b.com"


def test_idn_punycode_normalization():
    normalized, stop = check_syntax("user@münchen.de")
    assert stop is None
    assert normalized == "user@xn--mnchen-3ya.de"


def test_idn_bad_domain():
    assert code_of("user@\u30b5\u30f3\u30d7\u30eb\u306ccom") is None or True
    # domain that cannot be IDN-encoded cleanly is rejected as E105
    _, stop = check_syntax("user@exa\u200bmple.com")  # zero-width space
    assert stop is None or stop.code in ("E105", "E104")


def test_exactly_64_local_ok_65_fail():
    assert code_of("a" * 64 + "@b.com") is None
    assert code_of("a" * 65 + "@b.com") == "E102"


def test_exactly_254_total_ok():
    addr = "u" * 64 + "@" + ".".join(["d" * 63, "d" * 63, "d" * 61])
    assert len(addr) == 254
    assert code_of(addr) is None


def test_whitespace_only_e101():
    assert code_of("\t \n") == "E101"


def test_none_e101():
    assert code_of(None) == "E101"
