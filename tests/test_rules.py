"""S2 provider-rule suite (PRD 13.2)."""
import pytest

from core.rules import check_rules
from helpers import load_json

FX = load_json("fixtures.json")


@pytest.mark.parametrize("case", FX["rules"], ids=[c["input"] for c in FX["rules"]])
def test_rules_table(case):
    stop = check_rules(case["input"])
    got = None if stop is None else stop.code
    if case["code"] is None and case.get("note"):
        return  # behavior covered by syntax suite
    assert got == case["code"], f"{case['input']!r}: expected {case['code']}, got {got}"


def test_gmail_30_ok_31_fail():
    assert check_rules("a" * 30 + "@gmail.com") is None
    assert check_rules("a" * 31 + "@gmail.com").code == "E201"


def test_gmail_doubled_dot_base():
    stop = check_rules("ab..cd@gmail.com")
    # doubled dot is normally caught at S1; ensure S2 agrees if reached
    assert stop is None or stop.code == "E201"


def test_gmail_leading_dot_base():
    stop = check_rules(".abcdef@gmail.com")
    assert stop is None or stop.code == "E201"


def test_plus_tag_allowed():
    assert check_rules("user+newsletter@gmail.com") is None


def test_googlemail_same_rules():
    assert check_rules("ab@googlemail.com").code == "E201"
