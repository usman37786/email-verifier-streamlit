"""Error-model property tests + breaker thresholds (PRD 13.5, 13.6, 5.2).

Invariant under test: an S-class error NEVER produces `undeliverable`; it
always produces `unknown` + retryable. V-codes map to their documented status.
"""
import pytest

from core.models import ERROR_CODES, Status, make_stop_cause, result_from_code
from core.pipeline import BatchError, RunState, verify_batch

ALL_CODES = sorted(ERROR_CODES.keys())
S_CODES = sorted(c for c, e in ERROR_CODES.items() if e["class"] == "S")
V_CODES = sorted(c for c, e in ERROR_CODES.items() if e["class"] == "V")


# --- property tests ---------------------------------------------------------

@pytest.mark.parametrize("code", S_CODES)
def test_property_s_class_never_undeliverable(code):
    result = result_from_code("someone@example.com", code)
    assert result.status == Status.UNKNOWN
    assert result.stop_cause.retryable is True
    assert result.status != Status.UNDELIVERABLE


@pytest.mark.parametrize("code", V_CODES)
def test_property_v_class_documented_status(code):
    result = result_from_code("someone@example.com", code)
    expected = ERROR_CODES[code]["status"]
    assert result.status.value == expected


def test_registry_covers_e001_to_e706_no_gaps():
    expected = (
        [f"E00{i}" for i in range(1, 6)]
        + [f"E10{i}" for i in range(1, 6)]
        + ["E201"]
        + [f"E30{i}" for i in range(1, 6)]
        + [f"E40{i}" for i in range(1, 10)]
        + ["E501"]
        + [f"E6{i:02d}" for i in range(1, 19)]
        + [f"E70{i}" for i in range(1, 7)]
    )
    assert set(ALL_CODES) == set(expected)


def test_every_s_code_is_unknown_and_retryable_in_registry():
    for code in S_CODES:
        entry = ERROR_CODES[code]
        assert entry["status"] == "unknown", code
        assert entry["retryable"] is True, code


def test_stop_cause_stage_labels_are_long_form():
    stop = make_stop_cause("E610")
    assert stop.stage == "S6_smtp"
    assert stop.code_class == "V"


# --- breaker thresholds (exact, PRD 5.2) ------------------------------------

def test_b1_trips_on_e001_immediately():
    state = RunState()
    trip = state.observe("E001")
    assert trip is not None
    assert "CONFIG_OR_AUTH_FAILURE" in trip.message
    assert trip.scope == "run"


def test_b1_trips_on_e603():
    state = RunState()
    trip = state.observe("E603")
    assert trip is not None and "CONFIG_OR_AUTH_FAILURE" in trip.message


def test_b2_five_in_a_row_trips():
    state = RunState()
    for _ in range(4):
        assert state.observe("E406") is None
    assert state.observe("E408") is not None  # 5th consecutive


def test_b2_four_in_a_row_does_not_trip():
    state = RunState()
    for _ in range(4):
        assert state.observe("E407") is None


def test_b2_eleven_of_last_twenty_trips():
    state = RunState()
    codes = ["E406"] * 10 + ["E408"] + ["OK"] * 9
    trip = None
    for code in codes:
        trip = state.observe(code)
    assert trip is not None and "DNS_OUTAGE" in trip.message


def test_b2_exactly_ten_of_twenty_does_not_trip():
    state = RunState()
    # 10 hits spread out (never 5 in a row): ratio is exactly 50%, not >50%.
    codes = []
    for _ in range(10):
        codes.extend(["E406", "OK"])
    codes.extend(["OK"] * 10)
    for code in codes:
        assert state.observe(code) is None
    assert state.trip is None


def test_b2_consecutive_counter_resets():
    state = RunState()
    for _ in range(4):
        assert state.observe("E406") is None
    assert state.observe("OK") is None
    for _ in range(4):
        assert state.observe("E406") is None


def test_b3_five_in_a_row_trips():
    state = RunState()
    for _ in range(4):
        assert state.observe("E614", "a.example") is None
    trip = state.observe("E614", "b.example")
    assert trip is not None and "PROBE_IP_BLOCKED" in trip.message


def test_b3_ratio_across_domains_trips():
    state = RunState()
    codes = [("E614", f"d{i}.example") for i in range(7)] + [("OK", "x.example")] * 13
    trip = None
    for code, dom in codes:
        trip = state.observe(code, dom)
    assert trip is not None and "PROBE_IP_BLOCKED" in trip.message


def test_b3_single_domain_ratio_does_not_trip():
    # 7 hits from ONE domain is not "across different domains".
    state = RunState()
    seq = ["E614", "OK"] * 7 + ["OK"] * 6
    for code in seq:
        state.observe(code, "same.example")
    assert state.trip is None


def test_b3_six_hits_across_domains_no_trip():
    state = RunState()
    seq = [("E614", f"d{i}.example") for i in range(6)] + [("OK", "z.example")] * 14
    for code, dom in seq:
        trip = state.observe(code, dom)
        # the first five entries are consecutive E614 -> would trip; space them
    # note: six consecutive would trip via consecutive rule, so rebuild spaced
    state2 = RunState()
    spaced = []
    for i in range(6):
        spaced.append(("E614", f"d{i}.example"))
        spaced.append(("OK", "z.example"))
    spaced += [("OK", "z.example")] * 10
    for code, dom in spaced:
        assert state2.observe(code, dom) is None
    assert state2.trip is None


def test_b4_three_in_a_row_trips():
    state = RunState()
    assert state.observe("E602") is None
    assert state.observe("E602") is None
    trip = state.observe("E602")
    assert trip is not None and "PROBE_DOWN" in trip.message


def test_b4_two_in_a_row_no_trip():
    state = RunState()
    assert state.observe("E602") is None
    assert state.observe("E602") is None


def test_b5_platform_limit_immediate():
    for code in ("E701", "E702", "E703"):
        state = RunState()
        trip = state.observe(code)
        assert trip is not None and "PLATFORM_LIMIT" in trip.message


def test_b6_three_e705_total_trips():
    state = RunState()
    assert state.observe("E705") is None
    assert state.observe("OK") is None
    assert state.observe("E705") is None
    trip = state.observe("E705")
    assert trip is not None and "UNSTABLE_RUNTIME" in trip.message




# --- resume_from / batch behavior (PRD 8.2) ---------------------------------

def _doh_for_domains(*domains):
    from helpers import make_doh

    mapping = {}
    for dom in domains:
        mapping[f"{dom}|MX"] = {"Status": 0, "Answer": [
            {"name": dom, "type": 15, "data": f"10 mx.{dom}."}]}
        mapping[f"{dom}|A"] = {"Status": 0, "Answer": []}
        mapping[f"{dom}|AAAA"] = {"Status": 0, "Answer": []}
        mapping[f"mx.{dom}|A"] = {"Status": 0, "Answer": [
            {"name": f"mx.{dom}", "type": 1, "data": "93.184.216.60"}]}
        mapping[f"mx.{dom}|AAAA"] = {"Status": 0, "Answer": []}
    return make_doh(mapping)


def test_batch_empty_raises_e003():
    with pytest.raises(BatchError) as exc:
        verify_batch([], {})
    assert exc.value.code == "E003"


def test_batch_over_max_bulk_raises_e004():
    with pytest.raises(BatchError) as exc:
        verify_batch([f"u{i}@x.example" for i in range(101)], {})
    assert exc.value.code == "E004"


def test_batch_subrequest_budget_resume_from():
    emails = [f"user{i}@example{i}.com" for i in range(6)]
    batch = verify_batch(emails, {
        "smtp": False, "max_workers": 1, "subrequest_budget": 3,
        "doh_query": _doh_for_domains(*[f"example{i}.com" for i in range(6)]),
    })
    assert batch.run_status == "halted"
    assert batch.processed == 3
    assert batch.resume_from == 3
    assert batch.not_processed == emails[3:]
    assert batch.stop_cause.code == "E701"
    assert batch.stop_cause.scope == "run"


def test_batch_summary_counts():
    emails = ["plainaddress", "a@b", "info@company.com"]
    batch = verify_batch(emails, {"smtp": False})
    assert batch.summary["undeliverable"] == 2
    assert batch.summary["risky"] == 1
    assert batch.processed == 3
    assert batch.run_status == "ok"
    assert batch.resume_from is None


def test_batch_results_ordered_with_input():
    emails = ["a@b.com", "bad@@x.com", "c@d.com"]
    batch = verify_batch(emails, {"smtp": False,
                                  "doh_query": _doh_for_domains("b.com", "d.com")})
    assert batch.results[1].email == "bad@@x.com"
    assert batch.results[1].reason_code == "E103"
    assert batch.results[0].reason_code == "E601"
    assert batch.results[2].reason_code == "E601"


def test_batch_breaker_dns_outage_halts_and_resumes():
    def always_timeout(name, rtype, timeout_ms):
        from core.dns_check import DohTimeout

        raise DohTimeout("outage")

    emails = [f"u{i}@downer{i}.example" for i in range(8)]
    batch = verify_batch(emails, {"smtp": False, "max_workers": 1,
                                  "doh_query": always_timeout})
    assert batch.run_status == "halted"
    assert batch.stop_cause is not None
    assert "DNS_OUTAGE" in batch.stop_cause.message
    assert batch.processed == 5  # trips after the 5th consecutive E406
    assert batch.resume_from == 5
    assert batch.not_processed == emails[5:]
    for r in batch.results:
        if r is not None:
            assert r.status.value == "unknown"
            assert r.reason_code == "E406"
