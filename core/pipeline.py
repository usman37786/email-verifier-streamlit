"""Pipeline: orchestrates S1-S6 with halt policy, deadline, breakers, cache.

One pipeline, three runtimes: Streamlit calls this directly (local mode); the
Worker re-implements the same stage order/codes in JS; tests inject fake DoH
and SMTP factories. Invariant: an S-class error NEVER yields undeliverable.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import config
from .dns_check import check_domain
from .fingerprint import fingerprint
from .lists_check import check_lists
from .models import (DEFAULT_SCORES, HEURISTIC_CODES, OK_CODE, Result, Status,
                     StopCause, make_stop_cause, ok_result, result_from_code)
from .rules import check_rules
from .smtp_check import probe_email, probe_via_service
from .syntax import check_syntax

CATCHALL_ADVICE = (
    "This domain accepts mail for any address, so acceptance proves nothing "
    "about the person. Do not treat it as valid: confirm interest through "
    "double opt-in and judge by engagement and bounce rate after the first "
    "campaign."
)

_RESULT_CACHE: Dict[tuple, Tuple[dict, float]] = {}
_CACHE_LOCK = threading.Lock()


def clear_all_caches() -> None:
    """Test hook: drop every module-level cache."""
    with _CACHE_LOCK:
        _RESULT_CACHE.clear()
    from . import dns_check, smtp_check

    dns_check.clear_cache()
    smtp_check.reset_caches()


def _cache_key(email: str, opts: dict) -> tuple:
    return (
        email.strip().lower(),
        opts.get("halt_policy") or config.get_halt_policy(),
        opts.get("mode") or config.get_mode(),
        bool(opts.get("smtp", True)) and (opts.get("mode") or config.get_mode()) != "fast",
        opts.get("sender") or config.MAIL_FROM,
    )


def _result_cache_get(key: tuple) -> Optional[Result]:
    with _CACHE_LOCK:
        hit = _RESULT_CACHE.get(key)
    if not hit:
        return None
    payload, ts = hit
    if time.time() - ts > config.RESULT_CACHE_TTL_S:
        return None
    import copy

    return copy.deepcopy(payload)


def _result_cache_put(key: tuple, result: Result) -> None:
    """Cache only deterministic outcomes: never retryable S-class results."""
    if result.stop_cause is not None and result.stop_cause.retryable:
        return
    import copy

    with _CACHE_LOCK:
        if len(_RESULT_CACHE) > 10000:
            _RESULT_CACHE.clear()
        _RESULT_CACHE[key] = (copy.deepcopy(result), time.time())


class _DeadlineExceeded(Exception):
    pass


def _with_deadline(fn: Callable, timeout_s: float):
    """Hard wall-clock cutoff: the answer is abandoned, not waited on."""
    box: dict = {}
    done = threading.Event()

    def target() -> None:
        try:
            box["v"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["e"] = exc
        finally:
            done.set()

    threading.Thread(target=target, daemon=True).start()
    if not done.wait(max(timeout_s, 0.005)):
        raise _DeadlineExceeded()
    if "e" in box:
        raise box["e"]
    return box.get("v")


# --- Run-level circuit breakers (PRD 5.2) -----------------------------------
B1, B2, B3, B4, B5, B6 = "B1", "B2", "B3", "B4", "B5", "B6"
BREAKER_NAMES = {
    B1: "CONFIG_OR_AUTH_FAILURE",
    B2: "DNS_OUTAGE",
    B3: "PROBE_IP_BLOCKED",
    B4: "PROBE_DOWN",
    B5: "PLATFORM_LIMIT",
    B6: "UNSTABLE_RUNTIME",
}
_DNS_FAIL_CODES = {"E406", "E407", "E408"}
_PLATFORM_CODES = {"E701", "E702", "E703"}


class RunState:
    """Breaker bookkeeping for one batch/API run (thread-safe)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.trip: Optional[StopCause] = None
        self._consec: Dict[str, int] = {}
        self._window: List[Tuple[str, Optional[str]]] = []
        self._e705 = 0
        self.subrequests = 0
        self.subrequest_budget: Optional[int] = None

    def _trip(self, breaker: str, code: str) -> StopCause:
        cause = make_stop_cause(code, message=BREAKER_NAMES[breaker], scope="run")
        cause.stage = "S7_platform"
        self.trip = cause
        return cause

    def observe(self, code: Optional[str], domain: Optional[str] = None) -> Optional[StopCause]:
        """Record one stop cause; returns the trip cause when a breaker opens."""
        if code is None or self.trip is not None:
            return self.trip
        with self.lock:
            if code in ("E001", "E603"):
                return self._trip(B1, code)
            if code in _PLATFORM_CODES:
                return self._trip(B5, code)
            if code == "E705":
                self._e705 += 1
                if self._e705 >= 3:
                    return self._trip(B6, code)
            if code in _DNS_FAIL_CODES:
                self._consec[B2] = self._consec.get(B2, 0) + 1
            else:
                self._consec[B2] = 0
            if code == "E614":
                self._consec[B3] = self._consec.get(B3, 0) + 1
            else:
                self._consec[B3] = 0
            if code == "E602":
                self._consec[B4] = self._consec.get(B4, 0) + 1
            else:
                self._consec[B4] = 0
            self._window.append((code, domain))
            if len(self._window) > 20:
                self._window.pop(0)
            last20 = self._window[-20:]
            b2_hits = [c for c, _ in last20 if c in _DNS_FAIL_CODES]
            b3_hits = [(c, d) for c, d in last20 if c == "E614"]
            if self._consec[B2] >= 5 or len(b2_hits) > 10:
                return self._trip(B2, code)
            if self._consec[B3] >= 5 or (
                    len(b3_hits) > 6 and len({d for _, d in b3_hits}) >= 2):
                return self._trip(B3, code)
            if self._consec[B4] >= 3:
                return self._trip(B4, code)
            return None

SHORT_STAGES = ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"]


def _domain_of(email) -> Optional[str]:
    try:
        return str(email).rsplit("@", 1)[1].lower()
    except (IndexError, AttributeError):
        return None


def _skipped_after(code: str) -> List[str]:
    from .models import ERROR_CODES

    stage = ERROR_CODES[code]["stage"]  # short code, e.g. "S3"
    if stage not in SHORT_STAGES:
        return []
    return SHORT_STAGES[SHORT_STAGES.index(stage) + 1:]


def verify(email, opts: Optional[dict] = None) -> Result:
    """Verify one email address (PRD section 4 pipeline)."""
    t0 = time.monotonic()
    opts = dict(opts or {})
    halt_policy = opts.get("halt_policy") or config.get_halt_policy()
    mode = opts.get("mode") or config.get_mode()
    total_ms = float(opts.get("deadline_ms") or config.deadline_ms())
    run_state: Optional[RunState] = opts.get("_run_state")

    def remaining_ms() -> float:
        return total_ms - (time.monotonic() - t0) * 1000.0

    def elapsed_ms() -> int:
        return int((time.monotonic() - t0) * 1000)

    try:
        return _verify_inner(email, opts, halt_policy, mode, run_state,
                             remaining_ms, elapsed_ms)
    except _DeadlineExceeded:
        result = result_from_code(str(email), "E618",
                                  message="deadline exceeded",
                                  flags=["deadline_exceeded"],
                                  stages_skipped=["S6", "S7"],
                                  took_ms=elapsed_ms())
        if run_state:
            run_state.observe("E618", _domain_of(email))
        return result
    except Exception as exc:  # noqa: BLE001 - E705 wrapper is contract
        result = result_from_code(
            str(email), "E705",
            message=f"internal error: {type(exc).__name__}",
            took_ms=elapsed_ms())
        if run_state:
            run_state.observe("E705", _domain_of(email))
        return result


def _verify_inner(email, opts: dict, halt_policy: str, mode: str,
                  run_state: Optional[RunState],
                  remaining_ms: Callable, elapsed_ms: Callable) -> Result:
    use_cache = opts.get("use_cache", True)
    smtp_on = bool(opts.get("smtp", True)) and mode != "fast"
    key = _cache_key(email, opts) if use_cache else None
    if key:
        hit = _result_cache_get(key)
        if hit is not None:
            hit.cached = True
            hit.took_ms = elapsed_ms()
            return hit

    display = str(email)  # becomes the normalized address once S1 passes

    def halt(code: str, stages_done: List[str], message: Optional[str] = None,
             flags: Optional[List[str]] = None,
             did_you_mean: Optional[str] = None,
             advice: Optional[str] = None,
             mx: Optional[List[str]] = None,
             skipped_override: Optional[List[str]] = None) -> Result:
        r = result_from_code(
            display, code, message=message, flags=flags,
            did_you_mean=did_you_mean, stages_completed=stages_done,
            stages_skipped=skipped_override or _skipped_after(code),
            mx=mx, advice=advice, took_ms=elapsed_ms())
        if run_state is not None and r.stop_cause is not None:
            run_state.observe(code, _domain_of(email))
        if key:
            _result_cache_put(key, r)
        return r

    # --- S1: syntax ---
    normalized, stop = check_syntax(email)
    if stop is not None:
        return halt(stop.code, ["S1"], message=stop.message)
    addr: str = normalized
    display = addr  # results after S1 report the normalized address
    domain = addr.rsplit("@", 1)[1]

    # --- S2: provider rules ---
    stop = check_rules(addr)
    if stop is not None:
        return halt(stop.code, ["S1", "S2"], message=stop.message)

    # --- S3: lists & heuristics ---
    flags: List[str] = []
    did_you_mean = None
    advice = None
    heuristic_stop: Optional[StopCause] = None
    l_stop, l_flags, l_dym, l_advice = check_lists(addr)
    flags.extend(l_flags)
    if l_stop is not None:
        code = l_stop.code
        if code == "E305":
            return halt("E305", ["S1", "S2"], message=l_stop.message)
        heuristic = code in HEURISTIC_CODES
        if not heuristic or halt_policy == "strict":
            return halt(code, ["S1", "S2", "S3"], message=l_stop.message,
                        did_you_mean=l_dym, advice=l_advice)
        heuristic_stop = l_stop
        flags.append({"E301": "disposable_domain", "E303": "role_account",
                      "E304": "probable_typo"}.get(code, code.lower()))
        did_you_mean = l_dym
        advice = l_advice

    # --- S4: DNS via DoH ---
    outcome = check_domain(domain, doh=opts.get("doh_query"),
                           remaining_fn=remaining_ms)
    if outcome.stop is not None:
        return halt(outcome.stop.code, ["S1", "S2", "S3"],
                    message=outcome.stop.message, flags=flags,
                    did_you_mean=did_you_mean, advice=advice)
    flags.extend(outcome.flags)
    mx = list(outcome.mx)

    # --- S5: MX fingerprint ---
    fp = fingerprint(mx)
    gateway = fp.get("gateway")
    if gateway:
        if halt_policy == "strict":
            return halt("E501", ["S1", "S2", "S3", "S4", "S5"],
                        message=f"security gateway in front ({gateway}); "
                                "SMTP proof would be meaningless",
                        flags=flags, mx=mx)
        flags.append("gateway_fronted")
        if heuristic_stop is None:
            heuristic_stop = make_stop_cause("E501", f"gateway in front: {gateway}")

    # --- S6: SMTP probe (or DNS-only stop) ---
    if not smtp_on:
        # Soft-policy heuristics stay as flags here (halt_policy=soft means
        # they never stop the pipeline); the stop cause is the S6 gate.
        return halt("E601", ["S1", "S2", "S3", "S4", "S5"],
                    message="domain_ok_mailbox_unchecked",
                    flags=flags, did_you_mean=did_you_mean, advice=advice, mx=mx,
                    skipped_override=["S6", "S7"])

    if remaining_ms() <= config.DEADLINE_GUARD_MS:
        return halt("E618", ["S1", "S2", "S3", "S4", "S5"],
                    message="deadline exhausted before SMTP probe",
                    flags=flags + ["deadline_exceeded"], mx=mx,
                    skipped_override=["S6", "S7"])

    probe_url = opts.get("probe_url") or config.SMTP_PROBE_URL

    def do_probe():
        if probe_url:
            return probe_via_service(addr, opts)
        return probe_email(addr, mx, opts, remaining_fn=remaining_ms)

    try:
        verdict = _with_deadline(do_probe, max(remaining_ms(), 1) / 1000.0)
    except _DeadlineExceeded:
        return halt("E618", ["S1", "S2", "S3", "S4", "S5"],
                    message="deadline exceeded during SMTP probe",
                    flags=flags + ["deadline_exceeded"], mx=mx,
                    skipped_override=["S6", "S7"])

    fl = flags + list(verdict.flags)
    if verdict.stop_code is None:
        if heuristic_stop is not None:
            # soft policy: S6 ran to completion, but a S3/S5 heuristic caps
            # the verdict - never report `deliverable` for those.
            r = result_from_code(
                str(addr), heuristic_stop.code, message=heuristic_stop.message,
                flags=fl, did_you_mean=did_you_mean, advice=advice,
                stages_completed=["S1", "S2", "S3", "S4", "S5", "S6"],
                mx=mx, took_ms=elapsed_ms())
            if key:
                _result_cache_put(key, r)
            return r
        result = ok_result(addr, score=DEFAULT_SCORES["OK"],
                           flags=fl + ["smtp_proven"],
                           stages_completed=["S1", "S2", "S3", "S4", "S5", "S6"],
                           mx=mx, took_ms=elapsed_ms(),
                           reason=verdict.message)
        if key:
            _result_cache_put(key, result)
        return result

    code = verdict.stop_code
    if code == "E615":
        return halt("E615", ["S1", "S2", "S3", "S4", "S5", "S6"],
                    message=verdict.message, flags=fl, mx=mx,
                    advice=CATCHALL_ADVICE)
    if code == "E618":
        return halt("E618", ["S1", "S2", "S3", "S4", "S5"],
                    message=verdict.message, flags=fl + ["deadline_exceeded"],
                    mx=mx, skipped_override=["S6", "S7"])
    return halt(code, ["S1", "S2", "S3", "S4", "S5", "S6"],
                message=verdict.message, flags=fl, mx=mx)


@dataclass
class BatchResult:
    results: List[Optional[Result]]
    processed: int
    total: int
    run_status: str  # "ok" | "halted"
    stop_cause: Optional[StopCause]
    resume_from: Optional[int]
    not_processed: List[str]
    summary: Dict[str, int]

    def to_dict(self) -> dict:
        return {
            "results": [r.to_dict() if r else None for r in self.results],
            "processed": self.processed,
            "total": self.total,
            "run_status": self.run_status,
            "stop_cause": self.stop_cause.to_dict() if self.stop_cause else None,
            "resume_from": self.resume_from,
            "not_processed": list(self.not_processed),
            "summary": dict(self.summary),
        }


class BatchError(ValueError):
    """S0-level batch rejection (empty list, over MAX_BULK)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def verify_batch(emails: List[str], opts: Optional[dict] = None) -> BatchResult:
    """Verify a list of emails; group by domain; honor breakers + budget."""
    opts = dict(opts or {})
    total = len(emails)
    if total == 0:
        raise BatchError("E003")
    max_bulk = int(opts.get("max_bulk") or config.MAX_BULK)
    if total > max_bulk:
        raise BatchError("E004")

    state = RunState()
    budget = opts.get("subrequest_budget")
    state.subrequest_budget = int(budget) if budget is not None else None
    max_workers = int(opts.get("max_workers") or config.MAX_WORKERS)

    results: List[Optional[Result]] = [None] * total

    # Group indices by domain; single-label / malformed inputs still group.
    groups: Dict[str, List[int]] = {}
    for i, em in enumerate(emails):
        s = str(em).strip()
        if "@" in s:
            g = s.rsplit("@", 1)[1].lower()
        else:
            g = f"__row{i}"
        groups.setdefault(g, []).append(i)

    def run_group(indices: List[int]) -> None:
        for i in indices:
            if state.trip is not None:
                return
            if (state.subrequest_budget is not None
                    and state.subrequests >= state.subrequest_budget):
                state.observe("E701")
                return
            with state.lock:
                state.subrequests += 1
            opts_i = dict(opts)
            opts_i["_run_state"] = state
            res = verify(emails[i], opts_i)
            results[i] = res
            # stop causes are observed exactly once, inside verify()/halt()

    if max_workers <= 1 or len(groups) <= 1:
        for indices in groups.values():
            if state.trip is not None:
                break
            run_group(indices)
    else:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(groups))) as pool:
            futures = [pool.submit(run_group, idxs) for idxs in groups.values()]
            for fut in futures:
                fut.result()

    # resume_from = first input index without a returned result (PRD 8.2).
    resume_from: Optional[int] = None
    not_processed: List[str] = []
    for i in range(total):
        if results[i] is None:
            if resume_from is None:
                resume_from = i
            not_processed.append(str(emails[i]))

    processed = sum(1 for r in results if r is not None)
    summary: Dict[str, int] = {"deliverable": 0, "undeliverable": 0,
                               "risky": 0, "unknown": 0}
    for r in results:
        if r is not None:
            summary[r.status.value] += 1

    return BatchResult(
        results=results,
        processed=processed,
        total=total,
        run_status="halted" if state.trip is not None else "ok",
        stop_cause=state.trip,
        resume_from=resume_from,
        not_processed=not_processed,
        summary=summary,
    )
