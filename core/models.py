"""Result model + normative error-code registry (PRD section 5).

Two error classes:
  V (verdict) - final, no retry, maps to a documented status.
  S (system)  - our fault; ALWAYS status=unknown, retryable=True, NEVER undeliverable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Status(str, Enum):
    DELIVERABLE = "deliverable"
    UNDELIVERABLE = "undeliverable"
    RISKY = "risky"
    UNKNOWN = "unknown"


# Stage code -> StopCause.stage label used in JSON (PRD 5.4).
STAGE_LABELS = {
    "S0": "S0_request",
    "S1": "S1_syntax",
    "S2": "S2_rules",
    "S3": "S3_lists",
    "S4": "S4_dns",
    "S5": "S5_fingerprint",
    "S6": "S6_smtp",
    "S7": "S7_platform",
}

# All stages, in order, used to fill stages_skipped.
ALL_STAGES = ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"]

# result.level when a stage stops the pipeline (PRD 8.1: syntax|lists|dns|smtp).
LEVEL_FOR_STAGE = {
    "S0": "syntax",
    "S1": "syntax",
    "S2": "syntax",
    "S3": "lists",
    "S4": "dns",
    "S5": "lists",
    "S6": "smtp",
    "S7": "dns",
}


@dataclass
class StopCause:
    code: str
    code_class: str  # "V" or "S" (JSON key is "class")
    stage: str  # e.g. "S6_smtp"
    message: str
    retryable: bool
    retry_after_s: Optional[int] = None
    scope: Optional[str] = None  # "email" | "run" (run-level stops)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "class": self.code_class,
            "stage": self.stage,
            "message": self.message,
            "retryable": self.retryable,
            "retry_after_s": self.retry_after_s,
            "scope": self.scope,
        }


@dataclass
class Result:
    email: str
    status: Status
    score: int
    reason_code: str
    reason: str
    level: str
    flags: List[str] = field(default_factory=list)
    did_you_mean: Optional[str] = None
    halted: bool = False
    halt_scope: Optional[str] = None
    stop_cause: Optional[StopCause] = None
    stages_completed: List[str] = field(default_factory=list)
    stages_skipped: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    cached: bool = False
    took_ms: int = 0
    advice: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "status": self.status.value if isinstance(self.status, Status) else self.status,
            "score": self.score,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "level": self.level,
            "flags": list(self.flags),
            "did_you_mean": self.did_you_mean,
            "halted": self.halted,
            "halt_scope": self.halt_scope,
            "stop_cause": self.stop_cause.to_dict() if self.stop_cause else None,
            "stages_completed": list(self.stages_completed),
            "stages_skipped": list(self.stages_skipped),
            "mx": list(self.mx),
            "cached": self.cached,
            "took_ms": self.took_ms,
            "advice": self.advice,
        }


def _ec(code: str, cls: str, stage: str, message: str,
        status: str, retryable: bool, retry_after_s: Optional[int] = None,
        scope: Optional[str] = None) -> Dict[str, Any]:
    return {
        "code": code,
        "class": cls,
        "stage": stage,
        "message": message,
        "status": status,
        "retryable": retryable,
        "retry_after_s": retry_after_s,
        "scope": scope,
    }


# ---------------------------------------------------------------------------
# Normative registry: every code E001-E706 from PRD section 5.
# S-class entries always carry status="unknown", retryable=True.
# ---------------------------------------------------------------------------
ERROR_CODES: Dict[str, Dict[str, Any]] = {
    # S0: Request (run scope)
    "E001": _ec("E001", "S", "S0", "Auth failed or missing key", "unknown", True, scope="run"),
    "E002": _ec("E002", "S", "S0", "Malformed or non-JSON body", "unknown", True, scope="run"),
    "E003": _ec("E003", "S", "S0", "Empty list", "unknown", True, scope="run"),
    "E004": _ec("E004", "S", "S0", "Batch over MAX_BULK", "unknown", True, scope="run"),
    "E005": _ec("E005", "S", "S0", "Client rate-limited", "unknown", True, 60, scope="run"),
    # S1: Syntax (verdicts)
    "E101": _ec("E101", "V", "S1", "Empty or whitespace address", "undeliverable", False),
    "E102": _ec("E102", "V", "S1", "Address too long (>254 total, >64 local part)", "undeliverable", False),
    "E103": _ec("E103", "V", "S1", "Missing @ or multiple unquoted @", "undeliverable", False),
    "E104": _ec("E104", "V", "S1", "Illegal local part", "undeliverable", False),
    "E105": _ec("E105", "V", "S1", "Illegal domain", "undeliverable", False),
    # S2: Provider rules
    "E201": _ec("E201", "V", "S2", "Violates provider's own rules", "undeliverable", False),
    # S3: Lists & heuristics
    "E301": _ec("E301", "V", "S3", "Disposable domain", "risky", False),
    "E302": _ec("E302", "V", "S3", "Internal blocklist", "undeliverable", False),
    "E303": _ec("E303", "V", "S3", "Role account", "risky", False),
    "E304": _ec("E304", "V", "S3", "Probable typo", "risky", False),
    "E305": _ec("E305", "S", "S3", "Disposable list unavailable", "unknown", True, 300),
    # S4: DNS
    "E401": _ec("E401", "V", "S4", "NXDOMAIN", "undeliverable", False),
    "E402": _ec("E402", "V", "S4", "Null MX (RFC 7505)", "undeliverable", False),
    "E403": _ec("E403", "V", "S4", "No MX and no A/AAAA", "undeliverable", False),
    "E404": _ec("E404", "V", "S4", "MX hostname does not resolve", "undeliverable", False),
    "E405": _ec("E405", "V", "S4", "MX resolves to private/loopback/reserved IP", "undeliverable", False),
    "E406": _ec("E406", "S", "S4", "DNS timeout", "unknown", True, 60),
    "E407": _ec("E407", "S", "S4", "SERVFAIL or REFUSED", "unknown", True, 60),
    "E408": _ec("E408", "S", "S4", "DoH endpoint unreachable", "unknown", True, 60),
    "E409": _ec("E409", "S", "S4", "Malformed or truncated DNS response", "unknown", True, 60),
    # S5: MX fingerprint
    "E501": _ec("E501", "V", "S5", "Security gateway accepts all mail; SMTP proof meaningless", "risky", False),
    # S6: SMTP probe
    "E601": _ec("E601", "S", "S6", "Port 25 blocked or no probe configured", "unknown", True, 300),
    "E602": _ec("E602", "S", "S6", "Probe unreachable or timed out", "unknown", True, 120),
    "E603": _ec("E603", "S", "S6", "Probe auth failed", "unknown", True, None),
    "E604": _ec("E604", "S", "S6", "MX connect timeout", "unknown", True, 60),
    "E605": _ec("E605", "S", "S6", "Connection refused or reset", "unknown", True, 60),
    "E606": _ec("E606", "S", "S6", "Bad greeting or tarpit", "unknown", True, 60),
    "E607": _ec("E607", "S", "S6", "STARTTLS failure", "unknown", True, 60),
    "E608": _ec("E608", "S", "S6", "MAIL FROM rejected", "unknown", True, 300),
    "E609": _ec("E609", "S", "S6", "Session dropped mid-conversation", "unknown", True, 60),
    "E610": _ec("E610", "V", "S6", "RCPT 550/551/553 user unknown", "undeliverable", False),
    "E611": _ec("E611", "V", "S6", "Mailbox full (552 / 5.2.2)", "risky", False),
    "E612": _ec("E612", "V", "S6", "RCPT 4xx greylisting", "unknown", True, 600),
    "E613": _ec("E613", "S", "S6", "421/450 rate-limited by MX", "unknown", True, 900),
    "E614": _ec("E614", "S", "S6", "5.7.x policy block; our IP blocklisted / bad PTR", "unknown", True, 3600),
    "E615": _ec("E615", "V", "S6", "Catch-all domain: random address accepted too", "risky", False),
    "E616": _ec("E616", "V", "S6", "SSRF guard tripped (unsafe MX host)", "undeliverable", False),
    "E617": _ec("E617", "S", "S6", "All MX hosts failed", "unknown", True, 120),
    "E618": _ec("E618", "S", "S6", "Per-email wall-clock deadline exceeded", "unknown", True, 60),
    # S7: Platform
    "E701": _ec("E701", "S", "S7", "Subrequest budget exhausted", "unknown", True, None, scope="run"),
    "E702": _ec("E702", "S", "S7", "CPU / wall-time limit exceeded", "unknown", True, None, scope="run"),
    "E703": _ec("E703", "S", "S7", "Daily request quota exhausted", "unknown", True, None, scope="run"),
    "E704": _ec("E704", "S", "S7", "Cache / isolate failure", "unknown", True, 60),
    "E705": _ec("E705", "S", "S7", "Unhandled exception", "unknown", True, 60),
    "E706": _ec("E706", "S", "S7", "UI to API network failure or invalid upstream JSON", "unknown", True, 60, scope="run"),
}

OK_CODE = "OK"

# Default score per code (0-100). Deliverable OK = 95 (range 90-100 per PRD 6).
DEFAULT_SCORES: Dict[str, int] = {
    "OK": 95,
    "E101": 0, "E102": 0, "E103": 0, "E104": 0, "E105": 0,
    "E201": 5,
    "E301": 25, "E302": 0, "E303": 50, "E304": 35, "E305": 40,
    "E401": 5, "E402": 5, "E403": 5, "E404": 5, "E405": 5,
    "E406": 40, "E407": 40, "E408": 40, "E409": 40,
    "E501": 45,
    "E601": 40, "E602": 40, "E603": 40, "E604": 35, "E605": 35, "E606": 35,
    "E607": 35, "E608": 35, "E609": 35,
    "E610": 5, "E611": 45, "E612": 35, "E613": 35, "E614": 35,
    "E615": 50, "E616": 5, "E617": 35, "E618": 35,
    "E701": 35, "E702": 35, "E703": 35, "E704": 35, "E705": 35, "E706": 35,
}

# S3/S5 heuristics that become flags (not stops) under halt_policy=soft.
HEURISTIC_CODES = {"E301", "E303", "E304", "E501"}


def make_stop_cause(code: str, message: Optional[str] = None,
                    scope: Optional[str] = None) -> StopCause:
    """Build a StopCause from the registry; raises KeyError on unknown code."""
    entry = ERROR_CODES[code]
    return StopCause(
        code=code,
        code_class=entry["class"],
        stage=STAGE_LABELS[entry["stage"]],
        message=message if message is not None else entry["message"],
        retryable=bool(entry["retryable"]),
        retry_after_s=entry["retry_after_s"],
        scope=scope if scope is not None else entry["scope"],
    )


def status_for_code(code: str) -> Status:
    return Status(ERROR_CODES[code]["status"])


def level_for_code(code: str) -> str:
    if code == "E601":
        # DNS succeeded, mailbox unchecked: deepest *completed* stage is S4/S5.
        return "dns"
    return LEVEL_FOR_STAGE[ERROR_CODES[code]["stage"]]



def result_from_code(email: str, code: str, message: Optional[str] = None,
                     stage_override: Optional[str] = None,
                     flags: Optional[List[str]] = None,
                     did_you_mean: Optional[str] = None,
                     stages_completed: Optional[List[str]] = None,
                     stages_skipped: Optional[List[str]] = None,
                     mx: Optional[List[str]] = None,
                     advice: Optional[str] = None,
                     scope: Optional[str] = None,
                     took_ms: int = 0) -> Result:
    """Map an error code to a halted Result using the normative registry.

    This is the single mapping used by the pipeline and by the property test
    (S-class -> unknown + retryable; V-class -> documented status).
    """
    stop = make_stop_cause(code, message=message, scope=scope)
    if stage_override:
        stop.stage = stage_override
    entry = ERROR_CODES[code]
    return Result(
        email=email,
        status=Status(entry["status"]),
        score=DEFAULT_SCORES.get(code, 35),
        reason_code=code,
        reason=stop.message,
        level=level_for_code(code),
        flags=list(flags or []),
        did_you_mean=did_you_mean,
        halted=True,
        halt_scope=stop.scope or "email",
        stop_cause=stop,
        stages_completed=list(stages_completed or []),
        stages_skipped=list(stages_skipped or _default_skipped(stop.stage)),
        mx=list(mx or []),
        advice=advice,
        took_ms=took_ms,
    )


def ok_result(email: str, score: int = 95, flags: Optional[List[str]] = None,
              stages_completed: Optional[List[str]] = None,
              mx: Optional[List[str]] = None, took_ms: int = 0,
              reason: str = "mailbox accepted; random probe rejected") -> Result:
    """Successful SMTP-proven deliverable result."""
    return Result(
        email=email,
        status=Status.DELIVERABLE,
        score=score,
        reason_code=OK_CODE,
        reason=reason,
        level="smtp",
        flags=list(flags or []),
        did_you_mean=None,
        halted=False,
        halt_scope=None,
        stop_cause=None,
        stages_completed=list(stages_completed or ["S1", "S2", "S3", "S4", "S5", "S6"]),
        stages_skipped=[],
        mx=list(mx or []),
        advice=None,
        took_ms=took_ms,
    )

def _default_skipped(stage_label: str) -> List[str]:
    """Stages after the one identified by a StopCause.stage label."""
    order = [STAGE_LABELS[s] for s in ALL_STAGES]
    if stage_label not in order:
        return []
    idx = order.index(stage_label)
    return order[idx + 1:]

