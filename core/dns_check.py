"""S4: DNS via DNS-over-HTTPS (free, no key) with dnspython fallback.

The DoH query function is injectable so tests can drive recorded fixtures
without network. Queries MX + A + AAAA in parallel; per-query timeout is
capped by min(DOH_TIMEOUT_MS, remaining budget).
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import config

TYPE_A, TYPE_AAAA, TYPE_MX = 1, 28, 15
_RTYPE_NUM = {"A": TYPE_A, "AAAA": TYPE_AAAA, "MX": TYPE_MX}


class DohTimeout(Exception):
    pass


class DohHttpError(Exception):
    pass


class DohMalformed(Exception):
    pass


@dataclass
class DnsOutcome:
    stop: Optional[object] = None  # StopCause
    mx: List[str] = field(default_factory=list)
    ips: Dict[str, List[str]] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    implicit: bool = False


# --- DoH cache (1 h TTL, LRU-ish dict, thread-safe) -------------------------
_CACHE: Dict[Tuple[str, int], Tuple[dict, float]] = {}
_CACHE_LOCK = threading.Lock()
_MAX_CACHE = 5000


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def _cache_get(name: str, rtype: int) -> Optional[dict]:
    with _CACHE_LOCK:
        hit = _CACHE.get((name, rtype))
    if not hit:
        return None
    value, ts = hit
    if time.time() - ts > config.DOH_CACHE_TTL_S:
        return None
    return value


def _cache_put(name: str, rtype: int, value: dict) -> None:
    with _CACHE_LOCK:
        if len(_CACHE) >= _MAX_CACHE:
            # crude eviction: drop oldest quarter
            items = sorted(_CACHE.items(), key=lambda kv: kv[1][1])
            for key, _ in items[: _MAX_CACHE // 4]:
                _CACHE.pop(key, None)
        _CACHE[(name, rtype)] = (value, time.time())


def _parse_doh(data, name: str) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("Status"), int):
        raise DohMalformed("DoH response missing integer Status")
    status = data["Status"]
    answers = []
    raw = data.get("Answer")
    if raw is not None:
        if not isinstance(raw, list):
            raise DohMalformed("DoH Answer is not a list")
        for rr in raw:
            if not isinstance(rr, dict) or "data" not in rr:
                raise DohMalformed("DoH RR missing data")
            answers.append({"name": rr.get("name", name),
                            "type": int(rr.get("type", 0)),
                            "data": str(rr["data"])})
    return {"Status": status, "Answer": answers}


def default_doh_query(name: str, rtype: str, timeout_ms: int) -> dict:
    """Real DoH lookup: cloudflare-dns.com primary, dns.google fallback,
    dnspython as last resort. Returns parsed DoH-JSON or raises Doh*.``"""
    import requests

    deadline = time.monotonic() + max(timeout_ms, 1) / 1000.0
    last: Optional[Exception] = None
    saw_http_error = False
    for url in ("https://cloudflare-dns.com/dns-query",
                "https://dns.google/resolve"):
        left = deadline - time.monotonic()
        if left <= 0.02:
            break
        try:
            resp = requests.get(
                url, params={"name": name, "type": rtype},
                headers={"accept": "application/dns-json"},
                timeout=left,
            )
            if resp.status_code != 200:
                last = DohHttpError(f"HTTP {resp.status_code} from {url}")
                saw_http_error = True
                continue
            return _parse_doh(resp.json(), name)
        except requests.Timeout as exc:
            last = DohTimeout(str(exc))
            break  # budget spent; do not double the per-query cap
        except DohMalformed:
            raise
        except (requests.RequestException, ValueError) as exc:
            last = DohHttpError(str(exc))
            saw_http_error = True
    if last is None:
        last = DohTimeout("DNS budget exhausted")
    if isinstance(last, DohTimeout):
        raise last
    # DoH endpoints unreachable -> dnspython fallback with leftover budget.
    left = deadline - time.monotonic()
    if left > 0.05:
        try:
            return _dnspython_query(name, rtype, left)
        except DohTimeout:
            raise
        except Exception as exc:  # noqa: BLE001 - map to S-class below
            raise DohHttpError(str(exc)) from exc
    raise last


def _dnspython_query(name: str, rtype: str, timeout_s: float) -> dict:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = max(timeout_s, 0.05)
    resolver.lifetime = max(timeout_s, 0.05)
    try:
        answer = resolver.resolve(name, rtype)
        return {"Status": 0, "Answer": [
            {"name": name, "type": _RTYPE_NUM[rtype], "data": rr.to_text()}
            for rr in answer
        ]}
    except dns.resolver.NXDOMAIN:
        return {"Status": 3, "Answer": []}
    except dns.resolver.NoAnswer:
        return {"Status": 0, "Answer": []}
    except dns.resolver.NoNameservers as exc:
        raise DohHttpError(str(exc)) from exc
    except dns.exception.Timeout as exc:
        raise DohTimeout(str(exc)) from exc

def _query(doh: Callable, name: str, rtype: str,
           remaining_fn: Optional[Callable]) -> dict:
    """One logical DoH query with 1 h cache and per-query timeout cap."""
    num = _RTYPE_NUM[rtype]
    cached = _cache_get(name, num)
    if cached is not None:
        return cached
    budget = config.DOH_TIMEOUT_MS
    if remaining_fn is not None:
        budget = min(budget, max(0, int(remaining_fn())))
    if budget <= 25:
        raise DohTimeout("deadline exhausted before DNS query")
    data = doh(name, rtype, budget)
    parsed = _parse_doh(data, name)
    _cache_put(name, num, parsed)
    return parsed


def _is_unsafe_ip(ip_text: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(ip_text.split("%")[0])
    except ValueError:
        return True
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _collect_ips(doh: Callable, host: str,
                 remaining_fn: Optional[Callable]) -> Tuple[List[str], Optional[str]]:
    """Resolve A+AAAA in parallel for one host.

    Returns (ips, s_code_or_None). s_code is set when DNS itself failed
    (timeout/servfail/unreachable) as opposed to the host not existing.
    """
    def q(rtype: str):
        return _query(doh, host, rtype, remaining_fn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_a = pool.submit(q, "A")
        f_aaaa = pool.submit(q, "AAAA")
        results = {}
        for rtype, fut in (("A", f_a), ("AAAA", f_aaaa)):
            try:
                results[rtype] = ("ok", fut.result())
            except DohTimeout:
                results[rtype] = ("timeout", None)
            except DohMalformed:
                results[rtype] = ("malformed", None)
            except Exception:  # noqa: BLE001 - DohHttpError or unexpected
                results[rtype] = ("http", None)
    ips: List[str] = []
    s_code = None
    statuses = {v[1]["Status"] for v in results.values() if v[0] == "ok"}
    for rtype, (kind, value) in results.items():
        if kind != "ok":
            continue
        if rtype == "A" and value["Status"] == 3:
            continue  # NXDOMAIN handled via statuses
        for rr in value["Answer"]:
            if rr["type"] == _RTYPE_NUM[rtype]:
                ips.append(rr["data"].split(" ")[-1])
    if statuses == {3}:
        return [], None  # host does not exist (V-class: E404 territory)
    if not ips:
        kinds = {k for k, _ in results.values()}
        if "timeout" in kinds:
            s_code = "E406"
        elif "http" in kinds:
            s_code = "E408"
        elif "malformed" in kinds:
            s_code = "E409"
    return ips, s_code


def check_domain(domain: str, doh: Optional[Callable] = None,
                 remaining_fn: Optional[Callable] = None) -> DnsOutcome:
    """Run S4 for one domain. `doh(name, rtype, timeout_ms) -> DoH-JSON dict`
    is injectable for tests; it may raise DohTimeout/DohHttpError/DohMalformed
    (or any Exception, which is treated as E408)."""
    doh = doh or default_doh_query
    from .models import make_stop_cause

    def q(rtype: str):
        return _query(doh, domain, rtype, remaining_fn)

    # Wave 1: MX + A + AAAA in parallel (PRD 15.2).
    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {rt: pool.submit(q, rt) for rt in ("MX", "A", "AAAA")}
        res: Dict[str, Tuple[str, Optional[dict]]] = {}
        for rt, fut in futs.items():
            try:
                res[rt] = ("ok", fut.result())
            except DohTimeout:
                res[rt] = ("timeout", None)
            except DohMalformed:
                res[rt] = ("malformed", None)
            except Exception:  # noqa: BLE001
                res[rt] = ("http", None)

    mx_status, mx_answers = 0, []
    if res["MX"][0] == "ok":
        mx_status = res["MX"][1]["Status"]
        mx_answers = res["MX"][1]["Answer"]
    else:
        kind = res["MX"][0]
        code = {"timeout": "E406", "malformed": "E409"}.get(kind, "E408")
        return DnsOutcome(stop=make_stop_cause(code))

    if mx_status == 3:
        return DnsOutcome(stop=make_stop_cause("E401", "NXDOMAIN"))
    if mx_status in (2, 5):
        return DnsOutcome(stop=make_stop_cause("E407"))

    hosts: List[Tuple[int, str]] = []
    for rr in mx_answers:
        if rr["type"] != TYPE_MX:
            continue
        parts = rr["data"].strip().rstrip(".").split(" ", 1)
        if len(parts) == 2:
            try:
                pref = int(parts[0])
            except ValueError:
                continue
            host = parts[1].strip().rstrip(".").lower()
            if pref == 0 and host in ("", "."):
                return DnsOutcome(stop=make_stop_cause("E402", "null MX (RFC 7505)"))
            if host:
                hosts.append((pref, host))
    hosts.sort(key=lambda kv: kv[0])

    def a_answers(rtype: str) -> List[str]:
        kind, value = res[rtype]
        if kind != "ok" or value["Status"] != 0:
            return []
        return [rr["data"] for rr in value["Answer"]
                if rr["type"] == _RTYPE_NUM[rtype]]

    if not hosts:
        ips = a_answers("A") + a_answers("AAAA")
        if ips:
            unsafe = [ip for ip in ips if _is_unsafe_ip(ip)]
            if unsafe:
                return DnsOutcome(stop=make_stop_cause(
                    "E405", f"implicit MX points to unsafe IP {unsafe[0]}"))
            # RFC 5321 implicit MX on the domain's A/AAAA.
            return DnsOutcome(mx=[domain], ips={domain: ips},
                              flags=["implicit_mx"], implicit=True)
        kinds = {res[rt][0] for rt in ("A", "AAAA")}
        if "timeout" in kinds:
            return DnsOutcome(stop=make_stop_cause("E406"))
        if "http" in kinds:
            return DnsOutcome(stop=make_stop_cause("E408"))
        if "malformed" in kinds:
            return DnsOutcome(stop=make_stop_cause("E409"))
        return DnsOutcome(stop=make_stop_cause("E403", "no MX and no A/AAAA"))

    # Wave 2: resolve MX hosts.
    out_mx: List[str] = []
    out_ips: Dict[str, List[str]] = {}
    s_failure: Optional[str] = None
    saw_host = False
    for _pref, host in hosts:
        ips, s_code = _collect_ips(doh, host, remaining_fn)
        if ips:
            saw_host = True
            out_mx.append(host)
            out_ips[host] = ips
            for ip in ips:
                if _is_unsafe_ip(ip):
                    return DnsOutcome(stop=make_stop_cause(
                        "E405", f"MX {host} points to unsafe IP {ip}"))
        elif s_code and s_failure is None:
            s_failure = s_code
    if not out_mx:
        if s_failure:
            return DnsOutcome(stop=make_stop_cause(s_failure))
        if not saw_host:
            return DnsOutcome(stop=make_stop_cause(
                "E404", "MX hostname does not resolve"))
    return DnsOutcome(mx=out_mx, ips=out_ips)

