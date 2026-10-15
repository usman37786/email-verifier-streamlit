"""Single-process ASGI server: Streamlit UI + REST API on ONE port.

Run locally:
    uvicorn server:app --host 127.0.0.1 --port 8501

What you get on that one URL:
    /                  -> the Streamlit UI (app.py, exactly as `streamlit run`
                           would serve it)
    /_stcore/health    -> Streamlit's own health check
    /api/verify        -> REST API (also mirrored at /v1/verify so any client
    /api/verify/batch       that already speaks the Cloudflare Worker contract
    /api/health              works unchanged against either host)

WHY THIS FILE EXISTS
--------------------
`streamlit run app.py` only ever exposes the Streamlit UI. Historically people
injected REST routes into Streamlit's internal web server with a garbage-collector
trick (find the live Tornado Application via gc.get_referrers(), then splice a
Rule into wildcard_router.rules). That is dead on modern Streamlit: 1.65 no
longer ships Tornado at all -- `import tornado` is ModuleNotFoundError -- the
server is now Starlette + Uvicorn, and gc-scraping for a server object is both
private-internals and a version bomb.

1.65 replaced the *need* for that hack with a public hook: `st.App()` is an
ASGI application that serves the Streamlit UI *and* a user-supplied `routes=`
list. Those user routes are registered ahead of Streamlit's own routes, and
Streamlit explicitly validates they do not clash with its reserved prefixes
(/_stcore/, /_stcore/media/, /_stcore/components/v1/, /static). Nothing in this
file touches undocumented internals.

The launcher is the one real tradeoff, and it is now settled: `streamlit run`
auto-detects ASGI apps (streamlit.web.server.app_discovery parses this file and
looks for a bare assignment to st.App(...)/FastAPI(...)/Starlette(...)). So
`streamlit run server.py` runs the combined UI+API directly -- verified on
1.65.0, no custom run command needed on Streamlit Cloud. Use that same command
as the Cloud "Run command" and point it at server.py instead of app.py.

Two constraints that will bite you if you break them:
  1. The constructor must be a literal `app = st.App(...)`. Discovery is AST
     based and resolves the call against a fixed list of known classes; a
     factory call such as `app = _make_app()` resolves to nothing, discovery
     falls back to traditional Streamlit mode, and this module gets executed as
     a Streamlit script instead of served as an ASGI app.
  2. No UTF-8 BOM. `path.read_text()` keeps the BOM as a leading character,
     `ast.parse` raises SyntaxError, discovery returns is_asgi_app=False, and
     you silently get traditional mode. `Set-Content -Encoding UTF8` in
     PowerShell 5.1 writes a BOM; strip it.

For anything that must not move, the Cloudflare Worker in `worker/` remains the
durable home for the API.

Note on dependencies: this file imports `uvicorn` (lazily, via Streamlit's own
runner) and `starlette`. Neither is in requirements.txt on purpose -- streamlit
1.65.0 declares both as hard requirements (`Requires-Dist: starlette<2,>=0.46.0`,
`Requires-Dist: uvicorn<1,>=0.30.0`), so they arrive transitively. Do not pin
them separately; starlette 1.8.0 makes `Request.body` a coroutine, not the
property older versions expose.

This module imports only `core/` and Starlette routing. It is additive:
`streamlit run app.py` continues to work exactly as before.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import streamlit as st
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from core import config as config_mod
from core.models import result_from_code
from core.pipeline import BatchError, verify, verify_batch


# --------------------------------------------------------------------------
# Error codes. These MUST stay identical to worker/src/index.js so a client can
# switch hosts by changing the base URL alone. The registry there is the
# normative one: E001 auth, E002 malformed body, E003 empty list,
# E004 batch over MAX_BULK, E705 internal error.
# --------------------------------------------------------------------------
ERR_AUTH = "E001"
ERR_MALFORMED = "E002"
ERR_EMPTY = "E003"
ERR_OVER_LIMIT = "E004"
ERR_INTERNAL = "E705"


def _secret(name: str):
    """Read a Streamlit secret, or None if secrets are unavailable.

    Mirrors app.py::_secret so the API and the UI resolve settings the same way.
    On Streamlit Cloud, values from secrets.toml arrive here; locally there is
    no secrets file and this is a no-op.
    """
    try:
        return st.secrets.get(name)
    except Exception:  # noqa: BLE001 - no secrets file locally / not configured
        return None


def _api_key() -> str:
    """Optional shared-secret gate. Unset => API is open (dev only)."""
    return (
        os.environ.get("EMAIL_VERIFIER_API_KEY")
        or os.environ.get("API_KEY")
        or _secret("EMAIL_VERIFIER_API_KEY")
        or _secret("API_KEY")
        or ""
    )


def _authorized(request: Request) -> bool:
    key = _api_key()
    if not key:
        return True
    return (
        request.headers.get("x-api-key", "") == key
        or request.query_params.get("api_key", "") == key
    )


def _cfg() -> dict:
    """The same opts dict app.py::pipeline_opts() builds, env/secrets-driven.

    Keeping this identical to the UI's builder is what makes the API and the
    Streamlit app return the same score for the same address.
    """
    opts = {
        "halt_policy": config_mod.get_halt_policy(),
        "smtp": os.environ.get("SMTP_ENABLED", "1") not in ("0", "false", "False"),
        "deadline_ms": config_mod.deadline_ms(),
        "sender": config_mod.MAIL_FROM,
        "max_bulk": config_mod.MAX_BULK,
    }
    probe_url = (config_mod.SMTP_PROBE_URL or "").strip()
    if probe_url:
        opts["probe_url"] = probe_url.rstrip("/")
        opts["probe_key"] = config_mod.SMTP_PROBE_KEY or ""
    return opts


def _catchall_preference() -> str:
    pref = os.environ.get("CATCHALL_AS", "risky")
    return pref if pref in ("risky", "unknown") else "risky"


def _apply_catchall_preference(payload: dict) -> dict:
    """Mirror app.py::apply_catchall_preference so API scores match the UI's."""
    if payload.get("reason_code") == "E615" and _catchall_preference() != "risky":
        payload["status"] = "unknown"
    return payload


def _verify(email: str) -> Any:
    """E705 wrapper -- mirrors app.py::safe_verify; never leak a traceback."""
    try:
        return verify(email, _cfg())
    except Exception as exc:  # noqa: BLE001 - contract: never show tracebacks
        return result_from_code(
            str(email), ERR_INTERNAL,
            message=f"internal error ({type(exc).__name__}); please retry",
        )


def _result_to_dict(result: Any) -> dict:
    return result.to_dict() if hasattr(result, "to_dict") else dict(result)


async def _parse_emails(request: Request) -> list:
    """Accept GET ?email=.. / POST {"email":..} / POST {"emails":[..]} / bare list.

    Note: in this Starlette version request.body is a coroutine, not a property
    (async def body(self) -> bytes), so it must be awaited.
    """
    ctype = (request.headers.get("content-type") or "").lower()
    body = await request.body() if request.method != "GET" else b""

    if request.method == "GET" or not body:
        email = request.query_params.get("email") or request.query_params.get("emails")
        if not email:
            raise BatchError(ERR_EMPTY)
        return [email]

    if "application/x-www-form-urlencoded" in ctype:
        form = await request.form()
        raw = form.get("emails") or form.get("email")
        if not raw:
            raise BatchError(ERR_EMPTY)
        return [str(raw)]

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BatchError(ERR_MALFORMED) from exc

    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, dict):
        if "emails" in payload:
            value = payload["emails"]
            if isinstance(value, str):
                value = value.replace(",", "\n")
            return [str(v) for v in value]
        if "email" in payload:
            return [str(payload["email"])]
    if isinstance(payload, list):
        return [str(v) for v in payload]
    raise BatchError(ERR_MALFORMED)


def _err(code: str, status: int, message: str = "") -> JSONResponse:
    """Worker-shaped error envelope: {"error": {"code": ..., "message": ...}}."""
    return JSONResponse({"error": {"code": code, "message": message or code}}, status_code=status)


def _unauthorized(request: Request) -> JSONResponse | None:
    return None if _authorized(request) else _err(ERR_AUTH, 401, "invalid or missing API key")


async def _verify_single(request: Request) -> JSONResponse:
    """GET/POST /api/verify -- the primary endpoint."""
    denied = _unauthorized(request)
    if denied is not None:
        return denied

    started = time.monotonic()
    try:
        emails = await _parse_emails(request)
    except BatchError as exc:
        return _err(exc.code, 400)

    if not emails or not str(emails[0]).strip():
        return _err(ERR_EMPTY, 400)
    if len(emails) != 1:
        # Single endpoint, plural input: a malformed request, not a batch.
        return _err(ERR_MALFORMED, 400, "expected exactly one email; use /api/verify/batch")

    payload = _apply_catchall_preference(_result_to_dict(_verify(str(emails[0]).strip())))
    payload["request_ms"] = int((time.monotonic() - started) * 1000)
    return JSONResponse(payload)


async def _verify_batch(request: Request) -> JSONResponse:
    """GET/POST /api/verify/batch -- batch variant, same envelope shape."""
    denied = _unauthorized(request)
    if denied is not None:
        return denied

    started = time.monotonic()
    try:
        emails = await _parse_emails(request)
    except BatchError as exc:
        return _err(exc.code, 400)

    cleaned = [str(e).strip() for e in emails if str(e).strip()]
    if not cleaned:
        return _err(ERR_EMPTY, 400)
    if len(cleaned) > config_mod.MAX_BULK:
        return _err(ERR_OVER_LIMIT, 413)
    if sum(len(e.encode("utf-8")) for e in cleaned) > config_mod.MAX_INPUT_BYTES:
        return _err(ERR_OVER_LIMIT, 413)

    try:
        batch = verify_batch(cleaned, _cfg())
    except BatchError as exc:
        return _err(exc.code, 400)
    except Exception as exc:  # noqa: BLE001 - never leak a traceback
        return _err(ERR_INTERNAL, 500, f"internal error ({type(exc).__name__})")

    payload = _result_to_dict(batch)
    # Entries are None for not_processed rows, so guard the preference pass.
    payload["results"] = [
        _apply_catchall_preference(r) if isinstance(r, dict) else r
        for r in payload["results"]
    ]
    payload["request_ms"] = int((time.monotonic() - started) * 1000)
    return JSONResponse(payload)


async def _health(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


# --------------------------------------------------------------------------
# The ASGI app: Streamlit UI + REST routes, one process, one port.
#
# This MUST be a direct st.App(...) call, not wrapped in a factory function.
# `streamlit run` decides between "traditional Streamlit script" mode and
# "ASGI app" mode by AST-parsing this file (streamlit.web.server.app_discovery)
# and looking for a bare assignment to a known ASGI constructor such as
# st.App(...), FastAPI(...) or Starlette(...). A call like `app = _make_app()`
# resolves to no known class, so discovery falls back to traditional mode and
# executes this module as a Streamlit script instead of serving it as an ASGI
# app. Keeping the constructor literal is a load-bearing constraint, not style.
# --------------------------------------------------------------------------

# /v1/* mirrors the Cloudflare Worker contract (worker/src/index.js) so a client
# can switch hosts by changing the base URL alone.
app = st.App(
    "app.py",
    routes=[
        Route("/api/verify", _verify_single, methods=["GET", "POST"]),
        Route("/api/verify/batch", _verify_batch, methods=["GET", "POST"]),
        Route("/api/health", _health, methods=["GET"]),
        Route("/v1/verify", _verify_single, methods=["GET", "POST"]),
        Route("/v1/verify/batch", _verify_batch, methods=["GET", "POST"]),
    ],
)


if __name__ == "__main__":
    # `python server.py` == `streamlit run server.py` == `uvicorn server:app`.
    # Under uvicorn the module is imported as "server", so this block is skipped.
    app.run()
