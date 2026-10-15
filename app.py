"""Email Verifier - Streamlit UI (four tabs: Single, Bulk, Settings, Docs).

Local mode (default) calls core.pipeline in-process (the proven port-25
path); API mode posts to the Cloudflare Worker. Every user-facing code path
converts unexpected exceptions into `unknown` + E705 - never a raw traceback,
never a false "Invalid".
"""
import time

import pandas as pd
import streamlit as st

from core import config
from core import lists_check
from core.lists_check import get_db
from core.models import Result, result_from_code
from core.pipeline import RunState, verify

st.set_page_config(page_title="Email Verifier", page_icon="✉️", layout="wide")

STATUS_COLORS = {
    "deliverable": ("#0b6e2f", "#e6f6ec"),
    "undeliverable": ("#8b1a1a", "#fdecec"),
    "risky": ("#8a5a00", "#fff6e0"),
    "unknown": ("#3d4a5c", "#eef1f5"),
}
LEGACY_STATUS = {
    "deliverable": "Valid",
    "undeliverable": "Invalid",
    "risky": "Risky",
    "unknown": "Unknown",
}
STAGE_LABELS = ["S1", "S2", "S3", "S4", "S5", "S6"]

DEFAULTS = {
    "mode": "local",
    "halt_policy": "strict",
    "smtp_enabled": True,
    "mail_from": config.MAIL_FROM,
    "deadline_ms": 3000,
    "batch_delay_ms": 0,
    "domain_delay_ms": 0,
    "catchall_as": "risky",
    "api_base": "https://email-verifier.<you>.workers.dev",
    "api_key": "",
    "probe_url": "",
    "probe_key": "",
}


def _secret(name: str):
    """Read a Streamlit Cloud secret, or None if secrets are unavailable.

    On Streamlit Cloud, values from secrets.toml arrive here; locally there is
    no secrets.toml and this is a no-op, so the Settings tab still works.
    """
    try:
        return st.secrets.get(name)
    except Exception:  # noqa: BLE001 - no secrets file locally / not configured
        return None


# in-app setting key -> Streamlit Cloud secret name. Lets a deployment ship
# preconfigured; the Settings tab always takes precedence once it is used.
SECRET_KEYS = {
    "mode": "MODE",
    "api_base": "API_BASE",
    "api_key": "API_KEY",
    "probe_url": "SMTP_PROBE_URL",
    "probe_key": "PROBE_API_KEY",
}


def settings(key):
    if key not in st.session_state:
        value = _secret(SECRET_KEYS.get(key, key))
        st.session_state[key] = DEFAULTS[key] if value is None else value
    return st.session_state[key]


def pipeline_opts() -> dict:
    opts = {
        "halt_policy": settings("halt_policy"),
        "smtp": bool(settings("smtp_enabled")),
        "deadline_ms": int(settings("deadline_ms")),
        "sender": settings("mail_from"),
    }
    probe_url = (settings("probe_url") or "").strip()
    if probe_url:
        opts["probe_url"] = probe_url.rstrip("/")
        opts["probe_key"] = settings("probe_key") or ""
    return opts


def as_dict(value):
    """Results may be dataclasses or plain dicts; the UI always wants a dict."""
    return value.to_dict() if hasattr(value, "to_dict") else dict(value)


def apply_catchall_preference(result: dict) -> dict:
    """Settings toggle; the conservative fallback keeps status != deliverable."""
    if result.get("reason_code") == "E615" and settings("catchall_as") != "risky":
        result["status"] = "unknown"
    return result


def safe_verify(email, opts: dict) -> Result:
    """E705 wrapper - the only place the UI touches the pipeline directly."""
    try:
        return verify(email, opts)
    except Exception as exc:  # noqa: BLE001 - contract: never show tracebacks
        return result_from_code(
            str(email), "E705",
            message=f"internal error ({type(exc).__name__}); please retry")


def api_request(path: str, payload: dict = None, method: str = "POST") -> dict:
    """Call the Worker. Raises RuntimeError(E706) on network/JSON failure."""
    import json

    import requests

    base = str(settings("api_base")).rstrip("/")
    headers = {"Content-Type": "application/json"}
    key = settings("api_key")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        if method == "GET":
            resp = requests.get(base + path, headers=headers, timeout=30)
        else:
            resp = requests.post(base + path, headers=headers,
                                 data=json.dumps(payload or {}), timeout=30)
    except Exception as exc:  # noqa: BLE001 - UI-side network failure = E706
        raise RuntimeError(f"E706: cannot reach API ({type(exc).__name__})") from exc
    try:
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 - invalid JSON from upstream
        raise RuntimeError(
            f"E706: API returned invalid JSON (HTTP {resp.status_code})") from exc
    data.setdefault("_http_status", resp.status_code) if isinstance(data, dict) else None
    return data


def e706_banner(message: str, scope: str = "single"):
    st.error(f"**API connection problem (E706)** — {message}\n\n"
             "Rows were NOT marked invalid. Fix the connection and retry; "
             "results so far are preserved.")
    if st.button(f"Retry {scope} verification", key=f"e706_retry_{scope}"):
        st.session_state[f"_retry_{scope}"] = True
        st.rerun()


def result_to_row(r: dict) -> dict:
    status = r.get("status", "unknown")
    return {
        "Email": r.get("email", ""),
        "Status": LEGACY_STATUS.get(status, status),
        "Validation_Message": f"{r.get('reason_code', '?')}: {r.get('reason', '')}",
        "Score": r.get("score", ""),
        "Reason_Code": r.get("reason_code", ""),
        "Level": r.get("level", ""),
        "Did_You_Mean": r.get("did_you_mean") or "",
    }


def render_single(r: dict):
    status = r.get("status", "unknown")
    fg, bg = STATUS_COLORS.get(status, STATUS_COLORS["unknown"])
    st.markdown(
        f"<div style='background:{bg};color:{fg};border:1px solid {fg};"
        f"border-radius:8px;padding:14px 18px;font-size:20px;font-weight:700;"
        f"text-transform:uppercase'>{status}"
        f" &nbsp; <span style='font-size:14px;font-weight:400'>score "
        f"{r.get('score', '-')} / 100 · level {r.get('level', '-')} · "
        f"{r.get('took_ms', 0)} ms</span></div>",
        unsafe_allow_html=True)
    st.progress(min(int(r.get("score", 0)), 100) / 100)

    done = set(r.get("stages_completed", []))
    skipped = set(r.get("stages_skipped", []))
    cols = st.columns(len(STAGE_LABELS))
    for col, stage in zip(cols, STAGE_LABELS):
        mark = "✅" if stage in done else ("➖" if stage in skipped else "⬜")
        col.markdown(f"**{stage}** {mark}")

    if r.get("stop_cause"):
        sc = r["stop_cause"]
        retry = " · retryable" if sc.get("retryable") else " · final"
        st.markdown(
            f"<div style='background:#fdecec;border-left:5px solid #8b1a1a;"
            f"padding:10px 14px;border-radius:4px;color:#8b1a1a'>"
            f"<b>stop_cause {sc.get('code')}</b> ({sc.get('class')}-class, "
            f"{sc.get('stage')}{retry})<br>{sc.get('message')}</div>",
            unsafe_allow_html=True)
    if r.get("did_you_mean"):
        st.info(f"💡 Did you mean **{r['did_you_mean']}**? "
                "(paste the corrected address into Single check to confirm)")
    if r.get("advice"):
        st.caption(f"advice: {r['advice']}")
    if r.get("flags"):
        st.caption(f"flags: {', '.join(r['flags'])}")
    if r.get("stages_completed"):
        st.caption(f"stages completed: {', '.join(r['stages_completed'])}")


def collect_emails(textarea: str, uploaded) -> list:
    if uploaded is not None:
        frame = pd.read_csv(uploaded)
        frame.columns = [str(c).strip() for c in frame.columns]
        cols = [c for c in frame.columns if "email" in c.lower()]
        if not cols:
            cols = [frame.columns[0]]
        return [str(v).strip() for v in frame[cols[0]].tolist() if str(v).strip()]
    return [ln.strip() for ln in textarea.splitlines() if ln.strip()]


def group_by_domain(emails):
    grouped = {}
    for addr in emails:
        domain = addr.rsplit("@", 1)[1].lower() if "@" in addr else ""
        grouped.setdefault(domain, []).append(addr)
    return list(grouped.items())


def run_bulk_local(emails, opts, bar, note, state):
    results = []
    total = len(emails)
    domain_delay = max(0, int(settings("domain_delay_ms"))) / 1000.0
    batch_delay = max(0, int(settings("batch_delay_ms"))) / 1000.0
    # core.pipeline.verify() only consults the RunState breakers when opts
    # carries _run_state (pipeline.py reads opts["_run_state"]). Without that
    # line the local bulk path could never open a breaker, so an
    # environment-wide failure -- our outbound IP listed in an RBL, returning
    # E614 on every address -- burned one SMTP session per address for the
    # entire list, and the `if state.trip` guards below were polling a
    # RunState that could never trip. app.py always passes a real RunState().
    opts = dict(opts)
    if isinstance(state, RunState):
        opts["_run_state"] = state
    for n, (domain, group) in enumerate(group_by_domain(emails)):
        if state.trip:
            break
        for addr in group:
            r = safe_verify(addr, opts)
            results.append(apply_catchall_preference(as_dict(r)))
            done = len(results)
            bar.progress(min(done / total, 1.0))
            note.write(f"processed {done}/{total}")
            if state.trip:
                break
        if domain_delay and not state.trip:
            time.sleep(domain_delay)
        if batch_delay and n and not state.trip:
            time.sleep(batch_delay)
    return results


def run_bulk_api(emails, opts, bar, note):
    all_results = []
    remaining = list(emails)
    total = len(emails)
    for attempt in range(8):
        if not remaining:
            break
        chunk = remaining[:50]
        try:
            # The Worker's /v1/verify takes a single "email"; batches go to
            # /v1/verify/batch with an "emails" array (see worker/src/index.js
            # handleSingle / handleBatch).
            data = api_request("/v1/verify/batch",
                               {"emails": chunk, "options": opts})
        except RuntimeError as exc:
            e706_banner(str(exc), scope="bulk")
            return all_results, remaining, None
        results = data.get("results", [])
        if not isinstance(results, list):
            e706_banner(f"API returned no results (HTTP {data.get('_http_status')})",
                        scope="bulk")
            return all_results, remaining, None
        all_results.extend(results)
        all_results = [apply_catchall_preference(r) for r in all_results]
        bar.progress(min(len(all_results) / total, 1.0))
        note.write(f"processed {len(all_results)}/{total}")
        resume = data.get("resume_from") or []
        state_hint = data.get("run_state")
        if not resume:
            remaining = []
            break
        remaining = resume  # auto-resend the unprocessed remainder
        if attempt:
            time.sleep(1.0)
    return all_results, remaining, state_hint


def summary_counts(results):
    counts = {k: 0 for k in ("deliverable", "risky", "unknown", "undeliverable")}
    for r in results:
        counts[r.get("status", "unknown")] = counts.get(r.get("status", "unknown"), 0) + 1
    return counts


def render_bulk(results):
    counts = summary_counts(results)
    st.bar_chart({"deliverable": counts["deliverable"], "risky": counts["risky"],
                  "unknown": counts["unknown"], "undeliverable": counts["undeliverable"]})
    rows = [result_to_row(r) for r in results]
    df = pd.DataFrame(rows)
    st.dataframe(df, width="stretch")
    col = st.columns(5)
    download_csv(rows, "results_all.csv", "⬇ All", col[0])
    download_csv([r for r in rows if r["Status"] == "Valid"], "results_deliverable.csv",
                "⬇ Deliverable", col[1])
    download_csv([r for r in rows if r["Status"] == "Risky"], "results_risky.csv",
                "⬇ Risky", col[2])
    download_csv([r for r in rows if r["Status"] == "Unknown"], "results_unknown.csv",
                "⬇ Unknown", col[3])
    download_csv([r for r in rows if r["Status"] == "Invalid"],
                "results_undeliverable.csv", "⬇ Undeliverable", col[4])


def download_csv(rows, filename, label, col=None):
    frame = pd.DataFrame(rows)
    if frame.empty:
        frame = pd.DataFrame(columns=list(result_to_row({}).keys()))
    csv_bytes = frame.to_csv(index=False).encode("utf-8-sig")
    (col or st).download_button(label, data=csv_bytes, file_name=filename,
                                mime="text/csv")


def tab_single():
    st.markdown("Paste one address. Stop cause, stage checklist and timing are "
                "shown for every result.")
    if settings("mode") == "api":
        st.caption("API mode — this address is verified by the Worker.")
    email = st.text_input("Email address", placeholder="name@example.com")
    if (st.button("Verify") or st.session_state.pop("_retry_single", False)) \
            and email.strip():
        opts = pipeline_opts()
        if settings("mode") == "api":
            try:
                data = api_request("/v1/verify", {"email": email.strip(),
                                                  "options": opts})
                # /v1/verify responds with a single {result: {...}} object,
                # not a {results: [...]} list (that shape is /v1/verify/batch).
                result = data.get("result") if isinstance(data, dict) else None
                if not result:
                    e706_banner(f"API returned no result "
                                f"(HTTP {data.get('_http_status')})",
                                scope="single")
                else:
                    render_single(apply_catchall_preference(result))
            except RuntimeError as exc:
                e706_banner(str(exc), scope="single")
        else:
            render_single(apply_catchall_preference(
                as_dict(safe_verify(email.strip(), opts))))


def tab_bulk():
    st.markdown("Paste a list or upload a CSV. Columns containing **email** are "
                "detected automatically; results are grouped by domain.")
    left, right = st.columns([3, 2])
    textarea = left.text_area("Addresses (one per line)", height=180,
                              placeholder="a@b.com\nc@d.com")
    uploaded = right.file_uploader("or upload a CSV", type=["csv"])
    emails = collect_emails(textarea, uploaded)
    st.caption(f"{len(emails)} address(es) ready")
    if st.button("Run bulk check", disabled=not emails) or \
            st.session_state.pop("_retry_bulk", False):
        opts = pipeline_opts()
        bar = st.progress(0.0)
        note = st.empty()
        if settings("mode") == "api":
            results, remaining, _ = run_bulk_api(emails, opts, bar, note)
        else:
            results = run_bulk_local(emails, opts, bar, note, RunState())
            remaining = []
        if remaining:
            st.warning(f"Rate-limited: {len(remaining)} address(es) unprocessed. "
                       "Results so far are kept — run again to resend the "
                       "remainder.")
        render_bulk(results)


def tab_settings():
    with st.form("settings_form"):
        mode = st.radio("Mode", ["local", "api"], horizontal=True,
                        format_func=lambda v: "Local (default)" if v == "local"
                        else "API (Worker)",
                        index=0 if settings("mode") == "local" else 1)
        halt_policy = st.selectbox("halt_policy", ["soft", "strict"],
                                   index=1 if settings("halt_policy") == "strict"
                                   else 0)
        smtp_enabled = st.checkbox("SMTP probe (S6)",
                                   value=bool(settings("smtp_enabled")))
        skip_smtp = st.checkbox("skip-SMTP toggle (DNS only, stops at S5)",
                                value=not settings("smtp_enabled"))
        catchall_as = st.selectbox("treat-catch-all-as", ["risky", "unknown"],
                                   index=0 if settings("catchall_as") == "risky"
                                   else 1)
        mail_from = st.text_input("MAIL FROM", value=str(settings("mail_from")))
        deadline_ms = st.slider("request deadline (ms)", 500, 10000,
                                int(settings("deadline_ms")), step=100)
        batch_delay_ms = st.slider("batch delay (ms)", 0, 10000,
                                   int(settings("batch_delay_ms")), step=50)
        domain_delay_ms = st.slider("domain delay (ms)", 0, 10000,
                                    int(settings("domain_delay_ms")), step=50)
        api_base = st.text_input("API_BASE", value=str(settings("api_base")))
        api_key = st.text_input("API_KEY", value=str(settings("api_key")),
                                type="password")
        probe_url = st.text_input(
            "SMTP_PROBE_URL (blank = direct SMTP, needs outbound port 25)",
            value=str(settings("probe_url")),
            help="URL of the smtp-probe/ service, e.g. "
                 "https://probe.yourname.workers.dev. Leave blank to let this "
                 "app open SMTP sockets itself (only works off Streamlit Cloud).")
        probe_key = st.text_input("PROBE_API_KEY",
                                  value=str(settings("probe_key")),
                                  type="password")
        submitted = st.form_submit_button("Save settings")
    if submitted:
        st.session_state.update({
            "mode": "local" if mode == "Local (default)" else "api",
            "halt_policy": "strict" if halt_policy == "strict" else "soft",
            "smtp_enabled": bool(smtp_enabled) and not skip_smtp,
            "catchall_as": catchall_as,
            "mail_from": mail_from,
            "deadline_ms": deadline_ms,
            "batch_delay_ms": batch_delay_ms,
            "domain_delay_ms": domain_delay_ms,
            "api_base": api_base,
            "api_key": api_key,
            "probe_url": probe_url,
            "probe_key": probe_key,
        })
        st.success("Settings saved.")
    st.markdown("**Legacy parity**")
    db = get_db()
    st.markdown(
        f"- CSV output keeps the legacy `Status` + `Validation_Message` columns.\n"
        f"- Disposable config file: `{lists_check._BUNDLED}` "
        f"({len(db.disposable)} domains) — edits reload automatically.\n"
        f"- Batch/domain delay sliders replicate the old script's pacing.")
    if settings("mode") == "api":
        st.info("API mode is optional and never required: local mode runs the "
                "verified pipeline in-process. Network problems show an E706 "
                "banner with retry and never mark rows invalid.")


DOCS = """
### Endpoints (Cloudflare Worker)
- `GET  /health` → `{"ok": true, "version", "probe", "max_bulk"}`
- `GET  /v1/verify?email=a@b.com` → `{"result": {...}}`
- `POST /v1/verify` — `{"email": "a@b.com", "options": {...}}`
  → `{"result": {...}}`
- `POST /v1/verify/batch` — `{"emails": ["a@b.com"], "options": {...}}`
  → `{"results": [...], "run_state": {...}, "resume_from": []}`

Batches are capped at `MAX_BULK` (default 100); over-cap returns
`413 / E004`. Auth is `Authorization: Bearer <API_KEY>` when the
`API_KEY` secret is set. Unknown route → `404 / E002`.

### Environment variables
`API_BASE_URL` · `API_KEY` · `API_TIMEOUT_S` · `API_MAX_BATCH` · `API_MAX_DEPTH`
· `API_MAX_RETRIES` · `API_DELAY_MS` · `API_DOMAIN_DELAY_MS` · `BATCH_DELAY_MS`
· `SMTP_TIMEOUT_S` · `WORKER_API_BASE`

### Statuses
`deliverable` (SMTP accepted the mailbox) · `risky` (domain works, heuristics or
catch-all flag it; score capped at 59) · `unknown` (transient, retry) ·
`undeliverable` (final, never retried).

### Acceptable use
Verify addresses your users submit, or lists you already own. Do not scrape,
spam, or cold-contact strangers — you are responsible for your recipient lists.

### Notes
Catch-all domains always yield `risky` (E615), never `valid`. Retryable codes
(E605-E609, E612, E618) get at most one retry; final codes (E3xx, E4xx, E5xx,
E601-E604, E610, E615, E616) are never retried.
""".strip()


def tab_docs():
    st.markdown(DOCS)


def main():
    st.title("✉️ Email Verifier")
    st.markdown("Six-stage verification: syntax → disposable → blacklist → DNS → "
                "catch-all heuristics → SMTP probe. Statuses: "
                "**deliverable / risky / unknown / undeliverable** — never a "
                "false `Invalid`.")
    st.markdown(f"Mode: **{settings('mode').upper()}** · "
                f"halt_policy `{settings('halt_policy')}` · "
                f"deadline {settings('deadline_ms')} ms")
    tab1, tab2, tab3, tab4 = st.tabs(
        ["Single check", "Bulk", "Settings", "Docs"])
    with tab1:
        tab_single()
    with tab2:
        tab_bulk()
    with tab3:
        tab_settings()
    with tab4:
        tab_docs()


main()




