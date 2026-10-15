# Deploying email-verifier

Three runtimes, one pipeline. `core/` is the source of truth; the Worker JS
reimplements S1–S5 with the same codes. S6 (SMTP) is attempted in-process
where the host has raw TCP (Streamlit Cloud, `smtp-probe/`); the Cloudflare
Worker has no TCP sockets at all, so it delegates S6 to the probe.

| Host | What it serves | Outbound port 25 |
|---|---|---|
| **Cloudflare Worker** | JSON API **and** a static UI, one URL | Not available — needs the probe |
| **Streamlit Cloud** | Streamlit UI; plus a JSON API on the same URL if you launch `server.py` (§2b) | Appears to work; see §3 |
| **probe host** (any VPS/tunnel) | SMTP probe microservice | **Required** |

---

## Why there are two UIs

The split below is a choice, not a Streamlit limitation. `streamlit run` will
serve custom HTTP routes if the entry point declares an ASGI app
(`st.App(..., routes=[...])`) — see §2b, which puts the UI and the JSON API on
one Streamlit Cloud URL. The Worker is still the better home for the API when
you want an endpoint that is stable and independent of your UI deployments; S6
is also the one stage only a raw-TCP host can prove in-process.

The Worker now serves **both**:

- `GET /` — a no-build HTML UI (single + bulk verify)
- `GET /health`, `GET|POST /v1/verify`, `POST /v1/verify/batch` — the JSON API

So Cloudflare gives you UI *and* API on one host. Streamlit gives you the richer
UI (CSV upload/download, per-row stop cause, pacing controls) and talks to the
Worker in API mode, or runs the pipeline in-process in local mode.

Use whichever you want. They are interchangeable for the same address because
both are the same pipeline with the same error codes.

---

## 0. Install

### Python side (Streamlit UI + probe)

Verified working: **Python 3.13.13**. Streamlit Cloud needs Python >= 3.11
(pandas 3.x and dnspython 2.9 require it), so set the project's Python version
to **3.13** in the deploy dialog.

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt

# Sanity check — must print "deps ok"
python -c "import streamlit, pandas, dns, requests, pytest; print('deps ok')"
```

Pinned versions in `requirements.txt` (all confirmed installed here):

| Package | Version |
|---|---|
| streamlit | 1.65.0 |
| pandas | 3.0.6 |
| dnspython | 2.9.0 |
| requests | 2.34.2 |
| pytest | latest |

`smtp-probe/probe.py` is **stdlib-only** — it needs no pip install at all.

### Cloudflare Worker side

Verified working: **Node v24.21.0, npm 11.19.0**. Node 20+ is fine.

```bash
cd worker
npx --yes wrangler --version
```

There is **nothing to install** — `package.json` has no `dependencies` and no
`devDependencies`, and `src/index.js` is a single ES module with zero imports.
`wrangler` is invoked via `npx` (or installed globally with `npm i -g wrangler`).
Skip `npm install` entirely; there is nothing to fetch.

```bash
cd worker
npx --yes wrangler login      # opens a browser to authorise your account
npx --yes wrangler dev --port 8788   # 8787 is taken by the probe
npm test                      # 48 tests, node --test, no install needed
```

> **Port collision:** `wrangler dev` defaults to **8787**, which is also the
> probe's default port (`PROBE_PORT`). Run wrangler on 8788 or change
> `PROBE_PORT` — otherwise the second one to start will fail to bind.

---

## 1. Cloudflare Worker — API **+** UI

```bash
cd worker
npx wrangler login

# Secrets — never stored in wrangler.toml
npx wrangler secret put API_KEY            # unset = API is open
npx wrangler secret put SMTP_PROBE_URL     # https://probe.example.com ; optional
npx wrangler secret put SMTP_PROBE_KEY     # matches PROBE_API_KEY on the probe

npx wrangler deploy
```

Then:

```bash
BASE=https://email-verifier.<you>.workers.dev

# UI
curl -i "$BASE/"                 # 200 text/html

# API
curl -H "Authorization: Bearer $API_KEY" "$BASE/v1/verify?email=bad@@x.com"
# -> {"result":{...,"status":"undeliverable","reason_code":"E103",...}}

curl -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
     -d '{"emails":["bad@@x.com","notanemail"]}' "$BASE/v1/verify/batch"

curl "$BASE/health"              # 401 if API_KEY is set — expected
curl -H "Authorization: Bearer $API_KEY" "$BASE/health"
# -> {"ok":true,"version":"1.0","probe":"configured","max_bulk":100}
```

**Config** lives in `worker/wrangler.toml` `[vars]`: `MAX_BULK`, `HALT_POLICY`,
`DEADLINE_MS`, `RATE_SINGLE`, `RATE_BATCH`, `SUBREQUEST_BUDGET`. Secrets via
`wrangler secret put`. No npm dependencies, no install step.

**Notes**

- `GET /` is deliberately **unauthenticated**: a browser cannot attach an
  `Authorization` header to a top-level navigation, so gating it would make the
  UI unreachable whenever `API_KEY` is set. The page exposes no data; its own
  `fetch()` calls hit the gated `/v1/*` routes.
- `/` is also exempt from rate limiting. `/health` and `/v1/*` are still
  limited per client IP (`RATE_SINGLE`/`RATE_BATCH`).
- `CORS_ORIGIN` is optional. When unset, CORS headers are only emitted for
  requests that carry an `Origin` header (browsers), so server-to-server
  callers see an unchanged response shape.
- `MAX_BULK` is substituted into the UI's bulk-size hint, so the page can
  never advertise a limit larger than the enforced one.

---

## 2. Streamlit Cloud — UI

The default deployment is UI-only: `streamlit run app.py`, pipeline in-process.
If you also want the JSON API on the same URL, see §2b — same host, same port,
just a different entry point.

```bash
git push origin main
```

Then in Streamlit Community Cloud → **New app**:

| Field | Value |
|---|---|
| GitHub repo / branch | your repo / `main` |
| Python version | 3.13 |
| Run command | `streamlit run app.py` |
| Health check URL | `/_stcore/health` |
| Timeout | 60 s |

**Secrets** — Streamlit Cloud reads `secrets.toml` from the repo. Add:

```toml
MODE = "api"                                        # "local" or "api"
API_BASE = "https://email-verifier.you.workers.dev"
API_KEY  = "..."
SMTP_PROBE_URL = "https://probe.example.com"
PROBE_API_KEY  = "..."
```

`app.py` reads these on first session and seeds the Settings tab, so the app
ships preconfigured; the Settings tab still wins once you use it. Locally there
is no `secrets.toml`, so nothing changes for `streamlit run app.py`.

**Local check before deploying:**

```bash
pip install -r requirements.txt
streamlit run app.py --server.headless true
# second shell: curl -s -o NUL -w '%{http_code}\n' http://localhost:8501/_stcore/health  -> 200
```

## 2b. One process: Streamlit UI **+** JSON API on one URL (optional)

`server.py` is a second entry point. It runs the same `app.py` as the Streamlit
UI and registers REST routes on the same ASGI app — one process, one port, one
URL serving both.

```bash
streamlit run server.py --server.headless true
```

| Path | What it is |
|---|---|
| `/` | the Streamlit UI, unchanged |
| `/_stcore/health` | Streamlit's own health check |
| `/api/verify`, `/api/verify/batch`, `/api/health` | the JSON API |
| `/v1/verify`, `/v1/verify/batch` | same API on Worker-compatible paths |

On Streamlit Cloud, set **Run command** to `streamlit run server.py` instead of
`streamlit run app.py`. Nothing else changes.

**Why it works.** Streamlit 1.65 replaced Tornado with Starlette + Uvicorn and
added `st.App`, an ASGI application that takes a `routes=` list. `streamlit run`
AST-scans the entry script for a bare assignment to a known ASGI constructor
(`st.App` / `FastAPI` / `Starlette`); when it finds one it runs the file through
uvicorn as an ASGI app instead of as a Streamlit script. User routes are
registered ahead of Streamlit's own and validated not to collide with its
reserved prefixes.

**This replaces the "Tornado gc hack" in older tutorials.** The trick that
scrapes Streamlit's internal server with `gc.get_referrers()` to find a live
`Application` and splice a `Rule` into `wildcard_router.rules` is dead: Tornado
is not installed at all (`import tornado` → `ModuleNotFoundError`) and neither
`Application` nor `wildcard_router` exists anywhere in the package. `st.App(...,
routes=[...])` is the supported replacement and needs no garbage collector.

**Two load-bearing constraints in `server.py`.**

1. The constructor must be a literal `app = st.App(...)`. Discovery resolves the
   call against a fixed list of known classes by AST; a factory call such as
   `app = _make_app()` resolves to nothing and Streamlit silently falls back to
   treating the file as a Streamlit script.
2. No UTF-8 BOM. `path.read_text()` keeps the BOM as a leading character,
   `ast.parse` raises `SyntaxError`, discovery reports no ASGI app, and you
   silently get traditional mode. `Set-Content -Encoding UTF8` on PowerShell 5.1
   writes a BOM — strip it.

Same error codes as the Worker (`E001`/`E002`/`E003`/`E004`/`E705`) and the same
opts builder as `app.py`, so a client points at either host by changing the base
URL. Optional shared secret: set `EMAIL_VERIFIER_API_KEY` (or `API_KEY`) and
callers send `x-api-key`.

The API runs the pipeline in-process, so it proves S6 the same way the UI does
(§3) — genuinely better than the Worker, where S6 needs the probe. The trade:
Streamlit Cloud redeploys restart the API with the UI, and both share one
process's CPU. For a durable, independent endpoint keep using the Worker.

---

## 3. SMTP probe — S6, and who actually needs it

`core/pipeline.py:338` has exactly two paths for S6:

- `probe_url` empty → `probe_email()`, a real `smtplib` TCP connect to port 25
  by the app process itself.
- `probe_url` set → `probe_via_service()`, HTTP POST to the probe service.

**Cloudflare Workers** cannot open a raw TCP socket at all, so the Worker always
needs the probe.

**Streamlit Cloud is different.** An app running there in local mode with an
empty `SMTP_PROBE_URL` makes the port-25 connection itself, and a live deployment
has been observed doing exactly that (`deliverable`, `LEVEL SMTP`, S6 complete,
in-process, ~740 ms total). So the earlier assumption that Streamlit Cloud blocks
outbound 25 is **not** what the evidence shows — do not treat it as a given.

Confirm it in ten seconds on your own deployment: **Settings tab → is
`SMTP_PROBE_URL` empty?**

- Empty **and** S6 still checks → Streamlit can reach :25, in-process. **You do
  not need a probe at all for the Streamlit deployment.** This is the whole
  setup: one `streamlit run app.py`, no Worker, no probe.
- Empty **and** S6 stops with `E604`/`E605`/`E606`/`E609` → :25 is blocked on
  that host, so deploy the probe and point `SMTP_PROBE_URL` at it.
- `E601` means no probe *and* the SMTP toggle is off — not a network problem.

If you do deploy a probe, it is a single stdlib-only file (no pip install):

```bash
python smtp-probe/probe.py          # stdlib only, no pip install
curl http://localhost:8787/health   # {"ok":true,"port25":true}
```

Host it anywhere that can reach port 25 — a home VPS, Render, Fly.io, or a
Cloudflare Tunnel. Then set `SMTP_PROBE_URL` on the Worker and/or in the
Streamlit `secrets.toml`. **Without a probe, S6 stops at S5 with `unknown`
(E617) — never a false `invalid`.**

Set `PROBE_API_KEY` before exposing it publicly:

```bash
PROBE_API_KEY=long-random-secret python smtp-probe/probe.py
```

Verify it end to end against a local fake SMTP server:

```bash
python smtp-probe/smoke.py          # prints all four verdicts
```

---

## Endpoint reference

| Method | Path | Auth | Body | Response |
|---|---|---|---|---|
| GET | `/` | none | — | HTML UI |
| GET | `/health` | bearer | — | `{ok, version, probe, max_bulk}` |
| GET | `/v1/verify?email=a@b.com` | bearer | — | `{result}` |
| POST | `/v1/verify` | bearer | `{email, options?}` | `{result}` |
| POST | `/v1/verify/batch` | bearer | `{emails[], options?}` | `{results[], run_state, resume_from}` |
| POST | `/probe` | `X-Probe-Key` | `{email, sender?, timeout_s?, check_catchall?}` | `{code, smtp_code, message, catchall, level}` |

Errors: `401/E001` bad key · `400/E002` bad JSON · `400/E003` empty list ·
`413/E004` over MAX_BULK · `429/E005` rate limit · `500/E705` internal.

The same table, minus `/probe`, also exists on the Streamlit host under `/api/*`
(§2b) — `/api/verify`, `/api/verify/batch`, `/api/health` — with the same codes,
so a client can switch hosts by changing the base URL. There, auth is the
optional `x-api-key` header instead of bearer.

**Statuses:** `deliverable` (SMTP accepted the mailbox) · `risky` (domain works,
heuristics or catch-all flagged it; score capped at 59) · `unknown` (transient,
retry — never retried automatically) · `undeliverable` (final).

---

## Testing

```bash
python -m pytest tests -q     # Python: 221 tests
cd worker && npm test         # Worker JS: 48 tests
python smtp-probe/smoke.py    # live SMTP smoke
```

---

## 4. "Why is it `unknown`?" — reading the result

`unknown` is the correct, honest answer in three different situations. Check the
**Code** column to tell them apart:

| Code | Meaning | Fix |
|---|---|---|
| `E601` | No SMTP probe configured (or SMTP toggle off) | Set `SMTP_PROBE_URL`, or turn SMTP back on. Nothing is broken. |
| `E406` | DNS timed out | Raise the deadline — **Settings → deadline per check (ms)**, max 15000. The default 3000 ms is tight for MX + A + AAAA through two DoH endpoints in two waves. |
| `E408` | DoH endpoint unreachable | Network/firewall/proxy issue on the host; retry later. |
| `E617` | Probe reachable, verdict inconclusive | Retry; transient. |

Two things are worth knowing up front:

- **`E601` means S6 never ran** — SMTP toggle off, or no probe on a host that
  cannot reach :25. On Streamlit Cloud in local mode with `SMTP_PROBE_URL`
  empty, S6 runs in-process and a real `deliverable` verdict has been observed
  there, so do not expect `E601` by default (§3). The **Worker** is different:
  it has no TCP sockets at all, so it *does* need the probe.
- **The Worker serves two different UIs and they return the same codes.** The
  Worker's own `GET /` page shows a "Setup" box + "Single address" +
  "Bulk (max 100)"; Streamlit's `app.py` shows the "Mode: LOCAL" banner and the
  "Single check / Bulk / Settings / Docs" tabs with the S1–S6 checklist. If
  you are looking at the wrong UI, the settings you changed will not apply.

## Acceptable use

Verify addresses your users submit, or lists you already own. Do not scrape,
spam, or cold-contact strangers — you are responsible for your recipient lists.
No mail is ever sent: the SMTP conversation stops after `RCPT TO`.
