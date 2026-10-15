# Deploying email-verifier

Three runtimes, one pipeline. `core/` is the source of truth; the Worker JS
reimplements S1–S5 with the same codes; S6 (SMTP) is delegated to `smtp-probe/`.

| Host | What it serves | Outbound port 25 |
|---|---|---|
| **Cloudflare Worker** | JSON API **and** a static UI, one URL | Not available — needs the probe |
| **Streamlit Cloud** | Streamlit UI only | Not available — needs the probe |
| **probe host** (any VPS/tunnel) | SMTP probe microservice | **Required** |

---

## Why there are two UIs

Streamlit Community Cloud runs **one Streamlit app per deployment** and gives you
no way to register arbitrary HTTP routes — so it cannot serve a JSON API at all.
That is exactly why the API lives on the Worker.

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

Streamlit Cloud runs `streamlit run app.py` on one port and cannot serve custom
HTTP API routes. It is the UI; the API is the Worker.

```bash
git push origin main
```

Then in Streamlit Community Cloud → **New app**:

| Field | Value |
|---|---|
| GitHub repo / branch | your repo / `main` |
| Python version | 3.12 |
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

---

## 3. SMTP probe — S6 (needs outbound port 25)

Streamlit Cloud and Cloudflare both block outbound port 25, so S6 is delegated:

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

## Acceptable use

Verify addresses your users submit, or lists you already own. Do not scrape,
spam, or cold-contact strangers — you are responsible for your recipient lists.
No mail is ever sent: the SMTP conversation stops after `RCPT TO`.
