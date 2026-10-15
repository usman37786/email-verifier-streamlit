# smtp-probe — S6 SMTP probe microservice

`probe.py` is a single stdlib-only Python file (no pip installs). It does the
one thing a Cloudflare Worker and a Streamlit Cloud app cannot: open a TCP
socket to port 25.

```
python probe.py                      # http://0.0.0.0:8787
python probe.py --help               # no flags; everything is env-driven
```

## Endpoints

| Method | Path      | Body / Result |
|--------|-----------|---------------|
| GET    | `/health` | `{"ok": true, "port25": true}` — `port25` is a live 3 s TCP connect test to `aspmx.l.google.com:25`. `false` means this host cannot reach SMTP and you should not point a verifier at it. |
| POST   | `/probe`  | request `{"email", "sender", "timeout_s", "check_catchall"}` → response `{"code", "smtp_code", "message", "catchall", "level"}` |

Errors: `401` bad/missing `X-Probe-Key`, `400` bad JSON or bad email,
`404` unknown path.

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `PROBE_HOST` / `PROBE_PORT` | `0.0.0.0` / `8787` | HTTP bind |
| `PROBE_API_KEY` | *(unset = open)* | Require `X-Probe-Key`. **Set this before exposing publicly.** |
| `PROBE_SMTP_PORT` | `25` | SMTP port to dial. Use `2525` on hosts where 25 is blocked. |
| `PROBE_TIMEOUT_S` | `7` | Per-probe conversation budget |
| `PROBE_CONNECT_TIMEOUT_S` | `3` | MX resolution / dial budget |
| `MAIL_FROM` | `verify-probe@example.org` | `MAIL FROM` sender |
| `MX_CACHE_TTL_S` | `3600` | MX cache lifetime |
| `CATCHALL_TTL_S` | `86400` | Per-domain catch-all verdict cache |
| `PROBE_ALLOW_INSECURE` | `0` | Disables the SSRF guard. **Dev/test only.** |

## How a caller wires it in

The verifier core already speaks this protocol (`core/smtp_check.py:
probe_via_service`). Point it at the service and S6 is delegated instead of
attempted in-process:

```python
verify(email, {"smtp": True, "probe_url": "https://probe.example.workers.dev"})
```

Streamlit: Settings tab → **SMTP_PROBE_URL**. Cloudflare Worker: set the
`SMTP_PROBE_URL` secret.

## Correctness guarantees

- **No mail is ever sent.** The conversation is `EHLO` → `MAIL FROM` →
  `RCPT TO` (real address) → `RCPT TO` (random 20-char address) → `RSET` →
  `QUIT`. There is no `DATA`, `SEND`, or `SENDMAIL` in the file, and
  `tests/test_smtp_probe.py::test_no_mail_is_ever_sent` fails the build if
  one is added.
- **`classify_rcpt` / `classify_mail_from` are byte-identical to
  `core/smtp_check.py`**, so `reason_code`s match whether S6 runs locally or
  is delegated. `test_classify_rcpt_matches_core` asserts this against the
  real core on every run.
- **Connection and IP failures are S-class → `unknown`, never
  `undeliverable`.** A broken probe, a blocked port, or a dead MX yields
  `E60x`/`E617` (`status: unknown`). Only a real `550/551/553` from the
  recipient's own server yields `E610` (`undeliverable`).
- **Catch-all domains are `risky` (`E615`), never `deliverable`.**
- **SSRF guard:** MX hosts ending in `.local`, and MX hosts resolving only to
  private/loopback/link-local/reserved/multicast IPs, are refused before
  dialing (`E405`/`E616`). The connected peer IP is re-checked after connect
  to defeat DNS-rebinding.

## Host it

Any host with outbound SMTP. Cheapest options, no card required:

- **Cloudflare Tunnel** — `cloudflared tunnel` on a home machine or VPS
  gives you a public HTTPS URL with no open inbound ports.
- **Render / Fly.io free tier** — deploy `probe.py` as a web service.
- **A home VPS** — `systemd` unit + Caddy/nginx TLS termination.

Then set the verifier's `SMTP_PROBE_URL` to that HTTPS URL.

## Testing

```bash
cd project && python -m pytest tests/test_smtp_probe.py -q
```

30 tests, all offline: a minimal in-process SMTP server is driven over a
real socket, and `core.pipeline.verify` is exercised end-to-end against the
real HTTP handler.
