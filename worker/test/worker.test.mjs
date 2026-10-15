/* Worker test suite: imports the pure functions directly with node:test and
 * runs the shared fixtures (tests/fixtures/fixtures.json) used by Python too.
 * No network, no wrangler: node --test test
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ERROR_CODES,
  checkSyntax,
  checkRules,
  checkLists,
  checkDomain,
  makeFixtureDoh,
  fingerprint,
  isUnsafeIp,
  mapSmtpReply,
  makeStopCause,
  resultFromCode,
  CATCHALL_ADVICE,
  verifyEmail,
  verifyBatch,
  RunState,
  summarize,
  RateLimiter,
  CatchAllCache,
  DohTimeout,
  handleRequest,
  handleSingle,
  handleBatch,
  levelForCode,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = JSON.parse(readFileSync(join(HERE, "../../tests/fixtures/fixtures.json"), "utf8"));

function dohFor(fixName) {
  return makeFixtureDoh(FIXTURES.doh[fixName] || {});
}

/* --- S1 syntax ------------------------------------------------------------ */

test("S1 accepts every valid fixture address", () => {
  for (const email of FIXTURES.syntax_valid) {
    const out = checkSyntax(email);
    assert.equal(out.code, undefined, `${email} should parse, got ${out.code} ${out.message}`);
  }
});

test("S1 rejects every invalid fixture address with its documented code", () => {
  for (const { input, code } of FIXTURES.syntax_invalid) {
    const out = checkSyntax(input);
    assert.equal(out.code, code, `${input} expected ${code} got ${out.code}`);
  }
});

test("S1 total-length cap is E102, local-part cap is 64", () => {
  assert.equal(checkSyntax(FIXTURES.too_long_total).code, "E102");
  assert.equal(checkSyntax(`${"a".repeat(64)}@a.co`).code, undefined);
  assert.equal(checkSyntax(`${"a".repeat(65)}@a.co`).code, "E102");
});

test("S1 unwraps the display-name form like Python parseaddr", () => {
  assert.equal(checkSyntax("Some One <a@b.com>").email, "a@b.com");
  assert.equal(checkSyntax("Some One <bad@@x.com>").code, "E103");
});

/* --- S2 provider rules ---------------------------------------------------- */

test("S2 enforces the provider-local-part table", () => {
  for (const { input, code, note } of FIXTURES.rules) {
    // Fixture rows carrying a note are owned by the S1 syntax suite.
    if (code === null && note) continue;
    const out = checkRules(input);
    assert.equal(out && out.code ? out.code : null, code, input);
  }
});

/* --- S3 lists & heuristics ------------------------------------------------ */

test("S3 lists map fixtures to E301/E303/E304 with statuses from the registry", () => {
  for (const { input, code, status, did_you_mean, flag } of FIXTURES.lists) {
    const out = checkLists(input);
    assert.equal(out.stop ? out.stop.code : null, code, input);
    if (code) {
      assert.equal(ERROR_CODES[code].status, status, `${code} documented status`);
      if (did_you_mean) assert.equal(out.didYouMean, did_you_mean);
    }
    if (flag) assert.ok(out.flags.includes(flag), input);
  }
});

test("S3 lists match Python messages, advice text and check order", () => {
  // Python check_lists: blocklist -> typo -> disposable -> role, and every
  // V-code except E302/E305 carries an `advice` string.
  const t = checkLists("user@gmial.com");
  assert.equal(t.stop.code, "E304");
  assert.equal(t.stop.message, "probable typo: did you mean gmail.com?");
  assert.equal(t.didYouMean, "gmail.com");
  assert.equal(
    t.advice,
    "Did you mean user@gmail.com? Verify the source of this address before sending.",
  );

  const d = checkLists("x@mailinator.com");
  assert.equal(d.stop.code, "E301");
  assert.equal(d.stop.message, "disposable email domain");
  assert.equal(
    d.advice,
    "Disposable addresses rarely receive long-term mail; " +
      "request a permanent address if this contact matters.",
  );

  const r = checkLists("info@company.com");
  assert.equal(r.stop.code, "E303");
  assert.equal(r.stop.message, "role account (info@)");
  assert.equal(
    r.advice,
    "Role accounts are shared inboxes; engagement is usually low " +
      "and complaints are high. Mail to humans, not roles.",
  );

  const b = checkLists("victim@spamtrap.com", {
    blocklist: new Set(["spamtrap.com"]),
  });
  assert.equal(b.stop.code, "E302");
  assert.equal(b.stop.message, "Internal blocklist");
  assert.equal(b.advice, null);

  // Blocklist also matches the whole address, not just the domain.
  const b2 = checkLists("info@anything.com", {
    blocklist: new Set(["info@anything.com"]),
  });
  assert.equal(b2.stop.code, "E302");

  // Typo wins over disposable when both lists match.
  const both = checkLists("x@mailinator.com", {
    typos: { "mailinator.com": "mailinator.co" },
  });
  assert.equal(both.stop.code, "E304");
});

test("E615 catch-all carries the PRD 5.3 advice text", async () => {
  const r = await verifyEmail("user@good.com", {
    doh_query: makeFixtureDoh(FIXTURES.doh.ok),
    probe_fn: async () => ({ code: "OK", catchall: true, message: "accepts any mailbox" }),
  });
  assert.equal(r.reason_code, "E615");
  assert.equal(r.status, "risky");
  assert.ok(r.flags.includes("catchall_domain"));
  assert.equal(r.advice, CATCHALL_ADVICE);
});

/* --- S4 DNS --------------------------------------------------------------- */

test("S4 ok fixture resolves MX + A with no stop", async () => {
  const out = await checkDomain("good.com", dohFor("ok"));
  assert.equal(out.stop, null);
  assert.deepEqual(out.mx, ["mx.good.com"]);
  assert.deepEqual(Object.keys(out.ips), ["mx.good.com"]);
});

test("S4 fixture → code table (E401/E402/E403/E404/E405/E407)", async () => {
  const cases = [
    ["nonexistent-domain-xyz123.tld", "nxdomain", "E401"],
    ["nullmx.example", "nullmx", "E402"],
    ["noma.example", "noma", "E403"],
    ["ghost.example", "mxhost_nxdomain", "E404"],
    ["privmx.example", "privmx", "E405"],
    ["servfail.example", "servfail", "E407"],
  ];
  for (const [domain, fix, code] of cases) {
    const out = await checkDomain(domain, dohFor(fix));
    assert.equal(out.stop.code, code, `${domain} (${fix})`);
  }
});

test("S4 SSRF guard flags private IPs, IPv6 loopback and non-parseable text", () => {
  for (const bad of ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.2.2",
    "172.16.0.1", "::1", "fe80::1", "ff02::1", "not-an-ip"]) {
    assert.equal(isUnsafeIp(bad), true, bad);
  }
  for (const good of ["93.184.216.35", "8.8.8.8", "151.101.1.1",
    "2001:4860:4860::8888", "100.64.0.1"]) {
    assert.equal(isUnsafeIp(good), false, good);
  }
});

/* --- S5 fingerprint ------------------------------------------------------- */

test("S5 fingerprints MX hosts and flags security gateways", () => {
  const cases = [
    ["pphosted.mx.example.com", "Proofpoint", true],
    ["smtp.google.com.", "Google", false],
    ["protection.outlook.com", "Microsoft", false],
    ["messaging.mailgun.org", "MailGun", false],
    ["mx.unrelated-host.net", null, false],
  ];
  for (const [host, provider, gateway] of cases) {
    const out = fingerprint([host]);
    assert.equal(out.provider, provider, host);
    assert.equal(Boolean(out.gateway), gateway, host);
  }
});

/* --- S6 reply mapping ----------------------------------------------------- */

test("S6 SMTP reply classification matches the Python table", () => {
  const cases = [
    [250, "250 2.0.0 OK", "OK"],
    [550, "550 5.1.1 user unknown", "E610"],
    [553, "553 5.7.1 not allowed", "E614"],
    [552, "552 5.2.2 mailbox full", "E611"],
    [421, "421 4.7.0 too many", "E613"],
    [451, "451 4.7.1 temporary problem", "E612"],
    [454, "454 4.7.1 rate limit", "E612"],
    [554, "554 5.7.1 transaction failed", "E614"],
    [999, "999 unknown", "E606"],
  ];
  for (const [reply, detail, code] of cases) {
    assert.equal(mapSmtpReply(reply, detail).code, code, detail);
  }
});

/* --- Error model property tests ------------------------------------------- */

test("property: no S-class code ever yields undeliverable", () => {
  const sCodes = Object.values(ERROR_CODES).filter((e) => e.class === "S");
  assert.ok(sCodes.length >= 25, "the S-class table should be substantial");
  for (const entry of sCodes) {
    assert.equal(entry.status, "unknown", `${entry.code} must be unknown`);
    assert.equal(entry.retryable, true, `${entry.code} must be retryable`);
  }
});

test("property: every V-class code carries its documented status", () => {
  for (const [code, entry] of Object.entries(ERROR_CODES)) {
    if (entry.class !== "V") continue;
    // Mirrors test_error_model.test_property_v_class_documented_status:
    // the registry status is normative; only E612 (greylisting) is retryable.
    assert.ok(
      ["deliverable", "undeliverable", "risky", "unknown"].includes(entry.status),
      `${code} has undocumented status ${entry.status}`
    );
    if (entry.retryable) assert.equal(code, "E612", `${code} is an undocumented retryable V-code`);
  }
});

test("level mapping tracks the stage that produced the code", () => {
  assert.equal(levelForCode("E103"), "syntax");
  assert.equal(levelForCode("E301"), "lists");
  assert.equal(levelForCode("E401"), "dns");
  assert.equal(levelForCode("E610"), "smtp");
  assert.equal(levelForCode("E618"), "smtp");
  // E601 is the documented exception: DNS resolved, mailbox unconfirmed.
  assert.equal(levelForCode("E601"), "dns");
});

/* --- Pipeline end to end -------------------------------------------------- */

async function verifyOk(email) {
  return verifyEmail(email, {
    doh_query: dohFor("ok"),
    probe_fn: async () => ({ code: "OK", message: "mailbox accepted" }),
    deadline_ms: 3000,
  });
}

test("pipeline: healthy address is deliverable after all six stages", async () => {
  const r = await verifyOk("alice@good.com");
  assert.equal(r.status, "deliverable");
  assert.equal(r.reason_code, "OK");
  assert.equal(r.halted, false);
  assert.deepEqual(r.stages_completed, ["S1", "S2", "S3", "S4", "S5", "S6"]);
  assert.deepEqual(r.stages_skipped, []);
  assert.equal(r.stop_cause, null);
  assert.ok(r.mx.includes("mx.good.com"));
});

test("pipeline: syntax error halts at S1 and skips every later stage", async () => {
  const r = await verifyEmail("bad@@x.com", { probe_fn: async () => ({ code: "OK" }) });
  assert.equal(r.reason_code, "E103");
  assert.equal(r.status, "undeliverable");
  assert.deepEqual(r.stages_completed, ["S1"]);
  assert.ok(r.stages_skipped.includes("S6"));
  assert.equal(r.stop_cause.class, "V");
});

test("stop_cause uses long stage labels and email halt scope (PRD 5.4)", () => {
  // Python make_stop_cause: stage is the long label, scope stays null for
  // email-scope codes while Result.halt_scope defaults it to "email".
  for (const [code, label] of [["E103", "S1_syntax"], ["E301", "S3_lists"],
    ["E401", "S4_dns"], ["E501", "S5_fingerprint"], ["E610", "S6_smtp"],
    ["E704", "S7_platform"]]) {
    const cause = makeStopCause(code);
    assert.equal(cause.stage, label, code);
    assert.equal(cause.scope, null, `${code} stop_cause.scope is unset`);
  }
  const r = resultFromCode("a@b.com", "E610", "no such user", ["S1", "S2", "S3", "S4", "S5", "S6"]);
  assert.equal(r.halt_scope, "email");
  assert.equal(r.stop_cause.stage, "S6_smtp");
  assert.equal(r.stop_cause.scope, null);

  const run = resultFromCode("a@b.com", "E701", "budget exhausted", ["S1"]);
  assert.equal(run.halt_scope, "run");
  assert.equal(run.stop_cause.stage, "S7_platform");
  assert.equal(run.stop_cause.scope, "run");
});

test("pipeline: disposable domain halts at S3 and never touches DNS", async () => {
  let dnsSeen = false;
  const r = await verifyEmail("bob@tempmail.com", {
    doh_query: async () => { dnsSeen = true; return { Status: 0, Answer: [] }; },
    probe_fn: async () => ({ code: "OK" }),
  });
  assert.equal(r.reason_code, "E301");
  assert.equal(r.status, "risky");
  assert.deepEqual(r.stages_completed, ["S1", "S2", "S3"]);
  assert.equal(dnsSeen, false);
});

test("pipeline: DNS-only mode stops at S6 with E601 unknown", async () => {
  const r = await verifyEmail("alice@good.com", {
    doh_query: dohFor("ok"),
    probe_fn: async () => ({ code: "E601", message: "probe not configured" }),
  });
  assert.equal(r.reason_code, "E601");
  assert.equal(r.status, "unknown");
  assert.equal(r.stop_cause.retryable, true);
  assert.equal(r.halted, true);
});

test("summarize tallies the four documented statuses", () => {
  const r = summarize([
    { status: "deliverable" }, { status: "risky" },
    { status: "risky" }, { status: "unknown" },
  ]);
  assert.deepEqual(r, { deliverable: 1, undeliverable: 0, risky: 2, unknown: 1 });
});

/* --- Run-level breakers --------------------------------------------------- */

test("breaker B2 opens on repeated DNS transport failures and halts the run", async () => {
  // DNS outage (not NXDOMAIN, which is a verdict) → E406 after 5 in a row.
  const dohOutage = () => { throw new DohTimeout("doh down"); };
  const run = await verifyBatch(
    Array.from({ length: 7 }, (_v, i) => `n${i}@a.com`),
    { doh_query: dohOutage, probe_fn: async () => ({ code: "OK" }) });
  assert.equal(run.run_status, "halted");
  assert.equal(run.stop_cause.code, "E406");
  assert.equal(run.resume_from, run.processed);
  assert.ok(run.not_processed.length === run.total - run.processed);
});

test("breaker B3 opens on repeated SMTP policy rejections", () => {
  const st = new RunState(null);
  for (let i = 0; i < 4; i += 1) assert.equal(st.observe("E614", "a.com"), null);
  assert.equal(st.observe("E614", "a.com").code, "E614");
});

test("breaker B2 stays shut on ordinary verdicts between DNS faults", () => {
  const st = new RunState(null);
  for (let i = 0; i < 4; i += 1) {
    assert.equal(st.observe("E610", "a.com"), null); // verdict, resets the counter
    assert.equal(st.observe("E406", "a.com"), null);
  }
  assert.equal(st.observe("E406", "a.com"), null);
});

test("breaker B1 opens immediately on an auth/platform failure", () => {
  const st = new RunState(null);
  const cause = st.observe("E001", "example.com");
  assert.equal(cause.code, "E001");
  assert.equal(cause.scope, "run");
  assert.equal(st.observe("E401", "a.com"), cause);
});

test("subrequest budget trips B5 with E701", () => {
  const st = new RunState(2);
  assert.equal(st.countSubrequest(), null);
  assert.equal(st.countSubrequest(), null);
  const cause = st.countSubrequest();
  assert.equal(cause.code, "E701");
  assert.equal(st.trip, cause);
});

test("breaker B6 opens after three internal errors", () => {
  const st = new RunState(null);
  assert.equal(st.observe("E705", "a.com"), null);
  assert.equal(st.observe("E705", "a.com"), null);
  assert.equal(st.observe("E705", "a.com").code, "E705");
});

test("breaker B4 opens after three consecutive probe transport failures", () => {
  const st = new RunState(null);
  assert.equal(st.observe("E602", "a.com"), null);
  assert.equal(st.observe("E602", "a.com"), null);
  assert.equal(st.observe("E602", "a.com").code, "E602");
});

test("catch-all cache honours its TTL", () => {
  const c = new CatchAllCache(1000);
  assert.equal(c.get("a.com"), null);
  c.set("a.com", { is_catchall: true }, 100);
  assert.equal(c.get("a.com", 500).is_catchall, true);
  assert.equal(c.get("a.com", 1200), null);
});

test("rate limiter allows then throttles", () => {
  const rl = new RateLimiter(2, 60000);
  assert.equal(rl.allow("ip1", 0), null);
  assert.equal(rl.allow("ip1", 10), null);
  assert.ok(rl.allow("ip1", 20) > 0);
  assert.equal(rl.allow("ip2", 20), null);
});

/* --- HTTP layer ------------------------------------------------------------- */

const OK_ENV = {
  API_KEY: "test-key",
  MAX_BULK: 100,
  RATE_SINGLE: 60,
  RATE_BATCH: 10,
  DOH_URL: "https://dns.example/dns-query",
};
const AUTH = { authorization: "Bearer test-key" };

function envWith(overrides) {
  return Object.assign({}, OK_ENV, overrides || {});
}

function req(url, init) {
  return new Request(url, Object.assign({ headers: AUTH }, init || {}));
}

const FAKE_OPTIONS = {
  doh_query: makeFixtureDoh(FIXTURES.doh.ok),
  probe_fn: async () => ({ code: "OK", message: "mailbox accepted" }),
};

async function bodyOf(response) {
  return JSON.parse(await response.text());
}

test("HTTP GET /health reports version, probe state and MAX_BULK", async () => {
  const res = await handleRequest(req("https://w.test/health"), envWith({}));
  assert.equal(res.status, 200);
  const body = await bodyOf(res);
  assert.equal(body.ok, true);
  assert.equal(body.probe, "absent");
  assert.equal(body.max_bulk, 100);
  assert.equal(res.headers.get("content-type"), "application/json; charset=utf-8");
});

test("HTTP GET /v1/verify requires an email query parameter", async () => {
  const res = await handleRequest(req("https://w.test/v1/verify"), envWith({}));
  assert.equal(res.status, 400);
  const body = await bodyOf(res);
  assert.equal(body.error.code, "E002");
  assert.match(body.error.message, /email/);
});

test("HTTP OPTIONS preflight returns 204 with CORS headers", async () => {
  const res = await handleRequest(
    req("https://w.test/v1/verify", { method: "OPTIONS" }),
    envWith({ CORS_ORIGIN: "*" })
  );
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("access-control-allow-methods"), "GET, POST, OPTIONS");
});

test("HTTP auth gate rejects a missing or wrong bearer token with E001", async () => {
  for (const header of [null, "Bearer wrong"]) {
    const headers = header === null ? {} : { authorization: header };
    const res = await handleRequest(req("https://w.test/health", { headers }), envWith({}));
    assert.equal(res.status, 401);
    assert.equal((await bodyOf(res)).error.code, "E001");
  }
});

test("HTTP rate limiter throttles and sets retry-after", async () => {
  const env = envWith({ RATE_SINGLE: 1 });
  const first = await handleRequest(req("https://w.test/health"), env);
  assert.equal(first.status, 200);
  const blocked = await handleRequest(req("https://w.test/health"), env);
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get("retry-after")) > 0);
  assert.equal((await bodyOf(blocked)).error.code, "E005");
  // A different client IP keeps its own counter.
  const other = await handleRequest(
    req("https://w.test/health", {
      headers: { authorization: "Bearer test-key", "cf-connecting-ip": "203.0.113.9" },
    }),
    env
  );
  assert.equal(other.status, 200);
});

test("handleSingle verifies one address end to end", async () => {
  const res = await handleSingle(
    req("https://w.test/v1/verify"),
    envWith({}),
    { email: "alice@good.com", options: FAKE_OPTIONS }
  );
  assert.equal(res.status, 200);
  const result = (await res.json()).result;
  assert.equal(result.status, "deliverable");
  assert.equal(result.reason_code, "OK");
  assert.ok(result.mx.includes("mx.good.com"));
});

test("handleSingle rejects a body without an email", async () => {
  const res = await handleSingle(req("https://w.test/v1/verify"), envWith({}), { options: {} });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, "E002");
});

test("handleBatch verifies every address and summarises", async () => {
  const res = await handleBatch(
    req("https://w.test/v1/verify/batch"),
    envWith({}),
    { emails: ["alice@good.com", "bob@tempmail.com"], options: FAKE_OPTIONS }
  );
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.run_status, "ok");
  assert.equal(body.results.length, 2);
  assert.equal(body.summary.deliverable, 1);
  assert.equal(body.summary.risky, 1);
});

test("handleBatch enforces E003 (empty) and E004 (MAX_BULK)", async () => {
  const empty = await handleBatch(
    req("https://w.test/v1/verify/batch"),
    envWith({ MAX_BULK: 100 }),
    { emails: [], options: FAKE_OPTIONS }
  );
  assert.equal(empty.status, 400);
  assert.equal((await empty.json()).error.code, "E003");

  const tooBig = await handleBatch(
    req("https://w.test/v1/verify/batch"),
    envWith({ MAX_BULK: 2 }),
    { emails: ["a@a.com", "b@b.com", "c@c.com"], options: FAKE_OPTIONS }
  );
  assert.equal(tooBig.status, 413);
  assert.equal((await tooBig.json()).error.code, "E004");
});

test("handleBatch runs the subrequest budget from env.SUBREQUEST_BUDGET", async () => {
  const env = envWith({ SUBREQUEST_BUDGET: 4 });
  const emails = [1, 2, 3, 4, 5].map((n) => `x${n}@good.com`);
  const res = await handleBatch(
    req("https://w.test/v1/verify/batch"),
    env,
    { emails, options: FAKE_OPTIONS }
  );
  const body = await res.json();
  assert.equal(body.run_status, "halted");
  assert.equal(body.stop_cause.code, "E701");
  assert.equal(body.resume_from, body.processed);
  assert.equal(body.not_processed.length, body.total - body.processed);
});

test("HTTP POST /v1/verify rejects a body without an email with E002", async () => {
  const res = await handleRequest(
    req("https://w.test/v1/verify", {
      method: "POST",
      body: JSON.stringify({ options: {} }),
    }),
    envWith({})
  );
  assert.equal(res.status, 400);
  assert.equal((await bodyOf(res)).error.code, "E002");
});

test("HTTP rejects malformed JSON, unknown routes and unsupported methods", async () => {
  const badJson = await handleRequest(
    req("https://w.test/v1/verify", { method: "POST", body: "{not json" }),
    envWith({})
  );
  assert.equal(badJson.status, 400);
  assert.equal((await bodyOf(badJson)).error.code, "E002");

  const notFound = await handleRequest(
    req("https://w.test/v1/verify/nope", {
      method: "POST",
      body: JSON.stringify({ email: "a@good.com" }),
    }),
    envWith({})
  );
  assert.equal(notFound.status, 404);
  assert.equal((await bodyOf(notFound)).error.code, "E002");

  const badMethod = await handleRequest(
    req("https://w.test/v1/verify", { method: "DELETE" }),
    envWith({})
  );
  assert.equal(badMethod.status, 405);
  assert.equal((await bodyOf(badMethod)).error.code, "E002");
});

test("the default export wires fetch() to the router", async () => {
  const mod = (await import("../src/index.js")).default;
  assert.equal(typeof mod.fetch, "function");
  const res = await mod.fetch(req("https://w.test/health"), envWith({}));
  assert.equal(res.status, 200);
  assert.equal((await bodyOf(res)).ok, true);
});

/* --- Static UI page ------------------------------------------------------- */

test("GET / serves the HTML UI without authentication", async () => {
  const { uiHtml } = await import("../src/index.js");
  for (const path of ["/", "/index.html"]) {
    // No Authorization header at all: a browser cannot send one on navigation.
    const res = await handleRequest(
      req(`https://w.test${path}`, { headers: {} }),
      envWith({})
    );
    assert.equal(res.status, 200, path);
    assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8", path);
    assert.equal(res.headers.get("cache-control"), "no-store", path);
    const html = await res.text();
    assert.ok(html.startsWith("<!doctype html>"), path);
    assert.match(html, /<title>Email Verifier<\/title>/, path);
    assert.equal(html, uiHtml(OK_ENV), "page must equal uiHtml(env)");
  }
});

test("uiHtml substitutes MAX_BULK and leaves no placeholder behind", async () => {
  const { uiHtml } = await import("../src/index.js");
  const html = uiHtml({ MAX_BULK: "42" });
  assert.ok(html.includes("textContent = 42;"), "MAX_BULK must reach the page");
  assert.ok(!html.includes("__MAX__"), "placeholder must be replaced");
  const defaultHtml = uiHtml({});
  assert.ok(defaultHtml.includes("textContent = 100;"), "default MAX_BULK applies");
  // Exactly one substitution site: the bulk-size hint.
  assert.equal(html.match(/<\/script>/g).length, 1, "one script block");
  assert.equal(html.match(/<script>/g).length, 1, "one opening script tag");
});

test("the UI page is public but the JSON API routes stay gated", async () => {
  const env = envWith({});
  // Without a key the page loads...
  const page = await handleRequest(req("https://w.test/", { headers: {} }), env);
  assert.equal(page.status, 200);
  // ...while every /v1/* and /health route still demands the bearer token.
  for (const [method, path, body] of [
    ["POST", "/v1/verify", JSON.stringify({ email: "a@good.com" })],
    ["POST", "/v1/verify/batch", JSON.stringify({ emails: ["a@good.com"] })],
    ["GET", "/health", undefined],
    ["GET", "/v1/verify?email=a@good.com", undefined],
  ]) {
    const res = await handleRequest(
      req(`https://w.test${path}`, { method, body, headers: {} }),
      env
    );
    assert.equal(res.status, 401, `${method} ${path}`);
    assert.equal((await bodyOf(res)).error.code, "E001", `${method} ${path}`);
  }
});

test("the UI page is not rate limited while API routes are", async () => {
  const { uiHtml } = await import("../src/index.js");
  const env = envWith({ RATE_SINGLE: 1 });
  // /health consumes the single bucket; / keeps serving regardless.
  for (let i = 0; i < 3; i++) {
    assert.equal(
      (await handleRequest(req("https://w.test/health", { headers: AUTH }), env)).status,
      i === 0 ? 200 : 429,
      `/health call ${i + 1}`
    );
    const page = await handleRequest(req("https://w.test/", { headers: {} }), env);
    assert.equal(page.status, 200, `/ call ${i + 1}`);
  }
  assert.equal(await (await handleRequest(req("https://w.test/", { headers: {} }), env)).text(), uiHtml(env));
});
