/* Email Verifier — Cloudflare Worker (single file, zero dependencies).
 *
 * Ports S1–S5 of the Python pipeline (core/syntax.py, rules.py,
 * lists_check.py, dns_check.py, fingerprint.py) with the SAME codes,
 * stage order and statuses, so the shared fixture files in tests/fixtures
 * are used by both the Python and the JS test suites.
 *
 * S6 is delegated: if env.SMTP_PROBE_URL is configured we POST to the
 * smtp-probe microservice with X-Probe-Key; otherwise the pipeline stops at
 * S5 with E601 (unknown) — exactly like the Python side when no probe is
 * configured.
 */

export const VERSION = "1.0";
export const DEADLINE_MS = 3000;
export const DEFAULT_MAX_BULK = 100;
export const MAX_TOTAL = 254;
export const MAX_LOCAL = 64;
export const MAX_LABEL = 63;

const V = "V";
const S = "S";

function ec(code, klass, stage, message, status, retryable, retryAfter) {
  return {
    code,
    class: klass,
    stage,
    message,
    status,
    retryable,
    retry_after_s: retryAfter === undefined ? null : retryAfter,
    scope: null, // Python leaves scope unset for email-scope codes; Result fills "email"
  };
}

function ecRun(code, klass, stage, message, retryAfter) {
  return {
    code,
    class: klass,
    stage,
    message,
    status: "unknown",
    retryable: true,
    retry_after_s: retryAfter === undefined ? null : retryAfter,
    scope: "run",
  };
}

/** Stage code -> StopCause.stage label (PRD 5.4, mirrors core.models.STAGE_LABELS). */
const STAGE_LABELS = {
  S0: "S0_request", S1: "S1_syntax", S2: "S2_rules", S3: "S3_lists",
  S4: "S4_dns", S5: "S5_fingerprint", S6: "S6_smtp", S7: "S7_platform",
};

/** Mirrors core/models.py ERROR_CODES (normative PRD 5.1). */
export const ERROR_CODES = {
  E001: ecRun("E001", S, "S0", "Auth failed or missing key"),
  E002: ecRun("E002", S, "S0", "Malformed or non-JSON body"),
  E003: ecRun("E003", S, "S0", "Empty list"),
  E004: ecRun("E004", S, "S0", "Batch over MAX_BULK"),
  E005: ecRun("E005", S, "S0", "Client rate-limited", 60),
  E101: ec("E101", V, "S1", "Empty or whitespace address", "undeliverable", false),
  E102: ec("E102", V, "S1", "Address too long (>254 total, >64 local part)", "undeliverable", false),
  E103: ec("E103", V, "S1", "Missing @ or multiple unquoted @", "undeliverable", false),
  E104: ec("E104", V, "S1", "Illegal local part", "undeliverable", false),
  E105: ec("E105", V, "S1", "Illegal domain", "undeliverable", false),
  E201: ec("E201", V, "S2", "Violates provider's own rules", "undeliverable", false),
  E301: ec("E301", V, "S3", "Disposable domain", "risky", false),
  E302: ec("E302", V, "S3", "Internal blocklist", "undeliverable", false),
  E303: ec("E303", V, "S3", "Role account", "risky", false),
  E304: ec("E304", V, "S3", "Probable typo", "risky", false),
  E305: ec("E305", S, "S3", "Disposable list unavailable", "unknown", true, 300),
  E401: ec("E401", V, "S4", "NXDOMAIN", "undeliverable", false),
  E402: ec("E402", V, "S4", "Null MX (RFC 7505)", "undeliverable", false),
  E403: ec("E403", V, "S4", "No MX and no A/AAAA", "undeliverable", false),
  E404: ec("E404", V, "S4", "MX hostname does not resolve", "undeliverable", false),
  E405: ec("E405", V, "S4", "MX resolves to private/loopback/reserved IP", "undeliverable", false),
  E406: ec("E406", S, "S4", "DNS timeout", "unknown", true, 60),
  E407: ec("E407", S, "S4", "SERVFAIL or REFUSED", "unknown", true, 60),
  E408: ec("E408", S, "S4", "DoH endpoint unreachable", "unknown", true, 60),
  E409: ec("E409", S, "S4", "Malformed or truncated DNS response", "unknown", true, 60),
  E501: ec("E501", V, "S5", "Security gateway accepts all mail; SMTP proof meaningless", "risky", false),
  E601: ec("E601", S, "S6", "Port 25 blocked or no probe configured", "unknown", true, 300),
  E602: ec("E602", S, "S6", "Probe unreachable or timed out", "unknown", true, 120),
  E603: ec("E603", S, "S6", "Probe auth failed", "unknown", true, null),
  E604: ec("E604", S, "S6", "MX connect timeout", "unknown", true, 60),
  E605: ec("E605", S, "S6", "Connection refused or reset", "unknown", true, 60),
  E606: ec("E606", S, "S6", "Bad greeting or tarpit", "unknown", true, 60),
  E607: ec("E607", S, "S6", "STARTTLS failure", "unknown", true, 60),
  E608: ec("E608", S, "S6", "MAIL FROM rejected", "unknown", true, 300),
  E609: ec("E609", S, "S6", "Session dropped mid-conversation", "unknown", true, 60),
  E610: ec("E610", V, "S6", "RCPT 550/551/553 user unknown", "undeliverable", false),
  E611: ec("E611", V, "S6", "Mailbox full (552 / 5.2.2)", "risky", false),
  E612: ec("E612", V, "S6", "RCPT 4xx greylisting", "unknown", true, 600),
  E613: ec("E613", S, "S6", "421/450 rate-limited by MX", "unknown", true, 900),
  E614: ec("E614", S, "S6", "5.7.x policy block; our IP blocklisted / bad PTR", "unknown", true, 3600),
  E615: ec("E615", V, "S6", "Catch-all domain: random address accepted too", "risky", false),
  E616: ec("E616", V, "S6", "SSRF guard tripped (unsafe MX host)", "undeliverable", false),
  E617: ec("E617", S, "S6", "All MX hosts failed", "unknown", true, 120),
  E618: ec("E618", S, "S6", "Per-email wall-clock deadline exceeded", "unknown", true, 60),
  E701: ecRun("E701", S, "S7", "Subrequest budget exhausted"),
  E702: ecRun("E702", S, "S7", "CPU / wall-time limit exceeded"),
  E703: ecRun("E703", S, "S7", "Daily request quota exhausted"),
  E704: ec("E704", S, "S7", "Cache / isolate failure", "unknown", true, 60),
  E705: ec("E705", S, "S7", "Unhandled exception", "unknown", true, 60),
  E706: ecRun("E706", S, "S7", "UI to API network failure or invalid upstream JSON", 60),
};

export const OK_CODE = "OK";

/** Mirrors core/models.py DEFAULT_SCORES. */
export const DEFAULT_SCORES = {
  OK: 95,
  E101: 0, E102: 0, E103: 0, E104: 0, E105: 0,
  E201: 5,
  E301: 25, E302: 0, E303: 50, E304: 35, E305: 40,
  E401: 5, E402: 5, E403: 5, E404: 5, E405: 5,
  E406: 40, E407: 40, E408: 40, E409: 40,
  E501: 45,
  E601: 40, E602: 40, E603: 40, E604: 35, E605: 35, E606: 35,
  E607: 35, E608: 35, E609: 35,
  E610: 5, E611: 45, E612: 35, E613: 35, E614: 35,
  E615: 50, E616: 5, E617: 35, E618: 35,
  E701: 35, E702: 35, E703: 35, E704: 35, E705: 35, E706: 35,
};

export const HEURISTIC_CODES = new Set(["E301", "E303", "E304", "E501"]);

/** Breaker → stop-cause message (PRD 5.2). */
export const BREAKER_MESSAGES = {
  B1: "CONFIG_OR_AUTH_FAILURE",
  B2: "DNS_OUTAGE",
  B3: "PROBE_IP_BLOCKED",
  B4: "PROBE_DOWN",
  B5: "PLATFORM_LIMIT",
  B6: "UNSTABLE_RUNTIME",
};

/** Port of core.models.LEVEL_FOR_STAGE (PRD 8.1: syntax|lists|dns|smtp). */
const LEVEL_FOR_STAGE = {
  S0: "syntax", S1: "syntax", S2: "syntax",
  S3: "lists", S4: "dns", S5: "lists", S6: "smtp", S7: "dns",
};

/* --- bundled list data (S2/S3/S5) ------------------------------------------ */

/** Offline disposable set (superset of fixtures.json disposable_domains_js). */
export const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
  "throwaway.email", "throwawaymail.com", "tempmail.com", "tempmail.org",
  "temp-mail.org", "tempinbox.com", "tempr.email", "10minutemail.com",
  "trashmail.com", "trashmail.net", "discard.email", "sharklasers.com",
  "yopmail.com", "yopmail.fr", "mintemail.com", "fakeinbox.com", "fakeaddress.com",
  "getairmail.com", "mohmal.com", "getnada.com", "mailnesia.com", "dispostable.com",
  "inboxkitten.com", "maildrop.cc", "spamgourmet.com", "throwam.email", "mimail.fr",
  "mailshell.net", "binkyapis.com", "emailondeck.com", "moakt.com", "mytemp.email",
  "tmpmail.net", "tempail.com", "burnermail.io", "inboxalias.com",
  "safetymail.info", "anonbox.net",
]);

/** Likely-typos of big providers (core/lists_check.py TYPO_DOMAINS). */
export const TYPO_MAP = {
  "gmial.com": "gmail.com",
  "gmai.com": "gmail.com",
  "gmal.com": "gmail.com",
  "gmailm.com": "gmail.com",
  "gamil.com": "gmail.com",
  "gmaill.com": "gmail.com",
  "yaho.com": "yahoo.com",
  "yahooo.com": "yahoo.com",
  "hotmial.com": "hotmail.com",
  "hotmai.com": "hotmail.com",
  "hotmal.com": "hotmail.com",
  "outloook.com": "outlook.com",
  "outlok.com": "outlook.com",
  "outloo.com": "outlook.com",
  "protonmil.com": "protonmail.com",
  "mailcom.com": "mail.com",
};

/** Role / department addresses: risky, never "invalid". */
export const ROLE_LOCALS = new Set([
  "info", "information", "admin", "administrator", "support", "sales", "marketing",
  "contact", "enquiry", "enquiries", "inquiries", "inquiry", "help", "helpdesk",
  "billing", "accounts", "postmaster", "webmaster", "abuse", "noreply", "no-reply",
  "donotreply", "do-not-reply", "mailer-daemon", "office", "team", "general",
  "service", "services", "contactus", "feedback",
]);

export const FREE_PROVIDERS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com",
  "outlook.com", "live.com", "msn.com", "icloud.com", "me.com", "aol.com",
  "protonmail.com", "proton.me", "mail.com", "zoho.com", "gmx.com", "gmx.de",
  "yandex.com", "tutanota.com", "tutamail.com", "fastmail.com",
]);

export const GATEWAY_PATTERNS = [
  "mimecast", "proofpoint", "frontbridge", "messageprotect", "cloudmark",
  "agari", "mailgate", "seccureemail",
];

/* --- S1: syntax (port of core/syntax.py) ---------------------------------- */

const ATEXT = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
    "!#$%&'*+-/=?^_`{|}~.".split(""),
);

const LABEL_RE = /^[a-z0-9-]+$/;
const TLD_HAS_LETTER = /[a-z]/;
const HAS_NON_ASCII = /[^\x00-\x7f]/;

/** IDN → punycode (xn--…), mirroring Python's per-label idna encode. */
function toAsciiDomain(domain) {
  if (!HAS_NON_ASCII.test(domain)) return domain.toLowerCase();
  try {
    return new URL(`http://${domain}`).hostname.toLowerCase();
  } catch (err) {
    return null;
  }
}

/**
 * Returns { email } on success or { code, message } on failure.
 * Handles the display-name form `Some One <a@b.com>` like Python parseaddr.
 */
export function checkSyntax(raw) {
  const stop = (code, message) => ({ code, message });
  if (raw === null || raw === undefined) return stop("E101", "empty address");
  let s = String(raw).trim();
  const angle = s.match(/<([^<>]+)>/);
  if (angle) s = angle[1].trim();
  if (!s) return stop("E101", "empty or whitespace address");
  if (s.length > MAX_TOTAL) return stop("E102", "address longer than 254 characters");
  if (s.startsWith('"')) return stop("E104", "quoted local parts are not supported");
  const atCount = (s.match(/@/g) || []).length;
  if (atCount === 0) return stop("E103", "missing @");
  if (atCount > 1) return stop("E103", "multiple unquoted @");
  const parts = s.split("@");
  const local = parts[0];
  const domain = parts[1];
  if (!local || !domain) return stop("E103", "missing local part or domain");
  if (local.length > MAX_LOCAL) return stop("E102", "local part longer than 64 characters");
  if (local.startsWith(".") || local.endsWith(".")) {
    return stop("E104", "local part starts or ends with a dot");
  }
  if (local.includes("..")) return stop("E104", "consecutive dots in local part");
  for (const ch of local) {
    if (!ATEXT.has(ch)) return stop("E104", `illegal character in local part: ${ch}`);
  }
  const dom = toAsciiDomain(domain);
  if (dom === null) return stop("E105", "IDN domain cannot be punycode-encoded");
  if (dom.length > 253) return stop("E102", "domain longer than 253 characters");
  const labels = dom.split(".");
  if (labels.length < 2) return stop("E105", "domain must have at least two labels");
  for (const lbl of labels) {
    if (!lbl || lbl.length > MAX_LABEL) return stop("E105", "bad domain label length");
    if (lbl.startsWith("-") || lbl.endsWith("-")) {
      return stop("E105", "domain label starts or ends with hyphen");
    }
    if (!LABEL_RE.test(lbl)) return stop("E105", `illegal domain label: ${lbl}`);
  }
  const tld = labels[labels.length - 1];
  if (!TLD_HAS_LETTER.test(tld)) {
    return stop("E105", "numeric or invalid TLD (IP literals not allowed)");
  }
  if (tld.length < 2) return stop("E105", "TLD shorter than 2 characters");
  return { email: `${local}@${dom}` };
}

/* --- S2: provider rules (port of core/rules.py) --------------------------- */

const GMAIL_DOMAINS = new Set(["gmail.com", "googlemail.com"]);
const OUTLOOK_DOMAINS = new Set(["outlook.com", "hotmail.com", "live.com", "msn.com"]);
const YAHOO_DOMAINS = new Set([
  "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it",
  "ymail.com", "rocketmail.com",
]);

const GMAIL_LOCAL_RE = /^[a-z0-9.]+$/;
const OUTLOOK_LOCAL_RE = /^[a-z0-9._-]+$/;
const YAHOO_LOCAL_RE = /^[a-z0-9._-]+$/;

export function checkRules(email) {
  const at = email.lastIndexOf("@");
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const localL = local.toLowerCase();
  const stop = (message) => ({ code: "E201", message });

  if (GMAIL_DOMAINS.has(domain)) {
    // Window 6-30 evaluated on the full local part; sub-addressing (user+tag)
    // counts toward the window, the base part must stay clean.
    if (localL.length < 6 || localL.length > 30) {
      return stop("Gmail local part must be 6-30 characters");
    }
    const base = localL.split("+")[0];
    if (!base || !GMAIL_LOCAL_RE.test(base)) {
      return stop("Gmail local part may only contain a-z 0-9 and dots");
    }
    if (base.startsWith(".") || base.endsWith(".") || base.includes("..")) {
      return stop("Gmail local part dot placement invalid");
    }
    return null;
  }
  if (OUTLOOK_DOMAINS.has(domain)) {
    if (localL.length < 5 || localL.length > 64) {
      return stop("Outlook local part must be 5-64 characters");
    }
    const base = localL.split("+")[0];
    if (!OUTLOOK_LOCAL_RE.test(base)) {
      return stop("Outlook local part has illegal characters");
    }
    if (base.startsWith(".") || base.endsWith(".")) {
      return stop("Outlook local part dot placement invalid");
    }
    return null;
  }
  if (YAHOO_DOMAINS.has(domain)) {
    if (localL.length < 4 || localL.length > 64) {
      return stop("Yahoo local part must be 4-64 characters");
    }
    const base = localL.split("+")[0];
    if (!YAHOO_LOCAL_RE.test(base)) {
      return stop("Yahoo local part has illegal characters");
    }
    return null;
  }
  return null;
}

/* --- S3: lists & heuristics ----------------------------------------------- */

/**
 * Returns { stop, flags, didYouMean, advice }.
 * Lists are injectable so the JS tests can share the Python fixtures.
 */
export function checkLists(email, data) {
  data = data || {};
  const disposables = data.disposables || DISPOSABLE_DOMAINS;
  const blocklist = data.blocklist || new Set();
  const typos = data.typos || TYPO_MAP;
  const roles = data.roles || ROLE_LOCALS;
  const freeProviders = data.freeProviders || FREE_PROVIDERS;

  const out = { stop: null, flags: [], didYouMean: null, advice: null };
  const at = email.lastIndexOf("@");
  const local = email.slice(0, at).toLowerCase();
  const domain = email.slice(at + 1).toLowerCase();

  if (blocklist.has(email.toLowerCase()) || blocklist.has(domain)) {
    out.stop = makeStopCause("E302");
    return out;
  }
  // Typo wins over disposable: misspellings of major providers are often
  // listed by disposable feeds too, but the useful answer is the fix.
  if (Object.prototype.hasOwnProperty.call(typos, domain)) {
    const fixed = typos[domain];
    out.stop = makeStopCause("E304", `probable typo: did you mean ${fixed}?`);
    out.didYouMean = fixed;
    out.advice = `Did you mean ${local}@${fixed}? Verify the source of this address before sending.`;
    return out;
  }
  if (disposables.has(domain)) {
    out.stop = makeStopCause("E301", "disposable email domain");
    out.advice =
      "Disposable addresses rarely receive long-term mail; " +
      "request a permanent address if this contact matters.";
    return out;
  }
  if (roles.has(local)) {
    out.stop = makeStopCause("E303", `role account (${local}@)`);
    out.advice =
      "Role accounts are shared inboxes; engagement is usually low " +
      "and complaints are high. Mail to humans, not roles.";
    return out;
  }
  if (freeProviders.has(domain)) out.flags.push("free_provider");
  return out;
}

/* --- S5: MX fingerprint (port of core/fingerprint.py) --------------------- */

export const MX_TABLE = [
  ["mimecast", "Mimecast", true],
  ["pphosted", "Proofpoint", true],
  ["proofpoint", "Proofpoint", true],
  ["barracudanetworks", "Barracuda", true],
  ["messagelabs", "Symantec Cloud", true],
  ["mailprotect", "Bitdefender", true],
  ["irondport", "Cisco IronPort", true],
  ["ironport", "Cisco IronPort", true],
  ["forcepoint", "Forcepoint", true],
  ["sophos", "Sophos", true],
  ["trendmicro", "Trend Micro", true],
  ["mailcontrol", "Clearswift", true],
  ["synchronoss", "Synchronoss", true],
  ["google", "Google", false],
  ["googlemail", "Google", false],
  ["outlook", "Microsoft", false],
  ["protection.outlook", "Microsoft", false],
  ["yahoo", "Yahoo", false],
  ["yahoodns", "Yahoo", false],
  ["zoho", "Zoho", false],
  ["fastmail", "Fastmail", false],
  ["tutanota", "Tutanota", false],
  ["protonmail", "Proton", false],
  ["amazonses", "Amazon SES", false],
  ["sendgrid", "SendGrid", false],
  ["mailgun", "MailGun", false],
  ["postmark", "Postmark", false],
];

/** Gateways accept all mail for their customers → SMTP proof meaningless. */
export function fingerprint(mxCandidates) {
  const hosts = Array.isArray(mxCandidates) ? mxCandidates : [mxCandidates];
  for (const host of hosts) {
    const h = String(host || "").toLowerCase().replace(/\.$/, "");
    for (const [needle, provider, isGateway] of MX_TABLE) {
      if (h.includes(needle)) {
        return { provider, gateway: isGateway ? provider : null };
      }
    }
  }
  return { provider: null, gateway: null };
}

/* --- S4: DNS over HTTPS (port of core/dns_check.py) ----------------------- */

export const TYPE_A = 1;
export const TYPE_AAAA = 28;
export const TYPE_MX = 15;
const RTYPE_NUM = { A: TYPE_A, AAAA: TYPE_AAAA, MX: TYPE_MX };

export class DohTimeout extends Error {}
export class DohHttpError extends Error {}
export class DohMalformed extends Error {}

/** Mirrors the Python ipaddress checks used by the SSRF guard. */
export function isUnsafeIp(ipText) {
  if (typeof ipText !== "string") return true;
  const raw = ipText.trim().split("%")[0].replace(/^\[|\]$/g, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) {
    const o = raw.split(".").map(Number);
    if (o.some((x) => Number.isNaN(x) || x < 0 || x > 255)) return true;
    if (o[0] === 0 || o[0] === 10 || o[0] === 127) return true;
    if (o[0] === 169 && o[1] === 254) return true;       // link-local
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] === 192 && o[1] === 168) return true;
    if (o[0] === 192 && o[1] === 0 && (o[2] === 0 || o[2] === 2)) return true;
    if (o[0] === 192 && o[1] === 88 && o[2] === 99) return true;
    if (o[0] === 198 && o[1] >= 51 && o[1] <= 52) return true; // benchmark
    return o[0] >= 224;                                    // multicast/reserved
  }
  if (raw.includes(":")) {
    if (raw === "::" || raw === "::1" || raw === "0:0:0:0:0:0:0:1") return true;
    if (/^f[ec][0-9a-f]{2}:/i.test(raw)) return true;      // fc00::/7
    if (/^fe80:/i.test(raw)) return true;                  // link-local
    return /^ff[0-9a-f]{2}:/i.test(raw);                   // multicast
  }
  return true; // not a parseable address → treat as unsafe
}

export function parseDoh(data, name) {
  if (!data || typeof data !== "object" || typeof data.Status !== "number") {
    throw new DohMalformed("DoH response missing integer Status");
  }
  const answers = [];
  const raw = data.Answer;
  if (raw !== undefined && raw !== null) {
    if (!Array.isArray(raw)) throw new DohMalformed("DoH Answer is not a list");
    for (const rr of raw) {
      if (!rr || typeof rr !== "object" || !("data" in rr)) {
        throw new DohMalformed("DoH RR missing data");
      }
      answers.push({ name: rr.name || name, type: Number(rr.type || 0), data: String(rr.data) });
    }
  }
  return { Status: data.Status, Answer: answers };
}

/** doh(name, rtype, timeout_ms) over a {name|TYPE: response} fixture. */
export function makeFixtureDoh(mapping) {
  return (name, rtype, _timeoutMs) => {
    const value = mapping[`${name}|${rtype}`];
    return value === undefined ? { Status: 0, Answer: [] } : value;
  };
}

/** Cloudflare DoH, dns.google fallback (both free, no key). */
export function defaultDohQuery(fetchImpl, dohTimeoutMs) {
  const doh = fetchImpl || fetch;
  return async (name, rtype, timeoutMs) => {
    const timeout = (dohTimeoutMs && dohTimeoutMs > 0) ? dohTimeoutMs : timeoutMs;
    let last = null;
    for (const url of ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const resp = await doh(`${url}?name=${encodeURIComponent(name)}&type=${rtype}`, {
          headers: { accept: "application/dns-json" },
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (resp.status !== 200) {
          last = new DohHttpError(`HTTP ${resp.status} from ${url}`);
          continue;
        }
        return parseDoh(await resp.json(), name);
      } catch (err) {
        clearTimeout(timer);
        if (err && err.name === "AbortError") {
          last = new DohTimeout(`DNS timeout for ${name} ${rtype}`);
          break;
        }
        last = new DohHttpError(err && err.message ? err.message : "DoH request failed");
      }
    }
    throw last || new DohTimeout("DNS budget exhausted");
  };
}

async function run(fn) {
  try {
    return ["ok", await fn()];
  } catch (err) {
    if (err instanceof DohTimeout) return ["timeout", null];
    if (err instanceof DohMalformed) return ["malformed", null];
    return ["http", null];
  }
}

async function query(doh, name, rtype, remainingFn, cache) {
  const key = `${name}|${rtype}`;
  if (cache && cache.has(key)) return cache.get(key);
  const budget = remainingFn ? remainingFn() : Number.MAX_SAFE_INTEGER;
  if (budget <= 25) throw new DohTimeout("deadline exhausted before DNS query");
  const parsed = parseDoh(await doh(name, rtype, budget), name);
  if (cache) cache.set(key, parsed);
  return parsed;
}

async function collectIps(doh, host, remainingFn, cache) {
  const [ra, raaaa] = await Promise.all([
    run(() => query(doh, host, "A", remainingFn, cache)),
    run(() => query(doh, host, "AAAA", remainingFn, cache)),
  ]);
  const results = { A: ra, AAAA: raaaa };
  const statuses = new Set(Object.values(results)
    .filter(([kind]) => kind === "ok").map(([, v]) => v.Status));
  const ips = [];
  for (const [rtype, [kind, value]] of Object.entries(results)) {
    if (kind !== "ok") continue;
    if (rtype === "A" && value.Status === 3) continue; // NXDOMAIN via statuses
    for (const rr of value.Answer) {
      if (rr.type === RTYPE_NUM[rtype]) ips.push(rr.data.split(" ").pop());
    }
  }
  if (ips.length === 0 && statuses.size === 1 && statuses.has(3)) {
    return { ips: [], sCode: null }; // host does not exist → E404 territory
  }
  if (ips.length === 0) {
    const kinds = new Set(Object.values(results).map(([kind]) => kind));
    if (kinds.has("timeout")) return { ips, sCode: "E406" };
    if (kinds.has("http")) return { ips, sCode: "E408" };
    if (kinds.has("malformed")) return { ips, sCode: "E409" };
  }
  return { ips, sCode: null };
}

/** Run S4 for one domain. doh(name, rtype, timeout_ms) -> DoH-JSON dict. */
export async function checkDomain(domain, doh, remainingFn, cache) {
  const stop = (code, message) =>
    ({ stop: { code, message }, mx: [], ips: {}, flags: [], implicit: false });
  const [rMx, rA, rAaaa] = await Promise.all(
    ["MX", "A", "AAAA"].map((rt) => run(() => query(doh, domain, rt, remainingFn, cache))),
  );

  if (rMx[0] !== "ok") {
    return stop({ timeout: "E406", malformed: "E409" }[rMx[0]] || "E408");
  }
  const mxStatus = rMx[1].Status;
  if (mxStatus === 3) return stop("E401", "NXDOMAIN");
  if (mxStatus === 2 || mxStatus === 5) return stop("E407");

  const hosts = [];
  for (const rr of rMx[1].Answer) {
    if (rr.type !== TYPE_MX) continue;
    const parts = rr.data.trim().replace(/\.$/, "").split(" ");
    const pref = Number(parts[0]);
    if (parts.length !== 2 || Number.isNaN(pref)) continue;
    const host = (parts[1] || "").replace(/\.$/, "").toLowerCase();
    if (pref === 0 && (host === "" || host === ".")) {
      return stop("E402", "null MX (RFC 7505)");
    }
    if (host) hosts.push([pref, host]);
  }
  hosts.sort((a, b) => a[0] - b[0]);

  const aAnswers = (res, num) => {
    if (res[0] !== "ok" || res[1].Status !== 0) return [];
    return res[1].Answer.filter((rr) => rr.type === num).map((rr) => rr.data);
  };

  if (hosts.length === 0) {
    const ips = aAnswers(rA, TYPE_A).concat(aAnswers(rAaaa, TYPE_AAAA));
    if (ips.length > 0) {
      const unsafe = ips.find((ip) => isUnsafeIp(ip));
      if (unsafe) return stop("E405", `implicit MX points to unsafe IP ${unsafe}`);
      return { stop: null, mx: [domain], ips: { [domain]: ips }, flags: ["implicit_mx"], implicit: true };
    }
    const kinds = new Set([rA[0], rAaaa[0]]);
    if (kinds.has("timeout")) return stop("E406");
    if (kinds.has("http")) return stop("E408");
    if (kinds.has("malformed")) return stop("E409");
    return stop("E403", "no MX and no A/AAAA");
  }

  const outMx = [];
  const outIps = {};
  let sFailure = null;
  let sawHost = false;
  for (const [, host] of hosts) {
    const { ips, sCode } = await collectIps(doh, host, remainingFn, cache);
    if (ips.length > 0) {
      sawHost = true;
      outMx.push(host);
      outIps[host] = ips;
      const unsafe = ips.find((ip) => isUnsafeIp(ip));
      if (unsafe) return stop("E405", `MX ${host} points to unsafe IP ${unsafe}`);
    } else if (sCode && !sFailure) {
      sFailure = sCode;
    }
  }
  if (outMx.length === 0) {
    if (sFailure) return stop(sFailure);
    if (!sawHost) return stop("E404", "MX hostname does not resolve");
  }
  return { stop: null, mx: outMx, ips: outIps, flags: [], implicit: false };
}

/* --- S6 mapping: SMTP reply codes → error codes --------------------------- */

/**
 * Mirrors core/smtp_check.py reply classification. `reply` is an integer code,
 * `detail` is the reply text (used for 5.2.2 / 5.7.x sub-codes).
 */
export function mapSmtpReply(reply, detail) {
  const text = typeof detail === "string" ? detail.toLowerCase() : "";
  const sub = text.match(/(?:^|\s)([45])\.([1-9](?:\.\d+)?)/);
  const minor = sub ? sub[0].trim() : "";
  if (reply === 250) return { code: "OK", message: "mailbox accepted" };
  if (minor.startsWith("5.7.")) {
    return { code: "E614", message: "rejected by server policy" };
  }
  if (reply === 550 || reply === 551 || reply === 553) {
    return { code: "E610", message: `${reply}: user unknown or mailbox unavailable` };
  }
  if (reply === 552 || minor.startsWith("5.2.2")) {
    return { code: "E611", message: "mailbox full" };
  }
  if (reply === 421 || reply === 450) {
    return { code: "E613", message: "temporary failure, retry later" };
  }
  if (reply >= 400 && reply < 500) {
    return { code: "E612", message: "greylisting or transient deferral" };
  }
  if (reply >= 500 && reply < 600) {
    return { code: "E610", message: `${reply}: permanent SMTP failure` };
  }
  return { code: "E606", message: `unexpected SMTP reply ${reply}` };
}

/**
 * Delegate the SMTP proof to an external probe service (Workers cannot open
 * TCP sockets). Maps transport errors to E602 and auth failures to E603.
 */
export async function probeViaService(email, sender, env, fetchImpl, timeoutMs) {
  const doh = fetchImpl || fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 7000);
  try {
    const resp = await doh(env.SMTP_PROBE_URL, {
      method: "POST",
      headers: { "content-type": "application/json", "x-probe-key": env.SMTP_PROBE_KEY || "" },
      body: JSON.stringify({ email, sender, timeout_ms: timeoutMs || 7000 }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (resp.status === 401 || resp.status === 403) {
      return { code: "E603", message: "probe rejected our key" };
    }
    const data = await resp.json();
    return {
      code: data.code || (resp.status < 400 ? "OK" : "E602"),
      smtp_code: data.smtp_code || null,
      message: data.message || data.error || "probe returned no message",
      catchall: Boolean(data.catchall),
    };
  } catch (err) {
    clearTimeout(timer);
    if (err && err.name === "AbortError") {
      return { code: "E602", message: "probe timed out" };
    }
    return { code: "E602", message: `probe unreachable: ${err && err.message ? err.message : "network"}` };
  }
}

/* --- Result construction (port of core/models.py) -------------------------- */

export function makeStopCause(code, message, scope) {
  const entry = ERROR_CODES[code] || ERROR_CODES.E705;
  return {
    code,
    class: entry.class,
    stage: STAGE_LABELS[entry.stage] || entry.stage,
    message: message || entry.message,
    retryable: entry.retryable,
    retry_after_s: entry.retry_after_s,
    scope: scope || entry.scope || null,
  };
}

export function levelForCode(code) {
  // Port of core.models.level_for_code.
  if (code === "E601") return "dns"; // DNS resolved, mailbox unconfirmed
  const entry = ERROR_CODES[code];
  if (!entry) return "smtp";
  return LEVEL_FOR_STAGE[entry.stage] || "smtp";
}

const SHORT_STAGES = ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"];

/** Stages after the one that stopped the run (fail-fast bookkeeping). */
export function skippedAfter(code) {
  const stage = (ERROR_CODES[code] || {}).stage;
  const i = SHORT_STAGES.indexOf(stage);
  return i < 0 ? [] : SHORT_STAGES.slice(i + 1);
}

export function okResult(email, flags, stagesCompleted, mx, reason) {
  return {
    email,
    status: "deliverable",
    score: DEFAULT_SCORES.OK,
    reason_code: OK_CODE,
    reason: reason || "mailbox accepted",
    level: "smtp",
    flags: flags || [],
    did_you_mean: null,
    advice: null,
    halted: false,
    halt_scope: null,
    stop_cause: null,
    stages_completed: stagesCompleted,
    stages_skipped: [], // Python ok_result(): a healthy run skips nothing
    mx: mx || [],
    cached: false,
    took_ms: 0,
  };
}

export function resultFromCode(email, code, message, stagesCompleted, extra) {
  extra = extra || {};
  const entry = ERROR_CODES[code] || ERROR_CODES.E705;
  const halted = code !== OK_CODE;
  return {
    email,
    status: entry.status,
    score: DEFAULT_SCORES[code] !== undefined ? DEFAULT_SCORES[code] : 35,
    reason_code: code,
    reason: message || entry.message,
    level: levelForCode(code),
    flags: extra.flags || [],
    did_you_mean: extra.didYouMean || null,
    advice: extra.advice || null,
    halted,
    halt_scope: halted ? entry.scope || "email" : null,
    stop_cause: halted ? makeStopCause(code, message) : null,
    stages_completed: stagesCompleted,
    stages_skipped: extra.skipped || skippedAfter(code),
    mx: extra.mx || [],
    cached: false,
    took_ms: extra.tookMs || 0,
  };
}


export function summarize(results) {
  const out = { deliverable: 0, undeliverable: 0, risky: 0, unknown: 0 };
  for (const r of results) out[r.status] = (out[r.status] || 0) + 1;
  return out;
}

/* --- Run-level circuit breakers (PRD 5.2) ---------------------------------- */

/** PRD 5.3: catch-all acceptance proves nothing about the person. */
export const CATCHALL_ADVICE =
  "This domain accepts mail for any address, so acceptance proves nothing " +
  "about the person. Do not treat it as valid: confirm interest through " +
  "double opt-in and judge by engagement and bounce rate after the first " +
  "campaign.";

const DNS_FAIL_CODES = new Set(["E406", "E407", "E408"]);
const PLATFORM_CODES = new Set(["E701", "E702", "E703"]);

export class RunState {
  constructor(subrequestBudget) {
    this.trip = null;
    this.consecutive = { B2: 0, B3: 0, B4: 0 };
    this.window = [];
    this.e705 = 0;
    this.subrequests = 0;
    this.subrequestBudget = subrequestBudget === undefined ? null : subrequestBudget;
  }

  _trip(breaker, code) {
    const cause = makeStopCause(code, BREAKER_MESSAGES[breaker]);
    cause.stage = "S7_platform";
    cause.scope = "run";
    this.trip = cause;
    return cause;
  }

  /** Charge one outbound subrequest; trips B5/E701 when the budget is spent. */
  countSubrequest() {
    this.subrequests += 1;
    if (this.subrequestBudget !== null && this.subrequests > this.subrequestBudget) {
      return this._trip("B5", "E701");
    }
    return this.trip;
  }

  /** Record one stop cause; returns the trip cause when a breaker opens. */
  observe(code, domain) {
    if (!code || this.trip) return this.trip;
    if (code === "E001" || code === "E603") return this._trip("B1", code);
    if (PLATFORM_CODES.has(code)) return this._trip("B5", code);
    if (code === "E705") {
      this.e705 += 1;
      if (this.e705 >= 3) return this._trip("B6", code);
    }
    if (DNS_FAIL_CODES.has(code)) this.consecutive.B2 += 1;
    else this.consecutive.B2 = 0;
    if (code === "E614") this.consecutive.B3 += 1;
    else this.consecutive.B3 = 0;
    if (code === "E602") this.consecutive.B4 += 1;
    else this.consecutive.B4 = 0;

    this.window.push([code, domain]);
    if (this.window.length > 20) this.window.shift();
    const last20 = this.window.slice(-20);
    const b2Hits = last20.filter(([c]) => DNS_FAIL_CODES.has(c)).length;
    const b3Hits = last20.filter(([c]) => c === "E614");
    if (this.consecutive.B2 >= 5 || b2Hits > 10) return this._trip("B2", code);
    if (this.consecutive.B3 >= 5 ||
        (b3Hits.length > 6 && new Set(b3Hits.map(([, d]) => d)).size >= 2)) {
      return this._trip("B3", code);
    }
    if (this.consecutive.B4 >= 3) return this._trip("B4", code);
    return null;
  }
}

/* --- In-memory caches ------------------------------------------------------ */

export class CatchAllCache {
  constructor(ttlMs) {
    this.ttlMs = ttlMs === undefined ? 24 * 60 * 60 * 1000 : ttlMs;
    this.store = new Map();
  }

  get(domain, now) {
    const hit = this.store.get(domain);
    if (!hit) return null;
    const ts = now === undefined ? Date.now() : now;
    if (ts - hit.seen_at > this.ttlMs) {
      this.store.delete(domain);
      return null;
    }
    return hit;
  }

  set(domain, value, now) {
    const ts = now === undefined ? Date.now() : now;
    this.store.set(domain, Object.assign({ seen_at: ts }, value));
  }

  clear() {
    this.store.clear();
  }
}

/* --- Per-IP rate limit (PRD 8.5) ------------------------------------------- */

export class RateLimiter {
  constructor(ratePerMinute, windowMs) {
    this.rate = ratePerMinute;
    this.window = windowMs === undefined ? 60 * 1000 : windowMs;
    this.hits = new Map();
  }

  /** Returns null when allowed, otherwise the ms the client should back off. */
  allow(key, now) {
    const ts = now === undefined ? Date.now() : now;
    const cutoff = ts - this.window;
    const entries = (this.hits.get(key) || []).filter((t) => t > cutoff);
    if (entries.length >= this.rate) {
      this.hits.set(key, entries);
      return Math.max(entries[0] - ts, 1000);
    }
    entries.push(ts);
    this.hits.set(key, entries);
    return null;
  }
}

/* --- Pipeline (port of core/pipeline.py) ----------------------------------- */

const HEURISTIC_FLAGS = { E301: "disposable_domain", E303: "role_account", E304: "probable_typo" };
const STAGE_ALL = ["S1", "S2", "S3", "S4", "S5", "S6"];
const DEADLINE_GUARD_MS = 50;

function domainOf(email) {
  return String(email).split("@").pop().toLowerCase();
}

/**
 * Verify one address through S1–S6. Injectables: doh_query, probe_fn, sender,
 * probe_url, probe_key, halt_policy, deadline_ms, mode, smtp, _run_state,
 * dns_cache, catchall_cache, list overrides.
 */
export async function verifyEmail(raw, opts) {
  opts = opts || {};
  const haltPolicy = opts.halt_policy || "strict";
  const mode = opts.mode || "standard";
  const totalMs = Number(opts.deadline_ms || DEADLINE_MS);
  const runState = opts._run_state || null;
  const smtpOn = (opts.smtp === undefined ? true : Boolean(opts.smtp)) && mode !== "fast";
  const started = Date.now();
  const elapsedMs = () => Date.now() - started;
  const remainingMs = () => totalMs - elapsedMs();
  const probeUrl = opts.probe_url || (opts.env && opts.env.SMTP_PROBE_URL);
  const probeKey = opts.probe_key || (opts.env && opts.env.SMTP_PROBE_KEY) || "";
  const baseDoh = opts.doh_query || defaultDohQuery(opts.fetch, opts.doh_timeout_ms);
  const catchallCache = opts.catchall_cache || null;
  const preFive = STAGE_ALL.slice(0, 5);

  let display = String(raw);
  const halt = (code, stages, message, extra) => {
    extra = extra || {};
    const r = resultFromCode(display, code, message, stages, {
      flags: extra.flags,
      didYouMean: extra.didYouMean,
      advice: extra.advice,
      mx: extra.mx,
      skipped: extra.skipped,
      tookMs: elapsedMs(),
    });
    if (runState && r.stop_cause) runState.observe(code, domainOf(display));
    return r;
  };

  try {
    const s1 = checkSyntax(raw);
    if (s1.code) return halt(s1.code, ["S1"], s1.message);
    display = s1.email;
    const domain = domainOf(display);

    const s2 = checkRules(display);
    if (s2) return halt(s2.code, ["S1", "S2"], s2.message);

    let flags = [];
    let didYouMean = null;
    let advice = null;
    let heuristicStop = null;
    const lists = checkLists(display, {
      disposables: opts.disposables,
      blocklist: opts.blocklist,
      typos: opts.typos,
      roles: opts.roles,
      freeProviders: opts.freeProviders,
    });
    flags = flags.concat(lists.flags);
    if (lists.stop) {
      const code = lists.stop.code;
      if (code === "E305") return halt("E305", ["S1", "S2"], lists.stop.message);
      const heuristic = HEURISTIC_CODES.has(code);
      if (!heuristic || haltPolicy === "strict") {
        return halt(code, ["S1", "S2", "S3"], lists.stop.message,
          { flags, didYouMean: lists.didYouMean, advice: lists.advice });
      }
      heuristicStop = { code, message: lists.stop.message };
      flags.push(HEURISTIC_FLAGS[code] || code.toLowerCase());
      didYouMean = lists.didYouMean;
      advice = lists.advice;
    }

    const countingDoh = (name, rtype, timeoutMs) => {
      if (runState) runState.countSubrequest();
      return baseDoh(name, rtype, timeoutMs);
    };
    const dns = await checkDomain(domain, countingDoh, remainingMs, opts.dns_cache);
    if (dns.stop) {
      return halt(dns.stop.code, ["S1", "S2", "S3"], dns.stop.message,
        { flags, didYouMean, advice });
    }
    flags = flags.concat(dns.flags);
    const mx = dns.mx.slice();

    const fp = fingerprint(mx);
    if (fp.gateway) {
      if (haltPolicy === "strict") {
        return halt("E501", preFive,
          `security gateway in front (${fp.gateway}); SMTP proof would be meaningless`,
          { flags, mx });
      }
      flags.push("gateway_fronted");
      if (!heuristicStop) {
        heuristicStop = { code: "E501", message: `gateway in front: ${fp.gateway}` };
      }
    }

    if (!smtpOn) {
      return halt("E601", preFive, "domain_ok_mailbox_unchecked",
        { flags, didYouMean, advice, mx, skipped: ["S6", "S7"] });
    }
    if (remainingMs() <= DEADLINE_GUARD_MS) {
      return halt("E618", preFive, "deadline exhausted before SMTP probe",
        { flags: flags.concat(["deadline_exceeded"]), mx, skipped: ["S6", "S7"] });
    }

    let verdict;
    if (opts.probe_fn) {
      verdict = await opts.probe_fn(display, mx, opts);
    } else if (probeUrl) {
      const cached = catchallCache ? catchallCache.get(domain) : null;
      if (cached && cached.is_catchall) {
        verdict = { code: "E615", message: "catch-all domain (cached)", catchall: true };
      } else {
        if (runState) runState.countSubrequest();
        verdict = await probeViaService(display, opts.sender || `postmaster@${domain}`,
          { SMTP_PROBE_URL: probeUrl, SMTP_PROBE_KEY: probeKey },
          opts.fetch, Math.max(1, remainingMs()));
        if (verdict.code === "OK" && verdict.catchall && catchallCache) {
          catchallCache.set(domain, { is_catchall: true });
        }
      }
    } else {
      verdict = { code: "E601", message: "no SMTP probe configured" };
    }

    const fl = flags.concat(verdict.flags || []);
    if (runState && runState.trip) {
      return halt(runState.trip.code, preFive, runState.trip.message,
        { flags: fl, mx, skipped: ["S6", "S7"] });
    }
    if (!verdict.code || verdict.code === "OK") {
      if (verdict.catchall) {
        return halt("E615", STAGE_ALL,
          verdict.message || "catch-all domain accepts any mailbox",
          { flags: fl.concat(["catchall_domain"]), mx, advice: CATCHALL_ADVICE });
      }
      if (heuristicStop) {
        // soft policy: SMTP ran, but the S3/S5 heuristic caps the verdict.
        return resultFromCode(display, heuristicStop.code, heuristicStop.message, STAGE_ALL, {
          flags: fl, didYouMean, advice, mx, tookMs: elapsedMs(),
        });
      }
      const ok = okResult(display, fl.concat(["smtp_proven"]), STAGE_ALL, mx, verdict.message);
      ok.took_ms = elapsedMs();
      return ok;
    }
    if (verdict.code === "E618") {
      return halt("E618", preFive, verdict.message,
        { flags: fl.concat(["deadline_exceeded"]), mx, skipped: ["S6", "S7"] });
    }
    return halt(verdict.code, STAGE_ALL, verdict.message, { flags: fl, mx });
  } catch (err) {
    const result = resultFromCode(display, "E705",
      `internal error: ${err && err.name ? err.name : "Error"}`, ["S1"], { tookMs: elapsedMs() });
    if (runState) runState.observe("E705", domainOf(display));
    return result;
  }
}

/** Verify a batch, halting the whole run when a circuit breaker opens. */
export async function verifyBatch(emails, opts) {
  opts = opts || {};
  const runState = opts._run_state || new RunState(opts.subrequest_budget);
  const opts2 = Object.assign({}, opts, { _run_state: runState });
  const results = [];
  let halted = null;
  for (let i = 0; i < emails.length; i += 1) {
    if (halted) break;
    const r = await verifyEmail(emails[i], opts2);
    results.push(r);
    if (runState.trip) halted = runState.trip;
  }
  const processed = results.length;
  const notProcessed = halted ? emails.slice(processed) : [];
  return {
    results,
    processed,
    total: emails.length,
    run_status: halted ? "halted" : "ok",
    stop_cause: halted,
    resume_from: halted ? processed : null,
    not_processed: notProcessed,
    summary: summarize(results),
  };
}

/* --- HTTP layer ------------------------------------------------------------ */

export function jsonResponse(body, status, extraHeaders) {
  const headers = Object.assign({ "content-type": "application/json; charset=utf-8" }, extraHeaders || {});
  return new Response(JSON.stringify(body), { status, headers });
}

export function errorBody(code, message, extra) {
  return Object.assign({ error: { code, message } }, extra || {});
}

export function authFailure(request, env) {
  const expected = env.API_KEY;
  if (!expected) return null;
  const header = request.headers.get("authorization") || "";
  if (header === `Bearer ${expected}`) return null;
  return errorBody("E001", "missing or invalid Authorization: Bearer token");
}

export function corsHeaders(env, request) {
  const origin = (request && request.headers && request.headers.get("origin")) || "";
  // No Origin means this is not a browser request (curl, the Streamlit app,
  // another service). Emitting access-control-* there would change the
  // response shape for existing server-to-server clients for no reason.
  if (!origin && !env.CORS_ORIGIN) return {};
  return {
    "access-control-allow-origin": env.CORS_ORIGIN || origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-max-age": "86400",
  };
}

export function rateLimiters(env) {
  if (!env._limiters) {
    env._limiters = {
      single: new RateLimiter(Number(env.RATE_SINGLE || 60)),
      batch: new RateLimiter(Number(env.RATE_BATCH || 10)),
    };
  }
  return env._limiters;
}

export function clientIp(request) {
  return (request && request.headers && request.headers.get("cf-connecting-ip")) || "local";
}

export function workerOpts(env, requestOpts) {
  return Object.assign({
    deadline_ms: Number(env.DEADLINE_MS || DEADLINE_MS),
    halt_policy: env.HALT_POLICY || "strict",
    mode: env.MODE || "standard",
    smtp: env.SMTP || "true",
  }, requestOpts || {});
}

/** Shared S6 wiring: probe URL/key from env, caches per worker scope. */
export function pipelineOpts(env, requestOpts) {
  const opts = workerOpts(env, requestOpts);
  if (!env._catchall_cache) env._catchall_cache = new CatchAllCache();
  if (!env._dns_cache) env._dns_cache = new Map();
  opts.env = env;
  opts.catchall_cache = env._catchall_cache;
  opts.dns_cache = env._dns_cache;
  return opts;
}

async function readJson(request) {
  try {
    const text = await request.text();
    if (!text) return {};
    const data = JSON.parse(text);
    return data && typeof data === "object" ? data : null;
  } catch (err) {
    return null;
  }
}

export async function verifySingleEmail(email, env, requestOpts) {
  return verifyEmail(email, pipelineOpts(env, requestOpts));
}

export async function handleSingle(request, env, body) {
  const opts = body && body.options ? body.options : {};
  const email = body && typeof body.email === "string" ? body.email : null;
  if (!email) {
    return jsonResponse(errorBody("E002", "body must include a string 'email'"), 400);
  }
  return jsonResponse({ result: await verifySingleEmail(email, env, opts) });
}

export async function handleBatch(request, env, body) {
  const maxBulk = Number(env.MAX_BULK || DEFAULT_MAX_BULK);
  const emails = body && body.emails;
  if (!Array.isArray(emails)) {
    return jsonResponse(errorBody("E002", "body must include an 'emails' array"), 400);
  }
  if (emails.length === 0) {
    return jsonResponse(errorBody("E003", "batch must contain at least one email"), 400);
  }
  if (emails.length > maxBulk) {
    return jsonResponse(errorBody("E004", `batch of ${emails.length} exceeds MAX_BULK ${maxBulk}`), 413);
  }
  const opts = pipelineOpts(env, body.options);
  if (env.SUBREQUEST_BUDGET) opts.subrequest_budget = Number(env.SUBREQUEST_BUDGET);
  return jsonResponse(await verifyBatch(emails, opts));
}

/* A tiny no-build UI so the Worker can host a UI and a JSON API on one host.
 * It is unauthenticated on purpose: a browser cannot attach an Authorization
 * header to a top-level navigation. The page authenticates its own fetch()
 * calls, so the /v1/* JSON routes below stay gated. */

const UI_HEAD = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Email Verifier</title>
<style>
 body{font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f6f7f9;color:#1b1f24}
 .wrap{max-width:960px;margin:0 auto;padding:32px 20px 64px}
 h1{font-size:22px;margin:0 0 4px}
 .sub{color:#5b6672;margin:0 0 22px;font-size:13px}
 fieldset{border:1px solid #e2e6ea;border-radius:10px;padding:14px 16px 18px;margin:0 0 16px;background:#fff}
 legend{font-weight:600;font-size:13px;padding:0 6px}
 textarea,input[type=text]{width:100%;box-sizing:border-box;font:inherit;padding:9px 11px;border:1px solid #d4dae0;border-radius:8px}
 textarea{height:150px;resize:vertical}
 .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:10px}
 button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:9px 18px;font:inherit;font-weight:600;cursor:pointer}
 button:disabled{opacity:.5;cursor:default}
 .msg{margin-top:10px;font-size:13px;min-height:20px}
 .err{color:#b3261e}.ok{color:#0b6e2f}
 table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
 th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eceff2}
 th{background:#f1f4f7;font-weight:600}
 td.st-deliverable{color:#0b6e2f;font-weight:600}
 td.st-undeliverable{color:#b3261e;font-weight:600}
 td.st-risky{color:#8a5a00;font-weight:600}
 td.st-unknown{color:#3d4a5c;font-weight:600}
 code{background:#eef1f5;padding:1px 5px;border-radius:4px}
</style>
</head>
<body>
<div class="wrap">
`;

const UI_BODY = `
<h1>Email Verifier</h1>
<p class="sub">S1 syntax &rarr; S2 rules &rarr; S3 lists &rarr; S4 DNS &rarr; S5 fingerprint &rarr; S6 SMTP. No mail is ever sent: the SMTP conversation stops after RCPT.</p>

<fieldset>
<legend>Setup</legend>
<input type="text" id="key" placeholder="API key (leave blank if none is required)">
<div class="row"><button id="saveKey">Save key</button></div>
</fieldset>

<fieldset>
<legend>Single address</legend>
<input type="text" id="one" placeholder="name@example.com">
<div class="row"><button id="goOne">Verify</button><span class="msg" id="msgOne"></span></div>
<div id="outOne"></div>
</fieldset>

<fieldset>
<legend>Bulk (max <span id="max">100</span>)</legend>
<textarea id="many" placeholder="a@b.com&#10;c@d.com"></textarea>
<div class="row"><button id="goMany">Verify all</button><span class="msg" id="msgMany"></span></div>
<div id="summary"></div>
<div id="outMany"></div>
</fieldset>

<fieldset>
<legend>JSON API</legend>
<p><code>POST /v1/verify</code> {email, options} &middot; <code>POST /v1/verify/batch</code> {emails, options} &middot; <code>GET /health</code></p>
<p>Errors: <code>401/E001</code> bad key &middot; <code>400/E002</code> bad JSON &middot; <code>413/E004</code> over MAX_BULK &middot; <code>429/E005</code> rate limit.</p>
</fieldset>
</div>
`;

const UI_JS = `
<script>
var key = localStorage.getItem('ev_key') || '';
var keyEl = document.getElementById('key');
keyEl.value = key;
document.getElementById('max').textContent = __MAX__;

function setMsg(el, text, isErr) {
  el.textContent = text || '';
  el.className = 'msg ' + (isErr ? 'err' : 'ok');
}
function store() {
  key = keyEl.value.trim();
  localStorage.setItem('ev_key', key);
}
document.getElementById('saveKey').addEventListener('click', store);
keyEl.addEventListener('change', store);

function headers() {
  var h = { 'Content-Type': 'application/json' };
  if (key) h['Authorization'] = 'Bearer ' + key;
  return h;
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<"]/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
  });
}
function table(results) {
  if (!results.length) return '<p class="msg">No results.</p>';
  var html = '<table><thead><tr><th>Status</th><th>Email</th><th>Score</th><th>Code</th><th>Reason</th><th>ms</th></tr></thead><tbody>';
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    var cause = r.stop_cause || {};
    html += '<tr><td class="st-' + esc(r.status) + '">' + esc(r.status) + '</td>'
      + '<td>' + esc(r.email) + '</td>'
      + '<td>' + esc(r.score) + '</td>'
      + '<td><code>' + esc(cause.code || r.reason_code) + '</code></td>'
      + '<td>' + esc(cause.message || r.reason) + '</td>'
      + '<td>' + esc(r.took_ms) + '</td></tr>';
  }
  return html + '</tbody></table>';
}
function call(url, payload, msgEl, outEl, single) {
  store();
  setMsg(msgEl, 'Verifying...', false);
  fetch(url, { method: 'POST', headers: headers(), body: JSON.stringify(payload) })
    .then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, s: r.status, d: d }; });
    })
    .then(function (x) {
      var err = x.d && x.d.error;
      if (!x.ok) throw new Error('HTTP ' + x.s + (err ? ' ' + err.code + ': ' + err.message : ''));
      // /v1/verify returns one {result}; /v1/verify/batch returns {results}.
      var rows = single ? [x.d.result] : x.d.results;
      if (!rows) throw new Error('API returned no result');
      outEl.innerHTML = table(rows);
      if (!single) {
        var c = { deliverable: 0, risky: 0, undeliverable: 0, unknown: 0 };
        rows.forEach(function (r) { c[r.status] = (c[r.status] || 0) + 1; });
        document.getElementById('summary').innerHTML = '<p class="msg">deliverable ' + c.deliverable
          + ' / risky ' + c.risky + ' / undeliverable ' + c.undeliverable + ' / unknown ' + c.unknown + '</p>';
      }
      setMsg(msgEl, rows.length + ' result' + (rows.length === 1 ? '' : 's'), false);
    })
    .catch(function (e) { setMsg(msgEl, String(e), true); outEl.innerHTML = ''; });
}
document.getElementById('goOne').addEventListener('click', function () {
  var email = document.getElementById('one').value.trim();
  if (!email) return setMsg(document.getElementById('msgOne'), 'Enter an address.', true);
  call('/v1/verify', { email: email }, document.getElementById('msgOne'), document.getElementById('outOne'), true);
});
document.getElementById('goMany').addEventListener('click', function () {
  var emails = document.getElementById('many').value.split(/[\\r\\n,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  if (!emails.length) return setMsg(document.getElementById('msgMany'), 'Paste one address per line.', true);
  call('/v1/verify/batch', { emails: emails }, document.getElementById('msgMany'), document.getElementById('outMany'), false);
});
</script>
</body>
</html>`;

/** Assemble the page. `__MAX__` is substituted so the UI can never advertise
 *  a batch size larger than the enforced MAX_BULK. */
export function uiHtml(env) {
  const maxBulk = Number(env.MAX_BULK || DEFAULT_MAX_BULK);
  // String.replace with a non-regex only touches the first hit, which is what
  // we want: exactly one __MAX__ occurs, in the bulk-size hint.
  return (UI_HEAD + UI_BODY + UI_JS).replace("__MAX__", String(maxBulk));
}

export async function handleGet(request, env, url) {
  if (url.pathname === "/" || url.pathname === "/index.html") {
    return new Response(uiHtml(env), {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    });
  }
  if (url.pathname === "/health") {
    return jsonResponse({
      ok: true,
      version: VERSION,
      probe: env.SMTP_PROBE_URL ? "configured" : "absent",
      max_bulk: Number(env.MAX_BULK || DEFAULT_MAX_BULK),
    });
  }
  if (url.pathname === "/v1/verify") {
    const email = url.searchParams.get("email");
    if (!email) {
      return jsonResponse(errorBody("E002", "GET /v1/verify?email=... requires an email"), 400);
    }
    return jsonResponse({ result: await verifySingleEmail(email, env, {}) });
  }
  return jsonResponse(errorBody("E002", `unknown route ${url.pathname}`), 404);
}

/** Router: auth → rate limit → route → JSON body. Exported for node:test. */
export async function handleRequest(request, env, ctx) {
  // NB: `env` must stay the original object - the per-scope caches and the
  // rate limiters are attached to it by reference (see rateLimiters /
  // pipelineOpts), so copying here would rebuild them on every request.
  env = env || {};
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  // CORS on every response, not just OPTIONS: a preflight alone still leaves
  // the actual response unreadable by a cross-origin browser. Without an
  // Origin header (server-to-server calls, curl) this stays empty so the
  // response shape is unchanged for existing clients.
  const extra = corsHeaders(env, request);

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: extra });

  // The static page is unauthenticated: a browser cannot attach an
  // Authorization header to a top-level navigation, so gating it would make
  // the UI unreachable whenever API_KEY is set. It returns no data, and the
  // page's own fetch() calls still hit the gated /v1/* routes below.
  const isUi = url.pathname === "/" || url.pathname === "/index.html";

  if (!isUi) {
    const auth = authFailure(request, env);
    if (auth) return jsonResponse(auth, 401, extra);
  }

  const isBatch = url.pathname === "/v1/verify/batch";
  const bucket = (rateLimiters(env))[isBatch ? "batch" : "single"];
  const retryMs = isUi
    ? null
    : bucket.allow(`${clientIp(request)}:${url.pathname}`, Date.now());
  if (retryMs !== null) {
    return jsonResponse(errorBody("E005", "rate limit exceeded"), 429,
      Object.assign({ "retry-after": String(Math.ceil(retryMs / 1000)) }, extra));
  }

  try {
    if (method === "GET") return await handleGet(request, env, url);
    if (method !== "POST") {
      return jsonResponse(errorBody("E002", `method ${method} not allowed`), 405);
    }
    if (url.pathname === "/health") return await handleGet(request, env, url);

    const body = await readJson(request);
    if (body === null) {
      return jsonResponse(errorBody("E002", "request body must be valid JSON"), 400, extra);
    }
    if (isBatch) return await handleBatch(request, env, body);
    if (url.pathname === "/v1/verify") return await handleSingle(request, env, body);
    return jsonResponse(errorBody("E002", `unknown route ${url.pathname}`), 404, extra);
  } catch (err) {
    return jsonResponse(errorBody("E705", `internal error: ${err && err.name ? err.name : "Error"}`),
      500, extra);
  }
}

export default {
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  },
};





