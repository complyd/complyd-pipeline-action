'use strict';

const { ActionError } = require('./reduce');

const COLLECTOR_VERSION = require('../package.json').version;
/** The route's body cap (64 KiB). */
const MAX_BODY_BYTES = 64 * 1024;

/**
 * The observation envelope for one run of one repository
 * (`subject`, e.g. github:<repository id>). The id is the run's (on GitHub
 * `<run_id>-<run_attempt>-<schema>`), so a retried request is answered as a
 * duplicate and a re-run attempt is a new scan; a job may send one scan of
 * each schema.
 */
function envelope(payload, { id, subject, observedAt, schema = 'dependency_scan', collector = 'complyd_ci_scan' }) {
  return {
    envelope: 1,
    id,
    collector,
    collector_version: COLLECTOR_VERSION,
    schema,
    schema_version: 1,
    observed_at: observedAt,
    subject: { type: 'repository', id: subject },
    payload,
  };
}

/**
 * The envelope's bytes, under the route's 64 KiB: the least severe findings
 * go first and the scan is then marked truncated (counts keep the totals).
 */
function fit(env) {
  let body = JSON.stringify(env);
  if (Buffer.byteLength(body) <= MAX_BODY_BYTES) return body;
  const findings = [...env.payload.findings];
  let lo = 0;
  let hi = findings.length;
  // Binary search for the most findings that fit.
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    const trial = { ...env, payload: { ...env.payload, findings: findings.slice(0, mid), truncated: true } };
    if (Buffer.byteLength(JSON.stringify(trial)) <= MAX_BODY_BYTES) lo = mid;
    else hi = mid - 1;
  }
  body = JSON.stringify({
    ...env,
    payload: { ...env.payload, findings: findings.slice(0, lo), truncated: true },
  });
  return body;
}

/** What to do about each refusal. */
const ADVICE = {
  unauthenticated:
    "Complyd didn't accept the sign-in. Check the `trust` and `audience` inputs against Settings › Workload trusts, and that the trust isn't revoked.",
  stale_timestamp: "GitHub's sign-in token had expired. Re-run the job.",
  replayed_nonce: 'This sign-in token was already used. Re-run the job for a new one.',
  not_allowed:
    'This run may not send scans for this repository: a trust accepts only its own repositories, its default branch and the events it lists (pull request and feature-branch runs are refused).',
  stream_bound:
    "This repository's scan is linked to another trust or key. An Owner or Admin can release it or move it to this trust in Complyd.",
  out_of_order: 'Complyd already has a newer scan of this repository. Nothing to do.',
  idempotency_conflict:
    'This run attempt already sent a different scan. Re-run the job to send this one.',
  unknown_schema: 'Complyd no longer accepts this version of the action. Update it to the latest version.',
  upgrade_required: 'Complyd no longer accepts this version of the action. Update it to the latest version.',
  invalid_payload:
    "Complyd refused the scan's content. Please report this to Complyd with the action's log.",
  invalid_envelope:
    "Complyd refused the request's format (or the runner's clock is off). Please report this to Complyd with the action's log.",
  unsupported_media: "Complyd refused the request's format. Please report this to Complyd.",
  payload_too_large: 'The scan was too large to send. Please report this to Complyd.',
  rate_limited: 'Too many pushes right now. Try again later.',
  quota_exceeded: "Your workspace's daily storage for pushed data is used up. Try again tomorrow.",
  unavailable: "Complyd couldn't take the scan right now. Re-run the job in a few minutes.",
};

const KEY_UNAUTHENTICATED =
  "Complyd didn't accept the ingest key. Check COMPLYD_INGEST_KEY against Settings › Ingest keys, and that the key isn't revoked or expired.";

/** Per request; a stalled connection otherwise holds the job for minutes. */
const TIMEOUT_MS = 30_000;
const TRIES = 3;
/** Longest wait between tries, whatever Retry-After asks. */
const MAX_WAIT_S = 30;

const API_HOSTS = new Set(['api.complyd.ai', 'api-dev.complyd.ai']);
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Where the token may go: https on port 443 to exactly Complyd's API hosts.
 * Loopback (any port, http or https) only when `insecureLocal` is set, for
 * tests. Anything else is refused before a token is asked for.
 */
function allowedApiUrl(url, insecureLocal = false) {
  if (url.username || url.password) return false;
  if (insecureLocal && LOOPBACK.has(url.hostname)) return url.protocol === 'https:' || url.protocol === 'http:';
  return url.protocol === 'https:' && url.port === '' && API_HOSTS.has(url.hostname);
}

/**
 * The audience names the host the token is for: it must be one of Complyd's
 * and the same one the token is sent to, so a production token never goes to
 * the dev host (or the reverse) and no other service's token reaches Complyd.
 * Loopback `apiUrl` with `insecureLocal` (tests) is exempt.
 */
function audienceAllowed(audience, apiUrl, insecureLocal = false) {
  if (insecureLocal && LOOPBACK.has(apiUrl.hostname)) return true;
  let aud;
  try {
    aud = new URL(audience);
  } catch {
    return false;
  }
  return allowedApiUrl(aud) && aud.origin === apiUrl.origin;
}

const realSleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

/**
 * `request()` up to TRIES times: again after a network error, a timeout, a
 * 429 or a 5xx, waiting Retry-After (≤ MAX_WAIT_S) or 1 s, 2 s. An
 * ActionError from `request` is not retried. Resolves the last response;
 * after the last network failure, throws an ActionError naming `what`.
 */
async function withRetry(what, request, sleep = realSleep) {
  for (let i = 1; ; i += 1) {
    let res;
    try {
      res = await request();
    } catch (e) {
      if (e instanceof ActionError) throw e;
      if (i >= TRIES) {
        const why = e.name === 'TimeoutError' ? 'timed out' : (e.cause?.code ?? e.name);
        throw new ActionError('network', `Couldn't reach ${what} after ${TRIES} tries (${why}).`);
      }
      await sleep(2 ** (i - 1) * 1000);
      continue;
    }
    if ((res.status !== 429 && res.status < 500) || i >= TRIES) return res;
    const after = Number.parseInt(res.headers.get('retry-after') ?? '', 10);
    await sleep(Math.min(Number.isFinite(after) && after >= 0 ? after : 2 ** (i - 1), MAX_WAIT_S) * 1000);
  }
}

/**
 * Asks GitHub for an OIDC token for `audience` (the runner's token service;
 * it exists only with `permissions: id-token: write`). The token is masked
 * in the job's log (a GitHub runner reads the mask line from stdout).
 */
async function oidcToken(env, audience, fetchImpl = fetch, sleep = realSleep) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) {
    throw new ActionError(
      'oidc',
      'GitHub gave this job no sign-in token. Add `permissions: id-token: write` to the workflow or job.',
    );
  }
  const u = new URL(url);
  // The runner's request token goes there: never in clear, whatever the environment says.
  if (u.protocol !== 'https:') {
    throw new ActionError('oidc', "GitHub's token service address (ACTIONS_ID_TOKEN_REQUEST_URL) isn't https.");
  }
  u.searchParams.set('audience', audience);
  const res = await withRetry(
    "GitHub's token service",
    () =>
      fetchImpl(u, {
        headers: { Authorization: `bearer ${bearer}` },
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      }),
    sleep,
  );
  const body = res.ok ? await res.json().catch(() => null) : null;
  if (!body || typeof body.value !== 'string' || !body.value) {
    throw new ActionError('oidc', `GitHub didn't issue a sign-in token (HTTP ${res.status}).`);
  }
  if (env.GITHUB_ACTIONS === 'true') console.log(`::add-mask::${body.value}`);
  return body.value;
}

const OBSERVATION = /^obs_[A-Za-z0-9_-]{1,100}$/;
const POINTER = /^(\/[A-Za-z0-9_~.-]{0,64}){0,16}$/;

/**
 * POSTs the body with a new token per try (a token is single-use); the same
 * envelope id makes a re-post after a lost answer a duplicate, not a second
 * scan. Resolves Complyd's answer, throws an ActionError on a refusal. Only
 * known answer codes, a JSON pointer and an obs_ id are read from the answer,
 * so the server's text never reaches the job's log or outputs. `apiUrl` must
 * have passed allowedApiUrl.
 */
async function send({ apiUrl, trust, body, getToken }, fetchImpl = fetch, sleep = realSleep) {
  // An ingest key is sent without a trust header.
  const trustHeader = trust ? { 'X-Complyd-Trust': trust } : {};
  const res = await withRetry(
    `Complyd (${apiUrl.host})`,
    async () =>
      fetchImpl(new URL('/api/v1/observations', apiUrl), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${await getToken()}`,
          ...trustHeader,
        },
        body,
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      }),
    sleep,
  );
  const answer = await res.json().catch(() => ({}));
  if (res.status === 202) {
    if (!OBSERVATION.test(String(answer.observation))) {
      throw new ActionError('unavailable', `Complyd's answer had no observation id (HTTP ${res.status}).`);
    }
    return {
      observation: answer.observation,
      duplicate: answer.duplicate === true,
      unchanged: answer.unchanged === true,
    };
  }
  const code = typeof answer.error === 'string' && Object.hasOwn(ADVICE, answer.error) ? answer.error : 'unavailable';
  const pointer = typeof answer.pointer === 'string' && POINTER.test(answer.pointer) ? answer.pointer : null;
  const retry = Number.parseInt(res.headers.get('retry-after') ?? '', 10);
  const where = pointer ? ` (at ${pointer})` : '';
  const after = Number.isFinite(retry) ? ` Retry after ${retry} s.` : '';
  const advice = code === 'unauthenticated' && !trust ? KEY_UNAUTHENTICATED : ADVICE[code];
  throw new ActionError(code, `${code} (HTTP ${res.status})${where}: ${advice}${after}`);
}

module.exports = { envelope, fit, oidcToken, send, allowedApiUrl, audienceAllowed, withRetry, ADVICE, MAX_BODY_BYTES };
