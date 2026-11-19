'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { join } = require('path');
const { mkdtempSync, writeFileSync, readFileSync, truncateSync } = require('fs');
const { tmpdir } = require('os');
const { run, main, escape, MAX_RESULTS_BYTES, MAX_RESULT_FILES } = require('../src/index');
const { unprovenLine } = require('../src/scan');
const { envelope, fit, MAX_BODY_BYTES } = require('../src/post');
const { assertValid } = require('./schemas');

const TRUST = 'trw_11111111-1111-4111-8111-111111111111';
const AUDIENCE = `https://api.complyd.ai/observations/${TRUST}`;
const env = (over = {}) => ({
  INPUT_TRUST: TRUST,
  INPUT_AUDIENCE: AUDIENCE,
  INPUT_RESULTS: join(__dirname, 'fixtures', 'osv-scanner.json'),
  GITHUB_REPOSITORY_ID: '123456789',
  GITHUB_SHA: 'b'.repeat(40),
  GITHUB_RUN_ID: '987654321',
  GITHUB_RUN_ATTEMPT: '2',
  ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example.test/req?api-version=2.0',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-secret',
  ...over,
});

/** A fetch that serves the runner's token service and Complyd's route. */
const OK = { status: 202, body: { observation: 'obs_1', unchanged: false, duplicate: false } };
/**
 * A fetch that serves the runner's token service and Complyd's route; Complyd
 * answers `answers` in turn (the last one repeats), an Error is thrown.
 */
function stub(...answers) {
  if (!answers.length) answers = [OK];
  const calls = [];
  let tokens = 0;
  let posts = 0;
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    calls.push({ url: u, init });
    if (u.host === 'token.example.test') {
      tokens += 1;
      return new Response(JSON.stringify({ value: `jwt${tokens}-for-` + u.searchParams.get('audience') }), { status: 200 });
    }
    const answer = answers[Math.min(posts++, answers.length - 1)];
    if (answer instanceof Error) throw answer;
    return new Response(JSON.stringify(answer.body), { status: answer.status, headers: answer.headers ?? {} });
  };
  const waits = [];
  return { calls, fetchImpl, waits, sleep: async (ms) => void waits.push(ms) };
}

test('posts the reduced scan with the OIDC token for the trust audience', async () => {
  const { calls, fetchImpl } = stub();
  const { answer } = await run(env(), { fetchImpl, now: () => new Date('2026-11-13T08:00:00Z') });
  assert.equal(answer.observation, 'obs_1');
  const [token, post] = calls;
  assert.equal(token.url.searchParams.get('audience'), AUDIENCE);
  assert.equal(token.url.searchParams.get('api-version'), '2.0');
  assert.equal(token.init.headers.Authorization, 'bearer runner-secret');
  assert.equal(post.url.href, 'https://api.complyd.ai/api/v1/observations');
  assert.equal(post.init.headers.Authorization, `Bearer jwt1-for-${AUDIENCE}`);
  // No redirect is followed and every request has a deadline.
  for (const c of [token, post]) {
    assert.equal(c.init.redirect, 'error');
    assert.ok(c.init.signal instanceof AbortSignal);
  }
  assert.equal(post.init.headers['X-Complyd-Trust'], TRUST);
  const sent = JSON.parse(post.init.body);
  assert.deepEqual(
    { ...sent, payload: undefined },
    {
      envelope: 1,
      id: '987654321-2-dependency_scan',
      collector: 'complyd_ci_scan',
      collector_version: '1.3.0',
      schema: 'dependency_scan',
      schema_version: 2,
      observed_at: '2026-11-13T08:00:00.000Z',
      subject: { type: 'repository', id: 'github:123456789' },
      payload: undefined,
    },
  );
  assert.equal(sent.payload.commit, 'b'.repeat(40));
  assert.equal(sent.payload.findings.length, 4);
});

test('scan: sast posts a sast_scan of the run, its own envelope id, no path or line in the body', async () => {
  const { calls, fetchImpl } = stub();
  const { payload } = await run(
    env({ INPUT_SCAN: 'sast', INPUT_RESULTS: join(__dirname, 'fixtures', 'codeql.sarif') }),
    { fetchImpl, now: () => new Date('2026-11-14T08:00:00Z') },
  );
  const body = calls[1].init.body;
  const sent = JSON.parse(body);
  assert.equal(sent.id, '987654321-2-sast_scan');
  assert.equal(sent.schema, 'sast_scan');
  assert.equal(sent.collector, 'complyd_ci_scan');
  assert.deepEqual(sent.payload, payload);
  assert.deepEqual(Object.keys(sent.payload).sort(), ['commit', 'counts', 'files', 'findings', 'scanned_at', 'tool', 'truncated']);
  assert.equal(sent.schema_version, 2);
  assertValid('sast_scan.v2', sent.payload);
  assert.equal(sent.payload.findings.length, 4);
  assert.doesNotMatch(body, /\.js|services\/|web\/|scripts\/|startLine|uri|message|snippet/);
});

test('scan: sast merges several results files, a directory or a list, into one sast_scan', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sast-'));
  const real = join(__dirname, 'fixtures', 'real');
  for (const f of ['codeql-javascript.real.sarif', 'codeql-python.real.sarif']) {
    writeFileSync(join(dir, f.replace('.real', '')), readFileSync(join(real, f)));
  }
  writeFileSync(join(dir, 'notes.txt'), 'not sarif');
  const list = [join(real, 'codeql-python.real.sarif'), join(real, 'codeql-javascript.real.sarif')].join('\n');
  const sentBy = async (results) => {
    const { calls, fetchImpl } = stub();
    const { payload } = await run(env({ INPUT_SCAN: 'sast', INPUT_RESULTS: results }), {
      fetchImpl,
      now: () => new Date('2026-11-14T08:00:00Z'),
    });
    assert.equal(JSON.parse(calls[1].init.body).id, '987654321-2-sast_scan');
    return payload;
  };
  const fromDir = await sentBy(dir);
  assert.deepEqual(
    fromDir.findings.map((f) => f.rule),
    ['js/code-injection', 'py/command-line-injection', 'js/missing-rate-limiting', 'js/reflected-xss', 'js/sql-injection'],
  );
  assert.deepEqual(fromDir.counts, { critical: 2, high: 3, medium: 0, low: 0 });
  // The order of the list doesn't matter.
  assert.deepEqual(await sentBy(list), fromDir);
});

test('scan: sast results errors: an empty directory, too many files, an unreadable file; a dependency scan takes one file', async () => {
  const { calls, fetchImpl } = stub();
  const dir = mkdtempSync(join(tmpdir(), 'sast-'));
  await assert.rejects(run(env({ INPUT_SCAN: 'sast', INPUT_RESULTS: dir }), { fetchImpl }), /no \.sarif files/);
  const many = Array.from({ length: MAX_RESULT_FILES + 1 }, (_, i) => join(dir, `f${i}.sarif`)).join('\n');
  await assert.rejects(run(env({ INPUT_SCAN: 'sast', INPUT_RESULTS: many }), { fetchImpl }), /More than 50 results files/);
  await assert.rejects(
    run(env({ INPUT_SCAN: 'sast', INPUT_RESULTS: join(dir, 'missing.sarif') }), { fetchImpl }),
    /Couldn't read the results file \(ENOENT\)/,
  );
  await assert.rejects(
    run(env({ INPUT_RESULTS: `${join(__dirname, 'fixtures', 'osv-scanner.json')}\n${join(__dirname, 'fixtures', 'trivy.sarif')}` }), { fetchImpl }),
    /names one file for a dependency scan/,
  );
  assert.equal(calls.length, 0);
});

test('refuses an unknown scan kind before asking for a token', async () => {
  const { calls, fetchImpl } = stub();
  await assert.rejects(run(env({ INPUT_SCAN: 'secrets' }), { fetchImpl }), /dependencies \(default\), sast or ai_eval/);
  assert.equal(calls.length, 0);
});

test('without audience, signs in for <api-url host>/observations/<trust>; an explicit audience (rotated trust) still wins', async () => {
  for (const [over, aud, post] of [
    [{ INPUT_AUDIENCE: '' }, AUDIENCE, 'https://api.complyd.ai/api/v1/observations'],
    [{ INPUT_AUDIENCE: '', 'INPUT_API-URL': 'https://api-dev.complyd.ai' }, `https://api-dev.complyd.ai/observations/${TRUST}`, 'https://api-dev.complyd.ai/api/v1/observations'],
    [{ INPUT_AUDIENCE: 'https://api.complyd.ai/observations/trw_old' }, 'https://api.complyd.ai/observations/trw_old', 'https://api.complyd.ai/api/v1/observations'],
  ]) {
    const { calls, fetchImpl } = stub();
    await run(env(over), { fetchImpl });
    assert.equal(calls[0].url.searchParams.get('audience'), aud, JSON.stringify(over));
    assert.equal(calls[1].url.href, post);
  }
  const s = stub();
  await assert.rejects(run(env({ INPUT_AUDIENCE: '', 'INPUT_API-URL': 'https://evil.example' }), s), /must be https:\/\/api.complyd.ai/);
  assert.equal(s.calls.length, 0);
});

test('api-url must name the audience host: a production token never goes to the dev host, nor the reverse', async () => {
  const DEV = `https://api-dev.complyd.ai/observations/${TRUST}`;
  const { calls, fetchImpl } = stub();
  await run(env({ INPUT_AUDIENCE: DEV, 'INPUT_API-URL': 'https://api-dev.complyd.ai:443' }), { fetchImpl });
  assert.equal(calls[1].url.href, 'https://api-dev.complyd.ai/api/v1/observations');
  for (const over of [
    { 'INPUT_API-URL': 'https://api-dev.complyd.ai' },
    { INPUT_AUDIENCE: DEV, 'INPUT_API-URL': 'https://api.complyd.ai' },
    // Another service's audience: its token must not reach Complyd.
    { INPUT_AUDIENCE: 'sts.amazonaws.com', 'INPUT_API-URL': 'https://api.complyd.ai' },
    { INPUT_AUDIENCE: 'https://sts.amazonaws.com', 'INPUT_API-URL': 'https://api.complyd.ai' },
  ]) {
    const s = stub();
    await assert.rejects(run(env(over), s), /must match the audience's host/, JSON.stringify(over));
    assert.equal(s.calls.length, 0);
  }
});

test('says what to do on each refusal', async () => {
  const cases = [
    [{ status: 401, body: { error: 'unauthenticated' } }, /unauthenticated \(HTTP 401\): Complyd didn't accept the sign-in/],
    [{ status: 403, body: { error: 'not_allowed' } }, /default branch/],
    [{ status: 409, body: { error: 'stream_bound' } }, /linked to another trust/],
    [{ status: 400, body: { error: 'invalid_payload', pointer: '/payload/findings/3/package' } }, /at \/payload\/findings\/3\/package/],
    [{ status: 429, body: { error: 'rate_limited' }, headers: { 'Retry-After': '60' } }, /Retry after 60 s/],
    [{ status: 502, body: {} }, /unavailable \(HTTP 502\)/],
    // Only known codes and a JSON pointer are read from the answer.
    [{ status: 400, body: { error: 'x\n::notice::from-server', pointer: '/a\n::warning::b' } }, /^unavailable \(HTTP 400\): Complyd couldn't take/],
    [{ status: 400, body: { error: '__proto__' } }, /^unavailable \(HTTP 400\)/],
  ];
  for (const [answer, message] of cases) {
    await assert.rejects(run(env(), stub(answer)), { message });
  }
  await assert.rejects(run(env(), stub({ status: 202, body: { observation: 'obs_1\nfoo=bar' } })), /no observation id/);
});

test('needs id-token: write, a trust id and a results file', async () => {
  await assert.rejects(run(env({ ACTIONS_ID_TOKEN_REQUEST_URL: '' }), stub()), /permissions: id-token: write/);
  await assert.rejects(run(env({ INPUT_TRUST: 'abc' }), stub()), /trw_/);
  await assert.rejects(run(env({ INPUT_RESULTS: '/nope.json' }), stub()), /Couldn't read the results file \(ENOENT\)/);
  await assert.rejects(run(env({ GITHUB_REPOSITORY_ID: '' }), stub()), /only in GitHub Actions/);
  await assert.rejects(run(env({ GITHUB_RUN_ID: '' }), stub()), /GITHUB_RUN_ID/);
});

test("a results file that isn't JSON: its bytes are never echoed", async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pipeline-action-'));
  const file = join(dir, 'secrets.txt');
  writeFileSync(file, 'AWS_SECRET_ACCESS_KEY=abc');
  await assert.rejects(run(env({ INPUT_RESULTS: file }), stub()), (e) => {
    assert.equal(e.message, "Couldn't read the results file (it isn't JSON).");
    return true;
  });
});

test('a results file over the size cap is refused before it is read', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pipeline-action-'));
  const file = join(dir, 'big.json');
  writeFileSync(file, '');
  truncateSync(file, MAX_RESULTS_BYTES + 1); // sparse: no 50 MB written
  await assert.rejects(run(env({ INPUT_RESULTS: file }), stub()), /over 50 MB/);
});

test('the token only goes to Complyd over https (its API hosts only), asked for only then', async () => {
  for (const over of [
    { INPUT_AUDIENCE: `http://api.complyd.ai/observations/${TRUST}` },
    { INPUT_AUDIENCE: `https://evil.example/observations/${TRUST}` },
    { INPUT_AUDIENCE: `https://complyd.ai.evil.example/observations/${TRUST}` },
    { 'INPUT_API-URL': 'http://api.complyd.ai' },
    { 'INPUT_API-URL': 'https://user:pw@api.complyd.ai' },
    { 'INPUT_API-URL': 'http://10.0.0.1:8080' },
    { 'INPUT_API-URL': 'http://127.0.0.1:5130' },
    { 'INPUT_API-URL': 'https://docs.complyd.ai' },
    { 'INPUT_API-URL': 'https://complyd.ai' },
    { 'INPUT_API-URL': 'https://api.complyd.ai:8443' },
  ]) {
    const s = stub();
    await assert.rejects(run(env(over), s), /must be https:\/\/api.complyd.ai/);
    assert.equal(s.calls.length, 0, JSON.stringify(over));
  }
  const s = stub();
  await run(env({ INPUT_AUDIENCE: `https://api-dev.complyd.ai/observations/${TRUST}` }), s);
  assert.equal(s.calls[1].url.host, 'api-dev.complyd.ai');
  // The runner's request token goes to its token service over https only.
  const t = stub();
  await assert.rejects(run(env({ ACTIONS_ID_TOKEN_REQUEST_URL: 'http://token.example.test/req' }), t), /ACTIONS_ID_TOKEN_REQUEST_URL\) isn't https/);
  assert.equal(t.calls.length, 0);
});

test('retries a 5xx, a 429 and a network error with backoff, a new token per try, the same envelope id', async () => {
  const s = stub({ status: 503, body: {} }, { status: 429, body: {}, headers: { 'Retry-After': '120' } }, OK);
  const { answer } = await run(env(), s);
  assert.equal(answer.observation, 'obs_1');
  const posts = s.calls.filter((c) => c.init.method === 'POST');
  assert.equal(posts.length, 3);
  assert.deepEqual(posts.map((p) => p.init.headers.Authorization.slice(0, 11)), ['Bearer jwt1', 'Bearer jwt2', 'Bearer jwt3']);
  assert.equal(new Set(posts.map((p) => JSON.parse(p.init.body).id)).size, 1);
  // 1 s, then Retry-After capped at 30 s.
  assert.deepEqual(s.waits, [1000, 30_000]);

  const down = stub(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } }));
  await assert.rejects(run(env(), down), { code: 'network', message: /Couldn't reach Complyd \(api.complyd.ai\) after 3 tries \(ECONNRESET\)/ });
  assert.deepEqual(down.waits, [1000, 2000]);

  const late = stub({ status: 502, body: {} });
  await assert.rejects(run(env(), late), /unavailable \(HTTP 502\)/);
  assert.equal(late.calls.filter((c) => c.init.method === 'POST').length, 3);

  // A refusal is not retried.
  const no = stub({ status: 401, body: { error: 'unauthenticated' } });
  await assert.rejects(run(env(), no), /unauthenticated/);
  assert.equal(no.calls.length, 2);
});

test('main: escapes every command line and output, masks the token, warns about dropped findings', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pipeline-action-'));
  const output = join(dir, 'out');
  writeFileSync(output, '');
  const logs = [];
  const log = console.log;
  const realFetch = globalThis.fetch;
  console.log = (line) => logs.push(line);
  try {
    // A refusal whose code isn't known: no second command can appear.
    globalThis.fetch = stub({ status: 400, body: { error: 'x\n::notice::from-server' } }).fetchImpl;
    await main(env({ GITHUB_OUTPUT: output, GITHUB_ACTIONS: 'true' }));
    assert.equal(process.exitCode, 1);
    process.exitCode = 0;
    assert.ok(logs.every((l) => !l.includes('\n')), logs.join('|'));
    assert.ok(logs.some((l) => /^::add-mask::jwt1-for-/.test(l)));
    assert.match(logs.at(-1), /^::error::unavailable \(HTTP 400\)/);

    logs.length = 0;
    globalThis.fetch = stub().fetchImpl;
    await main(env({ GITHUB_OUTPUT: output, INPUT_RESULTS: join(__dirname, 'fixtures', 'trivy.sarif') }));
    assert.ok(logs.some((l) => /^::warning::Not sent: 1 findings the action couldn't read \(no usable package name 1\): CVE-2024-0002\./.test(l)), logs.join('|'));
    assert.equal(readFileSync(output, 'utf8'), 'observation=obs_1\ndropped=1\n');
    assert.ok(!logs.some((l) => /Couldn't check/.test(l)), logs.join('|'));

    // OSV-Scanner JSON names no version: Complyd won't count it as a scan that ran.
    logs.length = 0;
    await main(env());
    assert.ok(logs.some((l) => /^::warning::Complyd will read this scan as "Couldn't check".*set scanner-version/.test(l)), logs.join('|'));
  } finally {
    console.log = log;
    globalThis.fetch = realFetch;
  }
  assert.equal(escape('a%b\r\nc'), 'a%25b%0D%0Ac');
});

test('fits the body under 64 KiB, cutting the least severe findings first', () => {
  const findings = Array.from({ length: 500 }, (_, i) => ({
    advisory: `GHSA-${String(i).padStart(4, '0')}-aaaa-bbbb`,
    ecosystem: 'Maven',
    package: `org.example.very.long.group.name:artifact-with-a-long-name-${i}`,
    version: '1.0.0-SNAPSHOT',
    severity: i < 10 ? 'critical' : 'low',
    fixed_in: '1.0.1',
  }));
  const env1 = envelope(
    { tool: { name: 'x', version: '1' }, commit: 'a'.repeat(40), scanned_at: 't', counts: {}, findings, truncated: false },
    { id: '1-1-dependency_scan', subject: 'github:1', observedAt: 't' },
  );
  const body = fit(env1);
  assert.ok(Buffer.byteLength(body) <= MAX_BODY_BYTES);
  const sent = JSON.parse(body).payload;
  assert.equal(sent.truncated, true);
  assert.ok(sent.findings.length > 300 && sent.findings.length < 500);
  assert.equal(sent.findings[9].severity, 'critical');
});

test('scan: empty, dependency (1.0) and dependencies all send a dependency_scan; the wire collector stays complyd_ci_scan', async () => {
  for (const kind of ['', 'dependency', 'dependencies']) {
    const { calls, fetchImpl } = stub();
    await run(env({ INPUT_SCAN: kind }), { fetchImpl });
    const sent = JSON.parse(calls.at(-1).init.body);
    assert.equal(sent.schema, 'dependency_scan', kind);
    assert.equal(sent.id, '987654321-2-dependency_scan');
    // Complyd's registry knows the collector by this id; the tool's new name is not sent.
    assert.equal(sent.collector, 'complyd_ci_scan');
    assert.equal(sent.collector_version, require('../package.json').version);
  }
  // Inherited object keys are not scan kinds.
  for (const kind of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
    const s = stub();
    await assert.rejects(run(env({ INPUT_SCAN: kind }), s), /dependencies \(default\), sast or ai_eval/, kind);
    assert.equal(s.calls.length, 0);
  }
});

test('v2 dependency scan: the lockfile hash (input, else the one the scanner names), scanner-version; valid under Complyd\'s schema', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'complyd-lock-'));
  const lock = join(dir, 'package-lock.json');
  writeFileSync(lock, '{"lockfileVersion":3}\n');
  const sha = require('crypto').createHash('sha256').update('{"lockfileVersion":3}\n').digest('hex');
  const empty = join(dir, 'osv-empty.json');
  writeFileSync(empty, JSON.stringify({ results: [] }));
  const send = async (over) => {
    const { calls, fetchImpl } = stub();
    const r = await run(env(over), { fetchImpl });
    return { ...r, sent: JSON.parse(calls[1].init.body).payload };
  };
  // Clean OSV-Scanner run, lockfile and version given: proves it ran.
  const a = await send({ INPUT_RESULTS: empty, INPUT_LOCKFILE: lock, 'INPUT_SCANNER-VERSION': '2.7.1' });
  assert.deepEqual([a.sent.tool, a.sent.components, a.sent.lockfile_sha256], [{ name: 'osv-scanner', version: '2.7.1' }, 0, sha]);
  assert.equal(a.unproven, null);
  assertValid('dependency_scan.v2', a.sent);
  // No input: the lockfile the scanner's output names, relative to the workspace.
  const named = join(dir, 'osv-named.json');
  writeFileSync(named, JSON.stringify({ results: [{ source: { path: 'package-lock.json', type: 'lockfile' }, packages: [] }] }));
  const b = await send({ INPUT_RESULTS: named, GITHUB_WORKSPACE: dir, 'INPUT_SCANNER-VERSION': '2.7.1' });
  assert.equal(b.sent.lockfile_sha256, sha);
  // Not on disk (another machine's path): null, and the step warns it proves nothing.
  const c = await send({ INPUT_RESULTS: empty });
  assert.equal(c.sent.lockfile_sha256, null);
  assert.match(c.unproven, /Couldn't check.*version "unknown".*no package read/);
  assertValid('dependency_scan.v2', c.sent);
  // A lockfile input that can't be read fails before any request.
  const { calls, fetchImpl } = stub();
  await assert.rejects(run(env({ INPUT_LOCKFILE: join(dir, 'missing.lock') }), { fetchImpl }), /Couldn't read the lockfile/);
  await assert.rejects(run(env({ INPUT_LOCKFILE: dir }), { fetchImpl }), /Couldn't read the lockfile/);
  await assert.rejects(run(env({ 'INPUT_SCANNER-VERSION': '2.7.1; rm' }), { fetchImpl }), /scanner version/);
  await assert.rejects(run(env({ 'INPUT_FILES-SCANNED': '3' }), { fetchImpl }), /for a SAST scan/);
  await assert.rejects(run(env({ INPUT_SCAN: 'sast', INPUT_RESULTS: join(__dirname, 'fixtures', 'codeql.sarif'), 'INPUT_FILES-SCANNED': '-1' }), { fetchImpl }), /whole number/);
  await assert.rejects(run(env({ INPUT_SCAN: 'sast', INPUT_RESULTS: join(__dirname, 'fixtures', 'codeql.sarif'), INPUT_LOCKFILE: lock }), { fetchImpl }), /dependency scan/);
  assert.equal(calls.filter((x) => x.url.host === 'api.complyd.ai').length, 0);
});

test('unproven: mirrors Complyd\'s rule (known scanner, version number, packages or lockfile; SAST files)', () => {
  const dep = (over) => ({ tool: { name: 'osv-scanner', version: '2.7.1' }, findings: [], components: 5, lockfile_sha256: null, ...over });
  assert.equal(unprovenLine('dependency', dep()), null);
  assert.equal(unprovenLine('dependency', dep({ tool: { name: 'Trivy', version: 'v0.57.0' } })), null);
  assert.equal(unprovenLine('dependency', dep({ components: 0, lockfile_sha256: 'e'.repeat(64) })), null);
  assert.match(unprovenLine('dependency', dep({ tool: { name: 'my-script', version: '1.0' } })), /doesn't know the scanner "my-script"/);
  assert.match(unprovenLine('dependency', dep({ tool: { name: 'grype', version: 'dev' } })), /version "dev"/);
  assert.match(unprovenLine('dependency', dep({ components: 0 })), /no package read/);
  const f = { ecosystem: 'npm', package: 'a' };
  assert.match(unprovenLine('dependency', dep({ components: 1, findings: [f, { ...f, package: 'b' }] })), /no package read/);
  // A lockfile hash doesn't stand in for packages a scan lists but didn't count.
  assert.match(unprovenLine('dependency', dep({ components: 0, findings: [f], lockfile_sha256: 'e'.repeat(64) })), /no package read/);
  const sast = (over) => ({ tool: { name: 'Semgrep OSS', version: '1.95.0' }, findings: [], files: 3, ...over });
  assert.equal(unprovenLine('sast', sast()), null);
  assert.match(unprovenLine('sast', sast({ files: 0 })), /files-scanned/);
  assert.match(unprovenLine('sast', sast({ tool: { name: 'osv-scanner', version: '1.0.0' } })), /doesn't know/);
});

