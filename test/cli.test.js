'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { join } = require('path');
const { createServer } = require('http');
const { execFile } = require('child_process');
const { main, parse, options } = require('../src/cli');
const { run } = require('../src/index');

const TRUST = 'trw_11111111-1111-4111-8111-111111111111';
const AUDIENCE = `https://api.complyd.ai/observations/${TRUST}`;
const OSV = join(__dirname, 'fixtures', 'osv-scanner.json');
const CODEQL = join(__dirname, 'fixtures', 'codeql.sarif');
const SHA = 'c'.repeat(40);
const KEY = 'cing_abc123_' + 'k'.repeat(43);
const GITHUB = {
  GITHUB_REPOSITORY_ID: '123456789',
  GITHUB_SHA: 'b'.repeat(40),
  GITHUB_RUN_ID: '987654321',
  GITHUB_RUN_ATTEMPT: '2',
  ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example.test/req?api-version=2.0',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-secret',
};
const GITLAB = {
  CI_SERVER_URL: 'https://gitlab.com',
  CI_PROJECT_ID: '278964',
  CI_JOB_ID: '555',
  CI_COMMIT_SHA: SHA,
  CI_PROJECT_DIR: '/builds/acme/app',
  COMPLYD_ID_TOKEN: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwIn0.c2ln',
};

/** Serves the GitHub token service and Complyd's route (202 unless `answer` says else). */
function stub(answer = { status: 202, body: { observation: 'obs_1' } }) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    calls.push({ url: u, init });
    if (u.host === 'token.example.test') return new Response(JSON.stringify({ value: 'gh-jwt' }), { status: 200 });
    return new Response(JSON.stringify(answer.body), { status: answer.status });
  };
  return { calls, fetchImpl, posts: () => calls.filter((c) => c.init.method === 'POST'), sleep: async () => {} };
}

/** Runs the CLI in-process; resolves { code, out, err, s }. */
async function cli(argv, env, s = stub()) {
  const out = [];
  const err = [];
  const code = await main(argv, env, { ...s, now: () => new Date('2026-11-14T08:00:00Z'), out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out, err, s };
}

test('parse: the scan kind, repeated --input, the format; usage errors', () => {
  const { kind, values } = parse(['scan', 'sast', '--input', 'a.sarif', '--input', 'dir', '--format', 'sarif']);
  assert.equal(kind, 'sast');
  assert.deepEqual(values.input, ['a.sarif', 'dir']);
  assert.equal(parse(['scan', 'dependency', '--input', 'x']).values.format, 'auto');
  for (const [argv, message] of [
    [['--input', 'x'], /Name the scan/],
    [['secrets', '--input', 'x'], /Name the scan/],
    [['scan', 'dependency', 'sast', '--input', 'x'], /Name the scan/],
    [['scan', 'dependency'], /Set --input/],
    [['scan', 'dependency', '--input', 'x', '--format', 'xml'], /auto, sarif or osv/],
    [['scan', 'dependency', '--input', 'x', '--bogus'], /bogus/],
  ]) {
    assert.throws(() => parse(argv), { code: 'usage', message }, argv.join(' '));
  }
});

test('auth: --id-token-var is GitLab, --trust is GitHub, else the ingest key; each with its own subject and run key', () => {
  const opts = (argv, env) => {
    const { kind, values } = parse(['scan', 'dependency', '--input', OSV, ...argv]);
    return options(kind, values, env);
  };
  const gl = opts(['--trust', TRUST, '--id-token-var', 'COMPLYD_ID_TOKEN'], { ...GITHUB, ...GITLAB, COMPLYD_INGEST_KEY: KEY });
  assert.equal(gl.subject, 'gitlab-oidc:gitlab.com/278964');
  assert.equal(gl.runKey, 'gitlab-555');
  assert.equal(gl.trust, TRUST);
  assert.equal(gl.workspace, '/builds/acme/app');
  assert.equal(gl.apiUrl.href, 'https://api.complyd.ai/');

  const gh = opts(['--trust', TRUST, '--audience', AUDIENCE], { ...GITHUB, COMPLYD_INGEST_KEY: KEY });
  assert.equal(gh.subject, 'github:123456789');
  assert.equal(gh.runKey, '987654321-2');
  assert.equal(gh.commit, 'b'.repeat(40));

  const key = opts(['--repo', 'jenkins:acme/app', '--commit', SHA.toUpperCase(), '--run-id', 'acme » app #42'], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(key.trust, undefined);
  assert.equal(key.subject, 'jenkins:acme/app');
  assert.equal(key.commit, SHA);
  assert.match(key.runKey, /^ci-[0-9a-f]{32}$/);
  // The same build gives the same envelope id; no build id, a random one.
  assert.equal(opts(['--repo', 'jenkins:acme/app', '--run-id', 'acme » app #42'], { COMPLYD_INGEST_KEY: KEY }).runKey, key.runKey);
  // Same build number under another repository: another envelope id.
  assert.notEqual(opts(['--repo', 'jenkins:acme/other', '--run-id', 'acme » app #42'], { COMPLYD_INGEST_KEY: KEY }).runKey, key.runKey);
  assert.equal(opts(['--repo', 'r'], { COMPLYD_INGEST_KEY: KEY, CODEBUILD_BUILD_ID: 'p:1' }).runKey, opts(['--repo', 'r'], { COMPLYD_INGEST_KEY: KEY, BUILD_TAG: 'p:1' }).runKey);
  assert.notEqual(opts(['--repo', 'r'], { COMPLYD_INGEST_KEY: KEY }).runKey, opts(['--repo', 'r'], { COMPLYD_INGEST_KEY: KEY }).runKey);
});

test('auth errors, all before any request', () => {
  const opts = (argv, env) => {
    const { kind, values } = parse(['scan', 'dependency', '--input', OSV, ...argv]);
    return options(kind, values, env);
  };
  for (const [argv, env, message] of [
    [[], {}, /No sign-in/],
    [['--id-token-var', 'COMPLYD_ID_TOKEN'], GITLAB, /--trust/],
    [['--trust', 'trw_x', '--audience', AUDIENCE], GITHUB, /--trust/],
    [['--trust', TRUST, '--id-token-var', 'BAD-NAME'], GITLAB, /variable name/],
    [['--trust', TRUST, '--id-token-var', 'NOPE'], GITLAB, /no ID token in NOPE: on GitLab add it under id_tokens/],
    [['--trust', TRUST, '--id-token-var', 'COMPLYD_ID_TOKEN'], { ...GITLAB, CI_PROJECT_ID: '' }, /CI_PROJECT_ID/],
    [['--trust', TRUST, '--id-token-var', 'COMPLYD_ID_TOKEN'], { ...GITLAB, CI_JOB_ID: '' }, /CI_JOB_ID/],
    [['--trust', TRUST], GITHUB, /--audience/],
    [['--trust', TRUST, '--audience', AUDIENCE], { ...GITHUB, GITHUB_RUN_ID: '' }, /GITHUB_RUN_ID/],
    [[], { COMPLYD_INGEST_KEY: KEY }, /Set --repo .*subject prefix/],
    [['--repo', 'r'], { COMPLYD_INGEST_KEY: 'sk_live_x' }, /isn't an ingest key/],
    [['--trust', TRUST, '--id-token-var', 'CI_JOB_TOKEN'], { ...GITLAB, CI_JOB_TOKEN: 'glcbt-secret' }, /no ID token in CI_JOB_TOKEN/],
    [['--trust', TRUST, '--id-token-var', 'COMPLYD_ID_TOKEN', '--repo', 'gitlab-oidc:gitlab.com/1'], GITLAB, /Leave --repo out.*gitlab-oidc:gitlab.com\/278964/],
    [['--trust', TRUST, '--audience', AUDIENCE, '--repo', 'github:999'], GITHUB, /Leave --repo out.*github:123456789/],
    [['--repo', 'r', '--api-url', 'http://api.complyd.ai'], { COMPLYD_INGEST_KEY: KEY }, /must be https/],
    [['--repo', 'r', '--api-url', 'https://complyd.ai'], { COMPLYD_INGEST_KEY: KEY }, /must be https/],
    [['--repo', 'r', '--api-url', 'https://docs.complyd.ai'], { COMPLYD_INGEST_KEY: KEY }, /must be https/],
    [['--repo', 'r', '--api-url', 'https://api.complyd.ai:8443'], { COMPLYD_INGEST_KEY: KEY }, /must be https/],
    [['--repo', 'r', '--api-url', 'http://127.0.0.1:5130'], { COMPLYD_INGEST_KEY: KEY }, /must be https/],
    [['--repo', 'r', '--api-url', 'https://evil.example'], { COMPLYD_INGEST_KEY: KEY }, /must be https/],
    [['--trust', TRUST, '--audience', 'https://evil.example/x'], GITHUB, /must be https/],
    // The audience must name the host the token goes to.
    [['--trust', TRUST, '--audience', AUDIENCE, '--api-url', 'https://api-dev.complyd.ai'], GITHUB, /must match the audience's host/],
    [['--trust', TRUST, '--audience', 'https://api-dev.complyd.ai/x', '--api-url', 'https://api.complyd.ai'], GITHUB, /must match the audience's host/],
    [['--trust', TRUST, '--audience', 'sts.amazonaws.com', '--api-url', 'https://api.complyd.ai'], GITHUB, /must match the audience's host/],
  ]) {
    assert.throws(() => opts(argv, env), { message }, `${argv.join(' ')}`);
  }
});

test('ingest key: posts an OSV dependency scan with the key, no trust header, the same payload as the action', async () => {
  const { code, out, s } = await cli(['scan', 'dependency', '--input', OSV, '--repo', 'jenkins:acme/app', '--commit', 'b'.repeat(40), '--run-id', 'b42'], {
    COMPLYD_INGEST_KEY: KEY,
  });
  assert.equal(code, 0);
  assert.match(out.at(-1), /Stored as obs_1/);
  const [post] = s.posts();
  assert.equal(post.url.href, 'https://api.complyd.ai/api/v1/observations');
  assert.equal(post.init.headers.Authorization, `Bearer ${KEY}`);
  assert.equal(post.init.headers['X-Complyd-Trust'], undefined);
  const sent = JSON.parse(post.init.body);
  assert.match(sent.id, /^ci-[0-9a-f]{32}-dependency_scan$/);
  assert.deepEqual(sent.subject, { type: 'repository', id: 'jenkins:acme/app' });

  // The action, on the same file and commit, sends the same payload.
  const a = stub();
  await run(
    { INPUT_TRUST: TRUST, INPUT_AUDIENCE: AUDIENCE, INPUT_RESULTS: OSV, ...GITHUB },
    { fetchImpl: a.fetchImpl, now: () => new Date('2026-11-14T08:00:00Z') },
  );
  assert.deepEqual(JSON.parse(a.posts()[0].init.body).payload, sent.payload);
});

test('GitLab: posts a SARIF SAST scan with the job token and trust, salted by the GitLab subject', async () => {
  const argv = ['scan', 'sast', '--input', CODEQL, '--trust', TRUST, '--id-token-var', 'COMPLYD_ID_TOKEN', '--audience', AUDIENCE];
  const { code, s } = await cli(argv, GITLAB);
  assert.equal(code, 0);
  const [post] = s.posts();
  assert.equal(post.init.headers.Authorization, `Bearer ${GITLAB.COMPLYD_ID_TOKEN}`);
  assert.equal(post.init.headers['X-Complyd-Trust'], TRUST);
  const sent = JSON.parse(post.init.body);
  assert.equal(sent.id, 'gitlab-555-sast_scan');
  assert.equal(sent.schema, 'sast_scan');
  assert.equal(sent.subject.id, 'gitlab-oidc:gitlab.com/278964');
  assert.equal(sent.payload.commit, SHA);
  assert.equal(sent.payload.findings.length, 4);
  assert.doesNotMatch(post.init.body, /\.js|startLine|uri|snippet/);
  // The same SARIF on GitHub hashes differently (another subject, another salt).
  const gh = await cli(['scan', 'sast', '--input', CODEQL, '--trust', TRUST, '--audience', AUDIENCE], { ...GITHUB, GITHUB_SHA: SHA });
  const ghSent = JSON.parse(gh.s.posts()[0].init.body);
  assert.equal(ghSent.id, '987654321-2-sast_scan');
  assert.notDeepEqual(ghSent.payload.findings.map((f) => f.fingerprint), sent.payload.findings.map((f) => f.fingerprint));
});

test('exit codes: 1 on a refusal with advice for the key, 0 for out_of_order, 2 for usage; no server text echoed', async () => {
  const keyArgs = ['scan', 'dependency', '--input', OSV, '--repo', 'r', '--commit', SHA];
  const refused = await cli(keyArgs, { COMPLYD_INGEST_KEY: KEY }, stub({ status: 401, body: { error: 'unauthenticated' } }));
  assert.equal(refused.code, 1);
  assert.match(refused.err[0], /^error: unauthenticated \(HTTP 401\): Complyd didn't accept the ingest key/);
  const late = await cli(keyArgs, { COMPLYD_INGEST_KEY: KEY }, stub({ status: 409, body: { error: 'out_of_order' } }));
  assert.equal(late.code, 0);
  assert.match(late.err[0], /^warning: out_of_order/);
  const odd = await cli(keyArgs, { COMPLYD_INGEST_KEY: KEY }, stub({ status: 400, body: { error: 'x\nfrom-server' } }));
  assert.equal(odd.code, 1);
  assert.doesNotMatch(odd.err.join('\n'), /from-server/);
  const bad = await cli(['scan', 'dependency'], {});
  assert.equal(bad.code, 2);
  assert.equal(bad.s.calls.length, 0);
  const missing = await cli(['scan', 'dependency', '--input', '/nope.json', '--repo', 'r', '--commit', SHA], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(missing.code, 1);
  assert.match(missing.err[0], /Couldn't read the results file \(ENOENT\)/);
  assert.match((await cli(['--help'], {})).out[0], /^Usage: complyd-pipeline scan/);
  // An argument's text in a usage error can't start a workflow command on a line of its own.
  const injected = await cli(['--a\r\n::set-env name=X::1%'], {});
  assert.equal(injected.code, 2);
  assert.ok(injected.err.every((l) => !/[\r\n]/.test(l)), injected.err.join('|'));
  assert.match(injected.err[0], /^error: Unknown option '--a%0D%0A::set-env name'/);
});

test('integration: the bin posts to a local Complyd stub over http, with the ingest key', async (t) => {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      // The first try fails: the CLI retries the same envelope.
      const ok = seen.length > 1;
      res.writeHead(ok ? 202 : 503, { 'Content-Type': 'application/json', 'Retry-After': '0' });
      res.end(JSON.stringify(ok ? { observation: 'obs_local', duplicate: false, unchanged: false } : {}));
    });
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  t.after(() => server.close());
  const { port } = server.address();
  const bin = join(__dirname, '..', 'src', 'cli.js');
  const args = [bin, 'scan', 'sast', '--input', CODEQL, '--repo', 'codebuild:acme/app', '--api-url', `http://127.0.0.1:${port}`, '--insecure-local-api'];
  const { code, stdout, stderr } = await new Promise((ok) => {
    const env = { PATH: process.env.PATH, COMPLYD_INGEST_KEY: KEY, CODEBUILD_RESOLVED_SOURCE_VERSION: SHA, CODEBUILD_BUILD_ID: 'app:1234' };
    execFile(process.execPath, args, { env }, (e, stdout, stderr) => ok({ code: e ? e.code : 0, stdout, stderr }));
  });
  assert.equal(code, 0, stderr);
  assert.match(stdout, /Sent 4 findings .*\nStored as obs_local\./);
  assert.equal(seen.length, 2);
  for (const r of seen) {
    assert.equal(r.method, 'POST');
    assert.equal(r.url, '/api/v1/observations');
    assert.equal(r.headers.authorization, `Bearer ${KEY}`);
    assert.equal(r.headers['content-type'], 'application/json');
    assert.equal(r.headers['x-complyd-trust'], undefined);
  }
  assert.equal(seen[0].body, seen[1].body);
  const sent = JSON.parse(seen[1].body);
  assert.equal(sent.collector, 'complyd_ci_scan');
  assert.equal(sent.subject.id, 'codebuild:acme/app');
  assert.equal(sent.payload.commit, SHA);
  assert.match(sent.id, /^ci-[0-9a-f]{32}-sast_scan$/);
});

test('the same --repo as the token-derived subject is accepted; api-dev and :443 are allowed; loopback only with --insecure-local-api', () => {
  const opts = (argv, env) => {
    const { kind, values } = parse(['scan', 'dependency', '--input', OSV, ...argv]);
    return options(kind, values, env);
  };
  assert.equal(opts(['--trust', TRUST, '--id-token-var', 'COMPLYD_ID_TOKEN', '--repo', 'gitlab-oidc:gitlab.com/278964'], GITLAB).subject, 'gitlab-oidc:gitlab.com/278964');
  assert.equal(opts(['--repo', 'r', '--api-url', 'https://api-dev.complyd.ai:443'], { COMPLYD_INGEST_KEY: KEY }).apiUrl.host, 'api-dev.complyd.ai');
  assert.equal(opts(['--repo', 'r', '--api-url', 'http://127.0.0.1:5130', '--insecure-local-api'], { COMPLYD_INGEST_KEY: KEY }).apiUrl.port, '5130');
  assert.throws(() => opts(['--repo', 'r', '--api-url', 'https://evil.example', '--insecure-local-api'], { COMPLYD_INGEST_KEY: KEY }), /must be https/);
});

test('--input must be a regular file: a FIFO or device is refused before it is read', async () => {
  const { code, err } = await cli(['scan', 'dependency', '--input', '/dev/zero', '--repo', 'r', '--commit', SHA], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(code, 1);
  assert.match(err.join('\n'), /isn't a regular file/);
});

const CIRCLE_JOB = '0f1e2d3c-4b5a-4968-8776-655443322110';
const CIRCLE_PROJECT = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
const CIRCLECI = { CIRCLECI: 'true', CIRCLE_WORKFLOW_JOB_ID: CIRCLE_JOB, CIRCLE_SHA1: SHA, COMPLYD_ID_TOKEN: GITLAB.COMPLYD_ID_TOKEN };
const BITBUCKET = {
  BITBUCKET_BUILD_NUMBER: '7',
  BITBUCKET_REPO_UUID: '{5D3A2B1C-0F9E-4D8C-B7A6-958473625140}',
  BITBUCKET_STEP_UUID: '{11112222-3333-4444-8555-666677778888}',
  BITBUCKET_COMMIT: SHA,
  BITBUCKET_CLONE_DIR: '/opt/atlassian/pipelines/agent/build',
  BITBUCKET_STEP_OIDC_TOKEN: GITLAB.COMPLYD_ID_TOKEN,
};

test('subcommands: scan dependencies|dependency|sast|ai_eval, deploy record; anything else is a usage error', () => {
  assert.equal(parse(['scan', 'dependencies', '--input', 'x']).kind, 'dependency');
  assert.equal(parse(['scan', 'dependency', '--input', 'x']).kind, 'dependency');
  assert.equal(parse(['--input', 'x', 'scan', 'sast']).kind, 'sast');
  for (const argv of [['dependencies', '--input', 'x'], ['sast', '--input', 'x'], ['scan', '--input', 'x'], ['deploy', 'list', '--input', 'x'], ['scan', 'secrets', '--input', 'x']]) {
    assert.throws(() => parse(argv), { code: 'usage', message: /complyd-pipeline scan dependencies\|sast/ }, argv.join(' '));
  }
});

test('bin: complyd-pipeline runs from package.json, and the removed complyd-ci-scan is gone', async () => {
  const pkg = require('../package.json');
  const exec = (file, args) =>
    new Promise((ok) =>
      execFile(process.execPath, [join(__dirname, '..', file), ...args], { env: { PATH: process.env.PATH } }, (e, stdout, stderr) =>
        ok({ code: e ? e.code : 0, stdout, stderr }),
      ),
    );
  assert.deepEqual(Object.keys(pkg.bin), ['complyd-pipeline']);
  const current = await exec(pkg.bin['complyd-pipeline'], ['--version']);
  assert.deepEqual([current.code, current.stdout, current.stderr], [0, `${pkg.version}\n`, '']);
});

test('CircleCI: the token from --id-token-var, --repo circleci-oidc:<project id>, run key from the workflow job id', async () => {
  const argv = ['scan', 'dependencies', '--input', OSV, '--trust', TRUST, '--id-token-var', 'COMPLYD_ID_TOKEN'];
  const { code, s } = await cli([...argv, '--repo', `circleci-oidc:${CIRCLE_PROJECT}`], CIRCLECI);
  assert.equal(code, 0);
  const [post] = s.posts();
  assert.equal(post.init.headers.Authorization, `Bearer ${CIRCLECI.COMPLYD_ID_TOKEN}`);
  assert.equal(post.init.headers['X-Complyd-Trust'], TRUST);
  const sent = JSON.parse(post.init.body);
  assert.equal(sent.id, `circleci-${CIRCLE_JOB}-dependency_scan`);
  assert.equal(sent.subject.id, `circleci-oidc:${CIRCLE_PROJECT}`);
  assert.equal(sent.payload.commit, SHA);
  const noRepo = await cli(argv, CIRCLECI);
  assert.equal(noRepo.code, 2);
  assert.match(noRepo.err[0], /--repo to circleci-oidc:<project id>/);
  const noJob = await cli([...argv, '--repo', `circleci-oidc:${CIRCLE_PROJECT}`], { ...CIRCLECI, CIRCLE_WORKFLOW_JOB_ID: '' });
  assert.match(noJob.err[0], /CIRCLE_WORKFLOW_JOB_ID is missing/);
  // The subject must be a CircleCI project id: no other kind of subject, no other shape.
  for (const repo of ['github:123', 'circleci-oidc:x', `circleci-oidc:${CIRCLE_PROJECT}/x`, `gitlab-oidc:gitlab.com/1`]) {
    const bad = await cli([...argv, '--repo', repo], CIRCLECI);
    assert.equal(bad.code, 2, repo);
    assert.match(bad.err[0], /--repo to circleci-oidc:<project id>, the project's UUID/);
    assert.equal(bad.s.calls.length, 0);
  }
  const upper = await cli([...argv, '--repo', `circleci-oidc:${CIRCLE_PROJECT.toUpperCase()}`], CIRCLECI);
  assert.equal(JSON.parse(upper.s.posts()[0].init.body).subject.id, `circleci-oidc:${CIRCLE_PROJECT}`);
});

test('Bitbucket: BITBUCKET_STEP_OIDC_TOKEN, subject from the repository uuid without braces, run key from the step', async () => {
  const argv = ['scan', 'sast', '--input', CODEQL, '--trust', TRUST, '--id-token-var', 'BITBUCKET_STEP_OIDC_TOKEN'];
  const { code, s } = await cli(argv, BITBUCKET);
  assert.equal(code, 0);
  const sent = JSON.parse(s.posts()[0].init.body);
  assert.equal(sent.subject.id, 'bitbucket-oidc:5d3a2b1c-0f9e-4d8c-b7a6-958473625140');
  assert.equal(sent.id, 'bb-11112222-3333-4444-8555-666677778888-sast_scan');
  assert.equal(sent.payload.commit, SHA);
  assert.match((await cli([...argv, '--repo', 'bitbucket-oidc:other'], BITBUCKET)).err[0], /Leave --repo out/);
  assert.match((await cli(argv, { ...BITBUCKET, BITBUCKET_REPO_UUID: '' })).err[0], /BITBUCKET_REPO_UUID is missing/);
});

test('Azure DevOps with an ingest key: the commit from BUILD_SOURCEVERSION', () => {
  const { kind, values } = parse(['scan', 'dependencies', '--input', OSV, '--repo', 'azure-devops:acme/app', '--run-id', '42-1']);
  assert.equal(options(kind, values, { COMPLYD_INGEST_KEY: KEY, BUILD_SOURCEVERSION: SHA.toUpperCase() }).commit, SHA);
});

test('v2 flags: --scanner-version, --lockfile (only its hash is sent), --files-scanned; a warning when the scan proves nothing', async () => {
  const lock = join(__dirname, 'fixtures', 'osv-scanner.json');
  const sha = require('crypto').createHash('sha256').update(require('fs').readFileSync(lock)).digest('hex');
  const base = ['--repo', 'jenkins:acme/app', '--commit', SHA, '--run-id', 'b42'];
  const dep = await cli(['scan', 'dependencies', '--input', OSV, '--scanner-version', '2.7.1', '--lockfile', lock, ...base], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(dep.code, 0);
  const sent = JSON.parse(dep.s.posts()[0].init.body);
  assert.equal(sent.schema_version, 2);
  assert.deepEqual([sent.payload.tool, sent.payload.components, sent.payload.lockfile_sha256], [{ name: 'osv-scanner', version: '2.7.1' }, 3, sha]);
  assert.deepEqual(dep.err, []);
  const sast = await cli(['scan', 'sast', '--input', CODEQL, '--files-scanned', '42', ...base], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(JSON.parse(sast.s.posts()[0].init.body).payload.files, 42);
  // Without the version: sent, with a warning on stderr.
  const bare = await cli(['scan', 'dependencies', '--input', OSV, ...base], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(bare.code, 0);
  assert.match(bare.err.join('|'), /^warning: Complyd will read this scan as "Couldn't check".*--scanner-version/);
  // Wrong kind or value: refused before any request.
  const bad = await cli(['scan', 'sast', '--input', CODEQL, '--files-scanned', 'many', ...base], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(bad.code, 1);
  assert.equal(bad.s.posts().length, 0);
});
