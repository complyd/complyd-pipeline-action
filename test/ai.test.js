'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { join } = require('path');
const { createHash } = require('crypto');
const { execFileSync, spawnSync } = require('child_process');
const { mkdtempSync, writeFileSync, readFileSync, mkdirSync, cpSync, symlinkSync } = require('fs');
const { tmpdir } = require('os');
const { parseYaml } = require('../src/yaml');
const { parseConfig, loadConfig, hashFiles, repoConfig, ownerOf, globMatch, schemaVersion } = require('../src/ai-config');
const { PARSERS, FORMATS, buildPayload, fitSuites, decimal, providerModel, aiEnvelopeId } = require('../src/ai-eval');
const { envelope, MAX_BODY_BYTES } = require('../src/post');
const { deployRecord, sections, splitModel } = require('../src/ai-release');
const { main } = require('../src/cli');
const { run } = require('../src/index');
const { assertValid, errorsOf } = require('./schemas');

const AI = join(__dirname, 'fixtures', 'ai');
const REPO = join(AI, 'repo');
const SHA = 'c'.repeat(40);
const KEY = 'cing_abc123_' + 'k'.repeat(43);
const TRUST = 'trw_11111111-1111-4111-8111-111111111111';
const sha = (b) => createHash('sha256').update(b).digest('hex');
const fixture = (f) => JSON.parse(readFileSync(join(AI, `${f}.json`), 'utf8'));
const config = () => parseConfig(readFileSync(join(REPO, '.complyd', 'ai.yml'), 'utf8'));
const payloadOf = (format, role = 'candidate') =>
  buildPayload(PARSERS[format](fixture(format)), config(), { format, role, commit: SHA, runId: 'gitlab-555', ranAt: '2026-11-19T08:00:00.000Z', root: REPO });

/** A valid ai_eval payload under the version it needs (Complyd's schema files); v3 takes every v2 payload too. */
const assertSchema = (p) => {
  assertValid(`ai_eval.v${schemaVersion(p)}`, p);
  assertValid('ai_eval.v3', p);
};
/** repo_config: names, globs, required flags and decimal thresholds only. */
const assertRepoConfig = (r) => assertValid('ai_eval.v2#/$defs/repo_config', r);

test('yaml: the subset ai.yml uses', () => {
  const doc = parseYaml(`# c
version: 1
a: "x # not a comment" # comment
b: [one, "two, three", 4]
c: { k: v, n: 0.5 }
list:
  - p/one.txt
  - name: s
    deep:
      x: true
nested:
- item
empty:
`);
  assert.deepEqual(doc, {
    version: 1,
    a: 'x # not a comment',
    b: ['one', 'two, three', 4],
    c: { k: 'v', n: 0.5 },
    list: ['p/one.txt', { name: 's', deep: { x: true } }],
    nested: ['item'],
    empty: null,
  });
});

test('yaml: refuses what it would read wrongly, naming the line', () => {
  for (const [text, message] of [
    ['a: 1\n\tb: 2', /line 2: indent with spaces/],
    ['a: &x 1', /line 1: .*anchors/],
    ['a: |\n  text', /line 1: block text/],
    ['a: 1\na: 2', /line 2: "a" is listed twice/],
    ['a: 1\n   b: 2', /line 2: unexpected indentation/],
    ['a: [1, [2]]', /nested/],
    ['a: "open', /not closed/],
    ['a: 1\n---\nb: 2', /one document/],
  ]) {
    assert.throws(() => parseYaml(text), { message }, text);
  }
});

test('config: the fixture loads; errors say what to fix', () => {
  const cfg = config();
  assert.equal(cfg.suites.length, 3);
  assert.equal(cfg.suites[0].required, true);
  assert.deepEqual(cfg.suites[0].metrics.pass_rate, { threshold: { value: 0.9, direction: 'gte' }, category: 'unsafe_compliance' });
  assert.deepEqual(cfg.suites[1].prompts, ['prompts/support.txt']);
  for (const [text, message] of [
    ['suites: []', /version: set version: 1.*suites: list your eval suites/],
    ['version: 1\nsuites:\n  - name: a', /suites\[0\].prompts: list the prompt files/],
    ['version: 1\nprompts: [../x]\nsuites:\n  - name: a', /prompts\[0\]: "..\/x" must be relative/],
    ['version: 1\nprompts: [/etc/passwd]\nsuites:\n  - name: a', /must be relative/],
    ['version: 1\nprompts: [p]\nsuites:\n  - name: a\n    metrics:\n      x: { gte: 1, lte: 2 }', /metrics.x: set gte: or lte:, not both/],
    ['version: 1\nprompts: [p]\nsuites:\n  - name: a\n    test_set: { selection: random }', /selection: use one of production_sample/],
    ['version: 1\nprompts: [p]\nsuites:\n  - name: a\n    dataset: nope', /dataset: name one of the datasets/],
    ['version: 1\nprompts: [p]\nsuites:\n  - name: a\n    model: { provider: OpenAI, id: x }', /model.provider: use letters/],
    ['version: 1\nprompts: [p]\nsuites:\n  - name: a\n  - name: a', /"a" is used by two suites/],
    ['version: 1\nprompts: [p]\npromts: [q]\nsuites:\n  - name: a', /promts: unknown key/],
    ['version: 1\nprompts: [p]\nsuites:\n  - name: a\n    test_set: {}', /test_set.version: set the test set version/],
    ['version: 1\na: b: c', /Fix .complyd\/ai.yml/],
  ]) {
    assert.throws(() => parseConfig(text), { code: 'config', message }, text);
  }
});

test('hashing: one file is its own SHA-256; several are sha256sum lines sorted by path', () => {
  const prompt = readFileSync(join(REPO, 'prompts', 'support.txt'));
  assert.equal(hashFiles(REPO, ['prompts/support.txt'], 'x'), sha(prompt));
  const rubric = readFileSync(join(REPO, 'evals', 'rubric.md'));
  assert.equal(
    hashFiles(REPO, ['prompts/support.txt', 'evals/rubric.md'], 'x'),
    sha(`${sha(rubric)}  evals/rubric.md\n${sha(prompt)}  prompts/support.txt\n`),
  );
  assert.throws(() => hashFiles(REPO, ['nope.txt'], 'suites[0].prompts'), { code: 'config', message: /suites\[0\].prompts: couldn't read nope.txt/ });
  const p = payloadOf('promptfoo');
  assert.equal(p.suites[0].prompt_sha256, sha(prompt));
  assert.equal(p.suites[0].dataset.sha256, sha(readFileSync(join(REPO, 'evals', 'data', 'refusals.jsonl'))));
  assert.equal(p.suites[0].evaluator.rubric_sha256, sha(rubric));
});

test('decimal strings and provider ids', () => {
  assert.equal(decimal(0.94), '0.94');
  assert.equal(decimal(10), '10');
  assert.equal(decimal(1 / 3), '0.333333333');
  assert.equal(decimal(-0.0000000001), '0');
  assert.equal(decimal(1e12), undefined);
  assert.equal(decimal(NaN), undefined);
  assert.deepEqual(providerModel('openai:chat:gpt-4o'), { provider: 'openai', id: 'gpt-4o' });
  assert.deepEqual(providerModel('bedrock:meta.llama3-70b'), { provider: 'bedrock', id: 'meta.llama3-70b' });
  for (const p of ['file://provider.py', 'https://api.example.com/v1?key=secret', 'python:grader.py', 'nocolon']) assert.equal(providerModel(p), undefined, p);
});

test('promptfoo: one suite per prompt × provider, pass rate and named scores', () => {
  const p = payloadOf('promptfoo');
  assertSchema(p);
  assert.deepEqual(p.tool, { name: 'promptfoo', version: '0.112.3' });
  assert.equal(p.ran_at, '2026-11-18T10:21:04.512Z');
  assert.deepEqual(p.suites.map((s) => `${s.name} ${s.model.provider}/${s.model.id}`), ['safety-refusals openai/gpt-4o-mini', 'safety-refusals mistral/mistral-large-latest']);
  const [a, b] = p.suites;
  assert.deepEqual(a.cases, { total: 50, passed: 47, failed: 2, errored: 1 });
  assert.equal(a.passed, false);
  assert.deepEqual(a.metrics[0], { name: 'pass_rate', category: 'unsafe_compliance', value: '0.94', threshold: { value: '0.9', direction: 'gte' }, passed: true });
  assert.deepEqual(a.metrics.slice(1).map((m) => [m.name, m.value]), [['refusal', '0.93'], ['tone -polite-', '0.88']]);
  assert.equal(b.passed, true);
  assert.deepEqual(a.test_set, { version: '4', cases: 50, selection: 'curated' });
  assert.deepEqual(a.evaluator.parser, 'llm-rubric');
  // The fixture's tokenUsage has no numRequests: tokens and cost only; the second prompt reports none.
  assert.deepEqual(a.usage, { input_tokens: 40011, output_tokens: 10200, cost_usd: '0.0412' });
  assert.equal(Object.hasOwn(b, 'usage'), false);
  assert.equal(schemaVersion(p), 3);
});

test('deepeval: metrics averaged over cases; Toxicity is lower-is-better; the judge from the file', () => {
  const p = payloadOf('deepeval');
  assertSchema(p);
  const [s] = p.suites;
  assert.equal(s.name, 'answer-quality');
  assert.deepEqual(s.model, { provider: 'openai', id: 'gpt-4o-mini' });
  assert.deepEqual(s.cases, { total: 3, passed: 2, failed: 1, errored: 0 });
  const rel = s.metrics.find((m) => m.name === 'Answer Relevancy');
  // Mean 0.71 meets 0.7, but one case failed it: the runner's verdict stands.
  assert.deepEqual(rel, { name: 'Answer Relevancy', value: '0.71', threshold: { value: '0.7', direction: 'gte' }, passed: false });
  assert.deepEqual(s.metrics.find((m) => m.name === 'Toxicity').threshold, { value: '0.5', direction: 'lte' });
  assert.equal(s.evaluator.judge_model, 'gpt-4o');
  assert.equal(s.evaluator.version, 'deepeval-unknown');
  assert.equal(s.passed, false);
});

test('openai-evals: result counts and per-criteria pass rates', () => {
  const p = payloadOf('openai-evals');
  assertSchema(p);
  const [s] = p.suites;
  assert.equal(p.ran_at, '2026-11-18T10:00:00.000Z');
  assert.deepEqual(s.model, { provider: 'openai', id: 'gpt-4o-mini' });
  assert.deepEqual(s.cases, { total: 50, passed: 47, failed: 3, errored: 0 });
  assert.deepEqual(s.metrics.map((m) => [m.name, m.value, m.passed]), [['pass_rate', '0.94', true], ['refuses-cross-account-6f1a2b', '0.94', false]]);
  assert.deepEqual(s.usage, { calls: 50, input_tokens: 5500, output_tokens: 1200, cached_input_tokens: 0 });
  assert.throws(() => PARSERS['openai-evals']({ object: 'eval' }), { code: 'results' });
});

test('lm-eval: one suite per task, no case verdicts, samples as the test set size', () => {
  const p = payloadOf('lm-eval');
  assertSchema(p);
  const [s] = p.suites;
  assert.equal(p.tool.version, '0.4.8');
  assert.deepEqual(s.model, { provider: 'hf', id: 'acme/support-7b', version: '2026-10-01' });
  assert.deepEqual(s.cases, { total: 0, passed: 0, failed: 0, errored: 0 });
  assert.equal(s.test_set.cases, 1000);
  assert.deepEqual(s.metrics.map((m) => m.name), ['acc_norm', 'acc']);
  assert.equal(s.passed, true);
});

test('generic: the documented shape; a decimal string value; matched by name', () => {
  const p = payloadOf('generic', 'baseline');
  assertSchema(p);
  const [s] = p.suites;
  assert.equal(s.role, 'baseline');
  assert.deepEqual(s.model, { provider: 'acme', id: 'support-large', version: '3' });
  assert.deepEqual(s.metrics[1], { name: 'latency_p95_ms', value: '812.5', threshold: { value: '1500', direction: 'lte' }, passed: true });
});

test('minimisation: no prompt, output, case, rubric or dataset text in any envelope', () => {
  const secret = [
    readFileSync(join(REPO, 'prompts', 'support.txt'), 'utf8'),
    readFileSync(join(REPO, 'evals', 'rubric.md'), 'utf8'),
    readFileSync(join(REPO, 'evals', 'data', 'refusals.jsonl'), 'utf8'),
  ];
  for (const format of FORMATS) {
    const text = JSON.stringify(payloadOf(format));
    assert.ok(readFileSync(join(AI, `${format}.json`), 'utf8').includes('CANARY'), `${format} fixture has canaries`);
    assert.doesNotMatch(text, /CANARY/, format);
    for (const s of secret) assert.ok(!text.includes(s.trim().slice(0, 30)), format);
    assert.doesNotMatch(text, /invoices|ships tomorrow|bob@example/i, format);
  }
});

test("minimisation: an unlabelled promptfoo prompt's text is not echoed in the error", () => {
  const doc = fixture('promptfoo');
  doc.results.prompts[0].label = 'You are CANARY-PROMPT-SYSTEM, answer {{question}}';
  const cfg = parseConfig('version: 1\nprompts: [prompts/support.txt]\nsuites:\n  - name: a\n    test_set: { version: "1" }\n  - name: b\n    test_set: { version: "1" }');
  assert.throws(
    () => buildPayload(PARSERS.promptfoo(doc), cfg, { format: 'promptfoo', role: 'candidate', commit: SHA, runId: 'x', ranAt: 'x', root: REPO }),
    (e) => e.code === 'config' && /#1 \(unnamed\)/.test(e.message) && !/CANARY/.test(e.message),
  );
});

test('a thresholded metric missing from the results fails the suite, with a warning', () => {
  const cfg = parseConfig('version: 1\nprompts: [prompts/support.txt]\nsuites:\n  - name: a\n    test_set: { version: "1" }\n    metrics:\n      jailbreak_rate: { lte: 0.01 }');
  const warnings = [];
  const p = buildPayload(PARSERS.generic(fixture('generic')), cfg, { format: 'generic', role: 'candidate', commit: SHA, runId: 'x', ranAt: '2026-11-19T08:00:00.000Z', root: REPO, warn: (w) => warnings.push(w) });
  assert.equal(p.suites[0].passed, false);
  assert.ok(warnings.some((w) => /jailbreak_rate .* isn't in the results/.test(w)), warnings.join('\n'));
});

test('envelope ids: under the route limit for every CI, distinct for baseline and candidate', () => {
  const circle = `circleci-${'f'.repeat(8)}-ffff-4fff-8fff-${'f'.repeat(12)}`;
  for (const runKey of ['987654321-2', 'gitlab-12345678901234567890', circle, `ci-${'a'.repeat(32)}`]) {
    assert.match(aiEnvelopeId(runKey, 'candidate', 'promptfoo', 'r.json'), /^[A-Za-z0-9_-]{16,64}$/);
  }
  assert.notEqual(aiEnvelopeId('1-1', 'candidate', 'promptfoo', 'r.json'), aiEnvelopeId('1-1', 'baseline', 'promptfoo', 'r.json'));
});

/** Runs the CLI in-process with a stub Complyd; resolves { code, out, err, posts }. */
async function cli(argv, env = {}) {
  const out = [];
  const err = [];
  const posts = [];
  const fetchImpl = async (url, init) => {
    posts.push({ url: new URL(url), init });
    return new Response(JSON.stringify({ observation: 'obs_1' }), { status: 202 });
  };
  const code = await main(argv, env, { fetchImpl, sleep: async () => {}, now: () => new Date('2026-11-19T08:00:00Z'), out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out, err, posts };
}

test('CLI scan ai_eval --dry-run: prints the envelope, sends nothing, needs no sign-in', async () => {
  const r = await cli(['scan', 'ai_eval', '--format', 'promptfoo', '--input', join(AI, 'promptfoo.json'), '--workspace', REPO, '--commit', SHA, '--dry-run']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.posts.length, 0);
  const env = JSON.parse(r.out.join('\n'));
  assert.equal(env.collector, 'complyd_ai_release');
  assert.equal(env.schema, 'ai_eval');
  // promptfoo reports usage: v3.
  assert.equal(env.schema_version, 3);
  assertSchema(env.payload);
});

test('CLI scan ai_eval with an ingest key: posts ai_eval v1 as complyd_ai_release', async () => {
  const r = await cli(['scan', 'ai_eval', '--format', 'openai-evals', '--input', join(AI, 'openai-evals.json'), '--workspace', REPO, '--repo', 'jenkins:acme/app', '--commit', SHA, '--run-id', 'b42', '--role', 'baseline'], { COMPLYD_INGEST_KEY: KEY });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.posts.length, 1);
  const body = JSON.parse(r.posts[0].init.body);
  assert.equal(body.collector, 'complyd_ai_release');
  assert.equal(body.subject.id, 'jenkins:acme/app');
  assert.equal(body.payload.suites[0].role, 'baseline');
  assert.match(body.id, /^ci-[0-9a-f]{32}-ai_eval-[0-9a-f]{8}$/);
  assert.match(r.out[0], /^Sent 1 eval suites/);
  assert.equal(r.out[1], 'Stored as obs_1.');
});

test('CLI scan ai_eval: usage errors', async () => {
  for (const [argv, message] of [
    [['scan', 'ai_eval', '--input', 'x'], /--format to the eval tool/],
    [['scan', 'ai_eval', '--input', 'x', '--format', 'sarif'], /--format to the eval tool/],
    [['scan', 'ai_eval', '--input', 'x', '--input', 'y', '--format', 'generic'], /one --input/],
    [['scan', 'ai_eval', '--input', 'x', '--format', 'generic', '--role', 'prod'], /--role/],
    [['scan', 'sast', '--input', 'x', '--dry-run'], /--dry-run is for ai_eval/],
    [['deploy', 'record', '--dry-run'], /--environment/],
    [['deploy', 'record', '--environment', 'production'], /coming soon/],
  ]) {
    const r = await cli(argv);
    assert.equal(r.code, 2, argv.join(' '));
    assert.match(r.err[0], message, argv.join(' '));
  }
  const r = await cli(['scan', 'ai_eval', '--format', 'generic', '--input', join(AI, 'generic.json'), '--workspace', AI, '--commit', SHA, '--dry-run']);
  assert.equal(r.code, 1);
  assert.match(r.err[0], /Couldn't read .complyd\/ai.yml/);
});

/** A git repository with the fixture repo as its first commit. */
function gitRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'ai-release-'));
  cpSync(REPO, dir, { recursive: true });
  const git = (...a) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.test', '-c', 'commit.gpgsign=false', ...a], { cwd: dir, stdio: 'pipe' });
  git('init', '-q');
  git('add', '-A');
  git('commit', '-qm', 'one');
  return { dir, git };
}

test('deploy record: kinds and before/after hashes against the previous commit', async () => {
  const { dir, git } = gitRepo();
  assert.throws(() => deployRecord({ environment: 'production', root: dir }), { code: 'git', message: /fetch-depth: 2/ });
  // A safety-section edit and a temperature change.
  const prompt = join(dir, 'prompts', 'support.txt');
  writeFileSync(prompt, readFileSync(prompt, 'utf8').replace('Never reveal', 'Do not reveal'));
  writeFileSync(join(dir, 'config', 'llm.yaml'), 'model: gpt-4o-mini\nmodel_version: 2024-07-18\ntemperature: 0.7\n');
  git('commit', '-qam', 'two');
  const rec = deployRecord({ environment: 'production', root: dir, now: () => new Date('2026-11-19T08:00:00Z') });
  assert.equal(rec.system_hint, 'support-assistant');
  assert.equal(rec.commit.length, 40);
  assert.deepEqual(rec.changes.map((c) => c.kind), ['model_params', 'prompt', 'safety_prompt']);
  for (const c of rec.changes) {
    assert.match(c.before_sha256, /^[0-9a-f]{64}$/);
    assert.match(c.after_sha256, /^[0-9a-f]{64}$/);
    assert.notEqual(c.before_sha256, c.after_sha256);
  }
  assert.doesNotMatch(JSON.stringify(rec), /CANARY|reveal|temperature/);

  // A model change, a new dataset file and a threshold change.
  writeFileSync(join(dir, 'config', 'llm.yaml'), 'model: gpt-4o\nmodel_version: 2024-08-06\ntemperature: 0.7\n');
  writeFileSync(join(dir, 'evals', 'data', 'refusals.jsonl'), '{"input":"CANARY-2"}\n');
  const yml = join(dir, '.complyd', 'ai.yml');
  writeFileSync(yml, readFileSync(yml, 'utf8').replace('gte: 0.9,', 'gte: 0.95,'));
  git('commit', '-qam', 'three');
  const r = await cli(['deploy', 'record', '--environment', 'staging', '--system', 'support bot', '--workspace', dir, '--dry-run']);
  assert.equal(r.code, 0, r.err.join('\n'));
  const env = JSON.parse(r.out.join('\n'));
  assert.equal(env.schema, 'ai_release');
  assert.equal(env.collector, 'complyd_ai_release');
  assert.equal(env.payload.system_hint, 'support bot');
  assert.deepEqual(env.payload.changes.map((c) => c.kind), ['model', 'eval_suite', 'dataset']);

  // No change at all: an empty list.
  git('commit', '-q', '--allow-empty', '-m', 'four');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }).changes, []);
});

test('deploy record: a kind added since the previous commit has no before', () => {
  const { dir, git } = gitRepo();
  const yml = join(dir, '.complyd', 'ai.yml');
  mkdirSync(join(dir, 'rag'));
  writeFileSync(join(dir, 'rag', 'index.yaml'), 'top_k: 5\n');
  writeFileSync(yml, readFileSync(yml, 'utf8').replace('tools: [config/tools.json]', 'tools: [config/tools.json]\nretrieval: [rag/index.yaml]'));
  git('add', '-A');
  git('commit', '-qm', 'two');
  const rec = deployRecord({ environment: 'production', root: dir });
  assert.deepEqual(rec.changes, [{ kind: 'retrieval', after_sha256: rec.changes[0].after_sha256 }]);
  assert.equal(rec.retrieval_sha256, rec.changes[0].after_sha256);
});

test('safety sections and model keys', () => {
  assert.equal(sections('a\n<s>\nrule 1\n</s>\nb\n<s>\nrule 2\n</s>', { start: '<s>', end: '</s>' }), 'rule 1\n\u0000\nrule 2');
  assert.equal(sections('no markers', { start: '<s>', end: '</s>' }), null);
  assert.deepEqual(splitModel('model: x\n"model_version": "2"\ntemperature = 1', ['model', 'model_version']), { model: 'model: x\n"model_version": "2"', params: 'temperature = 1' });
});

test('action: scan ai_eval with format, input and role', async () => {
  const posts = [];
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    if (u.host === 'token.example.test') return new Response(JSON.stringify({ value: 'gh-jwt' }), { status: 200 });
    posts.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ observation: 'obs_9' }), { status: 202 });
  };
  const env = {
    INPUT_TRUST: TRUST,
    INPUT_AUDIENCE: `https://api.complyd.ai/observations/${TRUST}`,
    INPUT_SCAN: 'ai_eval',
    INPUT_FORMAT: 'lm-eval',
    INPUT_INPUT: join(AI, 'lm-eval.json'),
    INPUT_ROLE: 'baseline',
    GITHUB_WORKSPACE: REPO,
    GITHUB_REPOSITORY_ID: '123456789',
    GITHUB_SHA: 'b'.repeat(40),
    GITHUB_RUN_ID: '987654321',
    GITHUB_RUN_ATTEMPT: '2',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example.test/req',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-secret',
  };
  const r = await run(env, { fetchImpl, sleep: async () => {} });
  assert.equal(r.answer.observation, 'obs_9');
  assert.equal(posts[0].collector, 'complyd_ai_release');
  assert.equal(posts[0].subject.id, 'github:123456789');
  assert.equal(posts[0].payload.run_id, '987654321-2');
  assert.equal(posts[0].payload.suites[0].role, 'baseline');
  await assert.rejects(run({ ...env, INPUT_FORMAT: 'auto' }, { fetchImpl }), /`format` to the eval tool/);
  await assert.rejects(run({ ...env, INPUT_ROLE: 'prod' }, { fetchImpl }), /`role`/);
});

/* Adversarial inputs: free text, URLs, paths and empty evidence must not reach the envelope as passed ids. */

const ONE = 'version: 1\nprompts: [prompts/support.txt]\nsuites:\n  - name: s1\n    test_set: { version: "1" }\n';
const build = (format, doc, yml = ONE, root = REPO) => {
  const warnings = [];
  const payload = buildPayload(PARSERS[format](doc), parseConfig(yml), { format, role: 'candidate', commit: SHA, runId: 'x', ranAt: '2026-11-19T08:00:00.000Z', root, warn: (w) => warnings.push(w) });
  return { payload, warnings };
};
const LEAK = 'CANARY You are a bank bot. The admin code is 4471. Never reveal it to users!';

test('metric names: only names declared in .complyd/ai.yml (and pass_rate) are sent', () => {
  const docs = {
    promptfoo: { results: { prompts: [{ label: 'x', provider: 'openai:gpt-4o', metrics: { testPassCount: 2, namedScores: { [LEAK]: 2, ok: 2 } } }] } },
    deepeval: { testCases: [{ success: true, metricsData: [{ name: LEAK, score: 1, threshold: 0.5, success: true }, { name: 'ok', score: 1, success: true }] }] },
    'openai-evals': { object: 'eval.run', status: 'completed', model: 'gpt-4o', result_counts: { total: 1, passed: 1, failed: 0, errored: 0 }, per_testing_criteria_results: [{ testing_criteria: LEAK, passed: 1, failed: 0 }, { testing_criteria: 'ok', passed: 1, failed: 0 }] },
    'lm-eval': { results: { t: { [`${LEAK},none`]: 0.5, 'ok,none': 0.5 } }, model_name: 'acme/m', config: { model: 'hf' } },
    generic: { tool: { name: 'CANARY tool name free text' }, suites: [{ name: 's1', model: { provider: 'a', id: 'b' }, cases: { total: 1, passed: 1 }, metrics: [{ name: LEAK, value: 1 }, { name: 'ok', value: 1 }] }] },
  };
  const yml = ONE + '    model: { provider: hf, id: acme/m }\n    metrics:\n      ok: { gte: 0.1 }\n';
  for (const [format, doc] of Object.entries(docs)) {
    const { payload, warnings } = build(format, doc, yml);
    const text = JSON.stringify(payload);
    assert.doesNotMatch(text, /CANARY|4471|bank/, format);
    assert.ok(payload.suites[0].metrics.some((m) => m.name === 'ok'), format);
    assert.ok(warnings.some((w) => /1 metric\(s\) not listed/.test(w)), format);
  }
  // A metric left out still decides: a failed one fails the suite.
  const doc = { suites: [{ name: 's1', model: { provider: 'a', id: 'b' }, cases: { total: 1, passed: 1 }, passed: true, metrics: [{ name: 'secret', value: 0.1, passed: false }] }] };
  assert.equal(build('generic', doc).payload.suites[0].passed, false);
});

test('model and judge ids: URLs and local paths are refused', () => {
  for (const p of ['wss://llm.internal.example/x', 'grpc:///srv/model', 'local:/home/alice/ckpt', 'local:./ckpt', 'local:~/ckpt', 'local:C:/models/x']) assert.equal(providerModel(p), undefined, p);
  // lm-eval naming a checkpoint path: the model must come from the config.
  assert.throws(() => build('lm-eval', { results: { t: { 'acc,none': 0.5 } }, model_name: '/home/alice/CANARY-ckpt', config: { model: 'hf', model_args: 'pretrained=/home/alice/x' } }), { code: 'config', message: /set model:/ });
  // DeepEval's judge as an internal URL: left out, with a warning.
  const { payload, warnings } = build('deepeval', { hyperparameters: { model: 'openai/gpt-4o' }, testCases: [{ success: true, metricsData: [{ name: 'm', score: 1, success: true, evaluationModel: 'https://judge.internal.example/v1/CANARY' }] }] });
  assert.equal(payload.suites[0].evaluator.judge_model, undefined);
  assert.doesNotMatch(JSON.stringify(payload), /CANARY|internal/);
  assert.ok(warnings.some((w) => /judge model/.test(w)));
  // The config is held to the same rule.
  assert.throws(() => parseConfig(ONE + '    model: { provider: hf, id: /home/alice/ckpt }'), { code: 'config', message: /model.id: set the model id, not a URL/ });
  assert.throws(() => parseConfig(ONE + '    evaluator: { judge_model: "https://judge.internal.example/v1" }'), { code: 'config', message: /judge_model: set the judge model id/ });
});

test('symlinks out of the repository are not followed', () => {
  const outside = mkdtempSync(join(tmpdir(), 'ai-outside-'));
  writeFileSync(join(outside, 'secret.txt'), 'PIN=4471\n');
  writeFileSync(join(outside, 'keys.yml'), 'aws_secret_access_key: abc\n');
  const repo = mkdtempSync(join(tmpdir(), 'ai-links-'));
  mkdirSync(join(repo, 'd'));
  mkdirSync(join(repo, '.complyd'));
  writeFileSync(join(repo, 'in.txt'), 'prompt');
  symlinkSync(join(outside, 'secret.txt'), join(repo, 'p.txt'));
  symlinkSync(outside, join(repo, 'd', 'out'));
  symlinkSync(join(repo, 'in.txt'), join(repo, 'link-in.txt'));
  for (const path of ['p.txt', 'd/out/secret.txt', 'd/out/nope.txt']) {
    assert.throws(() => hashFiles(repo, [path], 'prompts'), (e) => e.code === 'config' && /inside the repository/.test(e.message) && !/ENOENT|EACCES/.test(e.message), path);
  }
  assert.equal(hashFiles(repo, ['link-in.txt'], 'prompts'), sha('prompt'));
  symlinkSync(join(outside, 'keys.yml'), join(repo, '.complyd', 'ai.yml'));
  assert.throws(() => loadConfig('.complyd/ai.yml', repo), (e) => e.code === 'config' && !/aws_secret/.test(e.message));
});

test('empty evidence never passes', () => {
  const pf = (metrics) => ({ results: { prompts: [{ label: 'x', provider: 'openai:gpt-4o', metrics }] } });
  assert.equal(build('promptfoo', pf({})).payload.suites[0].passed, false);
  const run0 = { object: 'eval.run', status: 'completed', model: 'gpt-4o', result_counts: { total: 0, passed: 0, failed: 0, errored: 0 } };
  assert.equal(build('openai-evals', run0).payload.suites[0].passed, false);
  const lm = { results: { t: { 'acc,none': 0.9 } }, model_name: 'acme/m', config: { model: 'hf' } };
  const r = build('lm-eval', lm);
  assert.equal(r.payload.suites[0].passed, false);
  assert.ok(r.warnings.some((w) => /no cases and no thresholded metric/.test(w)));
  assert.equal(build('lm-eval', lm, ONE + '    metrics:\n      acc: { gte: 0.5 }\n').payload.suites[0].passed, true);
  // generic: no `passed` with failed cases is not a pass.
  assert.equal(build('generic', { suites: [{ name: 's1', model: { provider: 'a', id: 'b' }, cases: { total: 2, passed: 1, failed: 1 } }] }).payload.suites[0].passed, false);
  // Two result suites with different labels don't both land on the only config suite.
  const two = { results: { prompts: [{ label: 'a', provider: 'openai:gpt-4o', metrics: { testPassCount: 1 } }, { label: 'b', provider: 'openai:gpt-4o', metrics: { testFailCount: 3 } }] } };
  assert.throws(() => build('promptfoo', two), { code: 'config', message: /add match:/ });
});

test('errors print a results label only when it has no spaces', () => {
  const two = ONE + '  - name: s2\n    test_set: { version: "1" }\n';
  const doc = { results: { prompts: [{ label: 'You are CANARY bank bot. The admin code is 4471', provider: 'openai:gpt-4o', metrics: {} }] } };
  assert.throws(() => build('promptfoo', doc, two), (e) => /#1 \(unnamed\)/.test(e.message) && !/CANARY|4471/.test(e.message));
});

test('hostile sizes: long whitespace, big config, many warnings and suites', () => {
  const t0 = Date.now();
  parseYaml(`a: x${' '.repeat(200_000)}y`);
  assert.ok(Date.now() - t0 < 1000, 'linear in the line length');
  assert.throws(() => parseConfig(`# ${'x'.repeat(256 * 1024)}\n${ONE}`), { code: 'config', message: /over 256 KB/ });
  assert.throws(() => PARSERS.promptfoo({ results: { prompts: [{ metrics: { namedScores: 'x'.repeat(1000) } }] } }), { code: 'results' });
  const many = { suites: Array.from({ length: 60 }, (_, i) => ({ name: `r${i}`, model: { provider: 'a', id: 'b' }, cases: { total: 1, passed: 1 } })) };
  const yml = 'version: 1\nprompts: [prompts/support.txt]\nsuites:\n' + many.suites.slice(0, 50).map((s) => `  - name: ${s.name}\n    test_set: { version: "1" }\n    metrics:\n      m: { gte: 1 }\n`).join('');
  const { payload, warnings } = build('generic', many, yml);
  assert.equal(payload.suites.length, 50);
  assert.equal(payload.truncated, true);
  assert.equal(warnings.length, 21);
  assert.match(warnings[20], /^30 more warnings not shown/);
});

test('config: unquoted decimal versions and __proto__ keys are refused', () => {
  assert.throws(() => parseConfig(ONE + '    prompt_version: 1.10'), { code: 'config', message: /prompt_version: quote it, e.g. "1.1"/ });
  assert.equal(parseConfig(ONE + '    prompt_version: 12').suites[0].prompt_version, '12');
  assert.throws(() => parseYaml('__proto__:\n  version: 1'), /__proto__/);
  assert.throws(() => parseYaml('a: { __proto__: 1 }'), /__proto__/);
});

test('generic: non-string ids are not models and do not crash', () => {
  for (const model of [{ provider: ['acme'], id: [['CANARY-arr']] }, { provider: { toString: 1 }, id: 'x' }]) {
    assert.throws(() => build('generic', { suites: [{ name: 's1', model, cases: { total: 1, passed: 1 } }] }), { code: 'config', message: /set model:/ });
  }
});

/* .complyd/ai.yml version 2: several systems, each with the paths it owns. */

const V2 = join(AI, 'ai.v2.yml');
/** A deploy record's keys without system_hint and the optional layer hashes. */
const RELEASE_KEYS = ['commit', 'environment', 'released_at', 'changes', 'model', 'tools', 'datasets', 'eval_run_ids', 'config_changed', 'repo_config'];
const v2 = () => parseConfig(readFileSync(V2));

test('config v2: systems with paths; suites listed across systems; v1 is one system owning **', () => {
  const cfg = v2();
  assert.equal(cfg.version, 2);
  assert.deepEqual(cfg.systems.map((s) => [s.system, s.paths]), [
    ['support-assistant', ['services/support/**', 'prompts/**', 'config/llm.yaml', 'evals/data/**']],
    ['AIS-0042', ['services/**', 'evals/rubric.md', 'config/tools.json']],
  ]);
  assert.deepEqual(cfg.suites.map((s) => s.name), ['safety-refusals', 'ranking-quality']);
  assert.equal(cfg.systems[1].model.files.length, 0);
  assert.deepEqual(cfg.systems[1].prompts, ['evals/rubric.md']);
  const one = config();
  assert.equal(one.version, 1);
  assert.equal(one.systems.length, 1);
  assert.deepEqual(one.systems[0].paths, ['**']);
  // One system may leave paths: out (it owns the repository).
  assert.deepEqual(parseConfig('version: 2\nsystems:\n  - system: a\n    prompts: [p]\n    suites:\n      - name: s\n        test_set: { version: "1" }').systems[0].paths, ['**']);
});

test('config v2: errors name the system entry and say what to fix', () => {
  const sys = (name, extra = '') => `  - system: ${name}\n${extra}    prompts: [p]\n    suites:\n      - name: ${name}-s\n        test_set: { version: "1" }\n`;
  for (const [text, message] of [
    ['version: 2', /systems: list your AI systems \(1 to 50\)/],
    ['version: 2\nsystems: []', /systems: list your AI systems/],
    ['version: 2\nsuites: []\nsystems:\n' + sys('a'), /suites: unknown key \(expected one of version, execution, systems\)/],
    ['version: 3\nprompts: [p]\nsuites:\n  - name: a', /version: set version: 1 \(or version: 2 with systems:\)/],
    ['version: 1\nsystems: []', /systems: unknown key/],
    ['version: 1\npaths: ["**"]\nprompts: [p]\nsuites:\n  - name: a', /paths: unknown key/],
    ['version: 2\nsystems:\n  - prompts: [p]\n    suites:\n      - name: a\n        test_set: { version: "1" }', /systems\[0\].system: set the system's name or its AIS-… reference/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: [x/**]\n') + sys('a', '    paths: [y/**]\n'), /systems\[1\].system: "a" is also systems\[0\]/],
    ['version: 2\nsystems:\n' + sys('a') + sys('b', '    paths: [y/**]\n'), /systems\[0\].paths: list the globs of the files that belong to this system/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: [../x/**]\n'), /systems\[0\].paths\[0\]: "..\/x\/\*\*" must be relative/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: [/etc/**]\n'), /must be relative/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: ["src/**.py"]\n'), /\*\* must be a whole path part/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: ["src/{a,b}/*"]\n'), /systems\[0\].paths\[0\]: set a glob of letters/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: [x/**]\n') + sys('b', '    paths: [./x/**]\n'), /systems\[1\].paths: "x\/\*\*" is also in systems\[0\].paths/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: [x/**]\n    promts: [q]\n'), /systems\[0\].promts: unknown key/],
    ['version: 2\nsystems:\n' + sys('a', '    paths: [x/**]\n') + sys('b', '    paths: [y/**]\n').replace('b-s', 'a-s'), /systems\[1\].suites\[0\].name: "a-s" is used by two suites \(suite names are unique across systems\)/],
    ['version: 2\nsystems:\n  - system: a\n    suites:\n      - name: s\n        test_set: { version: "1" }', /systems\[0\].suites\[0\].prompts: list the prompt files/],
  ]) {
    assert.throws(() => parseConfig(text), { code: 'config', message }, text);
  }
});

test('globs: * stays in a directory, ** spans any, ? is one character; the most specific glob owns a file; on a tie it belongs to neither', () => {
  const t = (g, f) => globMatch(g, f);
  assert.ok(t('src/**/*.py', 'src/a.py') && t('src/**/*.py', 'src/a/b/c.py'));
  assert.ok(!t('src/**/*.py', 'srcx/a.py') && !t('src/*.py', 'src/a/b.py'));
  assert.ok(t('**', 'any/file') && t('a/**', 'a/b/c') && !t('a/**', 'ab/c'));
  assert.ok(t('a/b?.txt', 'a/b1.txt') && !t('a/b?.txt', 'a/b/.txt') && !t('a.b', 'axb'));
  const cfg = v2();
  const owner = (f) => ownerOf(cfg, f)?.system;
  assert.equal(owner('services/support/handler.py'), 'support-assistant');
  assert.equal(owner('services/search/rank.py'), 'AIS-0042');
  assert.equal(owner('prompts/support.txt'), 'support-assistant');
  assert.equal(owner('README.md'), undefined);
  const tie = parseConfig(
    'version: 2\nsystems:\n  - system: a\n    paths: ["src/*/x"]\n    prompts: [src/b/x]\n    suites:\n      - name: s1\n        test_set: { version: "1" }\n  - system: b\n    paths: ["src/a/*"]\n    prompts: [src/a/y]\n    suites:\n      - name: s2\n        test_set: { version: "1" }',
  );
  assert.equal(ownerOf(tie, 'src/b/x').system, 'a');
  assert.equal(ownerOf(tie, 'src/a/x'), undefined);
});

test('globs: ownerOf matches the ownership vectors Complyd tests against', () => {
  const { cases } = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'repo-config-ownership.vectors.json'), 'utf8'));
  assert.equal(cases.length, 9);
  for (const c of cases) {
    const cfg = { systems: Object.entries(c.systems).map(([system, paths]) => ({ system, paths })) };
    assert.equal(ownerOf(cfg, c.file)?.system ?? null, c.owner, c.name);
  }
});

/** A v2 config of the given systems: [name, paths, extra yaml lines]; each also owns and declares prompts/<name>.txt. */
const sysYaml = (list) =>
  'version: 2\nsystems:\n' +
  list.map(([name, paths, extra = '']) => `  - system: ${name}\n    paths: ${JSON.stringify([...paths, `prompts/${name}.txt`])}\n    model: { provider: example-ai, id: m1 }\n    prompts: [prompts/${name}.txt]\n${extra}    suites:\n      - name: ${name}-s\n        test_set: { version: "1" }\n`).join('');

test('globs: matching is linear, whatever the glob and path (no backtracking blow-up)', () => {
  const probe = (glob, file) => {
    const code = `const { globMatch } = require(${JSON.stringify(join(__dirname, '..', 'src', 'ai-config.js'))}); process.stdout.write(String(globMatch(${JSON.stringify(glob)}, ${JSON.stringify(file)})));`;
    const r = spawnSync(process.execPath, ['-e', code], { timeout: 5000, encoding: 'utf8' });
    assert.equal(r.error, undefined, `timed out: ${glob}`);
    return r.stdout;
  };
  // Many * in one part, and many ** parts (before normalising): each took past a 1.5 s timeout as a RegExp.
  assert.equal(probe('*a'.repeat(30) + 'b', 'a'.repeat(60)), 'false');
  assert.equal(probe(Array(24).fill('**').join('/') + '/z', Array(40).fill('a').join('/') + '/y'), 'false');
  assert.equal(probe(Array(24).fill('*a').join('/') + '/z', Array(40).fill('a').join('/') + '/y'), 'false');
  const cfg = parseConfig(sysYaml([['a', ['*a'.repeat(30) + 'b']]]));
  const t0 = Date.now();
  assert.equal(ownerOf(cfg, 'a'.repeat(60)), undefined);
  assert.ok(Date.now() - t0 < 1000);
});

test('globs: equal globs are one spelling (consecutive ** collapse); the most literal glob wins, extra ** add nothing', () => {
  assert.deepEqual(parseConfig(sysYaml([['a', ['src/**/**/x', '**/**']]])).systems[0].paths, ['src/**/x', '**', 'prompts/a.txt']);
  assert.throws(() => parseConfig(sysYaml([['a', ['**']], ['b', ['**/**']]])), { code: 'config', message: /systems\[1\].paths: "\*\*" is also in systems\[0\].paths/ });
  const cfg = parseConfig(sysYaml([['a', ['src/**']], ['b', ['**/*/**/*/**/*/**/*']]]));
  assert.equal(ownerOf(cfg, 'src/file.js').system, 'a');
  assert.equal(ownerOf(cfg, 'lib/a/b/c/d').system, 'b');
  for (const [g, f, want] of [
    ['**/x', 'x', true],
    ['**/x', 'a/b/x', true],
    ['a/**/b', 'a/b', true],
    ['a/**', 'a', false],
    ['a/*/b', 'a/b', false],
    ['*.py', 'a/b.py', false],
    ['a?c', 'abc', true],
    ['a?c', 'ac', false],
  ]) {
    assert.equal(globMatch(g, f), want, `${g} ~ ${f}`);
  }
});

test('thresholds: only values the wire decimal holds exactly (≤ 12 integer, ≤ 9 fraction digits); errors name the field', () => {
  const metric = (v) => sysYaml([['a', ['**'], '']]).replace('test_set: { version: "1" }', `test_set: { version: "1" }\n        metrics:\n          tokens: { lte: ${v} }`);
  for (const v of ['1000000000000', '-1000000000000', '0.0000000001', '0.1234567891', '1e300']) {
    assert.throws(() => parseConfig(metric(v)), { code: 'config', message: /systems\[0\].suites\[0\].metrics.tokens.lte: set a number below 1000000000000 with at most 9 decimal places/ }, v);
  }
  for (const [v, wire] of [['999999999999', '999999999999'], ['0.123456789', '0.123456789'], ['-0.5', '-0.5'], ['0', '0']]) {
    assert.deepEqual(repoConfig(parseConfig(metric(v))).systems[0].suites[0].metrics, { tokens: { lte: wire } });
  }
});

test('ai_eval body: repo_config counts against the 64 KiB cap and is never cut; an error names it', () => {
  const long = (i, j) => `services/s${i}/` + 'd'.repeat(170) + `/p${j}/**`;
  const big = parseConfig(sysYaml([0, 1, 2, 3, 4].map((i) => [`s${i}`, Array.from({ length: 99 }, (_, j) => long(i, j))])));
  const env = (cfg, suites) => envelope({ suites, truncated: false, repo_config: repoConfig(cfg) }, { id: 'x', subject: 'x', observedAt: 'x', schema: 'ai_eval' });
  assert.ok(Buffer.byteLength(JSON.stringify(repoConfig(big))) > MAX_BODY_BYTES);
  assert.throws(() => fitSuites(env(big, [{ name: 'one' }])), { code: 'config', message: /^repo_config \(the summary of .complyd\/ai.yml: \d+ bytes\) doesn't fit Complyd's 64 KiB request/ });
  // repo_config fits, one suite too big beside it: that suite is named.
  assert.throws(() => fitSuites(env(v2(), [{ name: 'x'.repeat(MAX_BODY_BYTES) }])), { code: 'config', message: /^payload.suites\[0\] doesn't fit/ });
  // Suites are cut, repo_config kept whole.
  const body = JSON.parse(fitSuites(env(v2(), [{ name: 'a' }, { name: 'x'.repeat(MAX_BODY_BYTES) }])));
  assert.deepEqual(body.payload.suites.map((x) => x.name), ['a']);
  assert.equal(body.payload.truncated, true);
  assert.deepEqual(body.payload.repo_config, repoConfig(v2()));
});

test('repo_config: names, globs, required and thresholds, and the file hash; no file contents', () => {
  const r = repoConfig(v2());
  assert.deepEqual(r, {
    version: 2,
    config_sha256: sha(readFileSync(V2)),
    systems: [
      {
        system: 'support-assistant',
        paths: ['services/support/**', 'prompts/**', 'config/llm.yaml', 'evals/data/**'],
        suites: [{ name: 'safety-refusals', required: true, metrics: { pass_rate: { gte: '0.9' } } }],
      },
      {
        system: 'AIS-0042',
        paths: ['services/**', 'evals/rubric.md', 'config/tools.json'],
        suites: [{ name: 'ranking-quality', required: false, metrics: { ndcg: { gte: '0.75' }, toxicity: { lte: '0.01' } } }],
      },
    ],
  });
  assertRepoConfig(r);
  const one = repoConfig(config());
  assert.equal(one.version, 1);
  assert.equal(one.config_sha256, sha(readFileSync(join(REPO, '.complyd', 'ai.yml'))));
  assert.deepEqual(one.systems.map((s) => [s.system, s.paths, s.suites.map((x) => x.name)]), [['support-assistant', ['**'], ['safety-refusals', 'answer-quality', 'hellaswag']]]);
  // No system: in a v1 file: the entry has none (Complyd falls back to its own mapping).
  assert.equal(Object.hasOwn(repoConfig(parseConfig(ONE)).systems[0], 'system'), false);
});

test('scan ai_eval with a v2 config: suites matched across systems; repo_config sent; required warnings only for the results system', () => {
  const warnings = [];
  const p = buildPayload(PARSERS.generic(fixture('generic')), v2(), { format: 'generic', role: 'candidate', commit: SHA, runId: 'x', ranAt: '2026-11-19T08:00:00.000Z', root: REPO, warn: (w) => warnings.push(w) });
  assertSchema(p);
  assert.equal(p.suites[0].name, 'safety-refusals');
  assert.equal(p.suites[0].dataset.sha256, sha(readFileSync(join(REPO, 'evals', 'data', 'refusals.jsonl'))));
  assert.deepEqual(p.repo_config, repoConfig(v2()));
  assert.ok(!warnings.some((w) => /Required suite/.test(w)), warnings.join('\n'));
  // A v2 error names the system entry.
  const broken = readFileSync(V2, 'utf8').replace('path: evals/data/refusals.jsonl', 'path: evals/data/missing.jsonl');
  assert.throws(() => buildPayload(PARSERS.generic(fixture('generic')), parseConfig(broken), { format: 'generic', role: 'candidate', commit: SHA, runId: 'x', ranAt: 'x', root: REPO }), {
    message: /systems\[0\].datasets.refusals.path: couldn't read evals\/data\/missing.jsonl/,
  });
});

test('CLI scan ai_eval --dry-run with a v2 config prints repo_config', async () => {
  const { dir } = gitRepo();
  cpSync(V2, join(dir, '.complyd', 'ai.yml'));
  const r = await cli(['scan', 'ai_eval', '--format', 'generic', '--input', join(AI, 'generic.json'), '--workspace', dir, '--commit', SHA, '--dry-run']);
  assert.equal(r.code, 0, r.err.join('\n'));
  const env = JSON.parse(r.out.join('\n'));
  assertSchema(env.payload);
  assert.equal(env.payload.repo_config.version, 2);
  assert.doesNotMatch(r.out.join('\n'), /CANARY|safety:start|refusals\.jsonl/);
});

test('deploy record v1: config_changed and repo_config', () => {
  const { dir, git } = gitRepo();
  writeFileSync(join(dir, 'prompts', 'support.txt'), 'CANARY changed prompt\n');
  git('commit', '-qam', 'two');
  const rec = deployRecord({ environment: 'production', root: dir });
  assert.equal(rec.config_changed, false);
  assert.deepEqual(rec.repo_config, repoConfig(config()));
  const yml = join(dir, '.complyd', 'ai.yml');
  writeFileSync(yml, readFileSync(yml, 'utf8').replace('gte: 0.9,', 'gte: 0.95,'));
  git('commit', '-qam', 'three');
  const next = deployRecord({ environment: 'production', root: dir });
  assert.equal(next.config_changed, true);
  assert.deepEqual(next.repo_config.systems[0].suites[0].metrics, { pass_rate: { gte: '0.95' } });
  assert.notEqual(next.repo_config.config_sha256, rec.repo_config.config_sha256);
  assert.doesNotMatch(JSON.stringify([rec, next]), /CANARY/);
});

test('deploy record v2: one record per touched system, chosen by paths and AI files', async () => {
  const { dir, git } = gitRepo();
  const put = (f, text) => {
    mkdirSync(join(dir, f, '..'), { recursive: true });
    writeFileSync(join(dir, f), text);
  };
  put('services/support/handler.py', 'one\n');
  put('services/search/rank.py', 'one\n');
  cpSync(V2, join(dir, '.complyd', 'ai.yml'));
  git('add', '-A');
  git('commit', '-qm', 'two: v1 to v2');
  const recs = deployRecord({ environment: 'production', root: dir, now: () => new Date('2026-11-19T08:00:00Z') });
  assert.deepEqual(recs.map((r) => r.system_hint), ['support-assistant', 'AIS-0042']);
  for (const r of recs) {
    assert.equal(r.config_changed, true);
    assert.deepEqual(Object.keys(r).filter((k) => !k.endsWith('_sha256')).sort(), [...RELEASE_KEYS, 'system_hint'].sort());
    assert.deepEqual(r.repo_config, repoConfig(v2()));
  }
  // support-assistant kept its name across v1 → v2: compared with the v1 file's material (its tools moved to AIS-0042).
  assert.deepEqual(recs[0].changes.map((c) => [c.kind, 'before_sha256' in c, 'after_sha256' in c]), [
    ['eval_suite', true, true],
    ['tools', true, false],
    ['eval_method', true, true],
  ]);
  // AIS-0042 is new: every kind it has is new.
  assert.deepEqual(recs[1].changes.map((c) => [c.kind, 'before_sha256' in c]), [['model', false], ['prompt', false], ['eval_suite', false], ['tools', false], ['eval_method', false]]);

  // Only services/search/: AIS-0042 (services/**), nothing changed in its AI files.
  put('services/search/rank.py', 'two\n');
  git('commit', '-qam', 'three');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }).map((r) => [r.system_hint, r.config_changed, r.changes]), [['AIS-0042', false, []]]);

  // services/support/ is in both globs: the more specific one (support-assistant) owns it.
  put('services/support/handler.py', 'two\n');
  git('commit', '-qam', 'four');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }).map((r) => r.system_hint), ['support-assistant']);

  // A prompt edit: support-assistant, with its prompt kinds.
  writeFileSync(join(dir, 'prompts', 'support.txt'), 'CANARY new prompt\n');
  git('commit', '-qam', 'five');
  const five = deployRecord({ environment: 'production', root: dir });
  assert.deepEqual(five.map((r) => [r.system_hint, r.changes.map((c) => c.kind)]), [['support-assistant', ['prompt', 'safety_prompt']]]);
  assert.doesNotMatch(JSON.stringify(five), /CANARY|new prompt/);

  // Nothing of any system: no record, and the CLI says so; --system asks for one anyway.
  put('README.md', 'docs\n');
  git('add', '-A');
  git('commit', '-qm', 'six');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }), []);
  const r = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--dry-run']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(JSON.parse(r.out.join('\n')), []);
  assert.match(r.err[0], /touches no AI system/);
  const one = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--system', 'AIS-0042', '--dry-run']);
  assert.equal(one.code, 0, one.err.join('\n'));
  const envs = JSON.parse(one.out.join('\n'));
  assert.equal(envs.length, 1);
  assert.equal(envs[0].schema, 'ai_release');
  assert.equal(envs[0].payload.system_hint, 'AIS-0042');
  assert.deepEqual(envs[0].payload.changes, []);
  const unknown = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--system', 'nope', '--dry-run']);
  assert.equal(unknown.code, 2);
  assert.match(unknown.err[0], /lists no system "nope" \(it lists support-assistant, AIS-0042\)/);
});

test('deploy record v2: a changed file two systems match equally belongs to neither', () => {
  const { dir, git } = gitRepo();
  const yml =
    'version: 2\nsystems:\n  - system: a\n    paths: ["src/*/x"]\n    prompts: [src/b/x]\n    suites:\n      - name: s1\n        test_set: { version: "1" }\n  - system: b\n    paths: ["src/a/*"]\n    prompts: [src/a/y]\n    suites:\n      - name: s2\n        test_set: { version: "1" }\n';
  writeFileSync(join(dir, '.complyd', 'ai.yml'), yml);
  git('commit', '-qam', 'two');
  mkdirSync(join(dir, 'src', 'a'), { recursive: true });
  writeFileSync(join(dir, 'src', 'a', 'x'), 'x\n');
  git('add', '-A');
  git('commit', '-qm', 'three');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }), []);
});

test('deploy record v2: a config-only change (paths, rename, removal, comment) gives one record without a system', () => {
  const { dir, git } = gitRepo();
  const yml = join(dir, '.complyd', 'ai.yml');
  const commit = (text, msg) => {
    writeFileSync(yml, text);
    git('commit', '-qam', msg);
    return deployRecord({ environment: 'production', root: dir });
  };
  const base = [['a', ['src/**']], ['b', ['lib/**']]];
  commit(sysYaml(base), 'two');
  for (const [msg, text] of [
    ['paths only', sysYaml([['a', ['new-src/**']], ['b', ['lib/**']]])],
    ['rename', sysYaml([['a2', ['new-src/**']], ['b', ['lib/**']]])],
    ['removal', sysYaml([['a2', ['new-src/**']]])],
    ['comment only', '# a comment\n' + sysYaml([['a2', ['new-src/**']]])],
  ]) {
    const recs = commit(text, msg);
    assert.equal(recs.length, 1, msg);
    assert.deepEqual(Object.keys(recs[0]).sort(), ['commit', 'environment', 'released_at', 'changes', 'config_changed', 'repo_config'].sort(), msg);
    assertValid('ai_release.v2', recs[0]);
    assert.equal(recs[0].config_changed, true, msg);
    assert.deepEqual(recs[0].changes, [], msg);
    assert.deepEqual(recs[0].repo_config, repoConfig(parseConfig(text)), msg);
  }
  // A config change beside an owned file: that system's record carries it, no extra record.
  mkdirSync(join(dir, 'new-src'));
  writeFileSync(join(dir, 'new-src', 'x'), 'x\n');
  git('add', '-A');
  const recs = commit(sysYaml([['a2', ['new-src/**', 'more/**']]]), 'owned file and config');
  assert.deepEqual(recs.map((r) => [r.system_hint, r.config_changed]), [['a2', true]]);
});

test('config v2: every file a system declares must be its own (under its paths, not won by a more specific glob)', () => {
  const sys = (name, paths, extra) => `  - system: ${name}\n    paths: ${JSON.stringify(paths)}\n${extra}    suites:\n      - name: ${name}-s\n        prompts: [${name}/p.txt]\n        test_set: { version: "1" }\n`;
  const not = (where, file) => new RegExp(`${where.replace(/[[\].]/g, '\\$&')}: ${file} is not under this system's paths .*\\(add it to paths: or move it\\)`);
  for (const [extra, where, file] of [
    ['    tools: [config/tools.json]\n', 'systems[0].tools[0]', 'config/tools.json'],
    ['    prompts: [x/p.txt, config/p.txt]\n', 'systems[0].prompts[1]', 'config/p.txt'],
    ['    model:\n      files: [config/llm.yaml]\n', 'systems[0].model.files[0]', 'config/llm.yaml'],
    ['    safety:\n      files: [config/safety.md]\n', 'systems[0].safety.files[0]', 'config/safety.md'],
    ['    retrieval: [config/r.yaml]\n', 'systems[0].retrieval[0]', 'config/r.yaml'],
    ['    product_config: [config/pc.yaml]\n', 'systems[0].product_config[0]', 'config/pc.yaml'],
    ['    eval_method: [config/em.md]\n', 'systems[0].eval_method[0]', 'config/em.md'],
    ['    datasets:\n      d:\n        path: data/d.jsonl\n', 'systems[0].datasets.d.path', 'data/d.jsonl'],
  ]) {
    assert.throws(() => parseConfig('version: 2\nsystems:\n' + sys('x', ['x/**'], extra) + sys('y', ['y/**'], '')), { code: 'config', message: not(where, file) }, where);
  }
  // Suite files, its own prompts and its rubric.
  const suite = (lines) => 'version: 2\nsystems:\n' + sys('x', ['x/**'], '').replace('        test_set:', `${lines}        test_set:`) + sys('y', ['y/**'], '');
  assert.throws(() => parseConfig(suite('        files: [x/a, y/b]\n')), { message: not('systems[0].suites[0].files[1]', 'y/b') });
  assert.throws(() => parseConfig(suite('        evaluator: { rubric: rubric.md }\n')), { message: not('systems[0].suites[0].evaluator.rubric', 'rubric.md') });
  assert.throws(() => parseConfig(suite('').replace('prompts: [x/p.txt]', 'prompts: [y/p.txt]')), { message: not('systems[0].suites[0].prompts[0]', 'y/p.txt') });
  // Under its paths but won by a more specific glob of another system: the winner is named.
  const won = 'version: 2\nsystems:\n' + sys('a', ['src/**'], '    model:\n      files: [src/private/m]\n') + sys('b', ['src/private/**'], '');
  assert.throws(() => parseConfig(won.replace('a/p.txt', 'src/a.txt').replace('b/p.txt', 'src/private/b.txt')), {
    message: /systems\[0\]\.model\.files\[0\]: src\/private\/m is not under this system's paths \(it belongs to b: a more specific glob\) \(add it to paths: or move it\)/,
  });
  // A declared file two systems match equally: the field is named.
  const tie = 'version: 2\nsystems:\n' + sys('a', ['src/*/x'], '    tools: [src/a/x]\n') + sys('b', ['src/a/*'], '');
  assert.throws(() => parseConfig(tie.replace('a/p.txt', 'src/b/x').replace('b/p.txt', 'src/a/y')), { message: /systems\[0\]\.tools\[0\]: src\/a\/x matches the paths of a and b equally/ });
  // Owned files pass.
  assert.doesNotThrow(() => parseConfig('version: 2\nsystems:\n' + sys('x', ['x/**', 'config/tools.json'], '    tools: [config/tools.json]\n') + sys('y', ['y/**'], '')));
  // v1 owns **: any repository file may be declared.
  assert.doesNotThrow(() => parseConfig('version: 1\ntools: [anywhere/t.json]\nprompts: [p]\nsuites:\n  - name: a\n    test_set: { version: "1" }'));
});

test('CLI deploy record: a repo_config over the 64 KiB cap is an error naming it, not a cut record', async () => {
  const { dir, git } = gitRepo();
  const long = (i, j) => `services/s${i}/` + 'd'.repeat(170) + `/p${j}/**`;
  writeFileSync(join(dir, '.complyd', 'ai.yml'), sysYaml([0, 1, 2, 3, 4].map((i) => [`s${i}`, Array.from({ length: 99 }, (_, j) => long(i, j))])));
  git('commit', '-qam', 'two');
  const r = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--dry-run']);
  assert.equal(r.code, 1, r.out.join('\n'));
  assert.equal(r.out.join(''), '');
  assert.match(r.err.join('\n'), /repo_config \(the summary of .complyd\/ai.yml: \d+ bytes\) doesn't fit Complyd's 64 KiB request/);
});

test("Complyd's schemas: every dry-run deploy record and ai_eval envelope is valid under the version it names (test/fixtures/schemas)", async () => {
  // ai_eval: every format's results; v3 only where the tool reports usage.
  const usage = { promptfoo: true, 'openai-evals': true };
  for (const format of FORMATS) {
    const r = await cli(['scan', 'ai_eval', '--format', format, '--input', join(AI, `${format}.json`), '--workspace', REPO, '--commit', SHA, '--dry-run']);
    assert.equal(r.code, 0, r.err.join('\n'));
    const env = JSON.parse(r.out.join('\n'));
    assert.deepEqual([env.schema, env.schema_version], ['ai_eval', usage[format] ? 3 : 2], format);
    assertValid(`ai_eval.v${env.schema_version}`, env.payload);
  }

  // Deploy record, v1 config: model and dataset changed, a retrieval file added (a kind with no before).
  const { dir, git } = gitRepo();
  const yml = join(dir, '.complyd', 'ai.yml');
  mkdirSync(join(dir, 'rag'));
  writeFileSync(join(dir, 'rag', 'index.yaml'), 'top_k: 5\n');
  writeFileSync(yml, readFileSync(yml, 'utf8').replace('id: gpt-4o-mini', 'id: gpt-4o').replace('tools: [config/tools.json]', 'tools: [config/tools.json]\nretrieval: [rag/index.yaml]'));
  writeFileSync(join(dir, 'evals', 'data', 'refusals.jsonl'), '{"input":"CANARY-2"}\n');
  git('add', '-A');
  git('commit', '-qm', 'two');
  const deploy = async (...args) => {
    const r = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--dry-run', ...args]);
    assert.equal(r.code, 0, r.err.join('\n'));
    const out = JSON.parse(r.out.join('\n'));
    for (const env of [out].flat()) {
      assert.deepEqual([env.schema, env.schema_version, env.observed_at], ['ai_release', 2, env.payload.released_at]);
      assertValid('ai_release.v2', env.payload);
    }
    return out;
  };
  const one = (await deploy()).payload;
  assert.deepEqual(one.model, { provider: 'openai', id: 'gpt-4o', version: '2024-07-18' });
  assert.equal(one.system_hint, 'support-assistant');
  assert.equal(one.released_at, '2026-11-19T08:00:00.000Z');
  assert.deepEqual(one.datasets, [{ ref: 'datasets/refusals@3', sha256: sha('{"input":"CANARY-2"}\n') }]);
  assert.deepEqual([one.tools, one.eval_run_ids], [[], []]);
  const retrieval = one.changes.find((c) => c.kind === 'retrieval');
  assert.deepEqual(retrieval, { kind: 'retrieval', after_sha256: one.retrieval_sha256 });
  assert.ok(one.changes.some((c) => c.kind === 'model'));
  for (const k of ['params_sha256', 'prompt_sha256', 'safety_sha256', 'evaluator_sha256']) assert.match(one[k], /^[0-9a-f]{64}$/, k);
  assert.doesNotMatch(JSON.stringify(one), /CANARY/);

  // v2 config: one record per system, and a config-only record (no system, Complyd ignores its model).
  cpSync(V2, yml);
  git('commit', '-qam', 'three');
  const [only] = await deploy();
  assert.equal(Object.hasOwn(only.payload, 'system_hint'), false);
  assert.equal(only.payload.config_changed, true);
  writeFileSync(join(dir, 'prompts', 'support.txt'), 'CANARY new prompt\n');
  git('commit', '-qam', 'four');
  assert.deepEqual((await deploy()).map((e) => [e.payload.system_hint, e.payload.model.id]), [['support-assistant', 'gpt-4o-mini']]);
  assert.deepEqual((await deploy('--system', 'AIS-0042')).map((e) => [e.payload.system_hint, e.payload.model.id]), [['AIS-0042', 'acme/rank-1']]);

  // The validator is not vacuous: the record's old shape is refused.
  const old = { ...one, system: 'x', previous_commit: one.commit, changes: [{ kind: 'prompt', before_sha256: null }] };
  assert.ok(errorsOf('ai_release.v2', old).length);
  const { model, ...noModel } = one;
  assert.ok(errorsOf('ai_release.v2', noModel));
});

test('deploy record: a system without the deployed model is a config error naming where to set it', () => {
  const { dir, git } = gitRepo();
  const yml = join(dir, '.complyd', 'ai.yml');
  writeFileSync(yml, readFileSync(yml, 'utf8').replace(/  provider: openai.*\n  id: gpt-4o-mini\n  version: "2024-07-18"\n/, ''));
  git('commit', '-qam', 'two');
  assert.throws(() => deployRecord({ environment: 'production', root: dir }), { code: 'config', message: /model: deploy record needs the deployed model: set provider: and id:/ });
  // A model in the config is validated as a suite's is.
  assert.throws(() => parseConfig(readFileSync(yml, 'utf8').replace('model:\n', 'model:\n  provider: OpenAI\n  id: https://x/y\n')), { code: 'config', message: /model\.provider: .*model\.id: set the model id, not a URL/ });
});

// Execution per suite and the usage the tool reported (ai_eval / ai_release v3).

const CONFIG_TEXT = () => readFileSync(join(REPO, '.complyd', 'ai.yml'), 'utf8');
/** The fixture config with `lines` added under the first suite (safety-refusals). */
const configWith = (...lines) => parseConfig(CONFIG_TEXT().replace('  - name: safety-refusals\n', `  - name: safety-refusals\n${lines.map((l) => `    ${l}\n`).join('')}`));
const buildWith = (format, doc, cfg, role = 'candidate') => buildPayload(PARSERS[format](doc), cfg, { format, role, commit: SHA, runId: 'gitlab-555', ranAt: '2026-11-19T08:00:00.000Z', root: REPO });
const genericDoc = (suite) => ({ tool: { name: 'acme-harness', version: '2.1.0' }, suites: [{ ...fixture('generic').suites[0], ...suite }] });

test('config: execution per suite, per system or for the file; repo_config carries each suite’s; anything else is refused', () => {
  const v1 = parseConfig(CONFIG_TEXT().replace('version: 1\n', 'version: 1\nexecution: scripted\n').replace('  - name: answer-quality\n', '  - name: answer-quality\n    execution: live\n'));
  assert.deepEqual(v1.suites.map((s) => [s.name, s.execution]), [['safety-refusals', 'scripted'], ['answer-quality', 'live'], ['hellaswag', 'scripted']]);
  assert.deepEqual(repoConfig(v1).systems[0].suites.map((s) => s.execution), ['scripted', 'live', 'scripted']);
  assertValid('ai_eval.v3#/$defs/repo_config', repoConfig(v1));
  // Not stated: no key, so the config is what it was (v2).
  assert.equal(config().suites.some((s) => s.execution), false);
  assert.equal(JSON.stringify(repoConfig(config())).includes('execution'), false);

  const v2 = parseConfig(`version: 2
execution: replay
systems:
  - system: a
    paths: ["a/**"]
    execution: live
    prompts: [a/p]
    suites:
      - name: a-1
        test_set: { version: "1" }
      - name: a-2
        execution: scripted
        test_set: { version: "1" }
  - system: b
    paths: ["b/**"]
    prompts: [b/p]
    suites:
      - name: b-1
        test_set: { version: "1" }
`);
  assert.deepEqual(v2.suites.map((s) => [s.name, s.execution]), [['a-1', 'live'], ['a-2', 'scripted'], ['b-1', 'replay']]);

  for (const [text, message] of [
    [CONFIG_TEXT().replace('  - name: safety-refusals\n', '  - name: safety-refusals\n    execution: unknown\n'), /suites\[0\]\.execution: set live, scripted, replay/],
    [CONFIG_TEXT().replace('version: 1\n', 'version: 1\nexecution: Live\n'), /execution: set live, scripted, replay/],
    [CONFIG_TEXT().replace('  - name: safety-refusals\n', '  - name: safety-refusals\n    execution: [live]\n'), /suites\[0\]\.execution/],
  ]) {
    assert.throws(() => parseConfig(text), { code: 'config', message }, text.slice(0, 80));
  }
});

test('payload: no execution and no usage stays ai_eval v2, with no new key', () => {
  for (const format of ['deepeval', 'lm-eval', 'generic']) {
    const p = payloadOf(format);
    assert.equal(schemaVersion(p), 2, format);
    assert.doesNotMatch(JSON.stringify(p), /"execution"|"usage"/, format);
    assertValid('ai_eval.v2', p);
  }
});

test('promptfoo 0.126 (real output): calls and tokens of the target; a cache hit counts only the calls this run made', () => {
  const cfg = configWith('model: { provider: openai, id: gpt-4o-mini }', 'execution: live');
  const fresh = buildWith('promptfoo', fixture('promptfoo-0.126.real'), cfg);
  assertSchema(fresh);
  assert.equal(schemaVersion(fresh), 3);
  assert.deepEqual([fresh.tool, fresh.suites[0].cases], [{ name: 'promptfoo', version: '0.126.0' }, { total: 3, passed: 2, failed: 1, errored: 0 }]);
  assert.equal(fresh.suites[0].execution, 'live');
  assert.deepEqual(fresh.suites[0].usage, { calls: 3, input_tokens: 360, output_tokens: 90, cached_input_tokens: 120, cost_usd: '0.0063' });

  // Case two came from promptfoo's cache: incurredTokenUsage and incurredCost, never the top level's cached.
  const cached = buildWith('promptfoo', fixture('promptfoo-0.126-cache.real'), cfg);
  assertSchema(cached);
  assert.deepEqual(cached.suites[0].usage, { calls: 2, input_tokens: 240, output_tokens: 60, cached_input_tokens: 80, cost_usd: '0.0042' });

  // A cache hit without the incurred view (an older promptfoo) can't be split: no usage, not the totals.
  const old = fixture('promptfoo-0.126-cache.real');
  delete old.results.prompts[0].metrics.tokenUsage.incurredTokenUsage;
  delete old.results.prompts[0].metrics.incurredCost;
  assert.equal(Object.hasOwn(buildWith('promptfoo', old, cfg).suites[0], 'usage'), false);

  // promptfoo's 0 for what a provider didn't report is left out; calls it made are kept.
  const quiet = fixture('promptfoo-0.126.real');
  const m = quiet.results.prompts[0].metrics;
  Object.assign(m.tokenUsage, { prompt: 0, completion: 0, total: 0 });
  m.tokenUsage.completionDetails.cacheReadInputTokens = 0;
  m.cost = 0;
  assert.deepEqual(buildWith('promptfoo', quiet, cfg).suites[0].usage, { calls: 3 });
  // No call at all is a real 0 (Complyd flags it on a live suite).
  Object.assign(m.tokenUsage, { numRequests: 0 });
  assert.deepEqual(buildWith('promptfoo', quiet, cfg).suites[0].usage, { calls: 0, input_tokens: 0, output_tokens: 0 });
  assert.doesNotMatch(JSON.stringify(fresh), /CANARY/);

  // promptfoo ran another model than ai.yml names: its usage isn't that model's, so it is left out with a warning.
  const other = fixture('promptfoo-0.126.real');
  other.results.prompts[0].provider = 'openai:gpt-4o';
  const warnings = [];
  const parsed = PARSERS.promptfoo(other);
  const opts = { format: 'promptfoo', role: 'candidate', commit: SHA, runId: 'gitlab-555', ranAt: '2026-11-19T08:00:00.000Z', root: REPO, warn: (w) => warnings.push(w) };
  const mismatch = buildPayload(parsed, cfg, opts);
  assert.equal(Object.hasOwn(mismatch.suites[0], 'usage'), false);
  assert.equal(mismatch.suites[0].execution, 'live');
  assert.ok(warnings.some((w) => /usage was left out/.test(w)), warnings.join('\n'));
  // Same id: kept.
  other.results.prompts[0].provider = 'openai:gpt-4o-mini';
  assert.equal(buildPayload(PARSERS.promptfoo(other), cfg, opts).suites[0].usage.calls, 3);
});

test('openai-evals: only per_model_usage rows named after the model under test; none matching, no usage', () => {
  const run = fixture('openai-evals');
  run.per_model_usage.push({ model_name: 'o3-grader', invocation_count: 50, prompt_tokens: 9000, completion_tokens: 900, total_tokens: 9900, cached_tokens: 0 });
  const s = buildWith('openai-evals', run, config()).suites[0];
  assert.deepEqual(s.usage, { calls: 50, input_tokens: 5500, output_tokens: 1200, cached_input_tokens: 0 });
  // A dated snapshot name against the alias the run names: not the same model as far as the action can tell.
  const dated = fixture('openai-evals');
  dated.per_model_usage[0].model_name = 'gpt-4o-mini-2024-07-18';
  const p = buildWith('openai-evals', dated, config());
  assert.equal(Object.hasOwn(p.suites[0], 'usage'), false);
  assert.equal(schemaVersion(p), 2);
  // The run's data_source.model names it too.
  dated.data_source = { type: 'completions', model: 'gpt-4o-mini-2024-07-18' };
  assert.equal(buildWith('openai-evals', dated, config()).suites[0].usage.calls, 50);
});

test('generic: execution and usage as stated; a push moves a run away from live, never to it', () => {
  const usage = { calls: 200, input_tokens: 31000, output_tokens: 4200, cached_input_tokens: 1000, cost_usd: '4.12' };
  const p = buildWith('generic', genericDoc({ execution: 'live', usage }), config());
  assertSchema(p);
  assert.deepEqual([p.suites[0].execution, p.suites[0].usage], ['live', usage]);
  // A number cost is the tool's figure, to the micro-dollar.
  assert.equal(buildWith('generic', genericDoc({ usage: { cost_usd: 0.1234567 } }), config()).suites[0].usage.cost_usd, '0.123457');
  // A positive cost under half a micro-dollar is left out, not sent as "0"; a stated 0 stays.
  assert.deepEqual(buildWith('generic', genericDoc({ usage: { calls: 1, cost_usd: 1e-7 } }), config()).suites[0].usage, { calls: 1 });
  assert.equal(buildWith('generic', genericDoc({ usage: { cost_usd: 0 } }), config()).suites[0].usage.cost_usd, '0');
  assert.equal(buildWith('generic', genericDoc({ usage: { cost_usd: 99999999.999999 } }), config()).suites[0].usage.cost_usd, '99999999.999999');
  // An empty usage is "not reported".
  assert.equal(schemaVersion(buildWith('generic', genericDoc({ usage: {} }), config())), 2);

  const scripted = configWith('execution: scripted');
  // ai.yml's default when the results say nothing.
  assert.equal(buildWith('generic', genericDoc({}), scripted).suites[0].execution, 'scripted');
  // live → scripted or replay on a push is fine.
  assert.equal(buildWith('generic', genericDoc({ execution: 'replay' }), configWith('execution: live')).suites[0].execution, 'replay');
  // scripted → live is not: a person edits ai.yml.
  assert.throws(() => buildWith('generic', genericDoc({ execution: 'live' }), scripted), { code: 'config', message: /ran live, but suites\[0\]\.execution in \.complyd\/ai\.yml says scripted/ });

  for (const [suite, message] of [
    [{ execution: 'unknown' }, /suites\[0\]\.execution must be live, scripted, replay/],
    [{ usage: { calls: -1 } }, /usage\.calls must be a whole number/],
    [{ usage: { input_tokens: 1.5 } }, /usage\.input_tokens must be a whole number/],
    [{ usage: { output_tokens: '10' } }, /usage\.output_tokens must be a whole number/],
    [{ usage: { calls: 1e12 + 1 } }, /usage\.calls must be a whole number/],
    [{ usage: { cost_usd: '4,12' } }, /usage\.cost_usd must be the cost/],
    [{ usage: { cost_usd: -1 } }, /usage\.cost_usd must be the cost/],
    // Rounds up to 10^8, which Complyd's schema refuses.
    [{ usage: { cost_usd: 99999999.9999999 } }, /usage\.cost_usd must be the cost/],
    [{ usage: { total_tokens: 5 } }, /usage has an unknown key "total_tokens"/],
    [{ usage: [1] }, /usage must be an object/],
  ]) {
    assert.throws(() => buildWith('generic', genericDoc(suite), config()), { code: 'results', message }, JSON.stringify(suite));
  }
});

test("Complyd's v3 schemas refuse what the action never sends (the validator is not vacuous)", () => {
  const p = buildWith('generic', genericDoc({ execution: 'live', usage: { calls: 1 } }), config());
  assert.ok(errorsOf('ai_eval.v3', { ...p, suites: [{ ...p.suites[0], execution: 'unknown' }] }));
  assert.ok(errorsOf('ai_eval.v3', { ...p, suites: [{ ...p.suites[0], usage: {} }] }));
  assert.ok(errorsOf('ai_eval.v3', { ...p, suites: [{ ...p.suites[0], rescored: true }] }));
  assert.ok(errorsOf('ai_eval.v2', p));
});

test('scan ai_eval and deploy record: v3 envelopes when ai.yml states execution, valid under Complyd’s v3 schemas', async () => {
  const { dir, git } = gitRepo();
  const yml = join(dir, '.complyd', 'ai.yml');
  writeFileSync(yml, readFileSync(yml, 'utf8').replace('version: 1\n', 'version: 1\nexecution: scripted\n'));
  git('commit', '-qam', 'state execution');
  const r = await cli(['scan', 'ai_eval', '--format', 'lm-eval', '--input', join(AI, 'lm-eval.json'), '--workspace', dir, '--commit', SHA, '--dry-run']);
  assert.equal(r.code, 0, r.err.join('\n'));
  const env = JSON.parse(r.out.join('\n'));
  assert.equal(env.schema_version, 3);
  assert.equal(env.payload.suites[0].execution, 'scripted');
  assert.equal(Object.hasOwn(env.payload.suites[0], 'usage'), false);
  assertValid('ai_eval.v3', env.payload);

  const d = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--dry-run']);
  assert.equal(d.code, 0, d.err.join('\n'));
  const rec = JSON.parse(d.out.join('\n'));
  assert.deepEqual([rec.schema, rec.schema_version], ['ai_release', 3]);
  assert.deepEqual(rec.payload.repo_config.systems[0].suites.map((s) => s.execution), ['scripted', 'scripted', 'scripted']);
  assertValid('ai_release.v3', rec.payload);
  assert.ok(errorsOf('ai_release.v2', rec.payload));
});
