'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { join } = require('path');
const { createHash } = require('crypto');
const { execFileSync, spawnSync } = require('child_process');
const { mkdtempSync, writeFileSync, readFileSync, mkdirSync, cpSync, symlinkSync } = require('fs');
const { tmpdir } = require('os');
const { parseYaml } = require('../src/yaml');
const { parseConfig, loadConfig, hashFiles, repoConfig, ownerOf, globMatch } = require('../src/ai-config');
const { PARSERS, FORMATS, buildPayload, fitSuites, decimal, providerModel, aiEnvelopeId } = require('../src/ai-eval');
const { envelope, MAX_BODY_BYTES } = require('../src/post');
const { deployRecord, sections, splitModel } = require('../src/ai-release');
const { main } = require('../src/cli');
const { run } = require('../src/index');

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

/** The ai_eval v1 schema's shape and patterns, checked by hand (the action has no JSON Schema validator). */
function assertSchema(p) {
  const keys = (o, req, opt = []) => {
    for (const k of req) assert.ok(Object.hasOwn(o, k), `missing ${k}`);
    for (const k of Object.keys(o)) assert.ok(req.includes(k) || opt.includes(k), `unexpected ${k}`);
  };
  const re = (v, r, what) => assert.match(String(v), r, what);
  const count = (n) => assert.ok(Number.isInteger(n) && n >= 0 && n <= 10_000_000, `count ${n}`);
  const HEX = /^[0-9a-f]{64}$/;
  const REF = /^[A-Za-z0-9._:/@+-]{1,64}$/;
  const DEC = /^-?[0-9]{1,12}(\.[0-9]{1,9})?$/;
  keys(p, ['tool', 'format', 'commit', 'run_id', 'ran_at', 'suites', 'truncated'], ['repo_config']);
  if (p.repo_config) assertRepoConfig(p.repo_config);
  keys(p.tool, ['name', 'version']);
  re(p.tool.name, /^[A-Za-z0-9 ._/@+-]{1,64}$/);
  re(p.tool.version, /^[A-Za-z0-9._+-]{1,40}$/);
  assert.ok(FORMATS.includes(p.format));
  re(p.commit, /^([0-9a-f]{40}|[0-9a-f]{64})$/);
  re(p.run_id, /^[A-Za-z0-9._:/-]{1,128}$/);
  assert.equal(new Date(p.ran_at).toISOString(), p.ran_at);
  assert.ok(p.suites.length >= 1 && p.suites.length <= 50);
  assert.equal(typeof p.truncated, 'boolean');
  for (const s of p.suites) {
    keys(s, ['name', 'role', 'model', 'prompt_sha256', 'test_set', 'evaluator', 'metrics', 'cases', 'passed'], ['prompt_version', 'dataset', 'run_conditions_sha256', 'rescored', 'anchor_check']);
    re(s.name, /^[A-Za-z0-9 ._:/@+-]{1,128}$/);
    assert.ok(['baseline', 'candidate'].includes(s.role));
    keys(s.model, ['provider', 'id'], ['version']);
    re(s.model.provider, /^[a-z0-9][a-z0-9._-]{0,63}$/);
    re(s.model.id, /^[A-Za-z0-9._:/@+-]{1,128}$/);
    if (s.model.version) re(s.model.version, /^[A-Za-z0-9._:/@+-]{1,64}$/);
    if (s.prompt_version) re(s.prompt_version, REF);
    re(s.prompt_sha256, HEX);
    if (s.dataset) {
      keys(s.dataset, ['sha256'], ['ref']);
      re(s.dataset.sha256, HEX);
    }
    keys(s.test_set, ['version', 'cases'], ['selection', 'expected_version']);
    re(s.test_set.version, REF);
    count(s.test_set.cases);
    keys(s.evaluator, ['version', 'parser'], ['judge_model', 'rubric_sha256']);
    re(s.evaluator.version, REF);
    re(s.evaluator.parser, REF);
    if (s.evaluator.rubric_sha256) re(s.evaluator.rubric_sha256, HEX);
    assert.ok(s.metrics.length <= 50);
    for (const m of s.metrics) {
      keys(m, ['name', 'value', 'passed'], ['category', 'threshold']);
      re(m.name, /^[A-Za-z0-9 ._:/@+-]{1,64}$/);
      re(m.value, DEC);
      if (m.threshold) {
        keys(m.threshold, ['value', 'direction']);
        re(m.threshold.value, DEC);
        assert.ok(['gte', 'lte'].includes(m.threshold.direction));
      }
    }
    keys(s.cases, ['total', 'passed', 'failed', 'errored']);
    Object.values(s.cases).forEach(count);
    assert.equal(typeof s.passed, 'boolean');
  }
}

/** repo_config: names, globs, required flags and decimal thresholds only. */
function assertRepoConfig(r) {
  const keys = (o, req, opt = []) => assert.deepEqual(Object.keys(o).filter((k) => !opt.includes(k)).sort(), [...req].sort());
  keys(r, ['version', 'config_sha256', 'systems']);
  assert.ok([1, 2].includes(r.version));
  assert.match(r.config_sha256, /^[0-9a-f]{64}$/);
  for (const s of r.systems) {
    keys(s, ['paths', 'suites'], ['system']);
    if (s.system !== undefined) assert.match(s.system, /^[A-Za-z0-9 ._:/@+-]{1,128}$/);
    for (const g of s.paths) assert.match(g, /^[A-Za-z0-9 ._@+/*?-]{1,200}$/);
    for (const x of s.suites) {
      keys(x, ['name', 'required', 'metrics']);
      assert.equal(typeof x.required, 'boolean');
      for (const m of Object.values(x.metrics)) {
        assert.equal(Object.keys(m).length, 1);
        assert.ok(['gte', 'lte'].includes(Object.keys(m)[0]));
        assert.match(Object.values(m)[0], /^-?[0-9]{1,12}(\.[0-9]{1,9})?$/);
      }
    }
  }
}

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
  assert.equal(env.schema_version, 1);
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
  assert.equal(rec.system, 'support-assistant');
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
  assert.equal(env.payload.system, 'support bot');
  assert.deepEqual(env.payload.changes.map((c) => c.kind), ['model', 'eval_suite', 'dataset']);

  // No change at all: an empty list.
  git('commit', '-q', '--allow-empty', '-m', 'four');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }).changes, []);
});

test('deploy record: a kind added since the previous commit has a null before', () => {
  const { dir, git } = gitRepo();
  const yml = join(dir, '.complyd', 'ai.yml');
  mkdirSync(join(dir, 'rag'));
  writeFileSync(join(dir, 'rag', 'index.yaml'), 'top_k: 5\n');
  writeFileSync(yml, readFileSync(yml, 'utf8').replace('tools: [config/tools.json]', 'tools: [config/tools.json]\nretrieval: [rag/index.yaml]'));
  git('add', '-A');
  git('commit', '-qm', 'two');
  const rec = deployRecord({ environment: 'production', root: dir });
  assert.deepEqual(rec.changes, [{ kind: 'retrieval', before_sha256: null, after_sha256: rec.changes[0].after_sha256 }]);
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
const v2 = () => parseConfig(readFileSync(V2));

test('config v2: systems with paths; suites listed across systems; v1 is one system owning **', () => {
  const cfg = v2();
  assert.equal(cfg.version, 2);
  assert.deepEqual(cfg.systems.map((s) => [s.system, s.paths]), [
    ['support-assistant', ['services/support/**', 'prompts/**', 'config/llm.yaml']],
    ['AIS-0042', ['services/**']],
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
    ['version: 2\nsuites: []\nsystems:\n' + sys('a'), /suites: unknown key \(expected one of version, systems\)/],
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

test('globs: * stays in a directory, ** spans any, ? is one character; the most specific glob owns a file; a tie is an error', () => {
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
    'version: 2\nsystems:\n  - system: a\n    paths: ["src/*/x"]\n    prompts: [p]\n    suites:\n      - name: s1\n        test_set: { version: "1" }\n  - system: b\n    paths: ["src/a/*"]\n    prompts: [p]\n    suites:\n      - name: s2\n        test_set: { version: "1" }',
  );
  assert.equal(ownerOf(tie, 'src/b/x').system, 'a');
  assert.throws(() => ownerOf(tie, 'src/a/x'), { code: 'config', message: /src\/a\/x matches the paths of a and b equally: make one of their globs more specific/ });
});

/** A v2 config of the given systems: [name, paths, extra yaml lines]. */
const sysYaml = (list) =>
  'version: 2\nsystems:\n' +
  list.map(([name, paths, extra = '']) => `  - system: ${name}\n    paths: ${JSON.stringify(paths)}\n    prompts: [prompts/support.txt]\n${extra}    suites:\n      - name: ${name}-s\n        test_set: { version: "1" }\n`).join('');

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
  assert.deepEqual(parseConfig(sysYaml([['a', ['src/**/**/x', '**/**']]])).systems[0].paths, ['src/**/x', '**']);
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
  const big = parseConfig(sysYaml([0, 1, 2, 3, 4].map((i) => [`s${i}`, Array.from({ length: 100 }, (_, j) => long(i, j))])));
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
        paths: ['services/support/**', 'prompts/**', 'config/llm.yaml'],
        suites: [{ name: 'safety-refusals', required: true, metrics: { pass_rate: { gte: '0.9' } } }],
      },
      {
        system: 'AIS-0042',
        paths: ['services/**'],
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
  assert.deepEqual(recs.map((r) => r.system), ['support-assistant', 'AIS-0042']);
  for (const r of recs) {
    assert.equal(r.config_changed, true);
    assert.deepEqual(Object.keys(r), ['environment', 'system', 'commit', 'previous_commit', 'recorded_at', 'config_changed', 'changes', 'repo_config']);
    assert.deepEqual(r.repo_config, repoConfig(v2()));
  }
  // support-assistant kept its name across v1 → v2: compared with the v1 file's material (its tools moved to AIS-0042).
  assert.deepEqual(recs[0].changes.map((c) => [c.kind, c.before_sha256 !== null, c.after_sha256 !== null]), [
    ['eval_suite', true, true],
    ['tools', true, false],
    ['eval_method', true, true],
  ]);
  // AIS-0042 is new: every kind it has is new.
  assert.deepEqual(recs[1].changes.map((c) => [c.kind, c.before_sha256]), [['prompt', null], ['eval_suite', null], ['tools', null], ['eval_method', null]]);

  // Only services/search/: AIS-0042 (services/**), nothing changed in its AI files.
  put('services/search/rank.py', 'two\n');
  git('commit', '-qam', 'three');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }).map((r) => [r.system, r.config_changed, r.changes]), [['AIS-0042', false, []]]);

  // services/support/ is in both globs: the more specific one (support-assistant) owns it.
  put('services/support/handler.py', 'two\n');
  git('commit', '-qam', 'four');
  assert.deepEqual(deployRecord({ environment: 'production', root: dir }).map((r) => r.system), ['support-assistant']);

  // A prompt edit: support-assistant, with its prompt kinds.
  writeFileSync(join(dir, 'prompts', 'support.txt'), 'CANARY new prompt\n');
  git('commit', '-qam', 'five');
  const five = deployRecord({ environment: 'production', root: dir });
  assert.deepEqual(five.map((r) => [r.system, r.changes.map((c) => c.kind)]), [['support-assistant', ['prompt', 'safety_prompt']]]);
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
  assert.equal(envs[0].payload.system, 'AIS-0042');
  assert.deepEqual(envs[0].payload.changes, []);
  const unknown = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--system', 'nope', '--dry-run']);
  assert.equal(unknown.code, 2);
  assert.match(unknown.err[0], /lists no system "nope" \(it lists support-assistant, AIS-0042\)/);
});

test('deploy record v2: a changed file two systems own equally is a config error', () => {
  const { dir, git } = gitRepo();
  const yml =
    'version: 2\nsystems:\n  - system: a\n    paths: ["src/*/x"]\n    prompts: [prompts/support.txt]\n    suites:\n      - name: s1\n        test_set: { version: "1" }\n  - system: b\n    paths: ["src/a/*"]\n    prompts: [prompts/support.txt]\n    suites:\n      - name: s2\n        test_set: { version: "1" }\n';
  writeFileSync(join(dir, '.complyd', 'ai.yml'), yml);
  git('commit', '-qam', 'two');
  mkdirSync(join(dir, 'src', 'a'), { recursive: true });
  writeFileSync(join(dir, 'src', 'a', 'x'), 'x\n');
  git('add', '-A');
  git('commit', '-qm', 'three');
  assert.throws(() => deployRecord({ environment: 'production', root: dir }), { code: 'config', message: /src\/a\/x matches the paths of a and b equally/ });
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
    assert.deepEqual(Object.keys(recs[0]), ['environment', 'commit', 'previous_commit', 'recorded_at', 'config_changed', 'changes', 'repo_config'], msg);
    assert.equal(recs[0].config_changed, true, msg);
    assert.deepEqual(recs[0].changes, [], msg);
    assert.deepEqual(recs[0].repo_config, repoConfig(parseConfig(text)), msg);
  }
  // A config change beside an owned file: that system's record carries it, no extra record.
  mkdirSync(join(dir, 'new-src'));
  writeFileSync(join(dir, 'new-src', 'x'), 'x\n');
  git('add', '-A');
  const recs = commit(sysYaml([['a2', ['new-src/**', 'more/**']]]), 'owned file and config');
  assert.deepEqual(recs.map((r) => [r.system, r.config_changed]), [['a2', true]]);
});

test('deploy record v2: an AI file two systems name records only for its owner (the overlap winner)', () => {
  const { dir, git } = gitRepo();
  const both = '    model:\n      files: [src/p]\n';
  mkdirSync(join(dir, 'src', 'private'), { recursive: true });
  writeFileSync(join(dir, 'src', 'p'), 'one\n');
  writeFileSync(join(dir, '.complyd', 'ai.yml'), sysYaml([['a', ['src/**'], both], ['b', ['src/private/**'], both]]));
  git('add', '-A');
  git('commit', '-qm', 'two');
  writeFileSync(join(dir, 'src', 'p'), 'two\n');
  git('commit', '-qam', 'three');
  const recs = deployRecord({ environment: 'production', root: dir });
  assert.deepEqual(recs.map((r) => [r.system, r.changes.map((c) => c.kind)]), [['a', ['model']]]);
});

test('CLI deploy record: a repo_config over the 64 KiB cap is an error naming it, not a cut record', async () => {
  const { dir, git } = gitRepo();
  const long = (i, j) => `services/s${i}/` + 'd'.repeat(170) + `/p${j}/**`;
  writeFileSync(join(dir, '.complyd', 'ai.yml'), sysYaml([0, 1, 2, 3, 4].map((i) => [`s${i}`, Array.from({ length: 100 }, (_, j) => long(i, j))])));
  git('commit', '-qam', 'two');
  const r = await cli(['deploy', 'record', '--environment', 'production', '--workspace', dir, '--dry-run']);
  assert.equal(r.code, 1, r.out.join('\n'));
  assert.equal(r.out.join(''), '');
  assert.match(r.err.join('\n'), /repo_config \(the summary of .complyd\/ai.yml: \d+ bytes\) doesn't fit Complyd's 64 KiB request/);
});
