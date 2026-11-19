'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHmac } = require('crypto');
const { readFileSync } = require('fs');
const { join } = require('path');
const { reduceSast, ruleId } = require('../src/sast');
const { MAX_FINDINGS } = require('../src/reduce');
const { assertValid } = require('./schemas');

const fixture = (name) => JSON.parse(readFileSync(join(__dirname, 'fixtures', name), 'utf8'));
const opts = { commit: 'a'.repeat(40), scannedAt: '2026-11-14T08:00:00.000Z', subject: 'github:123456789' };
/** The fingerprint formula, written out: HMAC-SHA-256 keyed by github:<repository id>. */
const hmac = (s, repo = '123456789') => createHmac('sha256', `github:${repo}`).update(s).digest('hex');
/** No location detail of the fixtures may reach the payload. */
const LEAKS = /\.js|\.py|services|web\/|apps\/|tools\/|scripts|routes|res\.send|subprocess\.run|line|column|query|message|snippet|5a8c1e2f|requires login/i;

test('CodeQL: severity from security-severity, open results only, locations hashed', () => {
  const { payload, dropped } = reduceSast(fixture('codeql.sarif'), opts);
  assert.deepEqual(payload.tool, { name: 'CodeQL', version: '2.19.3' });
  assert.deepEqual(payload.counts, { critical: 1, high: 2, medium: 0, low: 1 });
  assert.deepEqual(
    payload.findings.map((f) => [f.rule, f.severity]),
    [
      ['js/code-injection', 'critical'],
      ['js/sql-injection', 'high'],
      ['js/sql-injection', 'high'],
      ['js/unused-local-variable', 'low'],
    ],
  );
  // The scanner's own fingerprint, hashed with the rule: stable across runs.
  assert.ok(
    payload.findings.some(
      (f) => f.fingerprint === hmac('js/sql-injection\nprimaryLocationLineHash=5a8c1e2f9b7d4c30:1'),
    ),
  );
  for (const f of payload.findings) {
    assert.deepEqual(Object.keys(f), ['rule', 'severity', 'fingerprint']);
    assert.match(f.fingerprint, /^[0-9a-f]{64}$/);
  }
  assert.equal(payload.truncated, false);
  assert.equal(dropped.count, 0);
  assert.doesNotMatch(JSON.stringify(payload), LEAKS);
});

test('Semgrep: severity from the level; "requires login" fingerprints fall back to a hash of file and matched code', () => {
  const { payload } = reduceSast(fixture('semgrep.sarif'), opts);
  assert.deepEqual(payload.tool, { name: 'Semgrep OSS', version: '1.95.0' });
  const xss = 'javascript.express.security.audit.xss.direct-response-write.direct-response-write';
  assert.deepEqual(
    payload.findings.map((f) => [f.rule, f.severity]),
    [
      ['python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use', 'high'],
      [xss, 'medium'],
      [xss, 'medium'],
    ],
  );
  // Two results of one rule stay two findings (their files differ).
  const fps = payload.findings.map((f) => f.fingerprint);
  assert.equal(new Set(fps).size, 3);
  assert.ok(fps.includes(hmac(`${xss}\napps/web/routes/profile.js\nres.send(req.query.name);\n`)));
  assert.doesNotMatch(JSON.stringify(payload), LEAKS);
});

test('the same location keeps its fingerprint when the line moves', () => {
  const doc = fixture('semgrep.sarif');
  const before = reduceSast(doc, opts).payload.findings;
  for (const r of doc.runs[0].results) r.locations[0].physicalLocation.region.startLine += 40;
  assert.deepEqual(reduceSast(doc, opts).payload.findings, before);
});

test('a result without a rule id is dropped and the scan marked truncated; duplicates merge at the most severe', () => {
  const doc = fixture('codeql.sarif');
  const [first] = doc.runs[0].results;
  doc.runs[0].results.push({ ...first, level: 'note', properties: { 'security-severity': '9.9' } });
  doc.runs[0].results.push({ message: { text: 'no rule' }, locations: first.locations });
  const { payload, dropped } = reduceSast(doc, opts);
  assert.equal(payload.truncated, true);
  assert.deepEqual(dropped, { count: 1, reasons: { 'no rule id': 1 }, ids: [] });
  assert.deepEqual(payload.counts, { critical: 2, high: 1, medium: 0, low: 1 });
});

test('more than 500 findings: the most severe 500 are sent, counts keep the totals, truncated', () => {
  const results = Array.from({ length: MAX_FINDINGS + 20 }, (_, i) => ({
    ruleId: `r/${i}`,
    level: i < 10 ? 'error' : 'note',
    partialFingerprints: { primaryLocationLineHash: `${String(i).padStart(16, '0')}:1` },
  }));
  const doc = { version: '2.1.0', runs: [{ tool: { driver: { name: 'CodeQL', semanticVersion: '2.19.3' } }, results }] };
  const { payload } = reduceSast(doc, opts);
  assert.equal(payload.findings.length, MAX_FINDINGS);
  assert.equal(payload.truncated, true);
  assert.deepEqual(payload.counts, { critical: 0, high: 10, medium: 0, low: MAX_FINDINGS + 10 });
  assert.equal(payload.findings[9].severity, 'high');
});

test('rule ids are kept in the schema pattern, a long one stable', () => {
  assert.equal(ruleId('js/sql-injection'), 'js/sql-injection');
  assert.equal(ruleId('my rule (custom)'), 'my-rule--custom-');
  const long = `a.${'b'.repeat(200)}`;
  assert.equal(ruleId(long).length, 128);
  assert.equal(ruleId(long), ruleId(long));
  assert.notEqual(ruleId(long), ruleId(`${long}c`));
});

test('refuses OSV-Scanner JSON or a forced osv format for a SAST scan', () => {
  assert.throws(() => reduceSast({ results: [] }, opts), /must be SARIF/);
  assert.throws(() => reduceSast(fixture('codeql.sarif'), { ...opts, format: 'osv' }), /must be SARIF/);
});

test('the fingerprint is salted by the repository: the same finding in another repository hashes differently', () => {
  const doc = fixture('codeql.sarif');
  const here = reduceSast(doc, opts).payload.findings.map((f) => f.fingerprint);
  const there = reduceSast(doc, { ...opts, subject: 'github:987654321' }).payload.findings.map((f) => f.fingerprint);
  assert.equal(here.length, there.length);
  assert.equal(here.filter((h) => there.includes(h)).length, 0);
  assert.throws(() => reduceSast(doc, { ...opts, subject: undefined }), /repository id is missing/);
});

test('whitespace in the matched code and the checkout directory of a file:// URI do not change the fingerprint', () => {
  const result = (uri, text) => ({
    ruleId: 'r/eval',
    level: 'error',
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { snippet: { text } } } }],
  });
  const doc = (r) => ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Semgrep OSS', semanticVersion: '1.0.0' } }, results: [r] }] });
  const fp = (r, workspace) => reduceSast(doc(r), { ...opts, workspace }).payload.findings[0].fingerprint;
  const base = fp(result('src/a.js', 'eval(x)'));
  assert.equal(fp(result('src/a.js', '  eval( x )\n')), fp(result('src/a.js', 'eval( x )')));
  assert.equal(fp(result('file:///home/runner/work/r/r/src/a.js', 'eval(x)'), '/home/runner/work/r/r'), base);
  assert.equal(fp(result('file:///other/dir/src/a.js', 'eval(x)'), '/other/dir/'), base);
  // Another file is another finding.
  assert.notEqual(fp(result('src/b.js', 'eval(x)')), base);
});

// Real output (test/fixtures/real/README.md): CodeQL 2.27.4 and Semgrep OSS 1.185.0 on a
// small sample repository. Fingerprints are pinned: they must never change, or every
// finding of every customer starts a new SLA clock.
const real = (name) => reduceSast(fixture(`real/${name}`), opts).payload;

test('real CodeQL (JavaScript): partialFingerprints decide the fingerprint, pinned', () => {
  const p = real('codeql-javascript.real.sarif');
  assert.deepEqual(p.tool, { name: 'CodeQL', version: '2.27.4' });
  assert.deepEqual(p.counts, { critical: 1, high: 3, medium: 0, low: 0 });
  assert.deepEqual(p.findings, [
    { rule: 'js/code-injection', severity: 'critical', fingerprint: '9d8d67e8bba52efeb5a35eb48080b3c764b0d4453253f8dc7433d44d9d733a2b' },
    { rule: 'js/missing-rate-limiting', severity: 'high', fingerprint: '180d3c4d33c047444ab0112b64511ab728114f82af1c6aa396198990ce266024' },
    { rule: 'js/reflected-xss', severity: 'high', fingerprint: '52cf6a1099fae85c1790249b1c16c0342b77c7f7d433ab295c6f64cf822c1676' },
    { rule: 'js/sql-injection', severity: 'high', fingerprint: '35521c336748b3921a95ff539ae3764d295523ecd0d7d63f3f03ca2207775c7c' },
  ]);
  // Written out: the rule and CodeQL's own line hash, nothing of the path.
  assert.equal(p.findings[0].fingerprint, hmac('js/code-injection\nprimaryLocationLineHash=2448f5b175dda4b1:1'));
  assert.equal(p.truncated, false);
  assert.doesNotMatch(JSON.stringify(p), /app\.js|web\/|startLine|2448f5b1/);
});

test('real CodeQL (Python), pinned', () => {
  const p = real('codeql-python.real.sarif');
  assert.deepEqual(p.findings, [
    { rule: 'py/command-line-injection', severity: 'critical', fingerprint: 'cd8d0227ff46684e5796c26118902a91a5204115877dfc84d6fccc87b321d374' },
  ]);
});

test('real Semgrep OSS: the "requires login" fingerprint is ignored, the hash is of rule, file and code, pinned', () => {
  const doc = fixture('real/semgrep.real.sarif');
  assert.ok(doc.runs[0].results.every((r) => r.fingerprints['matchBasedId/v1'] === 'requires login'));
  const p = reduceSast(doc, opts).payload;
  assert.deepEqual(p.tool, { name: 'Semgrep OSS', version: '1.185.0' });
  assert.deepEqual(p.counts, { critical: 0, high: 2, medium: 3, low: 0 });
  assert.deepEqual(
    p.findings.map((f) => f.fingerprint),
    [
      'bb206beff9951e40b55e8a512af6786714fa800cb02e105ee819925491eaf90a',
      '51d63366d330d5ef938e9f15d7c816c3b9ae5ae63373145084dfea5dc8e4db9b',
      '57e6fc18afbc9d64f759c224d99b481b6ec5a1e76725cf419a69bf41083885c5',
      '9ecf82f748749f579c44b350b22902de98663eec280723d4d3714ca80a7a4209',
      '507fc5ca626b6a734f82fd18af40b814967b88da17502a61f4f5942306c32306',
    ],
  );
  // Two results of one rule in one file stay two findings (their matched code differs).
  assert.equal(p.findings.filter((f) => f.rule.endsWith('direct-response-write')).length, 2);
  assert.doesNotMatch(JSON.stringify(p), /app\.js|run_job|web\/|tools\/|res\.send/);
});

test('v2 files: CodeQL\'s extracted files and every result\'s file, merged runs counted once; files-scanned and scannerVersion win', () => {
  const js = fixture('real/codeql-javascript.real.sarif');
  const py = fixture('real/codeql-python.real.sarif');
  // Each run lists both languages' files as artifacts: only its extracted one counts.
  assert.equal(reduceSast(js, opts).payload.files, 1);
  assert.equal(reduceSast(py, opts).payload.files, 1);
  assert.equal(reduceSast({ version: '2.1.0', runs: [...js.runs, ...py.runs] }, opts).payload.files, 2);
  // Semgrep names only the files with results.
  const semgrep = reduceSast(fixture('real/semgrep.real.sarif'), opts).payload;
  assert.ok(semgrep.files > 0);
  const clean = { version: '2.1.0', runs: [{ tool: { driver: { name: 'Semgrep OSS', semanticVersion: '1.95.0' } }, results: [] }] };
  assert.equal(reduceSast(clean, opts).payload.files, 0);
  const given = reduceSast(clean, { ...opts, filesScanned: 120, scannerVersion: '1.96.0' }).payload;
  assert.equal(given.files, 120);
  assert.equal(given.tool.version, '1.96.0');
  for (const p of [semgrep, given, reduceSast(js, opts).payload, reduceSast(fixture('codeql.sarif'), opts).payload]) assertValid('sast_scan.v2', p);
  assert.doesNotMatch(JSON.stringify(reduceSast(js, opts).payload), LEAKS);
});
