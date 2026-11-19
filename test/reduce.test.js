'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('fs');
const { join } = require('path');
const { reduce: reduceAll, parsePurl, findPurl, fromScore, MAX_FINDINGS } = require('../src/reduce');

const { assertValid } = require('./schemas');

const reduce = (doc, o) => reduceAll(doc, o).payload;

const fixture = (name) => JSON.parse(readFileSync(join(__dirname, 'fixtures', name), 'utf8'));
const opts = { commit: 'a'.repeat(40), scannedAt: '2026-11-13T08:00:00.000Z' };

test('OSV-Scanner JSON: one finding per alias group, worst first, no paths', () => {
  const p = reduce(fixture('osv-scanner.json'), opts);
  assert.deepEqual(p, {
    tool: { name: 'osv-scanner', version: 'unknown' },
    commit: 'a'.repeat(40),
    scanned_at: opts.scannedAt,
    counts: { critical: 1, high: 2, medium: 1, low: 0 },
    findings: [
      { advisory: 'GHSA-aaaa-bbbb-cccc', ecosystem: 'npm', package: '@example/parser', version: '1.0.0', severity: 'critical', fixed_in: '1.0.1' },
      { advisory: 'GHSA-35jh-r3h4-6jhm', ecosystem: 'npm', package: 'example-template', version: '4.17.20', severity: 'high', fixed_in: '4.17.21', aliases: ['CVE-2021-23337'] },
      // No severity anywhere: sent as high, never hidden as low.
      { advisory: 'GHSA-dddd-eeee-ffff', ecosystem: 'PyPI', package: 'example-http', version: '2.0.0', severity: 'high', fixed_in: null },
      { advisory: 'PYSEC-2024-1', ecosystem: 'PyPI', package: 'example-http', version: '2.0.0', severity: 'medium', fixed_in: null },
    ],
    truncated: false,
    // The fixture's 3 packages; the caller sets the lockfile hash.
    components: 3,
    lockfile_sha256: null,
  });
  assert.doesNotMatch(JSON.stringify(p), /runner|package-lock|requirements/);
  assertValid('dependency_scan.v2', p);
});

test('v2: components counts every package OSV-Scanner lists (--all-packages), else the findings\' packages; lockfiles it names', () => {
  const doc = fixture('osv-scanner.json');
  doc.results[0].packages.push({ package: { name: 'clean-pkg', version: '1.0.0', ecosystem: 'npm' }, vulnerabilities: [], groups: [] });
  const r = reduceAll(doc, opts);
  assert.equal(r.payload.components, 4);
  assert.deepEqual(r.lockfiles, ['/home/runner/work/payments-api/package-lock.json', '/home/runner/work/payments-api/requirements.txt']);
  // SARIF has no inventory: the distinct packages of its findings (2 written).
  const t = reduceAll(fixture('trivy.sarif'), opts);
  assert.equal(t.payload.components, 2);
  for (const name of ['trivy.sarif', 'purl.sarif', 'real/osv-scanner.real.sarif', 'real/grype.real.sarif', 'real/osv-scanner.real.json']) {
    assertValid('dependency_scan.v2', reduce(fixture(name), opts));
  }
  // An empty scan reads 0 packages.
  assert.equal(reduce({ results: [] }, opts).components, 0);
  // Only lockfile names are offered to be hashed, never another path of the results file.
  const sarif = { version: '2.1.0', runs: [{ tool: { driver: { name: 'osv-scanner' } }, artifacts: [{ location: { uri: 'file:///etc/passwd' } }, { location: { uri: 'web/yarn.lock' } }], results: [] }] };
  assert.deepEqual(reduceAll(sarif, opts).lockfiles, ['web/yarn.lock']);
});

test('v2: scannerVersion is sent over the file\'s version (OSV-Scanner JSON names none)', () => {
  assert.equal(reduce(fixture('osv-scanner.json'), { ...opts, scannerVersion: '2.7.1' }).tool.version, '2.7.1');
  assert.deepEqual(reduce(fixture('trivy.sarif'), { ...opts, scannerVersion: '0.57.0' }).tool, { name: 'Trivy', version: '0.57.0' });
});

test('SARIF (Trivy): package lines from the message, ecosystem from the lockfile name, unreadable results mark it truncated', () => {
  const p = reduce(fixture('trivy.sarif'), opts);
  assert.deepEqual(p.tool, { name: 'Trivy', version: '0.56.2' });
  assert.deepEqual(p.findings, [
    { advisory: 'CVE-2022-25883', ecosystem: 'npm', package: 'example-semver', version: '7.3.7', severity: 'high', fixed_in: '7.5.2' },
    { advisory: 'CVE-2024-0001', ecosystem: 'crates.io', package: 'example-yaml', version: '0.1.0', severity: 'low', fixed_in: null },
  ]);
  // The third result names no package: not sent, and the list says so.
  assert.equal(p.truncated, true);
  assert.deepEqual(reduceAll(fixture('trivy.sarif'), opts).dropped, {
    count: 1,
    reasons: { 'no usable package name': 1 },
    ids: ['CVE-2024-0002'],
  });
  assert.doesNotMatch(JSON.stringify(p), /services\/web|Dockerfile/);
});

test('SARIF with package URLs (Grype style): advisory cut from the rule id, Maven group:artifact', () => {
  const p = reduce(fixture('purl.sarif'), opts);
  assert.deepEqual(p.tool, { name: 'grype', version: '0.80.0' });
  assert.deepEqual(p.findings, [
    { advisory: 'GHSA-xxxx-yyyy-zzzz', ecosystem: 'Maven', package: 'org.example:example-core', version: '2.14.1', severity: 'critical', fixed_in: null },
    { advisory: 'CVE-2023-1111', ecosystem: 'PyPI', package: 'example-lib', version: '1.0', severity: 'high', fixed_in: null },
  ]);
  assert.equal(p.truncated, false);
});

test('more than 500 findings: the 500 worst are sent, counts keep the totals, truncated', () => {
  const pkg = (i, sev) => ({
    package: { name: `lib-${i}`, version: '1.0.0', ecosystem: 'npm' },
    vulnerabilities: [{ id: `GHSA-${String(i).padStart(4, '0')}-aaaa-bbbb`, database_specific: { severity: sev } }],
  });
  const doc = {
    results: [{ packages: [...Array.from({ length: 520 }, (_, i) => pkg(i, 'LOW')), pkg(9999, 'CRITICAL')] }],
  };
  const p = reduce(doc, opts);
  assert.equal(p.findings.length, MAX_FINDINGS);
  assert.equal(p.findings[0].severity, 'critical');
  assert.deepEqual(p.counts, { critical: 1, high: 0, medium: 0, low: 520 });
  assert.equal(p.truncated, true);
});

test('refuses what it cannot read', () => {
  assert.throws(() => reduce({ hello: 1 }, opts), { code: 'results' });
  assert.throws(() => reduce({ results: [] }, { ...opts, commit: 'abc' }), { code: 'commit' });
  assert.deepEqual(reduce({ results: [] }, opts).findings, []);
});

test('helpers', () => {
  assert.deepEqual(parsePurl('pkg:npm/%40scope/name@1.2.3'), { ecosystem: 'npm', package: '@scope/name', version: '1.2.3' });
  assert.equal(parsePurl('nope'), null);
  assert.deepEqual([9, 7, 4, 0.1, 11, 'x'].map(fromScore), ['critical', 'high', 'medium', 'low', null, null]);
});

// Outputs of the real tools, from their own projects' golden test outputs
// (provenance in test/fixtures/real/README.md).
const real = (name) => reduceAll(fixture(join('real', name)), opts);

test('real OSV-Scanner SARIF: package and version from the message, all ids as aliases, ecosystem from the lockfile', () => {
  const r = real('osv-scanner.real.sarif');
  assert.deepEqual(r.payload.tool, { name: 'osv-scanner', version: '2.7.1' });
  assert.deepEqual(r.payload.findings, [
    { advisory: 'CVE-2021-23424', ecosystem: 'npm', package: 'ansi-html', version: '0.0.1', severity: 'high', fixed_in: null, aliases: ['GHSA-whgm-jr23-g3j9'] },
  ]);
  assert.equal(r.payload.truncated, false);
  assert.equal(r.dropped.count, 0);
  assert.doesNotMatch(JSON.stringify(r.payload), /rootdir|package-lock/);
});

test('real OSV-Scanner SARIF: a git dependency pinned by commit is sent with the commit as its version', () => {
  const r = real('osv-scanner-git.real.sarif');
  assert.deepEqual(
    r.payload.findings.map((f) => [f.advisory, f.package, f.version, f.aliases]),
    [
      ['CVE-2023-39137', 'https://github.com/brendan-duncan/archive.git', '6fc3b89f', ['GHSA-r285-q736-9v95']],
      ['CVE-2023-39139', 'https://github.com/brendan-duncan/archive.git', '6fc3b89f', ['GHSA-9v85-q87q-g4vg']],
    ],
  );
  assert.equal(r.payload.truncated, false);
});

test('real OSV-Scanner JSON: an empty version takes the commit, one finding per advisory and package', () => {
  const r = real('osv-scanner.real.json');
  assert.deepEqual(
    r.payload.findings.map((f) => [f.advisory, f.ecosystem, f.package, f.version, f.severity]),
    [
      ['OSV-1', 'npm', 'mine1', '1.2.3', 'high'],
      ['OSV-2', 'npm', 'mine2', 'abc123', 'high'],
    ],
  );
  assert.equal(r.payload.truncated, false);
});

test('real Trivy SARIF: package lines from the message', () => {
  const r = real('trivy.real.sarif');
  assert.deepEqual(r.payload.tool, { name: 'Trivy', version: 'dev' });
  assert.deepEqual(r.payload.findings[0], {
    advisory: 'CVE-2019-1549', ecosystem: 'unknown', package: 'libcrypto1.1', version: '1.1.1c-r0', severity: 'medium', fixed_in: '1.1.1d-r0',
  });
  assert.equal(r.payload.findings.length, 4);
  assert.equal(r.payload.truncated, false);
  assert.doesNotMatch(JSON.stringify(r.payload), /alpine-310\.tar/);
});

test("real Grype SARIF: advisory, package, version, type and the first fix from the rule's help", () => {
  const r = real('grype.real.sarif');
  assert.deepEqual(r.payload.findings, [
    { advisory: 'CVE-1999-0001', ecosystem: 'rpm', package: 'package-1', version: '1.1.1', severity: 'high', fixed_in: '1.2.1' },
    { advisory: 'CVE-1999-0002', ecosystem: 'deb', package: 'package-2', version: '2.2.2', severity: 'high', fixed_in: null },
  ]);
  assert.equal(r.payload.truncated, false);
  assert.doesNotMatch(JSON.stringify(r.payload), /some\/path/);
});

test('Trivy lists several fixed versions: the first is sent', () => {
  const doc = {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Trivy', version: '0.56.2' } },
      results: [{ ruleId: 'CVE-2024-9', message: { text: 'Package: lib\nInstalled Version: 1.0.0\nSeverity: HIGH\nFixed Version: 1.2.3, 2.0.1' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'go.mod' } } }] }],
    }],
  };
  assert.equal(reduce(doc, opts).findings[0].fixed_in, '1.2.3');
});

test('odd shapes: a prototype key as level, an array as fixed version, wrong types', () => {
  const sarif = (result) => ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'x' } }, results: [result] }] });
  const p = reduce(sarif({ ruleId: 'CVE-2024-1', level: '__proto__', message: { text: 'Package: a\nInstalled Version: 1.0.0' } }), opts);
  assert.equal(p.findings[0].severity, 'high');
  assert.deepEqual(Object.keys(p.counts), ['critical', 'high', 'medium', 'low']);
  const osv = { results: [{ packages: [{ package: { name: 'a', version: '1.0.0', ecosystem: 'npm' }, vulnerabilities: [{ id: 'GHSA-1', affected: [{ ranges: [{ events: [{ fixed: ['1.2.3'] }] }] }] }] }] }] };
  assert.equal(reduce(osv, opts).findings[0].fixed_in, null);
  for (const doc of [5, null, { results: 5 }, { results: [{ packages: [{ vulnerabilities: 5, groups: [{ ids: 5 }] }] }] }]) {
    try {
      reduce(doc, { ...opts, format: 'osv' });
    } catch (e) {
      assert.equal(e.code, 'results');
      assert.doesNotMatch(e.message, /TypeError|Cannot read/);
    }
  }
  assert.throws(() => reduce(5, { ...opts, format: 'sarif' }), { code: 'results' });
});

test('dropped findings are counted by reason, with their advisory ids', () => {
  const pkg = (id, name, version) => ({ package: { name, version, ecosystem: 'npm' }, vulnerabilities: [{ id }] });
  const r = reduceAll(
    { results: [{ packages: [pkg('GHSA-1', 'ok', '1.0.0'), pkg('GHSA-2', 'bad name!', '1.0.0'), pkg('GHSA-3', 'x', ''), pkg('bad id!', 'y', '1.0.0')] }] },
    opts,
  );
  assert.equal(r.payload.findings.length, 1);
  assert.equal(r.payload.truncated, true);
  assert.deepEqual(r.dropped, {
    count: 3,
    reasons: { 'no usable package name': 1, 'no usable version': 1, 'no usable advisory id': 1 },
    ids: ['GHSA-2', 'GHSA-3'],
  });
});

test('findPurl is linear on hostile text (no rescan from every pkg: prefix)', () => {
  const hostile = 'pkg:a/'.repeat(200_000); // 1.2 MB
  const t0 = process.hrtime.bigint();
  assert.equal(findPurl({ message: { text: hostile } }), null);
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 500, 'findPurl took over 500 ms');
  assert.equal(findPurl('see pkg:npm/%40scope/name@1.2.3 here'), 'pkg:npm/%40scope/name@1.2.3');
});

test('findings are ordered by code unit, whatever the locale', () => {
  const pkg = (id) => ({ package: { name: 'a', version: '1.0.0', ecosystem: 'npm' }, vulnerabilities: [{ id, database_specific: { severity: 'HIGH' } }] });
  const p = reduce({ results: [{ packages: [pkg('b-1'), pkg('B-1'), pkg('a-1')] }] }, opts);
  assert.deepEqual(p.findings.map((f) => f.advisory), ['B-1', 'a-1', 'b-1']);
});
