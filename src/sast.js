'use strict';

const { createHash, createHmac } = require('crypto');
const { ActionError, detect, fromScore, LEVEL, MAX_FINDINGS } = require('./reduce');

/**
 * Reduces a SAST scanner's SARIF 2.1.0 (CodeQL, Semgrep, …) to Complyd's
 * `sast_scan` v1 payload: tool {name, version}, commit, scanned_at, counts,
 * findings[] (≤ 500: rule id, severity, fingerprint) and truncated. A
 * finding's location is sent only as an HMAC-SHA-256 computed here, keyed by
 * the repository's subject id (`github:<repository id>`, `gitlab-oidc:…`; a salt,
 * not a secret): no file
 * path, line number, code snippet or message leaves the runner in clear. The
 * hash can still be confirmed by someone who holds the code or guesses the
 * path, since the repository id is stored beside it.
 */

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const TOOL_NAME = /^[A-Za-z0-9 ._/@+-]{1,64}$/;
const TOOL_VERSION = /^[A-Za-z0-9._+-]{1,40}$/;
// A scanner's own fingerprint is used only when it looks like a hash:
// Semgrep OSS writes the placeholder "requires login" for every result.
const HASHLIKE = /^[0-9a-f]{16,}(:[0-9]+)?$/i;

const list = (v) => (Array.isArray(v) ? v : []);
const str = (v) => (typeof v === 'string' ? v : null);
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const rank = (s) => SEVERITIES.indexOf(s);
/** Code-unit order: the same on every runner, whatever its locale. */
const byCode = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * A rule id in the schema's pattern: other characters become '-'; one over
 * 128 characters keeps its first 111 and a 16-hex hash of the whole, so it
 * stays the same id on every run.
 */
function ruleId(raw) {
  const s = raw.replace(/[^A-Za-z0-9._:/@+-]/g, '-');
  return s.length <= 128 ? s : `${s.slice(0, 111)}.${sha256(raw).slice(0, 16)}`;
}

/** The scanner's first hash-like fingerprint, in key order, or null. */
function scannerFingerprint(result) {
  for (const fp of [result.fingerprints, result.partialFingerprints]) {
    if (!fp || typeof fp !== 'object') continue;
    for (const key of Object.keys(fp).sort(byCode)) {
      if (HASHLIKE.test(str(fp[key]) ?? '')) return `${key}=${fp[key]}`;
    }
  }
  return null;
}

/**
 * A file location as the scanner wrote it, without the checkout's own
 * directory: a `file://` URI loses its scheme and, when it lies under the
 * workspace, the workspace's path, so a finding keeps its fingerprint when the
 * runner checks the code out somewhere else.
 */
function relativeUri(uri, workspace) {
  let u = uri.replace(/^file:\/\//i, '');
  if (workspace && uri !== u) {
    const w = workspace.replace(/\/+$/, '');
    if (w && u.startsWith(`${w}/`)) u = u.slice(w.length + 1);
  }
  return u;
}

/**
 * Where a finding is, as an HMAC-SHA-256 keyed by `salt` (the subject id,
 * e.g. `github:<repository id>`): of the rule and the scanner's own fingerprint, else of the rule, the
 * file and the matched code with its whitespace collapsed (no line number, so
 * a finding keeps its identity when code above it moves or a formatter runs).
 * Two findings of one rule in one file with no fingerprint or snippet are one.
 */
function fingerprint(rule, result, salt, workspace) {
  const hmac = (s) => createHmac('sha256', salt).update(s).digest('hex');
  const own = scannerFingerprint(result);
  if (own) return hmac(`${rule}\n${own}`);
  const loc = list(result.locations)[0]?.physicalLocation ?? {};
  const uri = relativeUri(str(loc.artifactLocation?.uri) ?? '', workspace);
  const snippet = (str(loc.region?.snippet?.text) ?? '').replace(/\s+/g, ' ').trim();
  const message = uri || snippet ? '' : (str(result.message?.text) ?? '');
  return hmac([rule, uri, snippet, message].join('\n'));
}

/** Results that are not open findings: passes, suppressed or fixed ones. */
function isOpen(result) {
  if (result.kind && result.kind !== 'fail') return false;
  if (result.baselineState === 'absent') return false;
  // Suppressed in the code or the tool (accepted, or no status given).
  return !list(result.suppressions).some((s) => !s?.status || s.status === 'accepted');
}

/**
 * Severity: `security-severity` (CVSS: 9+ critical, 7+ high, 4+ medium,
 * else low; CodeQL), else the level (`error` high, `warning` medium, `note`
 * low; Semgrep), else SARIF's default level, warning.
 */
function severityOf(result, rule) {
  const level = str(result.level) ?? str(rule.defaultConfiguration?.level) ?? 'warning';
  return (
    fromScore(result.properties?.['security-severity']) ??
    fromScore(rule.properties?.['security-severity']) ??
    LEVEL.get(level) ??
    'medium'
  );
}

/**
 * SARIF (parsed) → { payload, dropped }, as `reduce` for dependency scans. A
 * result with no rule id can't be named: it is dropped and marks the scan
 * truncated.
 */
function reduceSast(doc, { format = 'auto', commit, scannedAt, subject, workspace = '' }) {
  if ((format !== 'auto' && format !== 'sarif') || detect(doc) !== 'sarif') {
    throw new ActionError('results', "A SAST scan must be SARIF 2.1.0: check the scanner's output option.");
  }
  if (!/^[0-9a-f]{40}$/.test(String(commit))) {
    throw new ActionError('commit', "The commit (GITHUB_SHA, CI_COMMIT_SHA or --commit) isn't a 40-character SHA.");
  }
  if (typeof subject !== 'string' || !subject) {
    throw new ActionError('input', 'The repository id is missing.');
  }
  const salt = subject;
  let tool = null;
  let droppedCount = 0;
  const byKey = new Map();
  for (const run of list(doc.runs)) {
    const driver = run?.tool?.driver ?? {};
    tool ??= { name: driver.name, version: driver.semanticVersion ?? driver.version };
    const rules = list(driver.rules);
    const byId = new Map(rules.map((r) => [r?.id, r]));
    for (const result of list(run?.results)) {
      if (!result || typeof result !== 'object' || !isOpen(result)) continue;
      const index = result.ruleIndex ?? result.rule?.index;
      const rule = byId.get(result.ruleId) ?? (Number.isInteger(index) ? rules[index] : undefined) ?? {};
      const raw = str(result.ruleId) ?? str(result.rule?.id) ?? str(rule.id);
      if (!raw) {
        droppedCount += 1;
        continue;
      }
      const id = ruleId(raw);
      const f = { rule: id, severity: severityOf(result, rule), fingerprint: fingerprint(raw, result, salt, workspace) };
      const key = `${f.rule}#${f.fingerprint}`;
      const had = byKey.get(key);
      if (!had || rank(f.severity) < rank(had.severity)) byKey.set(key, f);
    }
  }
  const findings = [...byKey.values()].sort(
    (a, b) => rank(a.severity) - rank(b.severity) || byCode(a.rule, b.rule) || byCode(a.fingerprint, b.fingerprint),
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] += 1;
  const clean = (v, re, max, fallback) => {
    const s = String(v ?? '').replace(/[^A-Za-z0-9 ._/@+-]/g, '-').slice(0, max);
    return re.test(s) ? s : fallback;
  };
  const payload = {
    tool: {
      name: clean(tool?.name, TOOL_NAME, 64, 'unknown'),
      version: clean(tool?.version, TOOL_VERSION, 40, 'unknown'),
    },
    commit,
    scanned_at: scannedAt,
    counts,
    findings: findings.slice(0, MAX_FINDINGS),
    truncated: droppedCount > 0 || findings.length > MAX_FINDINGS,
  };
  const dropped = { count: droppedCount, reasons: droppedCount ? { 'no rule id': droppedCount } : {}, ids: [] };
  return { payload, dropped };
}

module.exports = { reduceSast, ruleId };
