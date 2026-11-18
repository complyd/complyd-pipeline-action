'use strict';

/**
 * Reduces a scanner's output to Complyd's `dependency_scan` v1 payload:
 * tool {name, version}, commit, scanned_at, counts, findings[] (≤ 500:
 * advisory, ecosystem, package, version, severity, fixed_in) and truncated.
 * The payload holds nothing else: no file paths, no code, no author,
 * committer or actor (the CI's sign-in token, sent beside it, is not part
 * of it). The patterns below are the payload schema's; a finding
 * that can't be written in them is not sent and marks the scan truncated,
 * so a cut list never reads as a complete one.
 */

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const MAX_FINDINGS = 500;

const PATTERN = {
  toolName: /^[A-Za-z0-9 ._/@+-]{1,64}$/,
  toolVersion: /^[A-Za-z0-9._+-]{1,40}$/,
  advisory: /^[A-Za-z0-9._:-]{1,64}$/,
  ecosystem: /^[A-Za-z0-9._ :-]{1,40}$/,
  package: /^[A-Za-z0-9@._/:+~-]{1,214}$/,
  version: /^[A-Za-z0-9._+:~-]{1,64}$/,
};

/** A CVSS base score (0–10) → its band; anything else → null. */
function fromScore(value) {
  const score = Number.parseFloat(String(value));
  if (!Number.isFinite(score) || score < 0 || score > 10) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/** A scanner's severity word → ours; anything else → null. */
function fromWord(value) {
  const w = String(value ?? '').toLowerCase();
  if (w === 'critical') return 'critical';
  if (w === 'high') return 'high';
  if (w === 'moderate' || w === 'medium') return 'medium';
  if (w === 'low' || w === 'negligible' || w === 'info') return 'low';
  return null;
}

/** Disallowed characters become '-', cut to the length the pattern allows. */
function clean(value, pattern, max, fallback) {
  const s = String(value ?? '')
    .replace(/[^A-Za-z0-9 ._/@+-]/g, '-')
    .slice(0, max);
  return pattern.test(s) ? s : fallback;
}

/** purl type → OSV ecosystem name (https://ossf.github.io/osv-schema/). */
const PURL_ECOSYSTEM = {
  npm: 'npm',
  pypi: 'PyPI',
  golang: 'Go',
  maven: 'Maven',
  cargo: 'crates.io',
  gem: 'RubyGems',
  nuget: 'NuGet',
  composer: 'Packagist',
  pub: 'Pub',
  hex: 'Hex',
  swift: 'SwiftURL',
};

/** Lockfile name → ecosystem, read only to name the ecosystem (never sent). */
const LOCKFILE_ECOSYSTEM = [
  [/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/, 'npm'],
  [/(^|\/)(requirements[^/]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock)$/, 'PyPI'],
  [/(^|\/)go\.(mod|sum)$/, 'Go'],
  [/(^|\/)Cargo\.lock$/, 'crates.io'],
  [/(^|\/)Gemfile\.lock$/, 'RubyGems'],
  [/(^|\/)(pom\.xml|gradle\.lockfile|build\.gradle(\.kts)?)$/, 'Maven'],
  [/(^|\/)composer\.lock$/, 'Packagist'],
  [/(^|\/)packages\.lock\.json$/, 'NuGet'],
  [/(^|\/)pubspec\.lock$/, 'Pub'],
  [/(^|\/)mix\.lock$/, 'Hex'],
];

function ecosystemOfPath(path) {
  const hit = LOCKFILE_ECOSYSTEM.find(([re]) => re.test(String(path ?? '')));
  return hit ? hit[1] : null;
}

/** `pkg:npm/%40scope/name@1.2.3` → {ecosystem, package, version}, or null. */
function parsePurl(purl) {
  const m = /^pkg:([a-z0-9.+-]+)\/([^@?#\s]+)@([^?#\s]+)/i.exec(String(purl));
  if (!m) return null;
  const type = m[1].toLowerCase();
  let name;
  let version;
  try {
    name = decodeURIComponent(m[2]);
    version = decodeURIComponent(m[3]);
  } catch {
    return null;
  }
  // Maven (and others) put the namespace before the name: group/artifact.
  if (type === 'maven') name = name.replace('/', ':');
  return {
    ecosystem: Object.hasOwn(PURL_ECOSYSTEM, type) ? PURL_ECOSYSTEM[type] : type,
    package: name,
    version,
  };
}

/** Longest text searched for a purl: a purl is short, a message may not be. */
const MAX_SEARCH = 64 * 1024;
// Bounded quantifiers and no `@` in the name: each try is O(1), the scan linear.
const PURL_IN_TEXT = /pkg:[a-z0-9.+-]{1,32}\/[^\s"'<>@]{1,256}@[^\s"'<>?#]{1,128}/i;

/** The first purl in a value (strings, arrays, objects up to 6 deep), or null. */
function findPurl(value, depth = 0) {
  if (depth > 6 || value === null || value === undefined) return null;
  if (typeof value === 'string') {
    return PURL_IN_TEXT.exec(value.slice(0, MAX_SEARCH))?.[0] ?? null;
  }
  if (typeof value !== 'object') return null;
  for (const v of Object.values(value)) {
    const hit = findPurl(v, depth + 1);
    if (hit) return hit;
  }
  return null;
}

const str = (v) => (typeof v === 'string' ? v : null);

/** OSV-Scanner JSON (`osv-scanner --format json`). */
function fromOsv(doc) {
  const raw = [];
  for (const result of list(doc.results)) {
    for (const pkg of list(result?.packages)) {
      const p = pkg?.package ?? {};
      const vulns = new Map(list(pkg.vulnerabilities).map((v) => [v?.id, v]));
      // One finding per group of aliases (GHSA-… and CVE-… of one issue).
      const groups = list(pkg.groups).length
        ? list(pkg.groups).map((g) => ({ ids: list(g?.ids), aliases: list(g?.aliases), max: g?.max_severity }))
        : [...vulns.keys()].map((id) => ({ ids: [id], aliases: [], max: undefined }));
      for (const g of groups) {
        const id = g.ids.find((i) => /^GHSA-/.test(i)) ?? g.ids[0];
        const vs = g.ids.map((i) => vulns.get(i)).filter(Boolean);
        const severity =
          fromScore(g.max) ??
          vs.map((v) => fromWord(v.database_specific?.severity)).find(Boolean) ??
          null;
        raw.push({
          advisory: id,
          aliases: [...g.ids, ...g.aliases, ...vs.flatMap((v) => list(v.aliases))],
          ecosystem: p.ecosystem,
          package: p.name,
          // A package pinned by commit (git dependency) has no version.
          version: str(p.version) || str(p.commit),
          severity,
          fixed_in: fixedIn(vs, p),
        });
      }
    }
  }
  return { tool: { name: 'osv-scanner', version: null }, raw };
}

const list = (v) => (Array.isArray(v) ? v : []);

/** The first `fixed` event of the affected range for this package. */
function fixedIn(vulns, p) {
  for (const v of vulns) {
    for (const a of list(v.affected)) {
      if (a?.package && (a.package.name !== p.name || a.package.ecosystem !== p.ecosystem)) {
        continue;
      }
      for (const r of list(a?.ranges)) {
        const fixed = str(list(r?.events).find((e) => str(e?.fixed))?.fixed);
        if (fixed) return fixed;
      }
    }
  }
  return null;
}

/**
 * "Label: value" lines of a SARIF text: Trivy's message ("Package: x\n
 * Installed Version: y\n…Fixed Version: z") and Grype's rule help ("Package:
 * x\nVersion: y\nFix Version: a,b\nType: npm"). A list of fixed versions
 * gives its first.
 */
function fromLines(text) {
  const t = String(text ?? '').slice(0, MAX_SEARCH);
  const line = (label) => new RegExp(`^(?:${label}):[ \\t]*(\\S[^\\n]*)$`, 'mi').exec(t)?.[1].trim() ?? null;
  const first = (v) => v?.split(/[,\s]+/)[0] || null;
  return {
    advisory: /^Vulnerability:?[ \t]+(\S+)[ \t]*$/mi.exec(t)?.[1] ?? null,
    package: line('Package'),
    version: line('Installed Version|Version'),
    fixed_in: first(line('Fixed Version|Fix Version')),
    severity: fromWord(line('Severity')),
    type: line('Type'),
  };
}

/**
 * OSV-Scanner's SARIF message: "Package 'name@1.2.3' is vulnerable to
 * 'CVE-…' (also known as 'GHSA-…', '…')." The name may hold an `@` (npm
 * scopes), so the version is after the last one.
 */
function fromOsvMessage(text) {
  const m = /^Package '([^']{1,512})' is vulnerable to '([^']{1,128})'/.exec(String(text ?? ''));
  if (!m) return null;
  const at = m[1].lastIndexOf('@');
  return at > 0 ? { package: m[1].slice(0, at), version: m[1].slice(at + 1), advisory: m[2] } : null;
}

/** Grype's package types → OSV ecosystem names (others pass through). */
const GRYPE_TYPE = {
  npm: 'npm',
  python: 'PyPI',
  'go-module': 'Go',
  'java-archive': 'Maven',
  gem: 'RubyGems',
  'rust-crate': 'crates.io',
  dotnet: 'NuGet',
  'php-composer': 'Packagist',
  'dart-pub': 'Pub',
  hex: 'Hex',
};

const LEVEL = new Map([
  ['error', 'high'],
  ['warning', 'medium'],
  ['note', 'low'],
  ['none', 'low'],
]);

/** SARIF 2.1.0 from a dependency scanner (osv-scanner, Trivy, Grype, …). */
function fromSarif(doc) {
  const raw = [];
  let tool = null;
  for (const run of list(doc.runs)) {
    const driver = run?.tool?.driver ?? {};
    tool ??= { name: driver.name, version: driver.semanticVersion ?? driver.version };
    const rules = new Map(list(driver.rules).map((r) => [r?.id, r]));
    for (const result of list(run?.results)) {
      const rule = rules.get(result?.ruleId) ?? list(driver.rules)[result?.ruleIndex] ?? {};
      const text = str(result.message?.text) ?? '';
      const props = result.properties ?? {};
      const purl = parsePurl(
        str(list(props.purls)[0]) ?? str(props.purl) ?? findPurl(result) ?? findPurl(rule.properties) ?? '',
      );
      const osv = fromOsvMessage(text);
      const msg = fromLines(text);
      const help = fromLines(rule.help?.text);
      const uri = result.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
      const tags = [...list(rule.properties?.tags), ...list(props.tags)];
      const level = result.level ?? rule.defaultConfiguration?.level;
      const severity =
        fromScore(rule.properties?.['security-severity']) ??
        fromScore(props['security-severity']) ??
        msg.severity ??
        help.severity ??
        tags.map(fromWord).find(Boolean) ??
        (typeof level === 'string' ? LEVEL.get(level) : undefined) ??
        null;
      const type = help.type ?? msg.type;
      raw.push({
        // Grype's rule ids carry the package after the advisory.
        advisory:
          osv?.advisory ??
          help.advisory ??
          /^(GHSA-[\w-]{14}|CVE-\d{4}-\d+)/.exec(str(result.ruleId) ?? '')?.[0] ??
          result.ruleId,
        // OSV-Scanner lists every id of the group as the rule's deprecated ids.
        aliases: list(rule.deprecatedIds),
        ecosystem:
          purl?.ecosystem ??
          (type && Object.hasOwn(GRYPE_TYPE, type) ? GRYPE_TYPE[type] : type) ??
          ecosystemOfPath(uri) ??
          'unknown',
        package: purl?.package ?? osv?.package ?? msg.package ?? help.package,
        version: purl?.version ?? osv?.version ?? msg.version ?? help.version,
        severity,
        fixed_in: msg.fixed_in ?? help.fixed_in,
      });
    }
  }
  return { tool: tool ?? { name: null, version: null }, raw };
}

/** 'sarif' or 'osv' for a parsed document, or null. */
function detect(doc) {
  if (doc && Array.isArray(doc.runs) && typeof doc.version === 'string') return 'sarif';
  if (doc && Array.isArray(doc.results)) return 'osv';
  return null;
}

const rank = (s) => SEVERITIES.indexOf(s);
/** Code-unit order: the same on every runner, whatever its locale. */
const byCode = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
/** Aliases sent per finding (the schema's maxItems). */
const MAX_ALIASES = 10;

/** Why a finding couldn't be sent, by the first field that doesn't fit. */
const DROP_REASON = {
  advisory: 'no usable advisory id',
  package: 'no usable package name',
  version: 'no usable version',
  ecosystem: 'no usable ecosystem',
};

/**
 * The scanner's output (parsed JSON) → { payload, dropped }: the
 * dependency_scan v1 payload, and the findings it couldn't send as
 * { reasons: {why: count}, ids: [advisory ids, ≤ 10] }. `commit` is the
 * scanned commit (40 hex), `scannedAt` an ISO time. A finding with no
 * severity is sent as high (never hidden as low); one whose fields don't fit
 * the schema is dropped and marks the scan truncated.
 */
function reduce(doc, { format = 'auto', commit, scannedAt }) {
  const kind = format === 'auto' ? detect(doc) : format;
  // A forced format still needs its top-level shape: an empty read of the
  // wrong document would send a scan with no findings, read as clean.
  if ((kind !== 'sarif' && kind !== 'osv') || detect(doc) !== kind) {
    throw new ActionError(
      'results',
      "The results file isn't SARIF 2.1.0 or OSV-Scanner JSON. Set `format` or check the scanner's output option.",
    );
  }
  if (!/^[0-9a-f]{40}$/.test(String(commit))) {
    throw new ActionError('commit', "The commit (GITHUB_SHA, CI_COMMIT_SHA or --commit) isn't a 40-character SHA.");
  }
  let read;
  try {
    read = kind === 'sarif' ? fromSarif(doc) : fromOsv(doc);
  } catch (e) {
    if (!(e instanceof TypeError)) throw e;
    throw new ActionError('results', `The results file isn't readable as ${kind === 'sarif' ? 'SARIF 2.1.0' : 'OSV-Scanner JSON'}.`);
  }
  const { tool, raw } = read;
  const dropped = { reasons: {}, ids: [] };
  let droppedCount = 0;
  const byKey = new Map();
  for (const r of raw) {
    const f = {
      advisory: str(r.advisory) ?? '',
      ecosystem: str(r.ecosystem) ?? '',
      package: str(r.package) ?? '',
      version: str(r.version) ?? '',
      severity: SEVERITIES.includes(r.severity) ? r.severity : 'high',
      fixed_in: str(r.fixed_in) && PATTERN.version.test(r.fixed_in) ? r.fixed_in : null,
    };
    const bad = ['advisory', 'package', 'version', 'ecosystem'].find((k) => !PATTERN[k].test(f[k]));
    if (bad) {
      droppedCount += 1;
      dropped.reasons[DROP_REASON[bad]] = (dropped.reasons[DROP_REASON[bad]] ?? 0) + 1;
      if (bad !== 'advisory' && dropped.ids.length < 10 && !dropped.ids.includes(f.advisory)) {
        dropped.ids.push(f.advisory);
      }
      continue;
    }
    const aliases = list(r.aliases).filter((a) => str(a) && a !== f.advisory && PATTERN.advisory.test(a));
    // One per advisory and package (two lockfiles), at its most severe.
    const key = `${f.advisory}#${f.ecosystem}#${f.package}`;
    const had = byKey.get(key);
    const all = [...new Set([...(had?.aliases ?? []), ...aliases])].sort(byCode).slice(0, MAX_ALIASES);
    const keep = !had || rank(f.severity) < rank(had.severity) ? f : had;
    byKey.set(key, all.length ? { ...keep, aliases: all } : keep);
  }
  const findings = [...byKey.values()].sort(
    (a, b) =>
      rank(a.severity) - rank(b.severity) ||
      byCode(a.advisory, b.advisory) ||
      byCode(a.ecosystem, b.ecosystem) ||
      byCode(a.package, b.package),
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] += 1;
  const payload = {
    tool: {
      name: clean(tool.name, PATTERN.toolName, 64, kind === 'osv' ? 'osv-scanner' : 'unknown'),
      version: clean(tool.version, PATTERN.toolVersion, 40, 'unknown'),
    },
    commit,
    scanned_at: scannedAt,
    counts,
    findings: findings.slice(0, MAX_FINDINGS),
    truncated: droppedCount > 0 || findings.length > MAX_FINDINGS,
  };
  return { payload, dropped: { count: droppedCount, ...dropped } };
}

class ActionError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

module.exports = { reduce, detect, parsePurl, findPurl, fromScore, LEVEL, ActionError, MAX_FINDINGS };
