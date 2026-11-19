'use strict';

const { createHash } = require('crypto');
const { readFileSync, statSync, realpathSync } = require('fs');
const { join, sep } = require('path');
const { ActionError } = require('./reduce');
const { parseYaml, YamlError } = require('./yaml');

const DEFAULT_CONFIG = '.complyd/ai.yml';
/** Largest file hashed (a dataset of a few hundred MB is read in one go). */
const MAX_HASH_BYTES = 512 * 1024 * 1024;
/** Largest .complyd/ai.yml read. */
const MAX_CONFIG_BYTES = 256 * 1024;

// Complyd's ai_eval / ai_release schema patterns.
const NAME = /^[A-Za-z0-9 ._:/@+-]{1,128}$/;
const REF = /^[A-Za-z0-9._:/@+-]{1,64}$/;
const DATASET_REF = /^[A-Za-z0-9._:/@+-]{1,200}$/;
const PROVIDER = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MODEL_ID = /^[A-Za-z0-9._:/@+-]{1,128}$/;
const MODEL_VERSION = /^[A-Za-z0-9._:/@+-]{1,64}$/;
const METRIC = /^[A-Za-z0-9 ._:/@+-]{1,64}$/;
const SELECTIONS = ['production_sample', 'curated', 'synthetic', 'regression', 'mixed'];
const MAX_SUITES = 50;
const MAX_SYSTEMS = 50;
const MAX_GLOBS = 100;
const GLOB = /^[A-Za-z0-9 ._@+\/*?-]{1,200}$/;
/** What one system (v1: the file) may set besides its name and paths. */
const SYSTEM_KEYS = ['model', 'prompts', 'safety', 'datasets', 'retrieval', 'tools', 'product_config', 'eval_method', 'suites'];
/** A model id that is not a URL or a local path (those can name internal hosts or home directories). */
const isModelId = (s) => typeof s === 'string' && MODEL_ID.test(s) && !s.includes('//') && !/^[/.~]/.test(s) && !/^[A-Za-z]:\//.test(s);
const JUDGE = /^[A-Za-z0-9._:/@+-]{1,200}$/;
const isJudge = (s) => typeof s === 'string' && JUDGE.test(s) && !s.includes('//') && !/^[/.~]/.test(s) && !/^[A-Za-z]:\//.test(s);

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * Validates the parsed `.complyd/ai.yml`. Collects every problem, each as
 * `<where>: <what to do>`, and throws one ActionError listing them.
 */
function validate(doc) {
  const errors = [];
  const bad = (where, why) => {
    errors.push(`${where}: ${why}`);
  };
  const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const known = (obj, where, keys) => {
    for (const k of Object.keys(obj)) if (!keys.includes(k)) bad(`${where}${k}`, `unknown key (expected one of ${keys.join(', ')})`);
  };
  /** The files the system being read declares, as { file, where }. */
  let declared = [];
  // Paths are repository-relative (no '..'); symlinks out of the repository are refused when read (insideFile).
  const path = (p, where) => {
    if (typeof p !== 'string' || !p.trim()) return bad(where, 'set it to a file path relative to the repository root');
    if (p.startsWith('/') || /^[A-Za-z]:/.test(p) || p.split(/[\\/]/).includes('..')) {
      return bad(where, `"${p}" must be relative to the repository root, without ".."`);
    }
    const file = p.replace(/^\.\//, '');
    declared.push({ file, where });
    return file;
  };
  const paths = (v, where) => {
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v)) return bad(where, 'set it to a list of file paths, e.g. [prompts/system.txt]') ?? [];
    return v.map((p, i) => path(p, `${where}[${i}]`)).filter(Boolean);
  };
  const str = (v, where, re, example) => {
    if (v === undefined || v === null) return undefined;
    // An unquoted 1.10 reads as the number 1.1: refuse it rather than send another version.
    if (typeof v === 'number' && !Number.isInteger(v)) return bad(where, `quote it, e.g. "${v}" (unquoted, a number like 1.10 reads as 1.1)`);
    const s = typeof v === 'number' ? String(v) : v;
    if (typeof s !== 'string' || !re.test(s)) return bad(where, `use letters, digits and . _ : / @ + - (e.g. ${example})`);
    return s;
  };
  // A glob: a repository-relative path where * matches within a directory, ** any directories and ? one character.
  const glob = (g, where) => {
    if (typeof g !== 'string' || !GLOB.test(g)) return bad(where, 'set a glob of letters, digits, . _ @ + - / * ? (e.g. "services/support/**")');
    const n = g.replace(/^\.\//, '');
    const segs = n.split('/');
    if (n.startsWith('/') || segs.some((x) => x === '' || x === '.' || x === '..')) return bad(where, `"${g}" must be relative to the repository root, without "..", "." or "//"`);
    if (segs.some((x) => x.includes('**') && x !== '**')) return bad(where, `"${g}": ** must be a whole path part, e.g. "src/**/*.py"`);
    // "**/**" matches what "**" does: one spelling, so equal globs compare equal.
    return segs.filter((x, i) => x !== '**' || segs[i - 1] !== '**').join('/');
  };

  /** { provider, id, version } of a model: map `m` at `where`. */
  const modelRef = (m, where) => {
    const provider = str(m.provider, `${where}.provider`, PROVIDER, 'openai');
    let id = str(m.id, `${where}.id`, MODEL_ID, 'gpt-4o-mini');
    if (id && !isModelId(id)) id = bad(`${where}.id`, 'set the model id, not a URL or a local path');
    if (!provider || !id) bad(where, 'set both provider: (lower case, e.g. openai) and id:');
    return { provider, id, version: str(m.version, `${where}.version`, MODEL_VERSION, '2024-07-18') };
  };

  /** One system's settings (v1: the whole file); `p` prefixes each error's place. */
  function system(doc, p) {
    declared = [];
    const cfg = {};
    cfg.model = { files: [], keys: [] };
    if (doc.model !== undefined) {
      if (!isMap(doc.model)) bad(`${p}model`, 'set provider: and id: (the deployed model) and/or files: (and optionally keys:)');
      else {
        known(doc.model, `${p}model.`, ['files', 'keys', 'provider', 'id', 'version']);
        cfg.model.files = paths(doc.model.files, `${p}model.files`);
        // The deployed model, for deploy record (eval results name their own).
        if (doc.model.provider !== undefined || doc.model.id !== undefined || doc.model.version !== undefined) cfg.model.ref = modelRef(doc.model, `${p}model`);
        if (doc.model.keys !== undefined) {
          if (!Array.isArray(doc.model.keys) || !doc.model.keys.every((k) => typeof k === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(k))) {
            bad(`${p}model.keys`, 'set it to a list of key names, e.g. [model, model_version]');
          } else cfg.model.keys = doc.model.keys;
        }
      }
    }
    cfg.prompts = paths(doc.prompts, `${p}prompts`);
    cfg.safety = { files: [], markers: null };
    if (doc.safety !== undefined) {
      if (!isMap(doc.safety)) bad(`${p}safety`, 'set files: and/or markers: { start: "…", end: "…" }');
      else {
        known(doc.safety, `${p}safety.`, ['files', 'markers']);
        cfg.safety.files = paths(doc.safety.files, `${p}safety.files`);
        const m = doc.safety.markers;
        if (m !== undefined) {
          if (!isMap(m) || typeof m.start !== 'string' || typeof m.end !== 'string' || !m.start || !m.end || m.start === m.end) {
            bad(`${p}safety.markers`, 'set start: and end: to the two different lines that enclose the safety section');
          } else cfg.safety.markers = { start: m.start, end: m.end };
        }
      }
    }
    cfg.datasets = {};
    if (doc.datasets !== undefined) {
      if (!isMap(doc.datasets)) bad(`${p}datasets`, 'set it to name: { path: …, ref: … } entries');
      else {
        for (const [name, d] of Object.entries(doc.datasets)) {
          const where = `${p}datasets.${name}`;
          if (!isMap(d)) {
            bad(where, 'set path: (and optionally ref:)');
            continue;
          }
          known(d, `${where}.`, ['path', 'ref']);
          cfg.datasets[name] = { path: path(d.path, `${where}.path`), ref: str(d.ref, `${where}.ref`, DATASET_REF, 'datasets/refusals@3') };
        }
      }
    }
    for (const k of ['retrieval', 'tools', 'product_config', 'eval_method']) cfg[k] = paths(doc[k], `${p}${k}`);

    cfg.suites = [];
    if (!Array.isArray(doc.suites) || !doc.suites.length || doc.suites.length > MAX_SUITES) {
      bad(`${p}suites`, `list your eval suites (1 to ${MAX_SUITES}), each with at least name:`);
    } else {
      doc.suites.forEach((s, i) => {
        const where = `${p}suites[${i}]`;
        if (!isMap(s)) return bad(where, 'expected name: and the suite settings');
        known(s, `${where}.`, ['name', 'match', 'required', 'prompts', 'prompt_version', 'dataset', 'model', 'test_set', 'evaluator', 'metrics', 'files']);
        const suite = { index: i, prefix: p };
        suite.name = str(s.name, `${where}.name`, NAME, 'safety-refusals');
        if (!suite.name) bad(`${where}.name`, 'set a name (letters, digits, spaces and . _ : / @ + -)');
        else if (names.has(suite.name)) bad(`${where}.name`, `"${suite.name}" is used by two suites${p ? ' (suite names are unique across systems)' : ''}`);
        names.add(suite.name);
        if (s.match !== undefined && (typeof s.match !== 'string' || !s.match)) bad(`${where}.match`, "set it to the suite's name in the tool's results");
        suite.match = s.match;
        if (s.required !== undefined && typeof s.required !== 'boolean') bad(`${where}.required`, 'set true or false');
        suite.required = s.required === true;
        suite.prompts = s.prompts === undefined ? cfg.prompts : paths(s.prompts, `${where}.prompts`);
        if (!suite.prompts.length) bad(`${where}.prompts`, 'list the prompt files this suite tests (or a top-level prompts:)');
        suite.prompt_version = str(s.prompt_version, `${where}.prompt_version`, REF, 'v12');
        if (s.dataset !== undefined) {
          if (typeof s.dataset !== 'string' || !Object.hasOwn(cfg.datasets, s.dataset)) bad(`${where}.dataset`, 'name one of the datasets: entries');
          else {
            suite.dataset = s.dataset;
            suite.datasetDef = cfg.datasets[s.dataset];
          }
        }
        if (s.model !== undefined) {
          const m = s.model;
          if (!isMap(m)) bad(`${where}.model`, 'set { provider: …, id: …, version: … }');
          else {
            known(m, `${where}.model.`, ['provider', 'id', 'version']);
            suite.model = modelRef(m, `${where}.model`);
          }
        }
        const t = s.test_set ?? {};
        if (!isMap(t)) bad(`${where}.test_set`, 'set { version: …, selection: … }');
        else {
          known(t, `${where}.test_set.`, ['version', 'selection', 'expected_version']);
          if (t.selection !== undefined && !SELECTIONS.includes(t.selection)) bad(`${where}.test_set.selection`, `use one of ${SELECTIONS.join(', ')}`);
          suite.test_set = {
            version: str(t.version, `${where}.test_set.version`, REF, '4'),
            selection: t.selection,
            expected_version: str(t.expected_version, `${where}.test_set.expected_version`, REF, '2'),
          };
          if (!suite.test_set.version && !suite.dataset) bad(`${where}.test_set.version`, 'set the test set version (or a dataset:, whose hash then names it)');
        }
        const e = s.evaluator ?? {};
        if (!isMap(e)) bad(`${where}.evaluator`, 'set { version: …, parser: …, judge_model: …, rubric: … }');
        else {
          known(e, `${where}.evaluator.`, ['version', 'parser', 'judge_model', 'rubric']);
          suite.evaluator = {
            version: str(e.version, `${where}.evaluator.version`, REF, '3'),
            parser: str(e.parser, `${where}.evaluator.parser`, REF, 'json-score'),
            judge_model: str(e.judge_model, `${where}.evaluator.judge_model`, JUDGE, 'openai/gpt-4o'),
            rubric: e.rubric === undefined ? undefined : path(e.rubric, `${where}.evaluator.rubric`),
          };
          if (suite.evaluator.judge_model && !isJudge(suite.evaluator.judge_model)) bad(`${where}.evaluator.judge_model`, 'set the judge model id, not a URL or a local path');
        }
        suite.metrics = {};
        if (s.metrics !== undefined) {
          if (!isMap(s.metrics)) bad(`${where}.metrics`, 'set metric_name: { gte: 0.95 } (or lte:, category:) entries');
          else {
            for (const [name, m] of Object.entries(s.metrics)) {
              const mw = `${where}.metrics.${name}`;
              if (!METRIC.test(name)) bad(mw, 'metric names use letters, digits, spaces and . _ : / @ + -');
              if (!isMap(m)) {
                bad(mw, 'set { gte: 0.95 } or { lte: 0.05 }, and/or category:');
                continue;
              }
              known(m, `${mw}.`, ['gte', 'lte', 'category']);
              if (m.gte !== undefined && m.lte !== undefined) bad(mw, 'set gte: or lte:, not both');
              const dir = m.gte !== undefined ? 'gte' : m.lte !== undefined ? 'lte' : null;
              // Sent as a decimal of at most 12 integer and 9 fraction digits: refuse what that would change.
              if (dir && (typeof m[dir] !== 'number' || decimal(m[dir]) === undefined || Number(decimal(m[dir])) !== m[dir])) {
                bad(`${mw}.${dir}`, 'set a number below 1000000000000 with at most 9 decimal places, e.g. 0.95');
              }
              suite.metrics[name] = {
                threshold: dir ? { value: m[dir], direction: dir } : undefined,
                category: str(m.category, `${mw}.category`, METRIC, 'unsafe_compliance'),
              };
            }
          }
        }
        suite.files = paths(s.files, `${where}.files`);
        cfg.suites.push(suite);
      });
    }
    return cfg;
  }

  if (!isMap(doc)) {
    bad('.complyd/ai.yml', 'expected a mapping with version: and suites: (or systems:)');
    throw new ActionError('config', `Fix .complyd/ai.yml: ${errors.join('; ')}`);
  }
  const names = new Set();
  let out;
  if (doc.version === 2) {
    known(doc, '', ['version', 'systems']);
    const list = Array.isArray(doc.systems) ? doc.systems : [];
    if (!list.length || list.length > MAX_SYSTEMS) bad('systems', `list your AI systems (1 to ${MAX_SYSTEMS}), each with system:, paths: and suites:`);
    const systems = [];
    const seen = new Map();
    const globs = new Map();
    const files = [];
    list.forEach((d, i) => {
      const p = `systems[${i}].`;
      if (!isMap(d)) return bad(`systems[${i}]`, 'expected system:, paths: and the system settings');
      known(d, p, ['system', 'paths', ...SYSTEM_KEYS]);
      const cfg = system(d, p);
      files.push(declared);
      cfg.system = str(d.system, `${p}system`, NAME, 'support-assistant');
      if (!cfg.system) bad(`${p}system`, "set the system's name or its AIS-… reference");
      else if (seen.has(cfg.system)) bad(`${p}system`, `"${cfg.system}" is also systems[${seen.get(cfg.system)}]`);
      else seen.set(cfg.system, i);
      if (d.paths === undefined && list.length === 1) cfg.paths = ['**'];
      else if (!Array.isArray(d.paths) || !d.paths.length || d.paths.length > MAX_GLOBS) {
        bad(`${p}paths`, `list the globs of the files that belong to this system (1 to ${MAX_GLOBS}), e.g. ["services/support/**"]`);
        cfg.paths = [];
      } else {
        cfg.paths = d.paths.map((g, j) => glob(g, `${p}paths[${j}]`)).filter(Boolean);
        cfg.paths.forEach((g) => {
          // The same glob in two systems ties for every file it matches.
          if (globs.has(g) && globs.get(g) !== i) bad(`${p}paths`, `"${g}" is also in systems[${globs.get(g)}].paths: a file it matches can't belong to both`);
          globs.set(g, i);
        });
      }
      systems.push(cfg);
    });
    out = { version: 2, systems, suites: systems.flatMap((s) => s.suites) };
    // A declared file the system doesn't own would never be recorded (deploy record gives a file to its owner only).
    if (!errors.length) {
      systems.forEach((cfg, i) => {
        for (const { file, where } of files[i]) {
          const o = owners(out, file);
          if (o.length > 1) bad(where, `${file} matches the paths of ${o.map((s) => s.system).join(' and ')} equally: make one of their globs more specific`);
          else if (o[0] !== cfg) bad(where, `${file} is not under this system's paths${o.length ? ` (it belongs to ${o[0].system}: a more specific glob)` : ''} (add it to paths: or move it)`);
        }
      });
    }
  } else {
    known(doc, '', ['version', 'system', ...SYSTEM_KEYS]);
    if (doc.version !== 1) bad('version', 'set version: 1 (or version: 2 with systems:)');
    const cfg = system(doc, '');
    cfg.system = str(doc.system, 'system', NAME, 'support-assistant');
    cfg.paths = ['**'];
    out = { ...cfg, version: 1, systems: [cfg] };
  }
  if (errors.length) throw new ActionError('config', `Fix .complyd/ai.yml: ${errors.slice(0, 10).join('; ')}${errors.length > 10 ? '; …' : ''}`);
  return out;
}

/** Parses and validates config text or bytes (from the working tree or a commit); `sha256` is the file's. */
function parseConfig(text) {
  if (Buffer.byteLength(text) > MAX_CONFIG_BYTES) throw new ActionError('config', 'Fix .complyd/ai.yml: it is over 256 KB.');
  let doc;
  try {
    doc = parseYaml(Buffer.isBuffer(text) ? text.toString('utf8') : text);
  } catch (e) {
    if (e instanceof YamlError) throw new ActionError('config', `Fix .complyd/ai.yml: ${e.message}.`);
    if (e instanceof RangeError) throw new ActionError('config', 'Fix .complyd/ai.yml: it is nested too deeply.');
    throw e;
  }
  return { ...validate(doc), sha256: sha256(text) };
}

/**
 * Wildcard match of `pat` against `items` in O(pat × items) steps: `star`
 * matches any run of items, every other token one item that `one` accepts.
 * Only the last star is ever backtracked to, so no input can blow it up
 * (a backtracking RegExp can: "*a*a…b" against "aaaa…").
 */
function wild(pat, items, star, one) {
  let p = 0;
  let i = 0;
  let starP = -1;
  let starI = 0;
  while (i < items.length) {
    if (p < pat.length && pat[p] === star) [starP, starI] = [p++, i];
    else if (p < pat.length && one(pat[p], items[i])) [p, i] = [p + 1, i + 1];
    else if (starP >= 0) [p, i] = [starP + 1, ++starI];
    else return false;
  }
  while (p < pat.length && pat[p] === star) p += 1;
  return p === pat.length;
}

/** Whether repository file `file` matches glob `g` (as validated): * within a path part, ** across parts, ? one character. */
function globMatch(g, file) {
  const segs = g.split('/');
  // A trailing ** is a directory's contents: at least one more part.
  if (segs[segs.length - 1] === '**') segs.splice(-1, 1, '*', '**');
  const part = (x, name) => wild(x, name, '*', (c, ch) => c === '?' || c === ch);
  return wild(segs, file.split('/'), '**', part);
}

/** How specific a glob is: its literal characters (not *, ? or /), so extra ** parts add nothing. */
const specificity = (g) => g.replace(/[*?/]/g, '').length;

/** The systems whose matching glob for `file` is the most specific: none, the owner, or several (a tie). */
function owners(cfg, file) {
  let best = -1;
  let found = [];
  for (const s of cfg.systems) {
    const n = Math.max(-1, ...s.paths.filter((g) => globMatch(g, file)).map(specificity));
    if (n > best) [best, found] = [n, [s]];
    else if (n === best && n >= 0) found.push(s);
  }
  return found;
}

/**
 * The system a repository file belongs to: the one whose matching glob is
 * the most specific; undefined when none matches or several tie (as Complyd
 * reads it: test/fixtures/repo-config-ownership.vectors.json).
 */
function ownerOf(cfg, file) {
  const found = owners(cfg, file);
  return found.length === 1 ? found[0] : undefined;
}

/** A number as the schema's decimal string (≤ 12 integer and 9 fraction digits), else undefined. */
function decimal(n) {
  if (typeof n !== 'number' || !Number.isFinite(n) || Math.abs(n) >= 1e12) return undefined;
  const s = n
    .toFixed(9)
    .replace(/(\.\d*?)0+$/, '$1')
    .replace(/\.$/, '');
  return s === '-0' ? '0' : s;
}

/**
 * What Complyd receives of the config: names, globs, required flags and
 * thresholds, and the file's SHA-256. Never a file's contents.
 */
function repoConfig(cfg) {
  return {
    version: cfg.version,
    config_sha256: cfg.sha256,
    systems: cfg.systems.map((s) => ({
      ...(s.system ? { system: s.system } : {}),
      paths: s.paths,
      suites: s.suites.map((x) => ({
        name: x.name,
        required: x.required,
        metrics: Object.fromEntries(
          Object.entries(x.metrics)
            .filter(([, m]) => m.threshold)
            .map(([name, m]) => [name, { [m.threshold.direction]: decimal(m.threshold.value) }]),
        ),
      })),
    })),
  };
}

/**
 * `path` under `root` with symlinks resolved, or null when it doesn't resolve
 * to a file inside `root`. One answer for missing, unreadable and outside, so
 * a link can't probe what exists outside the repository.
 */
function insideFile(root, path) {
  try {
    const r = realpathSync(root);
    const t = realpathSync(join(r, path));
    return t.startsWith(r + sep) && statSync(t).isFile() ? t : null;
  } catch {
    return null;
  }
}

/** The config file at `configPath` (relative to `root`). */
function loadConfig(configPath = DEFAULT_CONFIG, root = process.cwd()) {
  const file = insideFile(root, configPath);
  let text;
  try {
    if (!file || statSync(file).size > MAX_CONFIG_BYTES) throw new Error();
    text = readFileSync(file);
  } catch {
    throw new ActionError('config', `Couldn't read ${configPath} (a file of at most 256 KB inside the workspace): create it (see the README's AI release section) or pass --suite-config.`);
  }
  return parseConfig(text);
}

/** SHA-256 of a repository file; `where` names the config entry in the error. `cache` keeps hashes by path for one run. */
function hashFile(root, path, where, cache) {
  if (cache?.has(path)) return cache.get(path);
  const file = insideFile(root, path);
  let why = 'it must be a file inside the repository; paths are relative to the repository root';
  try {
    if (!file) throw new Error();
    if (statSync(file).size > MAX_HASH_BYTES) why = 'it is over 512 MB';
    else {
      const h = sha256(readFileSync(file));
      cache?.set(path, h);
      return h;
    }
  } catch {
    // falls through to the one error below
  }
  throw new ActionError('config', `${where}: couldn't read ${path} (${why}).`);
}

/**
 * One hash for a list of files: a single file's own SHA-256 (so anyone
 * holding the prompt can confirm it), else SHA-256 of `sha256sum`-style
 * lines (`<hash>  <path>`), sorted by path.
 */
function hashFiles(root, files, where, cache) {
  const list = [...new Set(files)].sort();
  if (list.length === 1) return hashFile(root, list[0], where, cache);
  return sha256(list.map((p) => `${hashFile(root, p, where, cache)}  ${p}\n`).join(''));
}

module.exports = { parseConfig, loadConfig, validate, repoConfig, ownerOf, globMatch, decimal, hashFile, hashFiles, sha256, isModelId, isJudge, DEFAULT_CONFIG, NAME, REF, PROVIDER, MODEL_ID, MODEL_VERSION, METRIC };
