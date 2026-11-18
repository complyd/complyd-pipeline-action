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

// The ai_eval v1 schema's patterns.
const NAME = /^[A-Za-z0-9 ._:/@+-]{1,128}$/;
const REF = /^[A-Za-z0-9._:/@+-]{1,64}$/;
const DATASET_REF = /^[A-Za-z0-9._:/@+-]{1,200}$/;
const PROVIDER = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MODEL_ID = /^[A-Za-z0-9._:/@+-]{1,128}$/;
const MODEL_VERSION = /^[A-Za-z0-9._:/@+-]{1,64}$/;
const METRIC = /^[A-Za-z0-9 ._:/@+-]{1,64}$/;
const SELECTIONS = ['production_sample', 'curated', 'synthetic', 'regression', 'mixed'];
const MAX_SUITES = 50;
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
  // Paths are repository-relative (no '..'); symlinks out of the repository are refused when read (insideFile).
  const path = (p, where) => {
    if (typeof p !== 'string' || !p.trim()) return bad(where, 'set it to a file path relative to the repository root');
    if (p.startsWith('/') || /^[A-Za-z]:/.test(p) || p.split(/[\\/]/).includes('..')) {
      return bad(where, `"${p}" must be relative to the repository root, without ".."`);
    }
    return p.replace(/^\.\//, '');
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

  if (!isMap(doc)) {
    bad('.complyd/ai.yml', 'expected a mapping with version: 1 and suites:');
    throw new ActionError('config', `Fix .complyd/ai.yml: ${errors.join('; ')}`);
  }
  known(doc, '', ['version', 'system', 'model', 'prompts', 'safety', 'datasets', 'retrieval', 'tools', 'product_config', 'eval_method', 'suites']);
  if (doc.version !== 1) bad('version', 'set version: 1');
  const cfg = { system: str(doc.system, 'system', NAME, 'support-assistant') };

  cfg.model = { files: [], keys: [] };
  if (doc.model !== undefined) {
    if (!isMap(doc.model)) bad('model', 'set files: (and optionally keys:)');
    else {
      known(doc.model, 'model.', ['files', 'keys']);
      cfg.model.files = paths(doc.model.files, 'model.files');
      if (doc.model.keys !== undefined) {
        if (!Array.isArray(doc.model.keys) || !doc.model.keys.every((k) => typeof k === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(k))) {
          bad('model.keys', 'set it to a list of key names, e.g. [model, model_version]');
        } else cfg.model.keys = doc.model.keys;
      }
    }
  }
  cfg.prompts = paths(doc.prompts, 'prompts');
  cfg.safety = { files: [], markers: null };
  if (doc.safety !== undefined) {
    if (!isMap(doc.safety)) bad('safety', 'set files: and/or markers: { start: "…", end: "…" }');
    else {
      known(doc.safety, 'safety.', ['files', 'markers']);
      cfg.safety.files = paths(doc.safety.files, 'safety.files');
      const m = doc.safety.markers;
      if (m !== undefined) {
        if (!isMap(m) || typeof m.start !== 'string' || typeof m.end !== 'string' || !m.start || !m.end || m.start === m.end) {
          bad('safety.markers', 'set start: and end: to the two different lines that enclose the safety section');
        } else cfg.safety.markers = { start: m.start, end: m.end };
      }
    }
  }
  cfg.datasets = {};
  if (doc.datasets !== undefined) {
    if (!isMap(doc.datasets)) bad('datasets', 'set it to name: { path: …, ref: … } entries');
    else {
      for (const [name, d] of Object.entries(doc.datasets)) {
        const where = `datasets.${name}`;
        if (!isMap(d)) {
          bad(where, 'set path: (and optionally ref:)');
          continue;
        }
        known(d, `${where}.`, ['path', 'ref']);
        cfg.datasets[name] = { path: path(d.path, `${where}.path`), ref: str(d.ref, `${where}.ref`, DATASET_REF, 'datasets/refusals@3') };
      }
    }
  }
  for (const k of ['retrieval', 'tools', 'product_config', 'eval_method']) cfg[k] = paths(doc[k], k);

  cfg.suites = [];
  if (!Array.isArray(doc.suites) || !doc.suites.length || doc.suites.length > MAX_SUITES) {
    bad('suites', `list your eval suites (1 to ${MAX_SUITES}), each with at least name:`);
  } else {
    const names = new Set();
    doc.suites.forEach((s, i) => {
      const where = `suites[${i}]`;
      if (!isMap(s)) return bad(where, 'expected name: and the suite settings');
      known(s, `${where}.`, ['name', 'match', 'required', 'prompts', 'prompt_version', 'dataset', 'model', 'test_set', 'evaluator', 'metrics', 'files']);
      const suite = { index: i };
      suite.name = str(s.name, `${where}.name`, NAME, 'safety-refusals');
      if (!suite.name) bad(`${where}.name`, 'set a name (letters, digits, spaces and . _ : / @ + -)');
      else if (names.has(suite.name)) bad(`${where}.name`, `"${suite.name}" is used by two suites`);
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
        else suite.dataset = s.dataset;
      }
      if (s.model !== undefined) {
        const m = s.model;
        if (!isMap(m)) bad(`${where}.model`, 'set { provider: …, id: …, version: … }');
        else {
          known(m, `${where}.model.`, ['provider', 'id', 'version']);
          const provider = str(m.provider, `${where}.model.provider`, PROVIDER, 'openai');
          let id = str(m.id, `${where}.model.id`, MODEL_ID, 'gpt-4o-mini');
          if (id && !isModelId(id)) id = bad(`${where}.model.id`, 'set the model id, not a URL or a local path');
          if (!provider || !id) bad(`${where}.model`, 'set both provider: (lower case, e.g. openai) and id:');
          suite.model = { provider, id, version: str(m.version, `${where}.model.version`, MODEL_VERSION, '2024-07-18') };
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
            if (dir && (typeof m[dir] !== 'number' || !Number.isFinite(m[dir]))) bad(`${mw}.${dir}`, 'set a number, e.g. 0.95');
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
  if (errors.length) throw new ActionError('config', `Fix .complyd/ai.yml: ${errors.slice(0, 10).join('; ')}${errors.length > 10 ? '; …' : ''}`);
  return cfg;
}

/** Parses and validates config text (from the working tree or a commit). */
function parseConfig(text) {
  if (Buffer.byteLength(text) > MAX_CONFIG_BYTES) throw new ActionError('config', 'Fix .complyd/ai.yml: it is over 256 KB.');
  let doc;
  try {
    doc = parseYaml(text);
  } catch (e) {
    if (e instanceof YamlError) throw new ActionError('config', `Fix .complyd/ai.yml: ${e.message}.`);
    if (e instanceof RangeError) throw new ActionError('config', 'Fix .complyd/ai.yml: it is nested too deeply.');
    throw e;
  }
  return validate(doc);
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
    text = readFileSync(file, 'utf8');
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

module.exports = { parseConfig, loadConfig, validate, hashFile, hashFiles, sha256, isModelId, isJudge, DEFAULT_CONFIG, NAME, REF, PROVIDER, MODEL_ID, MODEL_VERSION, METRIC };
