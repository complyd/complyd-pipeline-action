'use strict';

const { execFileSync } = require('child_process');
const { ActionError } = require('./reduce');
const { parseConfig, repoConfig, ownerOf, sha256, DEFAULT_CONFIG } = require('./ai-config');

/** The change kinds a deploy record reports, in this order. */
const KINDS = ['model', 'model_params', 'prompt', 'safety_prompt', 'eval_suite', 'dataset', 'retrieval', 'tools', 'product_config', 'eval_method'];
const ENVIRONMENT = /^[A-Za-z0-9._-]{1,64}$/;
const SYSTEM = /^[A-Za-z0-9 ._:/@+-]{1,128}$/;

const git = (root, args) => execFileSync('git', args, { cwd: root, maxBuffer: 512 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });

/** A file's bytes at `rev` (path relative to `root`), or null when the commit has no such file. */
function fileAt(root, rev, path) {
  try {
    return git(root, ['show', `${rev}:./${path}`]);
  } catch {
    return null;
  }
}

/** The text between the start and end marker lines (each section, joined), or null when there is none. */
function sections(text, { start, end }) {
  const out = [];
  let inside = null;
  for (const line of text.split(/\r?\n/)) {
    if (inside === null && line.trim() === start) inside = [];
    else if (inside !== null && line.trim() === end) {
      out.push(inside.join('\n'));
      inside = null;
    } else if (inside !== null) inside.push(line);
  }
  return out.length ? out.join('\n\u0000\n') : null;
}

/**
 * Splits a model config file into the model lines (`key:` / `key =` /
 * `"key":` for one of `keys`) and the rest (model parameters).
 * shortcut: line-based, so a key nested under another or split over lines
 * counts as a parameter; parse per file type if that ever matters.
 */
function splitModel(text, keys) {
  const re = new RegExp(`^\\s*["']?(${keys.map((k) => k.replace(/[.]/g, '\\.')).join('|')})["']?\\s*[:=]`);
  const model = [];
  const params = [];
  for (const line of text.split(/\r?\n/)) (re.test(line) ? model : params).push(line);
  return { model: model.join('\n'), params: params.join('\n') };
}

/**
 * Each kind's material at one commit, under that commit's config: a list of
 * [label, bytes] pairs. Hashes only ever leave this function.
 */
function material(cfg, read) {
  const m = Object.fromEntries(KINDS.map((k) => [k, []]));
  const add = (kind, label, bytes) => {
    if (bytes !== null && bytes !== undefined) m[kind].push([label, Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)]);
    else m[kind].push([label, null]);
  };
  for (const p of cfg.model.files) {
    const b = read(p);
    if (!cfg.model.keys.length || b === null) add('model', p, b);
    else {
      const { model, params } = splitModel(b.toString('utf8'), cfg.model.keys);
      add('model', p, model);
      add('model_params', p, params);
    }
  }
  const prompts = [...new Set([...cfg.prompts, ...cfg.suites.flatMap((s) => s.prompts)])];
  for (const p of prompts) {
    const b = read(p);
    add('prompt', p, b);
    if (cfg.safety.markers && b !== null) {
      const s = sections(b.toString('utf8'), cfg.safety.markers);
      if (s !== null) add('safety_prompt', `${p}#markers`, s);
    }
  }
  for (const p of cfg.safety.files) add('safety_prompt', p, read(p));
  // A suite's settings (thresholds, required, test set) are part of the suite; its evaluator is the method.
  const suiteDefs = cfg.suites.map(({ index, prefix, datasetDef, evaluator, ...s }) => s);
  add('eval_suite', DEFAULT_CONFIG + '#suites', JSON.stringify(suiteDefs));
  for (const p of new Set(cfg.suites.flatMap((s) => s.files))) add('eval_suite', p, read(p));
  for (const d of Object.values(cfg.datasets)) add('dataset', d.path, read(d.path));
  for (const k of ['retrieval', 'tools', 'product_config']) for (const p of cfg[k]) add(k, p, read(p));
  add('eval_method', DEFAULT_CONFIG + '#evaluators', JSON.stringify(cfg.suites.map((s) => [s.name, s.evaluator])));
  for (const p of new Set([...cfg.eval_method, ...cfg.suites.map((s) => s.evaluator.rubric).filter(Boolean)])) add('eval_method', p, read(p));
  return m;
}

/** One hash per kind: SHA-256 of sorted `<sha256|missing>  <label>` lines; null when none of its files exist. */
function digest(entries) {
  if (!entries.length || entries.every(([, b]) => b === null)) return null;
  const lines = [...new Map(entries)].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([label, b]) => `${b === null ? 'missing' : sha256(b)}  ${label}\n`);
  return sha256(lines.join(''));
}

/**
 * The deploy record (ai_release v1 draft): what changed in the configured AI
 * files between HEAD's parent and HEAD, as kinds and before/after hashes.
 * Each commit's files are read under that commit's own .complyd/ai.yml.
 * Returns one record for a version 1 config; for version 2 a list, one per
 * system the commit touches (its paths or its AI files), or just `system`'s.
 */
function deployRecord({ environment, system, root = process.cwd(), configPath = DEFAULT_CONFIG, now = () => new Date(), warn = () => {} }) {
  if (!ENVIRONMENT.test(environment ?? '')) throw new ActionError('usage', 'Set --environment to the environment name (letters, digits and . _ -), e.g. production.');
  if (system !== undefined && !SYSTEM.test(system)) throw new ActionError('usage', 'Set --system to a name of letters, digits, spaces and . _ : / @ + -.');
  let head;
  let prev;
  try {
    head = git(root, ['rev-parse', '--verify', 'HEAD^{commit}']).toString().trim();
  } catch {
    throw new ActionError('git', 'deploy record runs in a git checkout: no commit found.');
  }
  try {
    prev = git(root, ['rev-parse', '--verify', 'HEAD^1^{commit}']).toString().trim();
  } catch {
    throw new ActionError('git', 'No previous commit in this checkout: fetch two commits (actions/checkout fetch-depth: 2; GitLab GIT_DEPTH: 2).');
  }
  const cfgText = fileAt(root, 'HEAD', configPath);
  if (cfgText === null) throw new ActionError('config', `HEAD has no ${configPath}: commit it first (see the README's AI release section).`);
  const cfg = parseConfig(cfgText);
  let before = null;
  const prevText = fileAt(root, prev, configPath);
  if (prevText !== null) {
    try {
      before = parseConfig(prevText);
    } catch (e) {
      if (!(e instanceof ActionError)) throw e;
      warn(`The previous commit's ${configPath} isn't valid, so every kind is reported as changed.`);
    }
  }
  const common = {
    commit: head,
    previous_commit: prev,
    recorded_at: now().toISOString(),
    config_changed: prevText === null || !prevText.equals(cfgText),
  };
  const repo_config = repoConfig(cfg);
  /** One system's changes: its material at HEAD against the same system's at the previous commit. */
  const changesOf = (s) => {
    const was = before && (before.systems.find((b) => b.system === s.system) ?? (before.systems.length === 1 && cfg.systems.length === 1 ? before.systems[0] : null));
    const after = material(s, (p) => fileAt(root, 'HEAD', p));
    const old = was ? material(was, (p) => fileAt(root, prev, p)) : null;
    const changes = [];
    for (const kind of KINDS) {
      const a = digest(after[kind]);
      const b = old ? digest(old[kind]) : null;
      if (a !== b) changes.push({ kind, before_sha256: b, after_sha256: a });
    }
    return changes;
  };

  if (cfg.version === 1) {
    const hint = system ?? cfg.system;
    return { environment, ...(hint ? { system: hint } : {}), ...common, changes: changesOf(cfg), repo_config };
  }
  if (system !== undefined && !cfg.systems.some((s) => s.system === system)) {
    throw new ActionError('usage', `--system: ${configPath} lists no system "${system}" (it lists ${cfg.systems.map((s) => s.system).join(', ')}).`);
  }
  const files = git(root, ['diff', '--name-only', '--no-renames', '--relative', '-z', prev, head]).toString('utf8').split('\0').filter(Boolean);
  const hit = new Set(files.map((f) => ownerOf(cfg, f)).filter(Boolean));
  const records = [];
  for (const s of cfg.systems) {
    if (system !== undefined && s.system !== system) continue;
    const changes = changesOf(s);
    if (system !== undefined || hit.has(s) || changes.length) records.push({ environment, system: s.system, ...common, changes, repo_config });
  }
  return records;
}

module.exports = { deployRecord, KINDS, sections, splitModel };
