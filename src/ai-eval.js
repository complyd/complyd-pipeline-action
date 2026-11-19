'use strict';

const { createHash } = require('crypto');
const { ActionError } = require('./reduce');
const { hashFile, hashFiles, isModelId, isJudge, repoConfig, decimal, PROVIDER, MODEL_VERSION } = require('./ai-config');
const { MAX_BODY_BYTES } = require('./post');

const FORMATS = ['promptfoo', 'deepeval', 'openai-evals', 'lm-eval', 'generic'];
const ROLES = ['baseline', 'candidate'];
const MAX_SUITES = 50;
const MAX_METRICS = 50;
const MAX_COUNT = 10_000_000;
const MAX_WARNINGS = 20;
// No spaces: a tool name is an id, not a place for free text.
const TOOL_NAME = /^[A-Za-z0-9._/@+-]{1,40}$/;
const TOOL_VERSION = /^[A-Za-z0-9._+-]{1,40}$/;
const DECIMAL = /^-?[0-9]{1,12}(\.[0-9]{1,9})?$/;

/*
 * Each parser reads a tool's results document and keeps only numbers, model
 * ids, metric names and the tool's suite label (used to find the suite in
 * .complyd/ai.yml, never sent): no prompt, output, test case or dataset
 * text leaves it. Metric names are sent only when .complyd/ai.yml declares
 * them (buildPayload), as a tool may build them from test text.
 */

const bad = (format) => new ActionError('results', `The results file isn't readable as ${format} output: check --format and the file.`);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const numOrDecimal = (v) => (typeof v === 'string' && DECIMAL.test(v) ? Number(v) : num(v));
const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const count = (v, format) => {
  if (v === undefined || v === null) return 0;
  if (!Number.isInteger(v) || v < 0 || v > MAX_COUNT) throw bad(format);
  return v;
};
const cleanVersion = (v) => {
  const s = typeof v === 'number' ? String(v) : v;
  return typeof s === 'string' && TOOL_VERSION.test(s) ? s : 'unknown';
};
const isoTime = (v) => {
  if (v === undefined || v === null || v === '') return undefined;
  const d = typeof v === 'number' ? new Date(v < 1e11 ? v * 1000 : v) : new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
};
/** A metric name the schema takes: other characters become '-'. */
const metricName = (s) => String(s).replace(/[^A-Za-z0-9 ._:/@+-]/g, '-').slice(0, 64) || 'metric';
const rate = (part, total) => (total > 0 ? part / total : undefined);

/** "openai:chat:gpt-4o" → { provider: openai, id: gpt-4o }; undefined for files, URLs and scripts. */
function providerModel(s) {
  if (typeof s !== 'string') return undefined;
  const m = /^([A-Za-z0-9._-]+):(?:(?:chat|completion|completions|messages|responses|embedding|embeddings):)?(.+)$/.exec(s);
  if (!m) return undefined;
  const provider = m[1].toLowerCase();
  if (['file', 'http', 'https', 'python', 'exec', 'javascript', 'js', 'golang', 'ruby', 'webhook', 'echo', 'sequence'].includes(provider)) return undefined;
  return PROVIDER.test(provider) && isModelId(m[2]) ? { provider, id: m[2] } : undefined;
}

/** promptfoo `eval -o results.json`: one suite per prompt × provider. */
function promptfoo(doc) {
  const r = doc?.results;
  if (!r || !Array.isArray(r.prompts) || !r.prompts.length) throw bad('promptfoo');
  return {
    tool: { name: 'promptfoo', version: cleanVersion(doc.metadata?.promptfooVersion) },
    ranAt: isoTime(r.timestamp ?? doc.metadata?.evaluationCreatedAt),
    suites: r.prompts.map((p) => {
      const m = p?.metrics ?? {};
      if (!isMap(m) || (m.namedScores !== undefined && !isMap(m.namedScores))) throw bad('promptfoo');
      const cases = { passed: count(m.testPassCount, 'promptfoo'), failed: count(m.testFailCount, 'promptfoo'), errored: count(m.testErrorCount, 'promptfoo') };
      cases.total = cases.passed + cases.failed + cases.errored;
      const metrics = [{ name: 'pass_rate', value: rate(cases.passed, cases.total) }];
      for (const [k, v] of Object.entries(m.namedScores ?? {})) {
        const n = num(m.namedScoresCount?.[k]) || cases.total;
        metrics.push({ name: metricName(k), value: n ? num(v) / n : undefined });
      }
      return {
        label: typeof p?.label === 'string' ? p.label : undefined,
        model: providerModel(typeof p?.provider === 'string' ? p.provider : p?.provider?.id),
        metrics,
        cases,
        passed: cases.failed + cases.errored === 0,
      };
    }),
  };
}

/** DeepEval's test run (.deepeval/.latest_test_run.json): one suite, metrics averaged over its cases. */
const LOWER_IS_BETTER = /^(bias|toxicity|hallucination)( metric)?$/i;
function deepeval(doc) {
  const testCases = [...(Array.isArray(doc?.testCases) ? doc.testCases : []), ...(Array.isArray(doc?.conversationalTestCases) ? doc.conversationalTestCases : [])];
  if (!Array.isArray(doc?.testCases) && !Array.isArray(doc?.conversationalTestCases)) throw bad('deepeval');
  const cases = { total: testCases.length, passed: 0, failed: 0, errored: 0 };
  const byMetric = new Map();
  let judge;
  for (const tc of testCases) {
    const data = Array.isArray(tc?.metricsData) ? tc.metricsData : [];
    const errored = data.some((d) => d?.error);
    if (errored) cases.errored += 1;
    else if (tc?.success === true) cases.passed += 1;
    else cases.failed += 1;
    for (const d of data) {
      if (typeof d?.name !== 'string') continue;
      const agg = byMetric.get(d.name) ?? { sum: 0, n: 0, threshold: undefined, passed: true };
      if (num(d.score) !== undefined) {
        agg.sum += d.score;
        agg.n += 1;
      }
      if (agg.threshold === undefined && num(d.threshold) !== undefined) agg.threshold = d.threshold;
      if (d.success !== true || d.error) agg.passed = false;
      byMetric.set(d.name, agg);
      if (!judge && typeof d.evaluationModel === 'string') judge = d.evaluationModel;
    }
  }
  const metrics = [...byMetric].map(([name, a]) => ({
    name: metricName(name),
    value: a.n ? a.sum / a.n : undefined,
    threshold: a.threshold === undefined ? undefined : { value: a.threshold, direction: LOWER_IS_BETTER.test(name) ? 'lte' : 'gte' },
    passed: a.passed,
  }));
  const hp = doc.hyperparameters?.model;
  return {
    tool: { name: 'deepeval', version: 'unknown' },
    ranAt: undefined,
    suites: [
      {
        label: [doc.identifier, doc.testFile].find((v) => typeof v === 'string' && v),
        model: providerModel(typeof hp === 'string' ? hp.replace('/', ':') : undefined),
        judge,
        metrics,
        cases,
        passed: cases.total > 0 && cases.failed + cases.errored === 0,
      },
    ],
  };
}

/** An OpenAI Evals API run (`GET /v1/evals/{id}/runs/{run_id}`), or a list of them. */
function openaiEvals(doc) {
  const runs = doc?.object === 'list' && Array.isArray(doc.data) ? doc.data : [doc];
  if (!runs.length || !runs.every((r) => r?.object === 'eval.run' && r.result_counts)) throw bad('openai-evals');
  return {
    tool: { name: 'openai-evals', version: 'v1' },
    ranAt: isoTime(runs[0].created_at),
    suites: runs.map((r) => {
      const c = r.result_counts;
      const cases = { total: count(c.total, 'openai-evals'), passed: count(c.passed, 'openai-evals'), failed: count(c.failed, 'openai-evals'), errored: count(c.errored, 'openai-evals') };
      const metrics = [{ name: 'pass_rate', value: rate(cases.passed, cases.total) }];
      for (const t of Array.isArray(r.per_testing_criteria_results) ? r.per_testing_criteria_results : []) {
        const p = count(t?.passed, 'openai-evals');
        const f = count(t?.failed, 'openai-evals');
        if (typeof t?.testing_criteria === 'string') metrics.push({ name: metricName(t.testing_criteria), value: rate(p, p + f), passed: f === 0 });
      }
      return {
        label: [r.name, r.eval_id].find((v) => typeof v === 'string' && v),
        model: isModelId(r.model) ? { provider: 'openai', id: r.model } : undefined,
        metrics,
        cases,
        passed: r.status === 'completed' && cases.failed + cases.errored === 0,
      };
    }),
  };
}

/**
 * lm-evaluation-harness `--output_path` results JSON: one suite per task.
 * It has no per-case verdicts, so cases stay 0 (the sample count goes to
 * the test set) and only thresholds from .complyd/ai.yml can pass a suite
 * (buildPayload fails a suite with no cases and no threshold).
 */
function lmEval(doc) {
  if (!doc?.results || typeof doc.results !== 'object' || Array.isArray(doc.results)) throw bad('lm-eval');
  const modelId = [doc.model_name, /(?:^|,)(?:pretrained|model)=([^,]+)/.exec(doc.config?.model_args ?? '')?.[1]].find(isModelId);
  const provider = typeof doc.config?.model === 'string' ? doc.config.model.toLowerCase() : undefined;
  return {
    tool: { name: 'lm-eval', version: cleanVersion(doc.lm_eval_version) },
    ranAt: isoTime(doc.date),
    suites: Object.entries(doc.results).map(([task, r]) => {
      const metrics = [];
      for (const [key, v] of Object.entries(r ?? {})) {
        const [metric, filter] = key.split(',');
        if (filter === undefined || metric.endsWith('_stderr') || num(v) === undefined) continue;
        metrics.push({ name: metricName(filter === 'none' ? metric : `${metric}:${filter}`), value: v });
      }
      const samples = doc['n-samples']?.[task];
      return {
        label: task,
        model: modelId && provider && PROVIDER.test(provider) ? { provider, id: modelId } : undefined,
        metrics,
        cases: { total: 0, passed: 0, failed: 0, errored: 0 },
        testSetCases: Number.isInteger(samples?.effective) ? samples.effective : Number.isInteger(samples?.original) ? samples.original : undefined,
        passed: true,
      };
    }),
  };
}

/** Complyd's generic shape, for any other harness (see the README). */
function generic(doc) {
  if (!doc || !Array.isArray(doc.suites) || !doc.suites.length) throw bad('generic');
  const name = typeof doc.tool?.name === 'string' && TOOL_NAME.test(doc.tool.name) ? doc.tool.name : 'generic';
  return {
    tool: { name, version: cleanVersion(doc.tool?.version) },
    ranAt: isoTime(doc.ran_at),
    suites: doc.suites.map((s) => {
      if (!s || typeof s.name !== 'string' || !Array.isArray(s.metrics ?? []) || (s.cases !== undefined && !isMap(s.cases))) throw bad('generic');
      const c = s.cases ?? {};
      const m = isMap(s.model) ? s.model : {};
      const cases = { total: count(c.total, 'generic'), passed: count(c.passed, 'generic'), failed: count(c.failed, 'generic'), errored: count(c.errored, 'generic') };
      return {
        label: s.name,
        model:
          typeof m.provider === 'string' && PROVIDER.test(m.provider) && isModelId(m.id)
            ? { provider: m.provider, id: m.id, ...(typeof m.version === 'string' && MODEL_VERSION.test(m.version) ? { version: m.version } : {}) }
            : undefined,
        metrics: (s.metrics ?? [])
          .filter((x) => typeof x?.name === 'string')
          .map((x) => ({
            name: metricName(x.name),
            value: numOrDecimal(x.value),
            threshold:
              isMap(x.threshold) && ['gte', 'lte'].includes(x.threshold.direction) && numOrDecimal(x.threshold.value) !== undefined
                ? { value: numOrDecimal(x.threshold.value), direction: x.threshold.direction }
                : undefined,
            passed: typeof x.passed === 'boolean' ? x.passed : undefined,
          })),
        cases,
        passed: typeof s.passed === 'boolean' ? s.passed : cases.failed + cases.errored === 0,
      };
    }),
  };
}

const PARSERS = { promptfoo, deepeval, 'openai-evals': openaiEvals, 'lm-eval': lmEval, generic };

const meets = (v, t) => (t.direction === 'gte' ? v >= t.value : v <= t.value);

/** A suite label safe to print (a promptfoo label may be the prompt's own text, so no spaces). */
const shown = (label, i) => (typeof label === 'string' && /^[A-Za-z0-9._:/@+-]{1,64}$/.test(label) ? `"${label}"` : `#${i + 1} (unnamed)`);

/**
 * The parsed results + the config → ai_eval v1 payload. Each result suite
 * is matched to a config suite by `match:` (else `name:`), or to the only
 * suite when there is one and the results carry one label. Only metrics the
 * suite declares under `metrics:` (and `pass_rate`) are sent. Warnings go to
 * `warn` (at most MAX_WARNINGS, then a count).
 */
function buildPayload(parsed, cfg, { format, role, commit, runId, ranAt, root, warn: sink = () => {} }) {
  const errors = [];
  let truncated = parsed.suites.length > MAX_SUITES;
  const suites = [];
  const covered = new Set();
  const hashes = new Map();
  let warned = 0;
  const warn = (w) => {
    warned += 1;
    if (warned <= MAX_WARNINGS) sink(w);
  };
  // Several labels on one config suite would send results of different runs under one name.
  const oneLabel = new Set(parsed.suites.map((t) => t.label)).size === 1;
  parsed.suites.slice(0, MAX_SUITES).forEach((t, i) => {
    const c =
      cfg.suites.find((s) => s.match !== undefined && s.match === t.label) ??
      cfg.suites.find((s) => s.name === t.label) ??
      (cfg.suites.length === 1 && oneLabel ? cfg.suites[0] : undefined);
    if (!c) {
      errors.push(`no suite in .complyd/ai.yml matches the results' suite ${shown(t.label, i)}: add match: to the suite it belongs to`);
      return;
    }
    covered.add(c.name);
    const where = `${c.prefix}suites[${c.index}]`;
    const model = c.model ?? t.model;
    if (!model) {
      errors.push(`${where}.model: the results don't name the model (provider and id): set model: { provider: …, id: … }`);
      return;
    }
    const dataset = c.dataset ? { ...c.datasetDef } : undefined;
    const datasetSha = dataset && hashFile(root, dataset.path, `${c.prefix}datasets.${c.dataset}.path`, hashes);
    let judge = c.evaluator.judge_model;
    if (!judge && t.judge !== undefined) {
      if (isJudge(t.judge)) judge = t.judge;
      else warn(`${c.name}: the results' judge model isn't a model id (a URL or a path?) and was left out: set evaluator.judge_model.`);
    }

    let suitePassed = t.passed;
    const metrics = [];
    let undeclared = 0;
    for (const m of t.metrics) {
      const declared = Object.hasOwn(c.metrics, m.name);
      if (!declared && m.name !== 'pass_rate') {
        // Not sent, but its verdict still counts.
        undeclared += 1;
        if (m.passed === false || (m.threshold && num(m.value) !== undefined && !meets(m.value, m.threshold))) suitePassed = false;
        continue;
      }
      const conf = declared ? c.metrics[m.name] : {};
      const value = decimal(m.value);
      if (value === undefined) {
        warn(`${c.name}: metric ${m.name} has no usable value and was left out.`);
        if (conf.threshold) suitePassed = false;
        continue;
      }
      // The config's threshold wins over the tool's.
      const threshold = conf.threshold ?? m.threshold;
      const passed = (m.passed ?? true) && (threshold ? meets(m.value, threshold) : true);
      metrics.push({
        name: m.name,
        ...(conf.category ? { category: conf.category } : {}),
        value,
        ...(threshold ? { threshold: { value: decimal(threshold.value), direction: threshold.direction } } : {}),
        passed,
      });
    }
    if (undeclared) warn(`${c.name}: ${undeclared} metric(s) not listed under metrics: in .complyd/ai.yml were left out (list a metric there to send it).`);
    for (const name of Object.keys(c.metrics)) {
      if (c.metrics[name].threshold && !t.metrics.some((m) => m.name === name)) {
        warn(`${c.name}: metric ${name} (thresholded in .complyd/ai.yml) isn't in the results: the suite is marked failed.`);
        suitePassed = false;
      }
    }
    // Thresholded metrics first, so a cut keeps the ones that decide.
    metrics.sort((a, b) => Number(!!b.threshold) - Number(!!a.threshold));
    if (metrics.length > MAX_METRICS) truncated = true;
    if (metrics.some((m) => !m.passed)) suitePassed = false;
    // No cases and no threshold: nothing was checked, so it can't have passed.
    if (suitePassed && t.cases.total === 0 && !metrics.some((m) => m.threshold)) {
      warn(`${c.name}: no cases and no thresholded metric in the results: the suite is marked failed.`);
      suitePassed = false;
    }

    const tsVersion = c.test_set.version ?? `sha256:${datasetSha.slice(0, 16)}`;
    suites.push({
      name: c.name,
      role,
      model: { provider: model.provider, id: model.id, ...(model.version ? { version: model.version } : {}) },
      ...(c.prompt_version ? { prompt_version: c.prompt_version } : {}),
      prompt_sha256: hashFiles(root, c.prompts, `${where}.prompts`, hashes),
      ...(dataset ? { dataset: { ...(dataset.ref ? { ref: dataset.ref } : {}), sha256: datasetSha } } : {}),
      test_set: {
        version: tsVersion,
        cases: Math.min(t.testSetCases ?? t.cases.total, MAX_COUNT),
        ...(c.test_set.selection ? { selection: c.test_set.selection } : {}),
        ...(c.test_set.expected_version ? { expected_version: c.test_set.expected_version } : {}),
      },
      evaluator: {
        ...(judge ? { judge_model: judge } : {}),
        ...(c.evaluator.rubric ? { rubric_sha256: hashFile(root, c.evaluator.rubric, `${where}.evaluator.rubric`, hashes) } : {}),
        version: c.evaluator.version ?? (parsed.tool.version === 'unknown' ? `${format}-unknown` : parsed.tool.version),
        parser: c.evaluator.parser ?? format,
      },
      metrics: metrics.slice(0, MAX_METRICS),
      cases: t.cases,
      passed: suitePassed,
    });
  });
  if (errors.length) throw new ActionError('config', errors.slice(0, 5).join('; ') + '.');
  // Only for the systems these results are about (v2 lists several).
  const about = new Set(cfg.suites.filter((s) => covered.has(s.name)).map((s) => s.prefix));
  for (const s of cfg.suites) if (s.required && about.has(s.prefix) && !covered.has(s.name)) warn(`Required suite ${s.name} isn't in these results.`);
  if (warned > MAX_WARNINGS) sink(`${warned - MAX_WARNINGS} more warnings not shown.`);
  return {
    tool: parsed.tool,
    format,
    commit,
    run_id: runId,
    ran_at: parsed.ranAt ?? ranAt,
    suites,
    truncated,
    repo_config: repoConfig(cfg),
  };
}

/**
 * The envelope's bytes under the route's cap: trailing suites go first and
 * the run is marked truncated. repo_config is never cut: when it (or the one
 * suite left) can't fit, an error names it.
 */
function fitSuites(env) {
  let body = JSON.stringify(env);
  let n = env.payload.suites.length;
  while (Buffer.byteLength(body) > MAX_BODY_BYTES && n > 1) {
    n -= 1;
    body = JSON.stringify({ ...env, payload: { ...env.payload, suites: env.payload.suites.slice(0, n), truncated: true } });
  }
  if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw overCap({ ...env, payload: { ...env.payload, suites: [] } }, 'payload.suites[0]');
  return body;
}

/** The error for an envelope over the cap: repo_config's fault when `bare` (the envelope without the cuttable part) is over too, else `field`'s. */
function overCap(bare, field) {
  const size = Buffer.byteLength(JSON.stringify(bare.payload.repo_config ?? null));
  if (Buffer.byteLength(JSON.stringify(bare)) > MAX_BODY_BYTES) {
    return new ActionError('config', `repo_config (the summary of .complyd/ai.yml: ${size} bytes) doesn't fit Complyd's 64 KiB request: use fewer or shorter paths: globs, suites or metrics in .complyd/ai.yml.`);
  }
  return new ActionError('config', `${field} doesn't fit Complyd's 64 KiB request beside repo_config (${size} bytes): use fewer metrics, or fewer or shorter paths: globs in .complyd/ai.yml.`);
}

/** The envelope id for one results file of one run: a retry is a duplicate, baseline and candidate are two. */
const aiEnvelopeId = (runKey, role, format, input) =>
  `${runKey}-ai_eval-${createHash('sha256').update(`${role}\n${format}\n${input}`).digest('hex').slice(0, 8)}`;

module.exports = { PARSERS, FORMATS, ROLES, buildPayload, fitSuites, overCap, aiEnvelopeId, decimal, providerModel };
