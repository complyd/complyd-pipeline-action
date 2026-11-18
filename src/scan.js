'use strict';

const { readFileSync, statSync, readdirSync } = require('fs');
const { join } = require('path');
const { reduce, ActionError } = require('./reduce');
const { reduceSast } = require('./sast');
const { envelope, fit, send } = require('./post');
const { loadConfig, DEFAULT_CONFIG } = require('./ai-config');
const { PARSERS, buildPayload, fitSuites, aiEnvelopeId } = require('./ai-eval');

/** Largest results file read (a scanner's JSON for a big monorepo is a few MB). */
const MAX_RESULTS_BYTES = 50 * 1024 * 1024;

/** Most files one SAST scan may merge (CodeQL writes one per language). */
const MAX_RESULT_FILES = 50;

/**
 * The files named by `results`: one path per line. For a SAST scan a path
 * may be a directory (its `*.sarif` files, not its subdirectories) and
 * several are merged into one scan; a dependency scan takes exactly one file.
 */
function resultFiles(results, scan) {
  const paths = results.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (scan !== 'sast') {
    if (paths.length > 1) throw new ActionError('input', '`results` names one file for a dependency scan.');
    return paths;
  }
  const files = [];
  for (const path of paths) {
    let dir = false;
    try {
      dir = statSync(path).isDirectory();
    } catch {
      // Unreadable: reported with the file below.
    }
    if (!dir) files.push(path);
    else {
      const found = readdirSync(path, { withFileTypes: true })
        .filter((e) => e.isFile() && e.name.toLowerCase().endsWith('.sarif'))
        .map((e) => join(path, e.name));
      if (!found.length) throw new ActionError('results', 'The `results` directory has no .sarif files.');
      files.push(...found);
    }
  }
  if (files.length > MAX_RESULT_FILES) {
    throw new ActionError('results', `More than ${MAX_RESULT_FILES} results files: merge them or name fewer.`);
  }
  return [...new Set(files)].sort();
}

/** One results file, parsed; its bytes are never echoed in an error. */
function readResults(path, budget) {
  try {
    const stat = statSync(path);
    // A device or FIFO reports size 0 and would be read without bound.
    if (!stat.isFile()) throw new ActionError('results', "The results path isn't a regular file.");
    const size = stat.size;
    if (size > budget) {
      throw new ActionError('results', `The results files are over ${MAX_RESULTS_BYTES / 1024 / 1024} MB: scan fewer paths per step.`);
    }
    return { doc: JSON.parse(readFileSync(path, 'utf8')), size };
  } catch (e) {
    if (e instanceof ActionError) throw e;
    // Never e.message: JSON.parse quotes the file's first bytes.
    const why = e instanceof SyntaxError ? "it isn't JSON" : (e.code ?? 'unreadable');
    throw new ActionError('results', `Couldn't read the results file (${why}).`);
  }
}

/** A subject id as Complyd takes it (github:…, gitlab-oidc:…, or under an ingest key's prefix). */
const SUBJECT = /^[A-Za-z0-9:._/-]{1,200}$/;

/**
 * The shared path of the action and the CLI: read the scanner's files, reduce
 * them to dependency_scan v1 (or sast_scan v1), wrap them in one envelope and
 * post it. `apiUrl` must have passed allowedApiUrl; `getToken` gives the
 * bearer for each try (an OIDC token or the ingest key); `trust` is set for a
 * workload trust only. `runKey` makes the envelope id `<runKey>-<schema>`, so
 * a retry is a duplicate. `subject` also salts SAST fingerprints. Resolves
 * Complyd's answer, the payload sent and what couldn't be sent.
 */
async function scan(
  { results, scan: kind, format = 'auto', commit, subject, runKey, workspace = '', apiUrl, trust, getToken },
  { fetchImpl = fetch, now = () => new Date(), sleep } = {},
) {
  if (!SUBJECT.test(subject ?? '')) throw new ActionError('input', "The repository id isn't valid (letters, digits and : . _ / -).");
  let budget = MAX_RESULTS_BYTES;
  const docs = resultFiles(results, kind).map((path) => {
    const read = readResults(path, budget);
    budget -= read.size;
    return read.doc;
  });
  // CodeQL's files, one per language, are one scan: their runs are merged.
  const doc =
    docs.length > 1
      ? { version: docs[0]?.version, runs: docs.flatMap((d) => (Array.isArray(d?.runs) ? d.runs : [])) }
      : docs[0];
  const at = now().toISOString();
  const { payload, dropped } = (kind === 'sast' ? reduceSast : reduce)(doc, {
    format,
    commit,
    scannedAt: at,
    subject,
    workspace,
  });
  const schema = kind === 'sast' ? 'sast_scan' : 'dependency_scan';
  const body = fit(envelope(payload, { id: `${runKey}-${schema}`, subject, observedAt: at, schema }));
  const answer = await send({ apiUrl, trust, body, getToken }, fetchImpl, sleep);
  return { answer, payload: JSON.parse(body).payload, dropped };
}

/**
 * An AI eval run: read the tool's results file and .complyd/ai.yml, build
 * ai_eval v1 (hashes, counts and metric values only) and post it as
 * collector complyd_ai_release, unless `dryRun`. `workspace` is the
 * repository root the config's paths are relative to. Resolves Complyd's
 * answer (null on a dry run), the envelope sent (or that would be) and warnings.
 */
async function scanAi(
  { input, format, role = 'candidate', configPath = DEFAULT_CONFIG, commit, subject, runKey, workspace = process.cwd(), apiUrl, trust, getToken, dryRun = false },
  { fetchImpl = fetch, now = () => new Date(), sleep } = {},
) {
  if (!SUBJECT.test(subject ?? '')) throw new ActionError('input', "The repository id isn't valid (letters, digits and : . _ / -).");
  if (!/^([0-9a-f]{40}|[0-9a-f]{64})$/.test(commit ?? '')) {
    throw new ActionError('commit', "The commit (GITHUB_SHA, CI_COMMIT_SHA, --commit or the checkout's HEAD) isn't a 40- or 64-character SHA.");
  }
  const cfg = loadConfig(configPath, workspace);
  const { doc } = readResults(input, MAX_RESULTS_BYTES);
  const warnings = [];
  const at = now().toISOString();
  const payload = buildPayload(PARSERS[format](doc), cfg, {
    format,
    role,
    commit,
    runId: runKey,
    ranAt: at,
    root: workspace,
    warn: (w) => warnings.push(w),
  });
  const id = aiEnvelopeId(runKey, role, format, input);
  const body = fitSuites(envelope(payload, { id, subject, observedAt: at, schema: 'ai_eval', collector: 'complyd_ai_release' }));
  const sent = JSON.parse(body);
  if (dryRun) return { answer: null, envelope: sent, warnings };
  const answer = await send({ apiUrl, trust, body, getToken }, fetchImpl, sleep);
  return { answer, envelope: sent, warnings };
}

/** The lines both entries print after an AI eval push. */
function aiSummary({ answer, envelope: env }) {
  const s = env.payload.suites;
  const failed = s.filter((x) => !x.passed).length;
  return [
    `Sent ${s.length} eval suites (${s.length - failed} passed, ${failed} failed)${env.payload.truncated ? ', list cut' : ''}.`,
    answer.unchanged
      ? `Unchanged since the last run: Complyd recorded the check-in (${answer.observation}).`
      : `Stored as ${answer.observation}${answer.duplicate ? ' (already sent by this run)' : ''}.`,
  ];
}

/** One line of what couldn't be sent: "2 (no usable version 1, …): GHSA-…" (SAST: no ids). */
function droppedLine(dropped) {
  const why = Object.entries(dropped.reasons)
    .map(([reason, n]) => `${reason} ${n}`)
    .join(', ');
  const ids = dropped.ids.length ? `: ${dropped.ids.join(', ')}${dropped.count > dropped.ids.length ? ', …' : ''}` : '';
  return `Not sent: ${dropped.count} findings the action couldn't read (${why})${ids}. Complyd reads the SLA check as unknown until they are.`;
}

/** The lines both entries print after a push. */
function summary({ answer, payload }) {
  const c = payload.counts;
  return [
    `Sent ${payload.findings.length} findings (critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low})` +
      `${payload.truncated ? ', list cut: Complyd reads the SLA check as unknown' : ''}.`,
    answer.unchanged
      ? `Unchanged since the last scan: Complyd recorded the check-in (${answer.observation}).`
      : `Stored as ${answer.observation}${answer.duplicate ? ' (already sent by this run)' : ''}.`,
  ];
}

/**
 * Text for a workflow command or a log line: `%`, CR and LF escaped as the
 * runner expects, so text from a file, a server or an argument can't start a
 * command (`::…`) of its own on a new line.
 */
const escape = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');

/** An error as one line: an ActionError's advice, else only its kind (never a server's or a file's text). */
const errorLine = (e) =>
  e instanceof ActionError ? e.message : `Unexpected error (${e?.name ?? 'Error'}${e?.cause?.code ? `, ${e.cause.code}` : ''}).`;

module.exports = { scan, scanAi, aiSummary, summary, droppedLine, errorLine, escape, MAX_RESULTS_BYTES, MAX_RESULT_FILES };
