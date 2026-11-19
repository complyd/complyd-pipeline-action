'use strict';

const { appendFileSync } = require('fs');
const { ActionError } = require('./reduce');
const { oidcToken, allowedApiUrl, audienceAllowed } = require('./post');
const { FORMATS, ROLES } = require('./ai-eval');
const { DEFAULT_CONFIG } = require('./ai-config');
const { scan: push, scanAi, aiSummary, summary, droppedLine, errorLine, escape, MAX_RESULTS_BYTES, MAX_RESULT_FILES } = require('./scan');

/** An action input (GitHub passes `with:` values as INPUT_<NAME> variables). */
const input = (env, name) => (env[`INPUT_${name.toUpperCase()}`] ?? '').trim();

/**
 * The whole action: read the scanner's file, reduce it to dependency_scan
 * v1 (or sast_scan v1 with `scan: sast`), sign in with the job's OIDC token for the trust's audience and post
 * it. Resolves Complyd's answer, the payload sent and what couldn't be sent;
 * throws an ActionError with advice on any refusal. `env` is process.env on
 * a runner; `fetchImpl` and `sleep` are for tests.
 */
async function run(env = process.env, { fetchImpl = fetch, now = () => new Date(), sleep } = {}) {
  const trust = input(env, 'trust');
  let audience = input(env, 'audience');
  // `input` is the ai_eval spelling; either names the file.
  const results = input(env, 'results') || input(env, 'input');
  // `dependencies` is the CLI's word; `dependency` the 1.0 input, kept.
  const SCANS = { '': 'dependency', dependency: 'dependency', dependencies: 'dependency', sast: 'sast', ai_eval: 'ai_eval' };
  const scanInput = input(env, 'scan');
  const scan = Object.hasOwn(SCANS, scanInput) ? SCANS[scanInput] : undefined;
  if (!scan) throw new ActionError('input', 'Set `scan` to dependencies (default), sast or ai_eval.');
  const format = input(env, 'format') || 'auto';
  const role = input(env, 'role') || 'candidate';
  if (scan === 'ai_eval') {
    if (!FORMATS.includes(format)) throw new ActionError('input', `Set \`format\` to the eval tool: ${FORMATS.join(', ')}.`);
    if (!ROLES.includes(role)) throw new ActionError('input', 'Set `role` to candidate (default) or baseline.');
  }
  if (!/^trw_[0-9a-f-]{36}$/.test(trust)) {
    throw new ActionError('input', 'Set `trust` to the trust id from Complyd (trw_…).');
  }
  let apiUrl;
  try {
    apiUrl = new URL(input(env, 'api-url') || (audience ? new URL(audience).origin : 'https://api.complyd.ai'));
  } catch {
    throw new ActionError('input', "Set `audience` to the trust's audience from Complyd (https://…).");
  }
  // A new trust's audience is <api>/observations/<trust>; a rotated trust keeps its old one, so `audience` still wins.
  audience ||= new URL(`/observations/${trust}`, apiUrl).href;
  // Checked before the token is asked for: it only ever goes to Complyd over https.
  if (!allowedApiUrl(apiUrl) || !audienceAllowed(audience, apiUrl)) {
    throw new ActionError(
      'input',
      "Complyd's address must be https://api.complyd.ai: check `audience` (and `api-url`, which is for testing only and must match the audience's host).",
    );
  }
  if (!results) throw new ActionError('input', "Set `results` (or `input`) to the scanner's output file.");
  const repositoryId = env.GITHUB_REPOSITORY_ID;
  if (!/^[0-9]{1,20}$/.test(repositoryId ?? '')) {
    throw new ActionError('input', 'This runs only in GitHub Actions (GITHUB_REPOSITORY_ID is missing).');
  }
  const runId = env.GITHUB_RUN_ID ?? '';
  const runAttempt = env.GITHUB_RUN_ATTEMPT ?? '1';
  if (!/^[0-9]{1,20}$/.test(runId) || !/^[0-9]{1,6}$/.test(runAttempt)) {
    throw new ActionError('input', 'This runs only in GitHub Actions (GITHUB_RUN_ID is missing).');
  }

  const getToken = () => oidcToken(env, audience, fetchImpl, sleep);
  if (scan === 'ai_eval') {
    return scanAi(
      {
        input: results,
        format,
        role,
        configPath: input(env, 'suite-config') || DEFAULT_CONFIG,
        commit: env.GITHUB_SHA?.toLowerCase(),
        subject: `github:${repositoryId}`,
        runKey: `${runId}-${runAttempt}`,
        workspace: env.GITHUB_WORKSPACE || process.cwd(),
        apiUrl,
        trust,
        getToken,
      },
      { fetchImpl, now, sleep },
    );
  }
  return push(
    {
      results,
      scan,
      format,
      commit: env.GITHUB_SHA,
      subject: `github:${repositoryId}`,
      runKey: `${runId}-${runAttempt}`,
      workspace: env.GITHUB_WORKSPACE ?? '',
      apiUrl,
      trust,
      getToken,
    },
    { fetchImpl, now, sleep },
  );
}

/** Runner entry: logs, sets the outputs, fails the step on a refusal. */
async function main(env = process.env) {
  const out = (name, value) => {
    if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `${name}=${escape(value)}\n`);
  };
  try {
    const r = await run(env);
    if (r.envelope) {
      for (const w of r.warnings) console.log(`::warning::${escape(w)}`);
      for (const line of aiSummary(r)) console.log(escape(line));
      out('observation', r.answer.observation);
      out('dropped', '0');
      return;
    }
    const { answer, payload, dropped } = r;
    const [sent, stored] = summary({ answer, payload });
    console.log(sent);
    if (dropped.count) console.log(`::warning::${escape(droppedLine(dropped))}`);
    console.log(stored);
    // run() accepts only an obs_ id; escaped anyway, as every output is.
    out('observation', answer.observation);
    out('dropped', String(dropped.count));
  } catch (e) {
    const message = errorLine(e);
    // A newer scan already stored is not this job's failure.
    if (e?.code === 'out_of_order') console.log(`::warning::${escape(message)}`);
    else {
      console.log(`::error::${escape(message)}`);
      process.exitCode = 1;
    }
  }
}

module.exports = { run, main, escape, droppedLine, MAX_RESULTS_BYTES, MAX_RESULT_FILES };
