#!/usr/bin/env node
'use strict';

const { parseArgs } = require('util');
const { createHash, randomUUID } = require('crypto');
const { execFileSync } = require('child_process');
const { ActionError } = require('./reduce');
const { oidcToken, allowedApiUrl, audienceAllowed, envelope, MAX_BODY_BYTES } = require('./post');
const { scan, scanAi, aiSummary, summary, droppedLine, errorLine, escape } = require('./scan');
const { FORMATS, ROLES, overCap } = require('./ai-eval');
const { deployRecord } = require('./ai-release');
const { DEFAULT_CONFIG } = require('./ai-config');
const { version } = require('../package.json');

const USAGE = `Usage: complyd-pipeline scan dependencies|sast --input <file> [options]
       complyd-pipeline scan ai_eval --format <tool> --input <file> [options]
       complyd-pipeline deploy record --environment <env> --dry-run [--system <name>]

Sends a scanner's results to Complyd (dependency_scan v2 or sast_scan v2), or
an AI eval run's results (ai_eval v2: hashes, counts and metric values only).

  --input <path>        SARIF 2.1.0 or OSV-Scanner JSON (sast: SARIF; repeat it
                        or name a directory of .sarif files to merge them)
  --format <f>          auto (default), sarif or osv; for ai_eval: promptfoo,
                        deepeval, openai-evals, lm-eval or generic
  --scanner-version <v> The scanner's version, over its output's (OSV-Scanner
                        JSON names none), e.g. 2.7.1
  --lockfile <path>     dependencies: the lockfile the scanner read; only its
                        SHA-256 is sent. Default: the first one the scanner's
                        output names that is on disk
  --files-scanned <n>   sast: the number of files scanned, over the count the
                        SARIF gives (Semgrep names only files with findings)
  --role <r>            ai_eval: candidate (default) or baseline
  --suite-config <path> ai_eval, deploy record: the AI config, relative to the
                        workspace. Default: .complyd/ai.yml
  --dry-run             ai_eval, deploy record: print the envelope, send nothing
                        (deploy record: required; sending it is coming soon)
  --environment <env>   deploy record: where this deploy goes, e.g. production
  --system <name>       deploy record: the AI system's name (default: system: in
                        the AI config; version 2: one record per system the
                        commit touches, or only this system's)
  --repo <subject>      Complyd's repository id. Default: github:<repository id>
                        on GitHub, gitlab-oidc:<host>/<project id> on GitLab,
                        bitbucket-oidc:<repository uuid> on Bitbucket; required
                        on CircleCI (circleci-oidc:<project id>) and with an
                        ingest key (under the key's prefix)
  --commit <sha>        The scanned commit (40 hex). Default: GITHUB_SHA,
                        CI_COMMIT_SHA, CIRCLE_SHA1, BITBUCKET_COMMIT, GIT_COMMIT,
                        CODEBUILD_RESOLVED_SOURCE_VERSION or BUILD_SOURCEVERSION
  --run-id <id>         Ingest key only: this build's id, so a retry is not a
                        second scan. Default: BUILD_TAG, CODEBUILD_BUILD_ID, else random
  --workspace <dir>     The checkout directory (SAST file:// paths). Default: the
                        CI's checkout directory, else the current directory
  --trust <trw_…>       Sign in under this workload trust (GitHub Actions OIDC,
                        or GitLab CI, CircleCI, Bitbucket with --id-token-var)
  --audience <url>      The trust's audience (required on GitHub)
  --id-token-var <name> The variable that holds the job's ID token: GitLab's
                        id_tokens: entry, CircleCI's circleci run oidc get,
                        Bitbucket's BITBUCKET_STEP_OIDC_TOKEN
  --api-url <url>       For testing only, on the audience's host. Default: the
                        audience's origin, else https://api.complyd.ai
  --insecure-local-api  For tests: also allow --api-url on localhost (http)

Sign-in, in this order: --id-token-var (GitLab CI, CircleCI, Bitbucket),
--trust (GitHub Actions), else the COMPLYD_INGEST_KEY environment variable
(Jenkins, CodeBuild, Azure DevOps, …).
Exit codes: 0 sent (or Complyd already has a newer scan), 1 refused or failed, 2 usage.`;

const OPTIONS = {
  input: { type: 'string', multiple: true },
  format: { type: 'string', default: 'auto' },
  repo: { type: 'string' },
  commit: { type: 'string' },
  'run-id': { type: 'string' },
  workspace: { type: 'string' },
  trust: { type: 'string' },
  audience: { type: 'string' },
  'id-token-var': { type: 'string' },
  'api-url': { type: 'string' },
  'insecure-local-api': { type: 'boolean' },
  'scanner-version': { type: 'string' },
  lockfile: { type: 'string' },
  'files-scanned': { type: 'string' },
  role: { type: 'string', default: 'candidate' },
  'suite-config': { type: 'string', default: DEFAULT_CONFIG },
  'dry-run': { type: 'boolean' },
  environment: { type: 'string' },
  system: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean' },
};

const DEFAULT_API = 'https://api.complyd.ai';
const usage = (message) => new ActionError('usage', message);
/** The scan kinds (`dependency` is the 1.0 spelling, kept). */
const KINDS = { dependencies: 'dependency', dependency: 'dependency', sast: 'sast', ai_eval: 'ai_eval' };
const CIRCLECI_SUBJECT = /^circleci-oidc:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const UUID = /^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$/i;
const first = (...vs) => vs.find((v) => typeof v === 'string' && v.trim() !== '')?.trim();

/** argv (without node and the script) → the scan kind and options; throws a usage error. */
function parse(argv) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (e) {
    // parseArgs names the bad option; it holds no secret.
    throw usage(e.message);
  }
  const { values, positionals } = parsed;
  if (values.help || values.version) return { values, kind: null };
  if (positionals.length === 2 && positionals[0] === 'deploy' && positionals[1] === 'record') {
    if (!values.environment) throw usage('Set --environment to where this deploy goes, e.g. production.');
    // shortcut: Complyd doesn't take deploy records yet; send them once its ai_release schema ships.
    if (!values['dry-run']) throw usage('Sending deploy records to Complyd is coming soon: add --dry-run to print the record.');
    return { values, kind: 'deploy' };
  }
  if (positionals.length !== 2 || positionals[0] !== 'scan' || !Object.hasOwn(KINDS, positionals[1])) {
    throw usage('Name the scan: complyd-pipeline scan dependencies|sast|ai_eval … (or deploy record …)');
  }
  if (!values.input?.length) throw usage("Set --input to the scanner's output file.");
  if (KINDS[positionals[1]] === 'ai_eval') {
    if (!FORMATS.includes(values.format)) throw usage(`Set --format to the eval tool: ${FORMATS.join(', ')}.`);
    if (values.input.length > 1) throw usage('ai_eval takes one --input file per run of the command.');
    if (!ROLES.includes(values.role)) throw usage('Set --role to candidate (default) or baseline.');
  } else {
    if (!['auto', 'sarif', 'osv'].includes(values.format)) throw usage('Set --format to auto, sarif or osv.');
    if (values['dry-run']) throw usage('--dry-run is for ai_eval and deploy record.');
  }
  return { values, kind: KINDS[positionals[1]] };
}

/**
 * Who signs the push and what the CI says about the run: an ID token in a
 * variable (--id-token-var: GitLab CI, CircleCI, Bitbucket Pipelines),
 * GitHub's OIDC (--trust), or an ingest key (COMPLYD_INGEST_KEY). Each gives
 * its own default subject and run key; the same run key as the action on
 * GitHub, `gitlab-<job id>`, `circleci-<job id>` or `bb-<step uuid>` (as
 * Complyd's docs name them), so a retry is a duplicate. Nothing is fetched here.
 */
function authFrom(values, env, fetchImpl, sleep) {
  const tokenVar = values['id-token-var'];
  const trust = values.trust;
  if (tokenVar || trust) {
    if (!/^trw_[0-9a-f-]{36}$/.test(trust ?? '')) throw usage('Set --trust to the trust id from Complyd (trw_…).');
  }
  if (tokenVar) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(tokenVar)) throw usage('Set --id-token-var to a variable name, e.g. COMPLYD_ID_TOKEN.');
    const token = first(env[tokenVar]);
    // A JWT only: --id-token-var must not send some other secret (CI_JOB_TOKEN, …) as the bearer.
    if (!token || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(token)) {
      throw new ActionError(
        'oidc',
        `This job has no ID token in ${tokenVar}: on GitLab add it under id_tokens: with aud: set to the trust's audience (CircleCI: circleci run oidc get --v3 --aud; Bitbucket: oidc: audiences:).`,
      );
    }
    // CircleCI's project id is in no variable: --repo names it.
    if (env.CIRCLECI === 'true') {
      const job = UUID.exec(env.CIRCLE_WORKFLOW_JOB_ID ?? '')?.[1];
      return { source: 'circleci', trust, getToken: async () => token, subject: undefined, runKey: job && `circleci-${job.toLowerCase()}`, workspace: undefined };
    }
    if (env.BITBUCKET_BUILD_NUMBER) {
      const repo = UUID.exec(env.BITBUCKET_REPO_UUID ?? '')?.[1];
      const step = UUID.exec(env.BITBUCKET_STEP_UUID ?? '')?.[1];
      return {
        source: 'bitbucket',
        trust,
        // A step gets its token once, as on GitLab.
        getToken: async () => token,
        subject: repo && `bitbucket-oidc:${repo.toLowerCase()}`,
        runKey: step && `bb-${step.toLowerCase()}`,
        workspace: env.BITBUCKET_CLONE_DIR,
      };
    }
    const host = first(env.CI_SERVER_URL)?.replace(/^https:\/\//, '').replace(/\/+$/, '');
    const project = first(env.CI_PROJECT_ID);
    const job = first(env.CI_JOB_ID);
    return {
      source: 'gitlab',
      trust,
      // A GitLab job gets its token once: a retry sends the same one.
      getToken: async () => token,
      subject: host && /^[0-9]{1,20}$/.test(project ?? '') ? `gitlab-oidc:${host}/${project}` : undefined,
      runKey: /^[0-9]{1,20}$/.test(job ?? '') ? `gitlab-${job}` : undefined,
      workspace: env.CI_PROJECT_DIR,
    };
  }
  if (trust) {
    const audience = first(values.audience);
    if (!audience) throw usage("Set --audience to the trust's audience from Complyd (https://…).");
    const repo = first(env.GITHUB_REPOSITORY_ID);
    const runId = first(env.GITHUB_RUN_ID);
    const attempt = first(env.GITHUB_RUN_ATTEMPT) ?? '1';
    return {
      source: 'github',
      trust,
      getToken: () => oidcToken(env, audience, fetchImpl, sleep),
      subject: /^[0-9]{1,20}$/.test(repo ?? '') ? `github:${repo}` : undefined,
      runKey: /^[0-9]{1,20}$/.test(runId ?? '') && /^[0-9]{1,6}$/.test(attempt) ? `${runId}-${attempt}` : undefined,
      workspace: env.GITHUB_WORKSPACE,
    };
  }
  const key = first(env.COMPLYD_INGEST_KEY);
  if (!key) throw usage('No sign-in: set --trust (GitHub Actions, or GitLab CI with --id-token-var) or COMPLYD_INGEST_KEY.');
  if (!/^cing_[A-Za-z0-9_-]{1,200}$/.test(key)) throw usage("COMPLYD_INGEST_KEY isn't an ingest key (cing_…).");
  // The CI's build id may hold any text: hashed (with the repository, as two
  // repositories can share a build number) into the envelope id's alphabet and length.
  const build = first(values['run-id'], env.BUILD_TAG, env.CODEBUILD_BUILD_ID);
  return {
    source: 'key',
    trust: undefined,
    getToken: async () => key,
    subject: undefined,
    runKey: `ci-${build ? createHash('sha256').update(`${first(values.repo) ?? ''}\n${build}`).digest('hex').slice(0, 32) : randomUUID().replace(/-/g, '')}`,
    workspace: undefined,
  };
}

const commitFrom = (values, env) =>
  first(
    values.commit,
    env.GITHUB_SHA,
    env.CI_COMMIT_SHA,
    env.CIRCLE_SHA1,
    env.BITBUCKET_COMMIT,
    env.GIT_COMMIT,
    env.CODEBUILD_RESOLVED_SOURCE_VERSION,
    env.BUILD_SOURCEVERSION,
  );

/** The checkout's HEAD, for a run outside CI (a local dry run). */
function gitHead(dir) {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    return undefined;
  }
}

/**
 * What `scanAi` needs. A dry run without any sign-in (on a laptop) needs no
 * repository id or CI: it only prints the envelope.
 */
function aiOptions(values, env, deps) {
  const signedIn = values.trust || values['id-token-var'] || first(env.COMPLYD_INGEST_KEY);
  const o =
    values['dry-run'] && !signedIn
      ? { subject: first(values.repo) ?? 'dry-run', runKey: `ci-${randomUUID().replace(/-/g, '')}`, commit: commitFrom(values, env)?.toLowerCase(), workspace: first(values.workspace) ?? process.cwd() }
      : options('ai_eval', values, env, deps);
  return {
    ...o,
    commit: o.commit ?? gitHead(o.workspace),
    input: values.input[0],
    format: values.format,
    role: values.role,
    configPath: values['suite-config'],
    dryRun: values['dry-run'] === true,
  };
}

/** Everything `scan` needs, from the arguments and the CI's environment; throws before any request. */
function options(kind, values, env, { fetchImpl = fetch, sleep } = {}) {
  const auth = authFrom(values, env, fetchImpl, sleep);
  let subject = first(values.repo) ?? auth.subject;
  // Under OIDC the subject is the token's: a different --repo would only be refused (or worse) by the server.
  if (auth.source !== 'key' && auth.subject && subject !== auth.subject) {
    throw usage(`Leave --repo out: with this sign-in the repository is ${auth.subject}.`);
  }
  if (!subject) {
    throw usage(
      {
        key: "Set --repo to the repository id under your ingest key's subject prefix (e.g. gitlab:42/payments-api).",
        circleci: "Set --repo to circleci-oidc:<project id> (CircleCI's project settings).",
        github: 'Set --repo: GITHUB_REPOSITORY_ID is missing.',
        gitlab: 'Set --repo: CI_SERVER_URL or CI_PROJECT_ID is missing.',
        bitbucket: 'Set --repo: BITBUCKET_REPO_UUID is missing.',
      }[auth.source],
    );
  }
  // CircleCI's token names the project, not the repository: the subject must be that project's id.
  if (auth.source === 'circleci') {
    const project = CIRCLECI_SUBJECT.exec(subject)?.[1];
    if (!project) throw usage("Set --repo to circleci-oidc:<project id>, the project's UUID (CircleCI's project settings).");
    subject = `circleci-oidc:${project.toLowerCase()}`;
  }
  const runVar = { github: 'GITHUB_RUN_ID', gitlab: 'CI_JOB_ID', circleci: 'CIRCLE_WORKFLOW_JOB_ID', bitbucket: 'BITBUCKET_STEP_UUID' };
  if (!auth.runKey) throw usage(`${runVar[auth.source]} is missing: run this in the CI job.`);
  const commit = commitFrom(values, env);
  let apiUrl;
  try {
    apiUrl = new URL(first(values['api-url']) ?? (values.audience ? new URL(values.audience).origin : DEFAULT_API));
  } catch {
    throw usage('--audience and --api-url must be addresses (https://…).');
  }
  // Checked before any token is asked for or sent: it only ever goes to Complyd over https.
  const audience = first(values.audience);
  if (!allowedApiUrl(apiUrl, values['insecure-local-api']) || (audience && !audienceAllowed(audience, apiUrl, values['insecure-local-api']))) {
    throw usage(
      "Complyd's address must be https://api.complyd.ai: check --audience (and --api-url, which is for testing only and must match the audience's host).",
    );
  }
  return {
    results: values.input.join('\n'),
    scan: kind,
    format: values.format,
    commit: commit?.toLowerCase(),
    subject,
    runKey: auth.runKey,
    workspace: first(values.workspace, auth.workspace) ?? process.cwd(),
    apiUrl,
    trust: auth.trust,
    getToken: auth.getToken,
    scannerVersion: first(values['scanner-version']),
    lockfile: first(values.lockfile),
    filesScanned: first(values['files-scanned']),
  };
}

/** The CLI; resolves the exit code. Lines go to stdout, warnings and errors to stderr. */
async function main(argv = process.argv.slice(2), env = process.env, deps = {}) {
  const { out: print = console.log, err: printErr = console.error } = deps;
  // Escaped as the action's lines are: an argument's text (in a usage error) can't start a workflow command.
  const out = (line) => print(escape(line));
  const err = (line) => printErr(escape(line));
  try {
    const { values, kind } = parse(argv);
    if (values.help || values.version) {
      print(values.help ? USAGE : version);
      return 0;
    }
    if (kind === 'deploy') {
      const root = first(values.workspace) ?? process.cwd();
      const now = deps.now ?? (() => new Date());
      const rec = deployRecord({ environment: values.environment, system: values.system, root, configPath: values['suite-config'], now, warn: (w) => err(`warning: ${w}`) });
      // v2: every record carries repo_config and config_changed, which v1 refuses.
      const wrap = (payload) => {
        const env = envelope(payload, { id: `ci-${randomUUID().replace(/-/g, '')}-ai_release`, subject: first(values.repo) ?? 'dry-run', observedAt: payload.released_at, schema: 'ai_release', collector: 'complyd_ai_release', schemaVersion: 2 });
        // The same 64 KiB cap as a sent scan, repo_config included.
        if (Buffer.byteLength(JSON.stringify(env)) > MAX_BODY_BYTES) throw overCap({ ...env, payload: { ...payload, changes: [] } }, 'payload.changes');
        return env;
      };
      // A version 2 config gives one record per touched system: a list, maybe empty.
      if (Array.isArray(rec) && !rec.length) err('warning: this commit touches no AI system listed in the AI config: no deploy record.');
      print(JSON.stringify(Array.isArray(rec) ? rec.map(wrap) : wrap(rec), null, 2));
      return 0;
    }
    if (kind === 'ai_eval') {
      const r = await scanAi(aiOptions(values, env, deps), deps);
      for (const w of r.warnings) err(`warning: ${w}`);
      // Every string in it matched the schema's patterns: no line can start a workflow command.
      if (!r.answer) print(JSON.stringify(r.envelope, null, 2));
      else for (const line of aiSummary(r)) out(line);
      return 0;
    }
    const { answer, payload, dropped, unproven } = await scan(options(kind, values, env, deps), deps);
    const [sent, stored] = summary({ answer, payload });
    out(sent);
    if (dropped.count) err(`warning: ${droppedLine(dropped)}`);
    if (unproven) err(`warning: ${unproven}`);
    out(stored);
    return 0;
  } catch (e) {
    // A newer scan already stored is not this job's failure.
    if (e?.code === 'out_of_order') {
      err(`warning: ${errorLine(e)}`);
      return 0;
    }
    err(`error: ${errorLine(e)}`);
    if (e?.code === 'usage') err('Run complyd-pipeline --help for the options.');
    return e?.code === 'usage' ? 2 : 1;
  }
}

module.exports = { main, parse, options, USAGE };

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  });
}
