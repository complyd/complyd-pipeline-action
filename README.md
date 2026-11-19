# Complyd pipeline

Sends your pipeline's dependency scan, SAST scan or AI eval results from GitHub Actions to [Complyd](https://complyd.ai),
signed in with the workflow's own OIDC token: no secret to store. The same
code runs as a command line tool, `complyd-pipeline`, for GitLab CI,
CircleCI and Bitbucket Pipelines (signed in with the job's own ID token) and
for Jenkins, AWS CodeBuild, Azure DevOps or any other CI (with an ingest
key): see [Other CI systems](#other-ci-systems). Complyd's
vulnerability checks then read it: scans run regularly, and critical and high
findings are fixed within your SLA.

The action reads your scanner's output (SARIF 2.1.0 or OSV-Scanner JSON) and
sends, per finding, only the advisory id (and its other ids), ecosystem, package, version,
severity and fixed version, beside the commit, the repository id and the run id.
The scan holds no file paths, code, author, committer or actor. The sign-in
token sent with it is your CI's own and does name the repository, branch,
workflow and the user who started the run (on GitLab also their e-mail
address): see [What Complyd receives](#what-complyd-receives). A SAST scan
(`scan: sast`) sends even less: see [SAST scans](#sast-scans). An AI eval
run (`scan: ai_eval`) sends hashes, counts and metric values, never prompts or
outputs: see [AI release](#ai-release).

## Set up

1. In Complyd, open **Settings › Workload trusts › Create trust**, tick
   **Complyd CI scan** (the name Complyd lists this tool's scans under), and
   enter the repository's owner id and repository id
   (`gh api repos/OWNER/REPO --jq '.owner.id, .id'`) and its default branch.
2. Copy the **trust id** (`trw_…`) it shows.
3. Add the action after your scanner step, on the default branch:

```yaml
name: Dependency scan
on:
  push:
    branches: [main]
  schedule:
    - cron: '17 3 * * *' # daily: keeps "scans run regularly" passing
  workflow_dispatch:

permissions:
  id-token: write # lets the job ask GitHub for a sign-in token
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - name: Scan dependencies
        uses: google/osv-scanner-action/osv-scanner-action@32d3cd482bdadfb38b186c0ad1b031902d55d932 # v2.7.1
        continue-on-error: true # findings make osv-scanner exit 1
        with:
          scan-args: |-
            --format=json
            --output=osv-results.json
            --recursive
            ./
      - name: Send the dependency scan to Complyd
        # Pin the release commit (see Releases); @v1 follows every v1.x.y.
        uses: complyd/complyd-pipeline-action@<v1.1.0 commit SHA> # v1.1.0
        with:
          trust: trw_00000000-0000-4000-8000-000000000000 # your trust id
          results: osv-results.json
```

The action signs in for the audience `https://api.complyd.ai/observations/<trust>`,
the one Complyd gives a new trust. If Complyd shows the trust with a different
audience (a rotated trust keeps its old one), add it: `audience: <as shown>`.

Any scanner that writes SARIF works too (Trivy: `format: sarif`; Grype:
`output-format: sarif`): point `results` at its file. The readers are tested
on real OSV-Scanner (JSON and SARIF), Trivy and Grype output
(`test/fixtures/real`).

Send one scan of each kind per repository per run: a second dependency
scan from the same run attempt (a matrix, or two scanners) is refused as
`idempotency_conflict`.
Merge the scanners' findings into one file, or use one scanner.

## SAST scans

With `scan: sast` the action reads a SAST scanner's SARIF 2.1.0 (CodeQL,
Semgrep, or any tool that writes SARIF) and sends a `sast_scan`: per finding
only the **rule id**, the **severity** and a **fingerprint**. No file path,
line number, code snippet or message is sent in clear.

**What the fingerprint is, plainly.** It is a hash (HMAC-SHA-256, keyed by
`github:<your repository id>`, which is not a secret and is stored beside it)
of the rule id and where the finding is. The salt keeps your fingerprints from
matching another workspace's, but anyone who can read the scan Complyd stores
**and** holds your code, or can guess a finding's file path, can test a guess
against the hash and confirm it. No path is ever sent in clear, but the hash
is not a secret. If that is not acceptable, don't send SAST scans. (An
optional secret key for the hash is not offered yet: it would add a secret to
this action, and losing or rotating it would restart every first-seen date.)

- **What is hashed**: the rule id and the scanner's own fingerprint when it
  writes a hash-like one (CodeQL's `partialFingerprints`), else the rule id,
  the file path and the matched code with its whitespace collapsed (Semgrep
  OSS writes the placeholder `requires login` as its fingerprint, which is
  not used). With neither a fingerprint nor matched code, it is the rule id
  and the file path alone, which is the easiest to guess. There is no line
  number in it, so a finding keeps its first-seen date when code above it
  moves or a formatter changes its spacing. A `file://` location loses the
  workflow's workspace path first.
- **Severity**: `security-severity` (CodeQL; CVSS bands: 9+ critical, 7+
  high, 4+ medium, else low), else the result level (`error` high, `warning`
  medium, `note` low), else medium (SARIF's default level, `warning`). Only
  critical and high findings count for the SLA check. CodeQL gives some
  non-vulnerability queries a high score (for example a missing rate limit),
  and they count too: switch those queries off in the scanner if they
  shouldn't.
- **Not sent**: passing results, results with a `kind` other than `fail`
  (`open`, `review`, `informational`, `notApplicable`), suppressed results
  (accepted, or with no status), and results fixed since the baseline
  (`baselineState: absent`). A result without a rule id can't be named: it is
  not sent and marks the scan cut.
- **The rule id is sent as the scanner writes it**, including the names of
  your own rules (Semgrep names a local rule after its file's folder, e.g.
  `rules.internal.auth.my-rule`) and the tool's name and version. An id over
  128 characters is cut and ends in a hash.

**Limits**
- At most 500 findings, and the whole request must fit in 64 KiB: with long
  rule ids that can be fewer than 500. The most severe go first, so every
  critical and high finding is sent unless there are too many of them; the
  scan is then marked cut and Complyd reads the SLA check as "Couldn't
  check", never as a pass, even when only low findings were left out.
- A fingerprint changes when the file is renamed or moved, when the matched
  code changes beyond whitespace (Semgrep), when you switch scanner, or when
  a rule is renamed. Complyd then sees a new finding and its first-seen date
  starts again: an edit that isn't a fix restarts the SLA clock. (The 30-day
  memory doesn't cover this: it is keyed by the same fingerprint.)
- CodeQL's own line hash has no path in it, so the same line in two files is
  one finding (it stays open until both are fixed; the count is one low).
  Without a scanner fingerprint or matched code, several findings of one rule
  in one file are also one.
- The finding's location is not shown in Complyd, only the rule id: open the
  scanner's own results to find the code.

**Several files, e.g. CodeQL with more than one language.** CodeQL writes one
SARIF file per language. Name them all: `results` takes a directory (its
`*.sarif` files, not its subdirectories) or one path per line, and the action
merges them into one `sast_scan` of the run (up to 50 files; the same 50 MB in
all). Sending one file per step is not an option: a second `sast_scan` from
one run attempt is refused as `idempotency_conflict`, and a later one would
replace the earlier findings. A directory scan sorts the files by name, so
the scan's tool is the first file's.

The SAST scan is its own record in Complyd: it never replaces the
repository's dependency findings, and a daily dependency scan doesn't keep
the SAST scan's "scans run regularly" passing (or the reverse). One job may
send both, one step each. A repository with CodeQL for JavaScript and Python:

```yaml
      - name: CodeQL
        uses: github/codeql-action/analyze@<commit SHA> # v3
        with:
          output: codeql-results # one SARIF file per language: javascript.sarif, python.sarif
      - name: Send the SAST scan to Complyd
        uses: complyd/complyd-pipeline-action@<v1.1.0 commit SHA> # v1.1.0
        with:
          trust: trw_00000000-0000-4000-8000-000000000000
          scan: sast
          results: codeql-results # the directory: every language is sent together
```

Semgrep: `semgrep scan --config auto --sarif --output semgrep.sarif`, then
`results: semgrep.sarif`. The readers are tested on real CodeQL 2.27.4 and
Semgrep OSS 1.185.0 output (`test/fixtures/real`), with the fingerprints
pinned.

## Other CI systems

`complyd-pipeline` is the action's code as a command (Node 20 or later, no
dependencies). It reads the same files, sends the same payload with the same
limits and retries, and fails the job the same way.

```sh
complyd-pipeline scan dependencies|sast --input <file> [--format auto|osv|sarif] [--repo <id>] [--commit <sha>] [sign-in options]
```

`--input` can be repeated, or name a directory of `.sarif` files, for a SAST
scan (as `results` in the action). `complyd-pipeline --help` lists every
option. Exit code 0: sent, or Complyd already has a newer scan; 1: refused
or failed (the line says what to do); 2: a wrong option.

**Renamed in 1.1.0.** The command was `complyd-ci-scan dependency|sast …`.
That name still works in 1.1.x, with the same options, and prints a
deprecation line on stderr; it goes away in 1.2.0. Change it to
`complyd-pipeline scan dependencies|sast …`.

Install it from this repository, pinned to a release commit
(`npm install --global github:complyd/complyd-pipeline-action#<commit SHA>`), or
build the image from the `Dockerfile` (distroless Node, no shell). The npm
package `@complyd/pipeline` and the image `ghcr.io/complyd/pipeline` are
published from the release workflow once a release is approved (see
[RELEASING.md](RELEASING.md)); until then, install from the repository.

**Sign-in**, the first that applies:

1. `--trust` with `--id-token-var <NAME>`: the job's own ID token in `$NAME`.
   **GitLab CI** (from `id_tokens:`), **CircleCI** (from `circleci run oidc
   get`) or **Bitbucket Pipelines** (`BITBUCKET_STEP_OIDC_TOKEN`).
2. `--trust` with `--audience`: **GitHub Actions** OIDC, as the action.
3. The `COMPLYD_INGEST_KEY` environment variable: an **ingest key** (Settings
   › Ingest keys) for any other CI. Keep it in the CI's secret store.

   **An ingest key is weaker than 1 and 2.** It can't prove which repository
   or branch a build ran on: `--repo`, `--commit` and the branch are
   whatever the caller says. Anyone who can read the key can replace the
   findings of every repository under its prefix, for example with a clean
   scan. So: create **one key per repository, with the narrowest prefix**
   (`jenkins:acme/payments-api`, not `jenkins:acme/`); and expose it **only
   to builds of the default or another protected branch**, never to pull
   request or feature-branch builds (guard the stage, as the Jenkins,
   CodeBuild and Azure DevOps examples do).

**The repository id** (`--repo`) is what Complyd files the scan under. On
GitHub it is `github:<repository id>`, on GitLab
`gitlab-oidc:<GitLab host>/<project id>` and on Bitbucket
`bitbucket-oidc:<repository uuid>`, all read from the job; leave `--repo`
out. On CircleCI it is `circleci-oidc:<project id>` (the project's UUID from
CircleCI's project settings): set it; anything else is refused before a
request. With an ingest key it is required and
must start with the key's subject prefix (e.g. prefix `jenkins:acme/`,
`--repo jenkins:acme/payments-api`); `github:`, `gitlab-oidc:`,
`circleci-oidc:` and `bitbucket-oidc:` ids are refused for keys. Keep it the
same on every run: a SAST fingerprint is keyed by it, and a new id is a new
repository in Complyd.

**The commit** comes from `--commit`, else `GITHUB_SHA`, `CI_COMMIT_SHA`
(GitLab), `CIRCLE_SHA1`, `BITBUCKET_COMMIT`, `GIT_COMMIT` (Jenkins Git
plugin), `CODEBUILD_RESOLVED_SOURCE_VERSION` or `BUILD_SOURCEVERSION` (Azure
DevOps). **One push per run and scan kind**: with an ingest key the push's
id comes from `--run-id`, else `BUILD_TAG` (Jenkins) or `CODEBUILD_BUILD_ID`,
else a random one, so a retried request is not stored twice; on GitLab it is
`gitlab-<job id>`, on CircleCI `circleci-<workflow job id>` and on Bitbucket
`bb-<step uuid>`.

### GitLab CI

Create a trust with **CI provider: GitLab CI** (Settings › Workload trusts),
then copy its trust id and audience:

```yaml
dependency-scan:
  image: node:22-alpine
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  id_tokens:
    COMPLYD_ID_TOKEN:
      aud: https://api.complyd.ai/observations/trw_00000000-0000-4000-8000-000000000000 # its audience
  variables:
    OSV_SCANNER_VERSION: '2.0.2'
    # From the release's osv-scanner_SHA256SUMS; update it with the version.
    OSV_SCANNER_SHA256: 3abcfd7126c453a00421487e721b296e0cb68085bd431d6cef60872774170fc8
  script:
    - wget -qO /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
    - echo "${OSV_SCANNER_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c -
    - chmod +x /usr/local/bin/osv-scanner
    # osv-scanner exits 1 when it finds something: that is still a scan to send.
    - osv-scanner scan source -r --format json . > osv-results.json || [ $? -eq 1 ]
    - npm install --global --ignore-scripts github:complyd/complyd-pipeline-action#<commit SHA>
    - >
      complyd-pipeline scan dependencies --input osv-results.json
      --trust trw_00000000-0000-4000-8000-000000000000
      --audience https://api.complyd.ai/observations/trw_00000000-0000-4000-8000-000000000000
      --id-token-var COMPLYD_ID_TOKEN
```

This one job downloads a scanner and holds the ID token. To keep the token
away from third-party code, scan in one job (no `id_tokens:`) and pass
`osv-results.json` as an artifact to a second job that alone declares
`id_tokens:` and runs only `complyd-pipeline`.

A GitLab job gets its ID token once, at job start: if Complyd answers
`unavailable` and the retry is refused as `replayed_nonce`, re-run the job.
The job's timeout must be 3 hours or less (GitLab sets the token's lifetime
to it). For a SAST scan, run the scanner in its own job and pass its SARIF
as an artifact to a job like this one with `complyd-pipeline scan sast
--input <file>`.

### Jenkins

Create an ingest key for **Complyd CI scan** with the narrowest subject prefix,
`jenkins:acme/payments-api` (one key per repository, see Sign-in above), and
store it as a secret text credential:

```groovy
stage('Send the dependency scan to Complyd') {
  when { branch 'main' }
  steps {
    withCredentials([string(credentialsId: 'complyd-ingest-key', variable: 'COMPLYD_INGEST_KEY')]) {
      sh '''
        docker run --rm -e COMPLYD_INGEST_KEY -e BUILD_TAG -v "$PWD:/src:ro" -w /src complyd-pipeline \
          scan dependencies --input osv-results.json --repo jenkins:acme/payments-api --commit "$GIT_COMMIT"
      '''
    }
  }
}
```

(`complyd-pipeline` is the image built from this repository's `Dockerfile`,
or `ghcr.io/complyd/pipeline@sha256:<digest>` once published; on an agent
with Node 20+, install the command as above instead.)

A published image's tag can be moved, so use it by the digest from the
release notes and check it came from this repository's release workflow
before you give it your key:

```sh
gh attestation verify oci://ghcr.io/complyd/pipeline@sha256:<digest> \
  --repo complyd/complyd-pipeline-action \
  --signer-workflow complyd/complyd-pipeline-action/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

### AWS CodeBuild

Keep the ingest key (prefix `codebuild:acme/payments-api`, one per
repository) in Secrets Manager. CodeBuild webhooks often build pull
requests, so send only from the default branch:

```yaml
version: 0.2
env:
  secrets-manager:
    COMPLYD_INGEST_KEY: complyd/ingest-key
phases:
  install:
    runtime-versions:
      nodejs: 20
    commands:
      - npm install --global --ignore-scripts github:complyd/complyd-pipeline-action#<commit SHA>
  build:
    commands:
      - semgrep scan --config auto --sarif --output semgrep.sarif
      # CODEBUILD_WEBHOOK_HEAD_REF is refs/heads/<branch> for a webhook build; this
      # fails closed for a pull request, a tag or a manual build without it.
      - |
        if [ "$CODEBUILD_WEBHOOK_HEAD_REF" = "refs/heads/main" ]; then
          complyd-pipeline scan sast --input semgrep.sarif --repo codebuild:acme/payments-api
        else
          echo "Not the default branch: scan not sent."
        fi
```

The commit (`CODEBUILD_RESOLVED_SOURCE_VERSION`) and the run
(`CODEBUILD_BUILD_ID`) are read from the build. Unlike a workload trust, an
ingest key can't tell which branch a build ran on, which is why the key is
only exposed to the default branch's builds (Sign-in, above).

### CircleCI

Create a trust with **CI provider: CircleCI** for the project, then copy its
trust id and audience. The job asks CircleCI for a token for that audience
(`--v3`: the default falls back to a v1 token, which Complyd refuses); the
project id is in CircleCI's project settings:

```yaml
jobs:
  dependency-scan:
    docker:
      - image: cimg/node:22.11
    steps:
      - checkout
      # … run OSV-Scanner, writing osv-results.json
      - run:
          name: Send the dependency scan to Complyd
          command: |
            npm install --global --ignore-scripts github:complyd/complyd-pipeline-action#<commit SHA>
            COMPLYD_ID_TOKEN=$(circleci run oidc get --v3 --aud "https://api.complyd.ai/observations/trw_00000000-0000-4000-8000-000000000000") \
              complyd-pipeline scan dependencies --input osv-results.json \
                --trust trw_00000000-0000-4000-8000-000000000000 \
                --id-token-var COMPLYD_ID_TOKEN \
                --repo circleci-oidc:<project id>
workflows:
  scan:
    jobs:
      - dependency-scan:
          filters:
            branches:
              only: main
```

A token lives one hour. Pushes from an SSH rerun of the job, and from a
fork's pull request built under the project, are refused (`not_allowed`).

CircleCI's token is issued per **project**, not per repository: its subject
names the organisation, the project and the user, so a trust on CircleCI
accepts any job of that project. Keep one repository per CircleCI project
you send from.

### Bitbucket Pipelines

Create a trust with **CI provider: Bitbucket Pipelines** (the workspace's
identity provider URL is under Repository settings › OpenID Connect), then
turn on OIDC for the step with the trust's audience. The repository id and
the run are read from the step:

```yaml
pipelines:
  branches:
    main:
      - step:
          name: Dependency scan
          image: node:22-alpine
          oidc:
            audiences:
              - https://api.complyd.ai/observations/trw_00000000-0000-4000-8000-000000000000
          script:
            # … run OSV-Scanner, writing osv-results.json
            - npm install --global --ignore-scripts github:complyd/complyd-pipeline-action#<commit SHA>
            - >
              complyd-pipeline scan dependencies --input osv-results.json
              --trust trw_00000000-0000-4000-8000-000000000000
              --id-token-var BITBUCKET_STEP_OIDC_TOKEN
```

Keep the step's `max-time` at 175 minutes or less (the default, 120, is
fine): Bitbucket sets the token's lifetime to it plus 5 minutes, and Complyd
refuses tokens that live over 3 hours. A step gets its token once: one push
per scan kind, and a retry means re-running the step.

### Azure DevOps

Azure Pipelines' OIDC tokens always carry Azure's own audience, so Complyd
doesn't take them: use an ingest key (prefix `azure-devops:acme/payments-api`,
one per repository) kept as a secret pipeline variable, and send only from
the default branch:

```yaml
trigger:
  branches:
    include: [main]
pool:
  vmImage: ubuntu-latest
steps:
  # … run OSV-Scanner, writing osv-results.json
  - script: |
      npm install --global --ignore-scripts github:complyd/complyd-pipeline-action#<commit SHA>
      complyd-pipeline scan dependencies --input osv-results.json \
        --repo azure-devops:acme/payments-api \
        --run-id "$(Build.BuildId)-$(System.JobAttempt)"
    displayName: Send the dependency scan to Complyd
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    env:
      COMPLYD_INGEST_KEY: $(COMPLYD_INGEST_KEY)
```

The commit is read from `BUILD_SOURCEVERSION`. Limit who can run the
pipeline with the secret (branch policies, pipeline permissions): anyone who
can read the variable can push as the key.

## AI release

With `scan: ai_eval` (the command: `complyd-pipeline scan ai_eval`) the
action sends the results of an AI eval run, so Complyd can show which prompt,
model, test set and evaluator a release was checked with, and whether its
required suites passed. It reads the eval tool's results file and
`.complyd/ai.yml` in your repository:

| `format` | Tool | File to point `input` at |
|---|---|---|
| `promptfoo` | promptfoo | `promptfoo eval -o results.json` (one suite per prompt × provider) |
| `deepeval` | DeepEval | `.deepeval/.latest_test_run.json` after `deepeval test run` |
| `openai-evals` | OpenAI Evals API | the run object, `GET /v1/evals/{eval_id}/runs/{run_id}` (or a list of runs) |
| `lm-eval` | lm-evaluation-harness | the `results_*.json` under `--output_path` (one suite per task) |
| `generic` | anything else | Complyd's generic shape, below |

**Data minimisation.** Complyd never receives prompts, model outputs, test
cases or dataset contents. Per suite it receives only: the suite, metric and
category names, metric values and thresholds, case counts, the model's
provider and id, the test set and evaluator versions, the judge model's id,
and SHA-256 hashes of the prompt, dataset and rubric files (computed in your
CI). A hash does not reveal a file's content, though a short or guessable
file can be confirmed by someone who guesses it. For one file the hash is
the file's own SHA-256; for several it is the SHA-256 of `sha256sum`-style
lines (`<sha256>  <path>`, sorted by path). The readers keep numbers and ids
only: a metric is sent only when its name is listed under the suite's
`metrics:` in `.complyd/ai.yml` (`pass_rate` always), and a model or judge id
that looks like a URL or a local path is left out. The tests check that no
prompt, output, case or metric-name text from the fixtures reaches what is
sent. Beside the suites, each run carries `repo_config`, a summary of
`.complyd/ai.yml` (see [What Complyd receives](#what-complyd-receives)).
Run with `--dry-run` to see exactly what would be sent.

The tool's own suite labels (a promptfoo prompt label can be the prompt's
text) are used only to find the suite in `.complyd/ai.yml` and are never
sent: the suite is sent under its `name:` from the config.

### `.complyd/ai.yml`

```yaml
version: 1
system: support-assistant            # optional: the AI system's name
model:                               # files that pick the model
  provider: openai                   # the deployed model (deploy record needs it)
  id: gpt-4o-mini
  version: "2024-07-18"              # optional
  files: [config/llm.yaml]
  keys: [model, model_version]       # these lines are the model; the rest are its parameters
prompts:                             # prompt files (hashed; default for every suite)
  - prompts/support.txt
safety:
  files: [prompts/guardrails.txt]    # whole files that are safety instructions
  markers: { start: "<!-- safety:start -->", end: "<!-- safety:end -->" }  # safety sections inside prompt files
datasets:
  refusals:
    path: evals/data/refusals.jsonl  # hashed, never sent
    ref: datasets/refusals@3         # optional label
retrieval: [config/retrieval.yaml]   # optional: RAG settings
tools: [config/tools.json]           # optional: tool / function definitions
product_config: [config/features.yaml]
eval_method: [evals/grader.py]       # optional: graders, scoring code
suites:
  - name: safety-refusals            # the name Complyd shows
    match: support-v2                # the suite's name in the tool's results (default: name)
    required: true                   # a release must pass it
    prompts: [prompts/support.txt]   # default: the top-level prompts
    prompt_version: v12
    dataset: refusals
    model: { provider: openai, id: gpt-4o-mini, version: "2024-07-18" }  # when the results don't say
    test_set: { version: "4", selection: curated }  # selection: production_sample, curated, synthetic, regression or mixed
    evaluator:
      version: "3"                   # default: the tool's version
      parser: llm-rubric             # default: the format
      judge_model: openai/gpt-4o
      rubric: evals/rubric.md        # hashed, never sent
    metrics:
      pass_rate: { gte: 0.95, category: unsafe_compliance }
      latency_p95_ms: { lte: 1500 }
    files: [promptfooconfig.yaml]    # the suite's own eval config
```

Paths are relative to the repository root and must stay inside it: a
symlink that leads outside the repository is refused. Quote versions
(`"1.10"`): an unquoted `1.10` is a number and is refused. A mistake fails the step with
each problem and what to change, e.g. `suites[0].test_set.version: set the
test set version (or a dataset:, whose hash then names it)`. Each suite needs
prompt files and a test set version (or a dataset). The file is read by a
strict YAML reader: anchors, tags and `|` / `>` text blocks are refused.

#### Version 2: several AI systems in one repository

When a repository holds more than one AI system, list them under `systems:`.
Each entry takes the same keys as a version 1 file (`model:`, `prompts:`,
`safety:`, `datasets:`, `retrieval:`, `tools:`, `product_config:`,
`eval_method:`, `suites:`), plus `system:` (required) and `paths:`, the globs
of the files that belong to it. Version 1 files keep working unchanged: they
are one system that owns the whole repository.

```yaml
version: 2
systems:
  - system: support-assistant          # the AI system's name or its AIS-… reference
    paths: ["services/support/**", "prompts/support/**"]
    model:
      provider: openai
      id: gpt-4o-mini
      files: [services/support/llm.yaml]
      keys: [model]
    prompts: [prompts/support/system.txt]
    suites:
      - name: safety-refusals
        required: true
        test_set: { version: "4" }
        metrics:
          pass_rate: { gte: 0.95 }
  - system: search-ranker
    paths: ["services/**"]               # services/support/ stays with support-assistant: more specific
    model: { provider: example-ai, id: rerank-1 }
    prompts: [services/search/rerank.txt]
    suites:
      - name: ranking-quality
        test_set: { version: "2" }
        metrics:
          ndcg: { gte: 0.75 }
          toxicity: { lte: 0.01 }
```

- `paths:` globs are relative to the repository root, without `..`: `*`
  matches within a directory, `**` any number of directories (as a whole
  path part, e.g. `src/**/*.py`; `**/**` is the same as `**`), `?` one
  character. With a single system `paths:` may be left out (it owns `**`);
  with several it is required.
- A file matched by two systems belongs to the one whose matching glob is
  more specific: has more literal characters (not `*`, `?` or `/`), so
  `services/support/**` beats `services/**`, and extra `**` parts add
  nothing. A tie: the same glob in two systems (after `**/**` becomes
  `**`) fails validation, and so does a declared file two systems match
  equally; any other changed file two systems match equally belongs to
  neither (as Complyd reads it), so `deploy record` leaves it out.
- Every file a system declares (model files, prompts, safety, datasets,
  retrieval, tools, product config, eval method, a suite's prompts, files
  and rubric) must be its own: matched by its `paths:` and not won by a
  more specific glob of another system. `deploy record` gives a changed file
  to its owner only, so anything else is a config error, e.g.
  `systems[0].tools[0]: config/tools.json is not under this system's paths
  (add it to paths: or move it)`. Version 1 owns `**`, so any file is fine.
- A threshold (`gte:`/`lte:`) is a number below 1000000000000 with at most 9
  decimal places, as Complyd stores it; anything else is a config error.
- System names and suite names are unique across the file: a results suite
  is matched against every system's suites. Errors name the entry, e.g.
  `systems[1].paths: list the globs of the files that belong to this system`.

How each suite is filled in:

- **Metrics.** promptfoo: `pass_rate` and each named score's average;
  DeepEval: each metric's average score with its threshold (Bias, Toxicity
  and Hallucination are lower-is-better); OpenAI: `pass_rate` and each
  testing criterion's pass rate; lm-eval: each metric (`acc`, `acc_norm`,
  `exact_match:<filter>`, …), without its stderr. Only metrics listed under
  `metrics:` are sent (`{}` lists one without a threshold), under the name
  the tool gives with characters other than letters, digits, spaces and
  `. _ : / @ + -` changed to `-`. A metric left out still counts: if the tool
  failed it, the suite fails. A threshold under `metrics:` replaces the
  tool's; a thresholded metric missing from the results fails the suite.
- **Matching.** A results suite goes to the config suite whose `match:` (else
  `name:`) equals the tool's label. With one config suite, results with a
  single label go to it; results with several labels need `match:`.
- **Cases.** The tool's pass, fail and error counts. lm-eval has no per-case
  verdicts: its cases are 0 and its sample count is the test set size. A
  suite with no cases (any tool) passes only through a threshold: with none,
  it is sent as failed.
- **Role.** `role: baseline` for the version in production re-run as the
  comparison, `candidate` (default) for the change being released. Send each
  as its own step.

### GitHub Actions

Tick **Complyd AI release** when you create the trust (Settings › Workload
trusts), then:

```yaml
      - run: npx promptfoo@0.112.3 eval -c promptfooconfig.yaml -o promptfoo-results.json || true
      - name: Send the eval run to Complyd
        uses: complyd/complyd-pipeline-action@<commit SHA> # vX.Y.Z
        with:
          trust: trw_00000000-0000-4000-8000-000000000000
          audience: https://api.complyd.ai/observations/trw_00000000-0000-4000-8000-000000000000
          scan: ai_eval
          format: promptfoo
          input: promptfoo-results.json
          role: candidate
```

The trust's rules apply as for scans (its default branch and allowed events).

### GitLab CI

```yaml
ai-eval:
  image: node:22-alpine
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  id_tokens:
    COMPLYD_ID_TOKEN:
      aud: https://api.complyd.ai/observations/trw_00000000-0000-4000-8000-000000000000
  script:
    - npx promptfoo@0.112.3 eval -c promptfooconfig.yaml -o promptfoo-results.json || true
    - npm install --global --ignore-scripts github:complyd/complyd-pipeline-action#<commit SHA>
    - >
      complyd-pipeline scan ai_eval --format promptfoo --input promptfoo-results.json
      --trust trw_00000000-0000-4000-8000-000000000000
      --id-token-var COMPLYD_ID_TOKEN
```

### Any other CI (ingest key)

Create an ingest key for **Complyd AI release** (one per repository, see
Sign-in above):

```sh
lm_eval --model hf --model_args pretrained=acme/support-7b --tasks hellaswag --output_path out/
COMPLYD_INGEST_KEY=… complyd-pipeline scan ai_eval --format lm-eval \
  --input out/acme__support-7b/results_*.json --repo jenkins:acme/support-bot
```

Locally, `complyd-pipeline scan ai_eval --format … --input … --dry-run`
prints the envelope without any sign-in.

### Generic format

For any other harness, write this JSON (`value` a number or a decimal
string; `threshold`, `passed` and `model` optional; a suite without `passed`
passes when it has no failed or errored cases; `tool.name` is an id without
spaces):

```json
{
  "tool": { "name": "acme-harness", "version": "2.1.0" },
  "ran_at": "2026-11-18T09:00:00Z",
  "suites": [
    {
      "name": "safety-refusals",
      "model": { "provider": "acme", "id": "support-large", "version": "3" },
      "metrics": [
        { "name": "refusal_rate", "value": 0.97, "threshold": { "value": 0.95, "direction": "gte" }, "passed": true }
      ],
      "cases": { "total": 200, "passed": 194, "failed": 6, "errored": 0 },
      "passed": true
    }
  ]
}
```

Other keys are ignored and never sent.

### Deploy records (coming soon)

```sh
complyd-pipeline deploy record --environment production [--system support-assistant] --dry-run
```

compares the files `.complyd/ai.yml` names at the deployed commit and its
parent and prints which kinds changed, each with a before and after
SHA-256 (a kind with no files on one side has no hash there): `model`
(the model files and `model:`'s provider, id and version), `model_params`,
`prompt`, `safety_prompt`, `eval_suite` (suite files and settings),
`dataset`, `retrieval`, `tools`, `product_config` and `eval_method`
(evaluator settings, rubrics, graders). Beside its diff the record states
the deployed commit's facts: the deployed model (`model:`'s `provider:`,
`id:` and `version:`, required for `deploy record`), each layer's hash and
the datasets' hashes (see [What Complyd receives](#what-complyd-receives)).
The record also says whether `.complyd/ai.yml` itself changed
(`config_changed`) and carries `repo_config`. No file content is in the
record, and no path other than the globs under `paths:`.

With a version 2 file it prints a list: one record per system that owns a
changed file (the owner of a file two systems match, see above). When
`.complyd/ai.yml` changed (paths, a renamed or removed system, even a
comment) and no system owns a changed file, the list is one record without
`system_hint`, with no `changes` and no release facts (no model, tools,
datasets or eval run ids), carrying `config_changed: true` and the new
`repo_config`. A commit that touches none prints `[]` with a warning.
`--system` picks one system from the file (its record is printed even when
the commit doesn't touch it). It needs the parent commit
(`actions/checkout` `fetch-depth: 2`, GitLab `GIT_DEPTH: 2`). **Sending it
to Complyd is coming soon**: today it runs only with `--dry-run`.

Known limits of the dry run: it compares HEAD with its first parent only, so
a deploy that carries several commits shows the last commit's change (the
record will need the previously deployed commit before it is sent); a file
git can't show (over 512 MB, or a checkout git refuses because another user
owns it) reads as missing; and its hashes come from git's stored blobs, so
under Git LFS or line-ending conversion they differ from the working-tree
hashes `scan ai_eval` sends for the same file.

## Inputs

| Input | Required | Meaning |
|---|---|---|
| `trust` | yes | The trust id from Complyd, `trw_…` |
| `audience` | yes | The trust's audience from Complyd |
| `results` | yes* | Path of the scanner's output file. For `scan: sast`: a file, a directory of `*.sarif` files, or one path per line, merged into one scan |
| `input` | yes* | Same as `results` (*set one of them) |
| `scan` | no | `dependencies` (default; `dependency` also works), `sast` (SARIF only) or `ai_eval` |
| `format` | no | `auto` (default), `sarif` or `osv`; for `ai_eval`: `promptfoo`, `deepeval`, `openai-evals`, `lm-eval` or `generic` |
| `role` | no | `ai_eval` only: `candidate` (default) or `baseline` |
| `suite-config` | no | `ai_eval` only: the AI config, default `.complyd/ai.yml` |
| `api-url` | no | For testing only: Complyd's address, defaults to the audience's origin and must be on the same host |

The sign-in token goes only over https (port 443) to `api.complyd.ai` or
`api-dev.complyd.ai`, and only to the host its audience names (a production
audience never to `api-dev.complyd.ai`, nor the reverse); any other
`audience` or `api-url` fails the step before a token is asked for. (The command also takes
`--insecure-local-api`, for tests against a localhost server.) No
redirect is followed.

Outputs: `observation`, the id Complyd gave the stored scan; `dropped`, how
many findings the action couldn't read (see below).

## What Complyd receives

For a dependency scan, one observation per run (`<run id>-<run attempt>-dependency_scan`, so a
retried request is not stored twice): the scanner's name and version, the
commit, the scan time, the counts per severity (after merging duplicates,
before the 500 cut), up to 500 findings (most severe first) and whether the
list was cut. Each finding carries its advisory's other ids (`aliases`, e.g.
the CVE beside a GHSA id) when the scanner names them, so Complyd keeps its
first-seen date when an alias is published later or you switch scanner.

Every scan is sent as collector `complyd_ci_scan` with `collector_version`
set to this package's version: Complyd's id for this tool, unchanged by the
rename to Complyd pipeline. An AI eval run is sent as collector
`complyd_ai_release` (Complyd lists it as **Complyd AI release**), schema
`ai_eval` v2, one observation per results file and role
(`<run id>-<run attempt>-ai_eval-<hash>`): the eval tool's name and version,
the format, the commit, the run id, the run time, the suites (see
[AI release](#ai-release)), whether the list was cut (`truncated`) and
`repo_config`.

A deploy record (`deploy record`, dry run only for now) is schema
`ai_release` v2 of the same collector:

| Field | What it is |
|---|---|
| `commit` | the deployed commit |
| `environment` | `--environment` |
| `released_at` | when the record was made (also the envelope's `observed_at`) |
| `system_hint` | the system's name (`--system`, `system:`); left out of a config-only record |
| `changes` | per changed kind: `kind`, `before_sha256`, `after_sha256` (against the parent commit) |
| `model` | the deployed model: `provider`, `id`, `version` from `model:` |
| `params_sha256`, `prompt_sha256`, `safety_sha256`, `retrieval_sha256`, `config_sha256`, `evaluator_sha256` | the deployed commit's hash of the model parameters, prompts, safety sections, retrieval, product config and eval method (the `changes` hash of that kind; left out when it has no files) |
| `tools` | tool names: always `[]` for now (tool files are hashed under `changes`) |
| `datasets` | per dataset: its `ref:` and the file's SHA-256 at the deployed commit |
| `eval_run_ids` | always `[]` for now (Complyd links eval runs by commit) |
| `config_changed` | whether `.complyd/ai.yml` differs from the parent commit's |
| `repo_config` | below |

A layer hash is SHA-256 of sorted `<sha256|missing>  <file>` lines, so it is
not the file's own hash `scan ai_eval` sends. Not sent (optional in
Complyd's schema): `pull_request`, `endpoint_region`. Both schemas are
version 2 because of `repo_config` (and `config_changed`): Complyd's
version 1 refuses them. `test/fixtures/schemas` holds the copies of
Complyd's schema files the tests validate the dry-run output against.

An AI eval run and a deploy record also carry `repo_config`, what
`.complyd/ai.yml` says about where each system lives and what it must pass:
the file's version and SHA-256, and per system its name, its `paths:` globs
and its suites' names, `required:` flags and metric thresholds (as decimal
strings). Nothing else from the file and no file's contents: Complyd uses it
to place changes and to propose an eval plan, which you still approve in
Complyd. It is never cut: when it doesn't fit Complyd's 64 KiB request
(beside one suite, or a deploy record's changes), the run fails with an
error naming `repo_config`; shorten `paths:` or the suites in
`.complyd/ai.yml`.

```json
{
  "version": 2,
  "config_sha256": "<SHA-256 of .complyd/ai.yml>",
  "systems": [
    {
      "system": "support-assistant",
      "paths": ["services/support/**", "prompts/support/**"],
      "suites": [{ "name": "safety-refusals", "required": true, "metrics": { "pass_rate": { "gte": "0.95" } } }]
    },
    {
      "system": "search-ranker",
      "paths": ["services/**"],
      "suites": [{ "name": "ranking-quality", "required": false, "metrics": { "ndcg": { "gte": "0.75" }, "toxicity": { "lte": "0.01" } } }]
    }
  ]
}
```

A version 1 file gives one system with `"paths": ["**"]` (and no `system`
when the file has no `system:`).

For a SAST scan, one observation per run (`<run id>-<run attempt>-sast_scan`):
the same envelope, with each finding reduced to its rule id, severity and
fingerprint (see [SAST scans](#sast-scans)).

**The sign-in token.** Beside the scan, each request carries the sign-in
token your CI issues for the trust's audience (or your ingest key). Complyd
reads it to check the request against the trust. It is your CI's, not
something this tool writes, and its claims name the run, including who
started it:

- GitHub Actions: the repository and its owner, the ref, the commit, the
  workflow, the run id and event, and the actor (user name and id).
- GitLab CI: the project and namespace paths, the ref, the pipeline and job
  ids, and the user who started the pipeline: login, id **and e-mail
  address**.
- CircleCI: the organisation, the project and the id of the user who
  started the job.
- Bitbucket Pipelines: the workspace, the repository, the branch, the
  pipeline and step ids.

Your CI's documentation lists every claim. An ingest key carries none of
this.

- **More than 500 findings** (or more than fit in 64 KiB), or a finding the
  action can't read (a result without a package, a package name with unusual
  characters): the most severe ones that fit are sent and the scan is marked
  cut. Complyd then reads the SLA check as "Couldn't check" for this
  repository, never as a pass. The step logs a warning with how many findings
  it couldn't read, why, and their advisory ids.
- A git dependency pinned by commit (no version) is sent with the commit as
  its version.
- **No severity in the scanner's output**: the finding is sent as high.
- SARIF severity: `security-severity` (CVSS: 9+ critical, 7+ high, 4+ medium,
  else low), then the scanner's severity word, then the result level
  (`error` high, `warning` medium, `note` low).
- A finding missing from one scan keeps its first-seen date for 30 days, so
  one flaky scan doesn't restart its SLA clock.

Complyd accepts scans from the trust's default branch and its allowed events
only; pull request and feature-branch runs are refused, so they can't replace
the default branch's findings.

## Errors

The step fails with a line saying what to do, for example:

- `unauthenticated`: check the `trust` and `audience` inputs and that the
  trust isn't revoked.
- `not_allowed`: the run isn't on the default branch, uses an event the trust
  doesn't allow, or the repository isn't in the trust.
- "GitHub gave this job no sign-in token": add `permissions: id-token: write`.

A newer scan already stored (`out_of_order`) is a warning, not a failure. If
you'd rather never fail the job on Complyd's answer, add
`continue-on-error: true` to the step.

Each request has a 30 s deadline. A network error, a timeout, a 429 or a 5xx
is tried again up to 3 times in all (1 s, then 2 s apart, or the server's
`Retry-After` up to 30 s), with a new sign-in token each time; the same
observation id means a scan is never stored twice.

## Runners

The action runs on `node24`: GitHub-hosted runners have it; on GitHub
Enterprise Server or self-hosted runners, use a runner version that supports
`node24` actions. Behind a proxy, set `NODE_USE_ENV_PROXY: 1` beside your
`HTTPS_PROXY` in the step's `env`, or Node's fetch ignores the proxy.

## Releases

Whoever can move the `v1` tag runs code on every workflow that uses
`@v1`, with `id-token: write`. So this repository has, from its first
release on:

1. A ruleset on `main`: changes only through a pull request with one
   approval and the CI workflow (`.github/workflows/ci.yml`) passing; no
   force pushes, no deletion, no bypass.
2. A ruleset on tags `v*`: only the release maintainers may create, move
   or delete them (`v1` moves to each release; `vX.Y.Z` never moves).
   Releases are published as immutable releases.
3. A `release` environment with required reviewers (no self-review, no
   administrator bypass) that only `vX.Y.Z` tags may deploy to. The npm
   package and the image are published only from it (see
   [RELEASING.md](RELEASING.md)).
4. A release is `vX.Y.Z` on a commit of `main` whose `package.json` version is
   `X.Y.Z` (CI fails the tag otherwise: that version is what Complyd records as
   the collector version). Then `v1` is moved to the same commit.
5. Release notes give the commit SHA and the image digest, so you can pin
   `complyd/complyd-pipeline-action@<sha> # vX.Y.Z` (recommended; Dependabot keeps it
   up to date) or follow `@v1`.

Security reports: see [SECURITY.md](SECURITY.md).

## Develop

No dependencies. `npm test` runs the unit and integration tests (Node 20 or
later; the action itself runs on `node24`). Releasing: [RELEASING.md](RELEASING.md).
