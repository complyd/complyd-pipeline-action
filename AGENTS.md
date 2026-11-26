# AGENTS.md

Two kinds of reader:

- **You were asked to set up Complyd in a customer's repository** (Claude Code,
  Cursor, Copilot or another coding assistant): read
  [Set up the pipeline in a repository](#set-up-the-pipeline-in-a-repository).
- **You are changing this repository**: skip to
  [Working on this repository](#working-on-this-repository).

## Set up the pipeline in a repository

Goal: a workflow in the customer's GitHub repository that sends a dependency
scan (and, if wanted, a SAST scan) to Complyd on every push to the default
branch and once a day, signed in with GitHub's OIDC token. No secret, token
or API key is ever stored.

Follow these steps in order. Don't guess a value: every one comes from a
command below, from Complyd's MCP tools, or from the person you work with.

### 1. Check the prerequisites

- The repository is on GitHub.com and you can run `gh` in it
  (`gh auth status`). Other CIs: README, "Other CI systems".
- The person you work with has a Complyd workspace and is an **Owner** or
  **Admin** there (only they can create workload trusts).
- Best: Complyd's MCP server is connected to you, as that person, with the
  tools `check_pipeline_setup` and `create_workload_trust`. If it isn't,
  ask them to connect it (Claude Code:
  `claude mcp add --transport http complyd https://api.complyd.ai/mcp`, then
  `/mcp` › Authenticate; Cursor: `{ "mcpServers": { "complyd": { "url": "https://api.complyd.ai/mcp" } } }`
  in `.cursor/mcp.json`, then **Needs login**). If either tool is missing
  from your tool list, an Owner ticks it in Complyd under **AI apps ›
  Workspace**. Complyd asks the person to turn on two-factor sign-in before
  an AI app can connect. Without MCP, do step 3 by hand: README, "Set up".

### 2. Collect the repository's facts

```sh
gh repo view --json nameWithOwner,defaultBranchRef --jq '.nameWithOwner, .defaultBranchRef.name'
gh api repos/OWNER/REPO --jq '.owner.id, .id'   # numeric owner id, then repository id
```

Complyd matches the numeric ids, never the names.

### 3. Get a workload trust

1. Call `check_pipeline_setup` with `repository: OWNER/REPO`.
2. If it lists a trust with `state: active` that `allows.scans`, use its
   `trustId` (`trw_…`) and go to step 4.
3. Otherwise call `create_workload_trust`:

   ```json
   {
     "name": "OWNER/REPO pipeline",
     "collectors": ["complyd_ci_scan"],
     "ownerId": "<owner id>",
     "repositories": [{ "id": "<repository id>", "name": "OWNER/REPO" }],
     "ref": "refs/heads/<default branch>"
   }
   ```

   Add `"complyd_ai_release"` to `collectors` only if the repository runs
   AI evals (README, "AI release"). Leave `eventNames` out: the defaults
   (`push`, `schedule`, `workflow_dispatch`) match the workflow below.
4. **This creates nothing.** It returns a `confirmUrl`. Give that link to the
   person and ask them to open it and confirm in Complyd. You can't confirm
   it yourself, and you must not try. In a brand-new workspace Complyd first
   asks them to finish its short workspace setup; after that, they open the
   link again (or **AI apps › Waiting for you**).
5. When they say it's done, call `check_pipeline_setup` again: the trust is
   listed with its `trustId`.

If `audience` is `default` (a new trust), the workflow leaves `audience:`
empty. If it is `rotated`, or the workspace is not on `api.complyd.ai`
(a test environment), ask the person to copy the audience shown in
Complyd's **Settings › Workload trusts** into a `COMPLYD_AUDIENCE`
variable, the same way as below.

### 4. Store the trust id as a repository variable

A variable, not a secret (the trust id is not a credential):

```sh
gh variable set COMPLYD_TRUST --body trw_…
# gh older than 2.31 has no `variable` command:
gh api -X POST repos/OWNER/REPO/actions/variables -f name=COMPLYD_TRUST -f value=trw_…
```

### 5. Add the workflow

Create `.github/workflows/complyd-scan.yml` exactly like this. Keep every
pin (full commit SHA); don't swap in a tag like `@v1` or `@main`.

```yaml
name: Complyd scan
on:
  push:
    branches: [main] # the default branch: Complyd refuses runs on any other
  schedule:
    - cron: '17 3 * * *' # daily, so "scans run regularly" keeps passing
  workflow_dispatch:

permissions:
  id-token: write # lets the job ask GitHub for its sign-in token
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
            --output-file=osv-results.json
            --all-packages
            --recursive
            ./
      - name: Send the dependency scan to Complyd
        uses: complyd/complyd-pipeline-action@1f44978cc1f6daa05d4520fde6a3bf7519cc1439 # v1.4.0
        with:
          trust: ${{ vars.COMPLYD_TRUST }}
          audience: ${{ vars.COMPLYD_AUDIENCE }} # empty: the new trust's default
          results: osv-results.json
          scanner-version: 2.7.1 # OSV-Scanner's JSON doesn't name its version
```

Replace `main` with the default branch if it differs. Nothing else needs
editing. Optional extra steps, each in the README: a SAST scan with Semgrep
or CodeQL ("SAST scans"); AI evals ("AI release"). Use only the inputs in
[action.yml](action.yml). Send at most one step of each kind per run.

Show the person the file and the commands before you run or push anything.

### 6. Run it and verify

1. The workflow must run on the default branch: merge it there (through a
   pull request if the branch is protected). A run on a pull request or
   another branch is refused by design.
2. Start a run: `gh workflow run complyd-scan.yml`, then
   `gh run watch` (or wait for the push run).
3. The "Send the dependency scan to Complyd" step logs the stored
   observation id (`obs_…`).
4. Call `check_pipeline_setup` again. Done when `pushes` has a
   `dependency_scan` line with this run's commit. If not, follow its
   `hints` in order, and read the step's log: it names the error.

Common failures (README, "Errors"):

| Log says | Fix |
|---|---|
| GitHub gave this job no sign-in token | add `permissions: id-token: write` |
| Couldn't reach Complyd (api.complyd.ai) | the trust is on another Complyd host: set `COMPLYD_AUDIENCE` from Settings (step 3) |
| `unauthenticated` | wrong `trust`, a rotated trust's `audience`, or the trust was revoked; or the owner/repository id in the trust is wrong |
| `not_allowed` | the run isn't on the default branch, or its event isn't one the trust allows |
| `idempotency_conflict` | two dependency scans in one run; keep one |

Done: tell the person the trust id, the workflow path, and the run that
Complyd received.

## Working on this repository

### Layout

- `action.yml`: the GitHub Action (runs `src/main.js` on `node24`).
- `src/`: shared code; `src/cli.js` is the `complyd-pipeline` command for other CIs.
- `test/*.test.js`: Node's built-in test runner; real scanner output in `test/fixtures/real`.

### Build and test

No build step and no runtime dependencies. Node 20 or later.

```sh
npm ci                # dev dependencies for the tests (ajv, yaml)
npm test              # node --test test/*.test.js
npm pack --dry-run    # CI runs it too: expect action.yml, package.json, README, LICENSE, src/*
```

CI (`.github/workflows/ci.yml`) runs these on Node 20, 22 and 24. There is
no lint script. Run `npm test` before every commit.

### Rules

- **Public repository.** Commit only as the Complyd identity:
  `git -c user.name='Complyd' -c user.email='noreply@complyd.ai' commit …`.
  Check before pushing: `git log --format='%an <%ae>' origin/main..HEAD`.
  No personal names, e-mails or internal links in commits, code or docs.
- **Never log or send secrets.** The OIDC token, ingest key and request
  headers must not reach logs, errors or test snapshots. Data minimisation
  is the product: don't add a field to what is sent without updating
  "What Complyd receives" in README.md and SECURITY.md.
- **Keep docs in step with `action.yml`.** A new or changed input updates
  `action.yml` and README's "Inputs" table together.
- **Pin by full commit SHA** in workflows and README examples, never a
  placeholder.
- Changes reach `main` only through a reviewed pull request with CI green.

### Releasing

Follow [RELEASING.md](RELEASING.md); don't improvise. In short: bump
`package.json` `version` in a reviewed PR, tag the merged commit `vX.Y.Z`,
the release workflow publishes after a maintainer approves, then `v1` is
moved to the release commit. Never publish npm or the image from a laptop.
Then update the pinned release SHA in README.md, AGENTS.md and llms.txt.

Security reports: [SECURITY.md](SECURITY.md).
