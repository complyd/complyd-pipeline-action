# Releasing

The GitHub action is released by tag (see "Releases" in [README.md](README.md)).
The npm package `@complyd/pipeline` and the container image
`ghcr.io/complyd/pipeline` are published only by the release workflow
(`.github/workflows/release.yml`), and only after a maintainer approves it.
Never publish from a laptop: a laptop publish has no provenance and needs a
long-lived token.

One version for all three: `package.json` `version` is what Complyd records
as the collector version (collector `complyd_ci_scan`), whichever of them
sent the scan.

## 1. Tag the release

1. On `main`, set `package.json` `version` to `X.Y.Z` in a reviewed pull
   request, with CI green.
2. Tag that commit `vX.Y.Z`. CI checks the tag matches `package.json`; the
   release workflow checks it again and that the commit is on `main`.

## 2. The release workflow

The `vX.Y.Z` tag starts `.github/workflows/release.yml`:

1. **test** (Node 20, 22, 24): `npm test` and `npm pack --dry-run` (expect:
   action.yml, package.json, README, LICENSE, src/*).
2. **publish**, in the protected environment `release`: it waits until a
   maintainer approves, and fails at once if the environment has no required
   reviewers, lets administrators bypass, or admits any ref. Then it:
   1. checks the tag matches `package.json` and is a commit of `main`, and
      that Node 24's own npm is 11.5.1 or later (none is downloaded);
   2. builds the image and checks `--version` prints `X.Y.Z`;
   3. pushes `ghcr.io/complyd/pipeline:X.Y.Z` with the job's `GITHUB_TOKEN`
      (`packages: write`) and attaches a build provenance attestation.
      The image is linux/amd64 only;
   4. last, as it can't be redone: removes `"private": true` in the job's
      working copy only (never committed: it guards `main` against an
      accidental publish) and runs `npm publish --access public
      --provenance` with npm **trusted publishing** (OIDC, `id-token: write`).

   These checks run from the tagged commit's copy of the workflow, so they
   catch mistakes, not someone who can push a tag: the settings in §3 are
   what protect a release, and they are **mandatory**.

Once the workflow is green, move `v1` to the release commit and publish the
release notes with the commit SHA and the image digest (the job summary
shows it), so users can pin `ghcr.io/complyd/pipeline@sha256:…`.

Release notes for 1.4.0 must also say:

- promptfoo and openai-evals users move to `ai_eval` v3 automatically
  (the action now sends the usage those tools report), with no change to
  `.complyd/ai.yml`. Don't tag 1.4.0 until Complyd's API that accepts v3 is
  deployed, or those pushes are refused once `v1` moves.
- In the generic format, `usage` and `execution` keys are now validated: a
  harness that already wrote them in another shape fails the step instead
  of having them ignored.

The `Dockerfile` pins its base image by digest. Refresh the digest with each
release (the command is in the Dockerfile's comment: the registry's
`docker-content-digest` for the `nonroot` tag).

## 3. One-time setup (a repository admin), before the first tag

All of this is required, not advice: without it anyone with write access
can publish.

- **Ruleset on `main`**: pull request with one approval, the CI check
  required, no force push, no deletion, no bypass.
- **Ruleset on tags `v*`**: restrict creation, update and deletion; bypass
  only for the release maintainers. Turn on **immutable releases**.
- **Environment `release`** (Settings › Environments): required reviewers =
  the release maintainers, "Prevent self-review" on, "Allow administrators
  to bypass" off, deployment branches and tags limited to tags `v*.*.*` (not
  `v*`, which also matches `v1`). The workflow refuses to publish without
  reviewers, with administrator bypass on, or with no ref limit.
- **npm**: the `@complyd` scope belongs to the Complyd organisation, with 2FA
  required for publishing. On npmjs.com, add a trusted publisher to
  `@complyd/pipeline`: GitHub Actions, repository
  `complyd/complyd-pipeline-action`, workflow `release.yml`, environment `release`.
  npm adds a trusted publisher only to a package that exists, so the
  first version needs a token, and it still goes through the workflow, never
  a laptop: create a **granular access token** with read and write on
  `@complyd/pipeline` only (or the `@complyd` scope, if the package does
  not exist yet), the shortest expiry, and store it as the secret
  `NPM_FIRST_PUBLISH_TOKEN` of the `release` **environment** (not of the
  repository). After the first release, add the trusted publisher, set the
  package to refuse token publishing, delete the secret and revoke the
  token.
- **GHCR**: after the first push, open the `pipeline` package under the
  organisation, make it public, and give this repository write access
  (Package settings › Manage Actions access) if it isn't linked already.
  GHCR has no environment binding: any workflow here with `packages: write`
  could push a tag. The `main` and tag rulesets limit who can add one, and
  users pin the digest and verify the attestation (README, Jenkins), which an
  image pushed from any other workflow or ref fails.

## 4. After publishing

In a follow-up PR, replace the previous release SHA with the new one
everywhere (`grep -rn <old sha> README.md AGENTS.md llms.txt`), so no pin goes stale.
Update README's "Other CI systems" install lines to
`npm install --global @complyd/pipeline@X.Y.Z` and the image.

When this bumps the pin to 1.4.0, also remove the "from v1.4.0" notes
(`grep -n 'v1.4.0' README.md AGENTS.md llms.txt SECURITY.md`), including the "not
released yet" paragraph under "How a suite ran" and the AI-setup prompt's
"Don't add execution: … while the pin above is v1.3.0" (keep its advice on
when to set `execution:`).
