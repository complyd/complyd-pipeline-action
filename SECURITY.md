# Security policy

This action (and the `complyd-pipeline` command built from the same code,
formerly `complyd-ci-scan`) runs in your CI with `id-token: write`, a CI's
ID token (GitLab, CircleCI, Bitbucket) or an ingest key
and sends a dependency scan or a SAST scan to Complyd. We treat a flaw in it as a flaw in Complyd.

## Reporting a vulnerability

E-mail **security@complyd.ai** with what you found and how to reproduce it.
Please don't open a public issue or pull request for it. We reply to every
report and tell you what we'll do about it; we credit reporters who want to be
named once a fix is released.

## Supported versions

Only the latest `v1.x.y` release gets fixes. The moving `v1` tag always points
to it; if you pin a commit SHA, update it when we publish a security release.

## What the action does with your data

- It reads only the results file(s) you name. For a dependency scan it sends,
  per finding, the advisory ids, ecosystem, package, version, severity and
  fixed version. For a SAST scan (`scan: sast`) it sends, per finding, the
  rule id (as the scanner writes it, including your own rules' names),
  the severity and a fingerprint, beside the commit, the repository id and
  the run id. The scan holds no file paths, code, author, committer or actor.
- For an AI eval run (`scan: ai_eval`) it sends per suite names, ids, case
  counts, metric values and thresholds, and SHA-256 hashes of the prompt,
  dataset and rubric files, never their contents; and (from v1.4.0), when stated, how the
  suite ran (`execution`) and the model usage the eval tool reported (call
  and token counts, cost). README's "What Complyd receives" lists every field.
- Each request also carries the sign-in token your CI issues (or your ingest
  key). Complyd reads it to check the request against the trust. Its claims
  are your CI's and name the run, including who started it: on GitHub the
  repository, ref, commit, workflow and actor; on GitLab the project, ref and
  the user's login, id **and e-mail address**; on CircleCI the organisation,
  project and user id; on Bitbucket the workspace, repository and branch.
- The SAST fingerprint is an HMAC-SHA-256 of the rule and the finding's
  location, keyed by the repository id (`github:<repository id>`; on GitLab
  `gitlab-oidc:<host>/<project id>`; with an ingest key, your `--repo`). That salt is not a secret and
  is stored beside the hash, so it is a hash that someone who holds the code,
  or guesses a file path, can confirm; it is not encryption.
- It asks GitHub for an OIDC token for your trust's audience (the command
  may instead read a GitLab, CircleCI or Bitbucket ID token, or
  `COMPLYD_INGEST_KEY`) and sends it only over https (port 443) to
  `api.complyd.ai` or `api-dev.complyd.ai`, and only to the host the audience
  names (the command can also reach localhost, but only with
  `--insecure-local-api`, for tests). It follows no redirects and never
  prints a token or key.
- On GitHub Actions it masks the OIDC token it asked for: it prints
  `::add-mask::<token>` to stdout, which the runner reads and hides. If you
  redirect the command's stdout to a file, that line (with the token, single
  use and short-lived) is in the file. On other CIs nothing is printed and
  nothing is masked by this tool: mask the ID token or key with your CI's own
  secret settings.
- It has no runtime dependencies.
