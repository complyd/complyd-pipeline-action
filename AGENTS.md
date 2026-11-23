# AGENTS.md

For coding agents changing this repository. To *use* the action in another
repository, read [README.md](README.md) ("Set up with your AI assistant").

## Layout

- `action.yml`: the GitHub Action (runs `src/main.js` on `node24`).
- `src/`: shared code; `src/cli.js` is the `complyd-pipeline` command for other CIs.
- `test/*.test.js`: Node's built-in test runner; real scanner output in `test/fixtures/real`.

## Build and test

No build step and no runtime dependencies. Node 20 or later.

```sh
npm ci                # dev dependencies for the tests (ajv, yaml)
npm test              # node --test test/*.test.js
npm pack --dry-run    # CI runs it too: expect action.yml, package.json, README, LICENSE, src/*
```

CI (`.github/workflows/ci.yml`) runs these on Node 20, 22 and 24. There is
no lint script. Run `npm test` before every commit.

## Rules

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

## Releasing

Follow [RELEASING.md](RELEASING.md); don't improvise. In short: bump
`package.json` `version` in a reviewed PR, tag the merged commit `vX.Y.Z`,
the release workflow publishes after a maintainer approves, then `v1` is
moved to the release commit. Never publish npm or the image from a laptop.
Then update the pinned release SHA in README.md and llms.txt.

Security reports: [SECURITY.md](SECURITY.md).
