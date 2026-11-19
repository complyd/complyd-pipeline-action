# Complyd's schemas

Copied from Complyd's API (`apps/api/src/observations/collectors/complyd_ai_release/`),
branch `feat/ai-release-repo-config` at `a51af0c65` (PR #935, 19 Nov 2026), unchanged;
their SHA-256s match the ones Complyd's collector registers:

| File | SHA-256 |
|---|---|
| `ai_eval.v2.schema.json` | `069247723e893ecc4e591d3feeba24d72eae665c2e213d6d0c8aafe2033c34de` |
| `ai_release.v2.schema.json` | `c4b64ba5c5064c82cd55c671234d7e757c90178ab324f0d2268a442f12eab75f` |

v2 is v1 plus `repo_config` (and, for `ai_release`, `config_changed`). The
action always sends both, so it sends `schema_version: 2`; Complyd's v1
refuses them. The tests (`test/ai.test.js`) validate the action's dry-run
output against these files with Complyd's own validator settings
(`test/schemas.js`). When Complyd changes a schema, copy the new file here.

`../repo-config-ownership.vectors.json` is copied the same way from
`apps/api/src/ai-releases/domain/` (same commit): the file-ownership cases
both sides test against.

`dependency_scan.v2.schema.json` and `sast_scan.v2.schema.json` are copied
the same way from `apps/api/src/observations/collectors/complyd_ci_scan/`,
branch `fix/ci-scan-severity` at `31ef38f0b` (PR #949, 20 Nov 2026),
unchanged; their SHA-256s match the ones Complyd's collector registers:

| File | SHA-256 |
|---|---|
| `dependency_scan.v2.schema.json` | `dc22d15a46d22799ff0863a3ddfd524eb1a55488b92f3dc20d3d653d7c7af205` |
| `sast_scan.v2.schema.json` | `6a431f7ea861de7d2debc0c8776a2a67e089320f536dd389abd813ddb2ceba2e` |

v2 adds `components` and `lockfile_sha256` (dependency) and `files` (SAST);
Complyd still takes v1 but reads it as "Couldn't check". `test/run.test.js`
and `test/reduce.test.js` validate the action's payloads against them. The
scanner names Complyd counts a scan from (its `DEPENDENCY_SCANNERS` and
`SAST_SCANNERS`, same commit) are copied into `src/scan.js`
(`KNOWN_SCANNERS`), used only for the step's warning.
