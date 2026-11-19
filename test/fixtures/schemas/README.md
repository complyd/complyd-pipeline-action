# Complyd's schemas

Copied from Complyd's API (`apps/api/src/observations/collectors/complyd_ai_release/`),
branch `feat/ai-release-repo-config` at `ac2244df9` (PR #935, 19 Nov 2026), unchanged;
their SHA-256s match the ones Complyd's collector registers:

| File | SHA-256 |
|---|---|
| `ai_eval.v2.schema.json` | `069247723e893ecc4e591d3feeba24d72eae665c2e213d6d0c8aafe2033c34de` |
| `ai_release.v2.schema.json` | `8168d8b2556041328a546ee87e7a316c8b70d342d986e313f4a27cac336d36d7` |

v2 is v1 plus `repo_config` (and, for `ai_release`, `config_changed`). The
action always sends both, so it sends `schema_version: 2`; Complyd's v1
refuses them. The tests (`test/ai.test.js`) validate the action's dry-run
output against these files with Complyd's own validator settings
(`test/schemas.js`). When Complyd changes a schema, copy the new file here.
