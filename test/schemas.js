'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('fs');
const { join } = require('path');
const Ajv2020 = require('ajv/dist/2020');

/** Complyd's validator, as its collector registry builds it (strict, its keywords, its date-time). */
const ajv = new Ajv2020({ strict: true, allErrors: true });
ajv.addKeyword('x-complyd-privacy');
ajv.addKeyword('x-complyd-volatile');
ajv.addFormat('date-time', {
  type: 'string',
  validate: (v) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.test(v) && !Number.isNaN(Date.parse(v)),
});
for (const name of ['ai_eval.v2', 'ai_release.v2']) ajv.addSchema(JSON.parse(readFileSync(join(__dirname, 'fixtures', 'schemas', `${name}.schema.json`), 'utf8')), name);

/** Asserts `value` is valid under schema `ref` (e.g. ai_release.v2, ai_eval.v2#/$defs/repo_config); returns Ajv's errors otherwise. */
function assertValid(ref, value) {
  const validate = ajv.getSchema(ref);
  assert.ok(validate, `no schema ${ref}`);
  assert.ok(validate(value), `${ref}: ${JSON.stringify(validate.errors)}`);
}

/** Ajv's errors for `value` under `ref` (null when valid). */
function errorsOf(ref, value) {
  const validate = ajv.getSchema(ref);
  return validate(value) ? null : validate.errors;
}

module.exports = { assertValid, errorsOf };
