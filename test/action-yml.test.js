const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');

// GitHub refuses to load an action.yml that isn't strictly valid YAML
// (e.g. an unquoted ': ' inside a description).
test('action.yml is valid YAML with the keys GitHub requires', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'action.yml'), 'utf8');
  const doc = YAML.parseDocument(src, { prettyErrors: true });
  assert.deepStrictEqual(doc.errors.map(String), []);
  const a = doc.toJS();
  assert.ok(a.name && a.description);
  assert.ok(a.runs && a.runs.using && a.runs.main);
  assert.ok(fs.existsSync(path.join(__dirname, '..', a.runs.main)));
  for (const [k, v] of Object.entries(a.inputs)) {
    assert.strictEqual(typeof v.description, 'string', `inputs.${k}.description`);
  }
  for (const [k, v] of Object.entries(a.outputs)) {
    assert.strictEqual(typeof v.description, 'string', `outputs.${k}.description`);
  }
});
