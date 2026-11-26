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

// AGENTS.md is what a coding assistant copies into a customer's repository.
test('AGENTS.md workflow is valid YAML, uses only action.yml inputs, and every doc pins one release', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  const inputs = Object.keys(YAML.parse(read('action.yml')).inputs);
  const block = read('AGENTS.md').match(/```yaml\n([\s\S]*?)```/)[1];
  const wf = YAML.parse(block);
  assert.strictEqual(wf.permissions['id-token'], 'write');
  const steps = wf.jobs.scan.steps.filter((s) => (s.uses || '').startsWith('complyd/complyd-pipeline-action@'));
  assert.ok(steps.length >= 1);
  for (const s of steps) for (const k of Object.keys(s.with)) assert.ok(inputs.includes(k), `unknown input ${k}`);
  const pins = new Set(['README.md', 'AGENTS.md', 'llms.txt'].flatMap((f) =>
    [...read(f).matchAll(/complyd-pipeline-action[@#]([0-9a-f]{40})/g)].map((m) => m[1])));
  assert.strictEqual(pins.size, 1, `different release pins: ${[...pins]}`);
});
