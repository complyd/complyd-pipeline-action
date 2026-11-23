# AI eval fixtures

**Fixtures, not real tool output.** Each file was written by hand from the
tool's documented results shape, with made-up values:

| File | Tool | Shape |
|---|---|---|
| `promptfoo.json` | promptfoo | `promptfoo eval -o results.json` (results version 3: `results.prompts[].metrics`, `metadata.promptfooVersion`) |
| `deepeval.json` | DeepEval | `.deepeval/.latest_test_run.json` (`testCases[].metricsData[]`) |
| `openai-evals.json` | OpenAI Evals API | an eval run object (`GET /v1/evals/{eval_id}/runs/{run_id}`) |
| `lm-eval.json` | lm-evaluation-harness | `--output_path` results JSON (`results`, `n-samples`, `config`) |
| `generic.json` | any harness | Complyd's generic shape (README, "AI release") |
| `promptfoo-0.126*.real.json` | promptfoo 0.126.0 | real output (below) |

Two files **are real tool output**: promptfoo 0.126.0 (`promptfoo eval -o`)
run over a three-case config whose provider is a local stub (no model call)
that reports a fixed usage per reply (120 prompt and 30 completion tokens,
40 of them cache reads, $0.0021). `promptfoo-0.126.real.json` has no cache
hit; in `promptfoo-0.126-cache.real.json` the stub serves case two as
promptfoo's cache would (`cached: true`), so promptfoo writes
`incurredTokenUsage` and `incurredCost` beside the totals. Only the run's
`basePath` was replaced (`/work`).

Every prompt, input, output and case text in them contains `CANARY`: the
tests check none of it reaches the envelope. `repo/` is a repository with a
`.complyd/ai.yml` whose prompts, dataset and rubric the scan hashes.
`ai.v2.yml` is the same repository's config as version 2, with two systems
whose `paths:` overlap (`services/**` and `services/support/**`).
