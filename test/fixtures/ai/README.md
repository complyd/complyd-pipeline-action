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

Every prompt, input, output and case text in them contains `CANARY`: the
tests check none of it reaches the envelope. `repo/` is a repository with a
`.complyd/ai.yml` whose prompts, dataset and rubric the scan hashes.
