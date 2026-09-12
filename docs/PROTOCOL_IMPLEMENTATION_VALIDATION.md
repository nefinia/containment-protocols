# Validation record

Checked on 2026-09-12 using Python 3.12.14. Runtime code targets Python 3.10+
and uses the standard library. No real deployment address, credential, private
team message, or incident result is included in the deliverable.

## Automated software verification

Command, from the package root:

```bash
python -m unittest discover -s tests -v
```

Result: **37 tests discovered; 36 passed; one skipped; no failures.** The skipped
test is independent draft-07 validation with the optional `jsonschema` package,
which was unavailable in this environment. It is not counted as a pass.
Application-contract validation tests passed. This does not mean a general
JSON Schema implementation is bundled.

The checks exercise:

- Removal of scoring labels and arbitrary metadata before model requests;
  chronological prefixes, future-step rejection, and history reset.
- Strict JSON handling, public output contracts, complete source evidence attachment,
  malformed/truncated responses, and incomplete ensemble handling.
- Independent reviewer calls, equal ensemble sizes, matching broad prompts,
  common evidence/taxonomy, deterministic aggregation, and recorded seeds.
- Both supplied calling conventions and the stateful replay callback.
- Real HTTP requests to a local synthetic server for all three protocols,
  plus readiness caching, retries, model discovery, tokenization, structured
  generation, deduplicated token-count requests, and usage accounting with
  controlled transports.
- Incident-time detection lag, explicit label/error denominators, one human
  review recommendation per protocol/step, signal exports, and missing usage.
- Journal-to-analysis round trips, evidence mismatch rejection, repeated runs,
  CSV output, CLI execution, and protection against overwriting run outputs.

The local server supplies controlled responses. Its HTTP integration test is
separate from a real model evaluation and does not measure monitor quality.

## Shared endpoint verification

A live single-observation check succeeded against the user-supplied shared
endpoint. It discovered `Qwen/Qwen2.5-7B-Instruct` with a 4096-token context
limit, called the server tokenizer, generated structured JSON, and validated
a `continue` decision for an authorized synthetic local-file observation.
Readiness took approximately 169 seconds; 20 readiness requests were recorded.
This first check used the earlier prompt version with an empty signal list.

The first full synthetic run exposed invalid paraphrased evidence quotations
from the model. They were recorded as output-validation failures, never as
successful protocol decisions. Version 1.1.0 removes model-generated quotations:
the model selects a category and visible step, and the program attaches the
original observation. The final live check below uses that revised format.

The final live run used **implementation 1.1.0, prompt
`containment-review-v2`, and three synthetic observations**:

| Check | Result |
|---|---|
| Model | `Qwen/Qwen2.5-7B-Instruct` |
| Protocol conditions | General, four identical monitors, four specialists |
| Completed protocol evaluations | 9 of 9 |
| Valid individual reviewer outputs | 27 of 27 |
| Failed protocol evaluations | 0 |
| Generation requests / retries | 27 / 0 |
| Prompt tokens / completion tokens | 17,499 / 2,316 |
| Missing generation usage records | 0 |
| Readiness requests / tokenizer requests | 1 / 18 |
| Readiness time | Approximately 8.8 seconds for this run |
| Analysis export | All seven CSV/JSON files generated |
| Code fingerprint | Matches the packaged protocol implementation |

The final run and analysis exports are included in `verification/`. Model
actions are retained as generated and validated; this check does not assign
research significance to their differences. Earlier failed format checks are
separate from this completed run.


## Data and integration limits

- The archive's reconstructed timeline was rejected because step 12's timestamp
  precedes step 11's. It was not repaired or presented as the authoritative
  incident timeline. See `REVIEW.md` for the exact dates and source questions.
- The separate replay-engine source was not supplied. The callable adapter,
  prototype-compatible entry points, journal, and scoring join were verified;
  an end-to-end run inside that separate engine remains to be performed.
- No complete incident benchmark or human study was run. Synthetic and mock
  results are software verification, not evidence that a protocol contains
  the historical incident or improves on another protocol.
- The schemas cannot settle action priority, authorization policy, human-review
  thresholds, or the meaning of an unsafe label. Defaults are documented in
  `README.md`; preserve the chosen configuration for comparisons.
- Full historical prefixes must fit the model context budget. The client
  checks this explicitly and never silently discards older evidence.
- Human-escalation timing experiments and a model-based meta-aggregator remain
  outside the agreed initial three-protocol scope.

## First run in the team repository

Keep the repository's authoritative timeline and deployment script. Configure
the shared URL locally, then run:

```bash
python -m protocols.check_endpoint --timeout 600
python -m protocols.run_all --use-modal --timeline data/ground_truth_timeline.json --output results/live_01.json
```

If the endpoint or a reviewer fails, inspect the journal and error export.
Do not substitute a mock decision or count an operational failure as a model
detection. Use the README's callback example to connect the separate engine.
