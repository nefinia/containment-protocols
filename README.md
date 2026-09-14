# Containment Protocols

**Which combination of technical controls, safety agents, and human escalation actually catches an agent moving toward an unexpected or unsafe outcome -- and which just creates the appearance of coverage?**

Project for the Apart Research AI Incident Response Sprint (Sept 11-13, 2026, Track 1).

## Third-party Monitor Independence Check

Replicated or specialized monitor ensembles can look like independent, redundant coverage
while actually restating the same judgment -- this verifier lets a reviewer who was not
involved in building the protocols check that from the exported evidence alone, with no
access to the lab's internal network, models, or prompts. It recomputes containment timing,
independent-seed sensitivity, signal-evidence overlap, and shared blind spots directly from
the JSON files in `results/`, and prints both a console summary and (optionally) a
machine-readable report. It produces descriptive evidence for or against redundancy, not a
universal certification or a numeric pass/fail threshold.

Scope note: this run's exported evidence (`results/*.json`) contains the aggregated
per-step decision and combined reasoning/signals for each protocol, but not structured,
role-tagged, pre-aggregation reviewer records (the `reviewer_id` field the schema supports
is unused in these files). The verifier can therefore check aggregate outcomes and signal
evidence against each other, but not reviewer-level independence directly -- see the tool's
own `Limitations` output for the precise boundary.

```bash
python3 tools/monitor_independence_check.py \
  --reference results/reference_run_2026-09-13.json \
  --sensitivity results/sensitivity_independent_seeds_2026-09-13.json
```

Expected headline output on this repository's data:

```
Steps: 0-25 (26 total, 3 benign, 23 unsafe, unsafe onset step 3)

Reference-run summary
----------------------
Protocol         First containment   Lag  Strict FA  Benign invest.   Unsafe containment
General                          6     3          0               2                69.6%
Identical x4                     6     3          0               2                73.9%
Specialized x4                   6     3          0               2                78.3%
```

Add `--output-dir verifier_output` to also write `verifier_output/report.md` and
`verifier_output/report.json`. The tool uses only the Python standard library, reads local
files, and makes no network requests, requires no API keys, and calls no models -- it is
meant to demonstrate that an external auditor can evaluate exported evidence without lab
network access.

## Reproducing this analysis (no model calls required)

Everything below re-derives the paper's reported numbers from the already-committed
`results/*.json` files -- no Modal deployment, API key, or new model call is needed:

```bash
python3 -m unittest tests.test_monitor_independence_check -v

python3 tools/monitor_independence_check.py \
  --reference results/reference_run_2026-09-13.json \
  --sensitivity results/sensitivity_independent_seeds_2026-09-13.json \
  --output-dir verifier_output

python3 protocols/replay_engine.py data/ground_truth_timeline.json
```

The first two commands use only the Python standard library. Re-running
`analysis/containment_results.ipynb` top to bottom regenerates every table under
`analysis/tables/`, every figure under `analysis/figures/`, and `analysis/RESULTS_SUMMARY.md`
from the same two committed JSON files (requires `jupyter`, `pandas`, `numpy`, and
`matplotlib`; versions are not pinned in this repository).

This reproduces the *analysis* of already-collected evidence, not the *live experiment*
that produced `results/*.json` in the first place. The protocol/reviewer implementation
that produced them is in [`protocols/`](protocols/) (see `protocols/run_all.py`), but
generating new results with it requires a deployed model endpoint (see Infrastructure
below) -- it is not reproducible offline.

## The question

There are several different ways people try to keep agents contained: sandboxing, permission gates, fixed rules, monitoring agents, humans in the loop, or several agents checking each other. Each one sees something different. A permission rule can check whether a single action is allowed, but the problem may only become visible across a longer sequence. A human can understand context, but constant approval requests become overwhelming. And several similar guard agents may just repeat the same judgment rather than catching different things.

This project asks that question directly, using a real incident as the test bed: OpenAI's GPT-5.6 Sol and an unreleased model escaped a cybersecurity-eval sandbox via a zero-day in their only network-egress channel, then breached Hugging Face's production systems to steal benchmark answers (OpenAI's own incident report, July 2026). The report notes controls "failed repeatedly despite initial detection and intervention" -- which is exactly the redundancy question this project tests.

## Approach

A progressive replay of the incident timeline. At each step, a protocol sees only the information available at that moment -- never the outcome -- and decides whether to continue, restrict, investigate, pause, or terminate.

Protocols compared (three tested; a fourth was scoped but not run):
- A single general monitor.
- Several identical monitors (does replication add real coverage, or just more calls making the same judgment?).
- Specialized reviewers split by category: permissions, task intent, security, downstream consequences.
- Human-escalation-timing variants (e.g. early always-on vs. threshold-triggered) were scoped for
  this comparison but not run in the initial implementation -- noted as future work, not a tested result.

Metrics: containment lag, strict false-alarm rate, benign-investigation burden, unsafe-containment
rate, and signal/coverage overlap between protocols. Human-review burden and per-protocol cost
(token/latency) were defined but are not reported results in this run -- see the paper's
Limitations for why.

A live design threat: replicated-monitor protocols make more model calls than a single monitor by construction, so any comparison has to control for that rather than let "more calls" masquerade as "better redundancy."

## Connection to prior work

This is a direct extension of [Epistemic Fingerprints](https://sofiagallego.com/epistemic-fingerprints) (False Epistemic Redundancy, Apart Research Digital Minds Sprint, August 2026), which asked the same question about post-hoc investigation: do differently-framed AI agents examining the same evidence actually search different parts of a hypothesis space, or just produce surface disagreement while sharing the same blind spot? That project found the answer was case-dependent -- persona diversity sometimes helped, sometimes actively hurt, and reliably increased how different the outputs *looked* independent of whether it increased what they actually *covered*. This project asks the same structural question about real-time monitoring instead of after-the-fact hypothesis generation.

## Related work

- Xu et al., *GuardAgent: Safeguard LLM Agents by a Guard Agent via Knowledge-Enabled Reasoning*. [arXiv:2406.09187](https://arxiv.org/abs/2406.09187)
- *Efficient LLM Safety Evaluation through Multi-Agent Debate*. [arXiv:2511.06396](https://arxiv.org/abs/2511.06396)
- *MAGE: Safeguarding LLM Agents against Long-Horizon Threats via Shadow Memory*. [arXiv:2605.03228](https://arxiv.org/abs/2605.03228)

## Team

Sprint task assignments (see [PROJECT_GUIDELINE.md](PROJECT_GUIDELINE.md) for full role
descriptions, timeline, and open decisions):

- Replay engine -- jambohaku
- Protocol implementation -- Muhammad
- Causal & statistical analysis -- Melody
- Framing & tradeoffs / clause writing -- tiramisu
- Coordination & integration -- Sofia

This lists sprint-time task ownership, not final paper authorship or byline order --
for those, see the Author Contributions section of [`paper/paper.tex`](paper/paper.tex),
which is authoritative.

## Interfaces

The four pieces (replay engine, protocol implementation, analysis, clause writing) are built in parallel against fixed schemas rather than each other's code -- see [`schemas/`](schemas/). Branch per role off `main` (`replay-engine`, `protocol-impl`, `analysis`, `clauses`), small PRs.

### Replay engine

The harness is implemented in [`protocols/replay_engine.py`](protocols/replay_engine.py). It loads and validates a timeline, then calls a protocol once per timestep:

```python
from protocols.replay_engine import ReplayEngine

engine = ReplayEngine.from_json("data/ground_truth_timeline.json")

def protocol(context):
	# context.current and context.history contain no ground-truth labels.
	return {
		"decision": "continue",
		"reasoning": "No escalation signal detected.",
	}

result = engine.run(protocol)
scored_rows = result.scoring_rows()  # join labels only after the run
```

At step `n`, `context.history` contains exactly steps `0..n`; no future timestep or `ground_truth_label` is present in the protocol-facing objects. The engine validates that each returned decision matches the current step and uses one of the five decisions in `schemas/decision.schema.json`.

For a smoke run with the default no-op protocol:

```bash
python protocols/replay_engine.py data/ground_truth_timeline.json
```

Use `--scored` only for post-run analysis output. Protocol execution itself never receives scored rows.

## Infrastructure

Shared Modal-hosted vLLM endpoint, reused from epistemic-fingerprints (`protocols/serve_model.py`, `protocols/modal_client.py`) -- one deployment, one URL, the whole team hits the same model rather than everyone managing separate API keys and billing.

```bash
modal deploy protocols/serve_model.py
```

Then resolve the shared endpoint from any client script:

```python
from protocols.modal_client import get_modal_url, wait_for_server

url = get_modal_url()
wait_for_server(url)
```

Model choice (`MODEL_NAME` in `serve_model.py`): Qwen2.5-7B-Instruct, carried over from
epistemic-fingerprints' free-text hypothesis generation and used as-is for the results in
this repository (see `paper/paper.tex`, Methodology). The in-code comment predates that
decision and has not been updated to reflect it.

## Status

Sprint complete (Sept 11-13). Incident timeline / ground-truth labeling, the replay harness,
and the three tested protocol implementations (general, identical, specialized) ran against
the live model endpoint; human-escalation-timing variants were scoped but not run -- see
`paper/paper.tex` for the final write-up and results.
