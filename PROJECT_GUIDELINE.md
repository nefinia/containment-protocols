# Adaptive Containment Protocols — Project Outline

**Apart Research · AI Incident Response Sprint · Sept 11–13, 2026 · Track 1**
_Working doc — edit freely. Owner: Sofia. Last updated: 2026-09-11._

---

## The question

There are many ways we try to keep agents contained: sandboxing, permission gates, fixed rules, monitoring agents, humans in the loop, several agents checking each other. Each sees something different — a permission rule can check whether one action is allowed but miss a pattern that only shows up across a longer sequence; a human understands context but gets overwhelmed by constant approval requests; several similar guard agents may just repeat the same judgment instead of adding coverage.

**Which combination of technical controls, safety agents, and human escalation actually works best when an agent starts drifting toward an unsafe outcome?**

## Incident

We're using the OpenAI (GPT-5.6 Sol) / Hugging Face sandbox-escape incident, July 2026, as our timeline — the same case the sprint page points to, drawing on the resources it suggests: OpenAI's own incident report and the Hugging Face documentation of the breach.

## Approach

Progressive replay based on that incident timeline: each protocol only sees the information that would have been available at that point in time, and decides whether to continue, restrict, investigate, pause, or terminate.

**Protocols we compare:**
- One general monitor
- Several identical monitors
- Specialised reviewers (permissions, task intent, security, downstream consequences)
- Different moments for bringing a human into the loop

We compare them on detection time, false alarms, human-review burden, and cost — and turn the strongest findings into concrete standard clauses (clause → evidence → rough cost), the format Track 1 asks for.

Most existing work in this space reports benchmark-style metrics (detection curves, AUC); ours instead targets operational clauses a team could adopt directly.

## Coordination

Compute: Modal is already set up (API key configured), with `modal_client` and `serve_model` carried over from a previous repo.

Since the four core pieces (replay engine, protocol implementation, analysis, clause writing) are built largely in parallel, we're fixing the interfaces between them up front rather than relying on branch discipline alone:
- Replay-engine timestep output: JSON, fields TBD (`step`, `visible_info`, `timestamp`)
- Protocol decision output: JSON, `{step, decision: continue|restrict|investigate|pause|terminate, reasoning, timestamp}`

These live in a `/schemas` folder in the repo. Branch per role off `main` (`replay-engine`, `protocol-impl`, `analysis`, `clauses`), small PRs rather than one large merge Sunday.

## Research context and future directions

Work on safeguarding LLM agents has mostly focused on building better individual reviewers — guard agents with structured reasoning, debate-based safety evaluation, shadow-memory approaches to long-horizon threats (see Links, below). Less studied: whether adding more reviewers, of whatever kind, actually adds independent coverage, or just adds confidence around the same read. That's the specific gap this project targets — do different reviewers really catch different blind spots, or do they mainly agree with each other for the same reasons?

A closely related finding already exists (Ensemble Monitoring for AI Control, arxiv 2605.15377: diverse monitor signals outperform scaling identical monitors). Our contribution isn't the diversity-vs-redundancy claim itself — it's stress-testing that claim against one grounded, real incident with strict temporal information cuts, and translating the result into deployable clauses rather than benchmark metrics.

This weekend is a first, small test of that question in a real-time monitoring setting, using one real incident as the timeline. If the signal holds up, natural next steps: replicate the comparison across more incidents, test whether it holds across different model families, add the human-escalation-timing variant we scoped out for time, and work toward a general metric or checklist teams could apply to their own containment setups rather than one-off intuition.

## Task roles

| Role | What it involves | Owner |
|---|---|---|
| Replay engine | Build the harness that steps through the incident timeline and feeds each protocol only what would have been visible at that moment; log every decision (continue / restrict / investigate / pause / terminate) | jambohaku |
| Protocol implementation | Write/prompt the actual protocols being compared — general monitor, identical monitors, specialised reviewers, human-escalation variants | Muhammad |
| Causal & statistical analysis | Score each protocol's run: detection time, false-alarm rate, human-review burden, cost with real comparisons | Melody |
| Framing & tradeoffs | Push past "which is fastest" into safety-vs-cost tradeoffs (Pareto framing) for the final clauses | tiramisu |
| Standard / clause writing | Turn the findings into the clause → evidence → cost format | tiramisu |
| Coordination & integration | Own the open decisions, keep interfaces between the four pieces aligned, back up protocol implementation, assemble the final submission | Sofia |

## Timeline

- **By Sept 9:** team finalized, roles picked
- **Sept 9–10:** pre-read sources, short kickoff call to lock scope
- **Fri Sept 11:** build replay pipeline, get general-monitor baseline running
- **Sat Sept 12:** run remaining protocols, compare results
- **Sun Sept 13:** draft clauses, write up, submit (with buffer before deadline)

## Links

- Sprint: https://apartresearch.com/sprints/ai-incident-response-sprint-2026-09-11-to-2026-09-13
- Github repo: https://github.com/nefinia/containment-protocols
- Incident, OpenAI's own report: https://openai.com/index/hugging-face-model-evaluation-security-incident/
- Incident, coverage: https://techcrunch.com/2026/08/26/openai-releases-its-official-report-on-the-hugging-face-breach/
- Epistemic Fingerprints: https://sofiagallego.com/epistemic-fingerprints
- GuardAgent: https://arxiv.org/abs/2406.09187
- Multi-Agent Debate for Safety Eval: https://arxiv.org/abs/2511.06396
- MAGE (shadow memory): https://arxiv.org/abs/2605.03228
- Ensemble Monitoring for AI Control: https://arxiv.org/pdf/2605.15377
- MI9 Runtime Governance Framework: https://arxiv.org/pdf/2508.03858
- Swiss Cheese Model for AI Safety by Design: https://arxiv.org/html/2408.02205v3
