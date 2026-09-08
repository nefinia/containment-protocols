# Adaptive Containment Protocols — Project Guideline

**Apart Research · AI Incident Response Sprint · Sept 11–13, 2026 · Track 1**
_Working doc — edit freely. Owner: Sofia. Last updated: 2026-09-08._

---

## 1. The question

There are many ways we try to keep agents contained: sandboxing, permission gates, fixed rules, monitoring agents, humans in the loop, several agents checking each other. Each sees something different — a permission rule can check whether one action is allowed but miss a pattern that only shows up across a longer sequence; a human understands context but gets overwhelmed by constant approval requests; several similar guard agents may just repeat the same judgment instead of adding coverage.

**Which combination of technical controls, safety agents, and human escalation actually works best when an agent starts drifting toward an unsafe outcome?**

## 2. Incident we replay

The OpenAI (GPT-5.6 Sol) / Hugging Face sandbox-escape incident, July 2026 — the case the sprint page points to. Sources: OpenAI's official incident report, TechCrunch coverage, and any Hugging Face postmortem material.

## 3. Approach

Progressive replay along the incident timeline. Each protocol sees only the information available at that point in time, and at each step emits one decision:

`continue · restrict · investigate · pause · terminate`

**Protocols compared:**
1. One general monitor
2. Several identical monitors (N copies, majority vote)
3. Specialised reviewers — permissions / task intent / security / downstream consequences
4. Human-in-the-loop variants — differing on *when* the human is pulled in (early always-on, threshold-triggered, late/last-resort)

**Metrics (define precisely before Saturday):**
- **Detection time** — steps between first "unsafe" ground-truth event and first `restrict`/`pause`/`terminate`
- **False-alarm rate** — restrictive decisions on benign steps
- **Human-review burden** — count / rate of escalations to human
- **Cost** — tokens + wall-clock + $ per full replay

**Output:** strongest findings → standard clauses in `clause → evidence → rough cost` format (what Track 1 asks for), plus the submission writeup.

## 4. Why this matters beyond the weekend

Connects to Sofia's earlier work on epistemic diversity (https://sofiagallego.com/epistemic-fingerprints): do different reviewers really catch different blind spots, or do they mainly create more confidence around the same interpretation? This weekend is a small, honest test of that question applied to real-time monitoring rather than retrospective investigation.

---

## 5. Roles

| Role | What it involves | Owner |
|---|---|---|
| Replay engine | Harness that steps through the incident timeline, feeds each protocol only what would have been visible at that moment, logs every decision | TBD |
| Protocol implementation | Write/prompt the protocols — general monitor, identical monitors, specialised reviewers, human-escalation variants | Sofia + TBD |
| Causal & statistical analysis | Score each run on the four metrics with real comparisons, not eyeballing; handle variance across seeds | TBD |
| Framing & tradeoffs | Push past "which is fastest" into safety-vs-cost Pareto framing for the final clauses | TBD |
| Standard / clause writing | Turn findings into clause → evidence → cost format; assemble final submission | TBD |

## 6. How we work

- **Repo:** `containment-protocols` (GitHub). Branch per workstream, PR into `main`.
- **Comms:** short kickoff call Sept 9–10 to lock scope; async in Slack otherwise.
- **Definition of done for a protocol:** runs end-to-end on the replay, emits a decision log, metrics computed automatically.
- **Keep it honest:** log negative results and variance. Small test, not a finished answer.
- **Scope discipline:** if it doesn't feed a clause by Sunday noon, cut it.

## 7. Timeline

| When | Goal |
|---|---|
| Mon Sept 8, eve | Team finalized, roles picked |
| Sept 9–10 | Pre-read sources; kickoff call; lock scope + metric definitions |
| Fri Sept 11 | Build replay pipeline; general-monitor baseline running; hand-code incident timeline |
| Sat Sept 12 | Run remaining protocols; compute metrics; first comparison |
| Sun Sept 13 | Draft clauses; write up; submit with buffer before deadline |

## 8. Open decisions (resolve at kickoff)

- Which model(s) run the protocols? (cost vs. capability)
- How is incident "ground truth" (unsafe events) labelled, and by whom?
- How many replay seeds / runs per protocol for statistical power?
- Simulated human, or real teammate playing the human role?
- Granularity of the timeline — how many steps?

## 9. Links

- Sprint: https://apartresearch.com/sprints/ai-incident-response-sprint-2026-09-11-to-2026-09-13
- Incident (OpenAI report): https://openai.com/index/hugging-face-model-evaluation-security-incident/
- Incident (coverage): https://techcrunch.com/2026/08/26/openai-releases-its-official-report-on-the-hugging-face-breach/
- Epistemic Fingerprints: https://sofiagallego.com/epistemic-fingerprints
- GuardAgent: https://arxiv.org/abs/2406.09187
- Multi-Agent Debate for Safety Eval: https://arxiv.org/abs/2511.06396
- MAGE (shadow memory): https://arxiv.org/abs/2605.03228
