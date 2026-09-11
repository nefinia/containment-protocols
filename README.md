# Containment Protocols

**Which combination of technical controls, safety agents, and human escalation actually catches an agent moving toward an unexpected or unsafe outcome -- and which just creates the appearance of coverage?**

Project for the Apart Research AI Incident Response Sprint (Sept 11-13, 2026, Track 1).

## The question

There are several different ways people try to keep agents contained: sandboxing, permission gates, fixed rules, monitoring agents, humans in the loop, or several agents checking each other. Each one sees something different. A permission rule can check whether a single action is allowed, but the problem may only become visible across a longer sequence. A human can understand context, but constant approval requests become overwhelming. And several similar guard agents may just repeat the same judgment rather than catching different things.

This project asks that question directly, using a real incident as the test bed: OpenAI's GPT-5.6 Sol and an unreleased model escaped a cybersecurity-eval sandbox via a zero-day in their only network-egress channel, then breached Hugging Face's production systems to steal benchmark answers (OpenAI's own incident report, July 2026). The report notes controls "failed repeatedly despite initial detection and intervention" -- which is exactly the redundancy question this project tests.

## Approach

A progressive replay of the incident timeline. At each step, a protocol sees only the information available at that moment -- never the outcome -- and decides whether to continue, restrict, investigate, pause, or terminate.

Protocols compared:
- A single general monitor.
- Several identical monitors (does replication add real coverage, or just more calls making the same judgment?).
- Specialized reviewers split by category: permissions, task intent, security, downstream consequences.
- Different points at which a human is brought into the loop.

Metrics: detection lag, false-alarm rate, human-review burden, cost.

A live design threat: replicated-monitor protocols make more model calls than a single monitor by construction, so any comparison has to control for that rather than let "more calls" masquerade as "better redundancy."

## Connection to prior work

This is a direct extension of [Epistemic Fingerprints](https://sofiagallego.com/epistemic-fingerprints) (False Epistemic Redundancy, Apart Research Digital Minds Sprint, August 2026), which asked the same question about post-hoc investigation: do differently-framed AI agents examining the same evidence actually search different parts of a hypothesis space, or just produce surface disagreement while sharing the same blind spot? That project found the answer was case-dependent -- persona diversity sometimes helped, sometimes actively hurt, and reliably increased how different the outputs *looked* independent of whether it increased what they actually *covered*. This project asks the same structural question about real-time monitoring instead of after-the-fact hypothesis generation.

## Related work

- Xu et al., *GuardAgent: Safeguard LLM Agents by a Guard Agent via Knowledge-Enabled Reasoning*. [arXiv:2406.09187](https://arxiv.org/abs/2406.09187)
- *Efficient LLM Safety Evaluation through Multi-Agent Debate*. [arXiv:2511.06396](https://arxiv.org/abs/2511.06396)
- *MAGE: Safeguarding LLM Agents against Long-Horizon Threats via Shadow Memory*. [arXiv:2605.03228](https://arxiv.org/abs/2605.03228)

## Team

- Replay engine -- jambohaku
- Protocol implementation -- Muhammad
- Causal & statistical analysis -- Melody
- Framing & tradeoffs / clause writing -- tiramisu
- Coordination & integration -- Sofia

Full role descriptions, timeline, and open decisions: [PROJECT_GUIDELINE.md](PROJECT_GUIDELINE.md).

## Interfaces

The four pieces (replay engine, protocol implementation, analysis, clause writing) are built in parallel against fixed schemas rather than each other's code -- see [`schemas/`](schemas/). Branch per role off `main` (`replay-engine`, `protocol-impl`, `analysis`, `clauses`), small PRs.

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

Model choice (`MODEL_NAME` in `serve_model.py`) is a placeholder pending team discussion -- Qwen2.5-7B-Instruct was right for epistemic-fingerprints' free-text hypothesis generation, but monitor/reviewer judgment quality may call for a different tradeoff.

## Status

Sprint underway (Sept 11-13). Incident timeline / ground-truth labeling, the replay harness, and the protocol implementations are in progress.
