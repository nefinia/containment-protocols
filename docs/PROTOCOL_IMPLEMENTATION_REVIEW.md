# Review of the supplied implementations

The supplied archive was inspected without executing its code. It contains three
protocol modules, a standalone runner, a reconstructed 26-step test timeline,
and mock output files. It does not include the separate replay engine.

The archive's reconstructed timeline also fails chronological validation:
step 11 is dated `2026-07-09T03:00:00Z`, followed by step 12 dated
`2026-07-04T04:00:00Z`. The runner rejects this backward time transition.
This is a problem in the archive's fixture, not a finding about the separate
26-step timeline pasted in the conversation. Use the authoritative repository
file and reconcile any source questions below before research runs.

## Implementation findings addressed

| Finding | Consequence | Change |
|---|---|---|
| Two incompatible public calling conventions | Integration failures or inconsistent output handling | Support timestep dictionaries and the ZIP's three-field inputs; provide an explicit stateful callback |
| One-file endpoint assignment appears after the main block | Running the script can attempt SDK lookup before that assignment | Process configuration is resolved before requests |
| Only the current visible_info string is used | Long-horizon evidence is absent despite the research question | Accumulated sanitized history; fixed optional window; strict cutoff checks |
| Identical condition uses three reviewers; specialists use four | Reviewer count and cost confound specialization | Four versus four by default; actual token/call records retained |
| Greedy brace parsing and defaulted missing fields in one prototype | Invalid outputs can look like valid judgments | Strict JSON parsing, explicit required fields, visible-step evidence references |
| Specialists use disjoint preferred label vocabularies | Apparent signal diversity can be a naming artifact | One shared taxonomy with evidence-step keys |
| Some prompts instruct reviewers to ignore major classes of evidence | Artificial blind spots can determine the result | Specialization guides attention without forcing silence about evident serious risks |
| Temperature zero for identical repeated calls | Replication may be effectively deterministic | Recorded matched sampling settings and separate seeds; deterministic variants remain configurable |
| Repeated readiness checks and no request usage records | Latency and cost are difficult to interpret | Cached readiness; separate startup measurement; per-attempt usage and retries |
| Mixed result metadata inside public decision objects | Downstream identity and schema confusion | Pure decision objects plus separately identified analysis records |
| Single-monitor reviewer_id is non-null in the ZIP | Conflicts with the contract's documented convention | Null for single and final decisions |
| No explicit incomplete-ensemble semantics | A failed or undersized ensemble could be compared as complete | Incomplete ensembles have no final model decision |
| No bounded context policy | Long prefixes can exceed the deployed 4096-token limit | Exact server tokenization, explicit errors, and a shared configurable window |

The archive's corrected mock results are constant plumbing outputs. They are not
evidence of detection performance. No result files from either earlier prototype
are included as research findings in this package.

## Change prompted by live verification

The first implementation required the model to quote an exact evidence excerpt.
Live testing found paraphrased quotations that correctly failed validation but
also made an ensemble incomplete. Version 1.1.0 uses prompt version
`containment-review-v2`: reviewers select `{code, step}` references, constrained
to the observed prefix, and the program attaches the original observation text.
This preserves the team's public string-array schema and the common category/step
unit for analysis. It removes a quotation-format failure mode; it does not prove
that the selected category or decision is correct. Do not pool prompt v1 and v2
runs as the same experimental condition.

## Dataset questions requiring coordination

These are questions about the supplied evidence, not changes made to its labels.

1. Step 2 describes reads/writes over subsequent days at the initial timestamp.
   Step 21 includes activity through the day at 06:00. Both need observation
   availability cutoffs, interval endpoints, or separation into later steps.
2. Step 6 combines the July 4 outage and subsequent response. OpenAI's later
   account places incident opening on July 5 and the rebuild by July 8.
3. The supplied notes assign Hugging Face worker exploitation to July 9;
   OpenAI's later timeline places the HDF5 disclosure and template-injection
   execution on July 11. Reconcile source differences; do not silently invent
   an exact ordering.
4. The 181 mesh enrollments are described in Hugging Face's technical account
   as occurring over the campaign. The supplied step assigns them to a narrower
   interval. Confirm the interval-specific count.
5. Terms such as "network log" and "filesystem audit" describe reconstructed
   sensor views. Record which details are documented, reconstructed, or
   hypothetical, and who could have observed them at the chosen time.
6. The three benign labels and all-later-unsafe sequence require explicit
   semantics. An ongoing unsafe incident state is different from a judgment
   that each later remediation/disclosure action is itself unsafe.
7. Earlier cross-session communication can violate the proposed authorization
   policy while remaining benign under the team's chosen SSRF onset boundary.
   Report the policy and consider label-boundary sensitivity in analysis.

The provided source_summary is useful provenance context but contains hindsight
verdicts. It must not be used as the model's evidence stream. Removing verdict
words from a summary does not by itself prove that the remaining information
was available in real time.

Relevant primary references:

- [OpenAI's later account and incident timeline](https://openai.com/index/hugging-face-incident-and-the-road-ahead/)
- [Hugging Face technical reconstruction](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [vLLM 0.21.0 structured output interface](https://docs.vllm.ai/en/v0.21.0/features/structured_outputs/)

No new incident facts, revised ground-truth labels, or claims of successful
real-world containment are produced by this implementation.
