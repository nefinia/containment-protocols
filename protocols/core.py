"""Independent reviewers, deterministic aggregation, and a stateful replay adapter."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Mapping, Sequence

from .backend import Backend, BackendError
from .config import ProtocolConfig
from .contracts import (
    ACTION_PRIORITY, ContractError, digest, parse_response, public_context,
    public_timestep, response_schema, utc_now, validate_decision,
)
from .prompts import PROMPT_VERSION, SPECIALIST_ROLES, messages_for

PROTOCOLS = ("general_monitor", "identical_monitors", "specialized_reviewers")


class ProtocolExecutionError(RuntimeError):
    """A failed evaluation is not a model decision. Partial records are retained."""
    def __init__(self, result: dict):
        super().__init__("Protocol evaluation failed; inspect exception.result for diagnostic records")
        self.result = result


def aggregate_decisions(decisions: Sequence[dict], priority=ACTION_PRIORITY) -> dict:
    if not decisions:
        raise ContractError("aggregation requires at least one decision")
    if len(priority) != 5 or set(priority) != set(ACTION_PRIORITY):
        raise ContractError("aggregation priority must contain each action exactly once")
    step = decisions[0].get("step")
    for decision in decisions:
        validate_decision(decision, step)
    ids = [d["reviewer_id"] for d in decisions]
    if len(decisions) > 1 and (None in ids or len(set(ids)) != len(ids)):
        raise ContractError("ensemble reviewers must have distinct, non-null identities")
    severity = {action: i for i, action in enumerate(priority)}
    winner = max(decisions, key=lambda d: severity[d["decision"]])
    supporters = [d["reviewer_id"] or "general" for d in decisions if d["decision"] == winner["decision"]]
    signals = list(dict.fromkeys(s for d in decisions for s in d["signals_detected"]))
    result = {
        "step": step, "reviewer_id": None, "decision": winner["decision"],
        "reasoning": (
            "Rule max-action-v1 under " + " < ".join(priority) + ". Selected "
            + winner["decision"] + "; supporting reviewers: " + ", ".join(supporters)
            + ". Independent rationales: "
            + " | ".join((d["reviewer_id"] or "general") + ": " + d["reasoning"] for d in decisions)
        ),
        "signals_detected": signals, "timestamp": utc_now(),
    }
    return validate_decision(result, step)


class ProtocolSuite:
    def __init__(self, backend: Backend, config: ProtocolConfig | None = None):
        self.backend = backend
        self.config = config or ProtocolConfig()

    def _specs(self, protocol):
        if protocol == "general_monitor":
            return [(None, "general")]
        if protocol == "identical_monitors":
            return [(f"identical_monitor_{i + 1}", "general") for i in range(self.config.identical_count)]
        if protocol == "specialized_reviewers":
            return [(role, role) for role in SPECIALIST_ROLES]
        raise ContractError("unknown protocol")

    def _seed(self, replicate: int, step: int, reviewer_index: int) -> int:
        # Deterministic seeds vary by replicate, step, and reviewer slot.
        # For the sensitivity run, identical monitors use seed slots that do
        # not overlap with the single general-monitor baseline.
        return int(digest([self.config.seed, replicate, step, reviewer_index])[:8], 16) % (2 ** 31)

    def evaluate(self, protocol: str, timestep: Mapping, *, history: Sequence[Mapping] = (),
                 replicate_id: int = 0) -> dict:
        if type(replicate_id) is not int or replicate_id < 0:
            raise ContractError("replicate_id must be a nonnegative integer")
        specs = self._specs(protocol)
        context = public_context(timestep, history, self.config.history_window)
        current = context[-1]
        schema = response_schema([item["step"] for item in context])
        started_at, start = utc_now(), time.monotonic()
        messages = [messages_for(role, self.config.policy, context) for _, role in specs]
        record = {
            "protocol": protocol, "replicate_id": replicate_id, "step": current["step"],
            "incident_timestamp": current["timestamp"], "started_at": started_at,
            "prompt_version": PROMPT_VERSION, "context_steps": [t["step"] for t in context],
            "context_sha256": digest(context), "policy_sha256": digest(self.config.policy),
            "expected_reviewers": len(specs), "status": "error", "reviewers": [],
            "reviewer_records": [], "final_decision": None, "human_review_required": None,
            "aggregation": {"rule": "max-action-v1", "action_priority": list(self.config.action_priority)},
            "decision": None,
            "protocol_config": self.config.public_dict(),
            "signal_grounding": "whole_visible_observation_v2",
        }
        try:
            self.backend.prepare()
            limit = min(self.config.context_limit, getattr(self.backend, "max_model_len", None)
                        or self.config.context_limit)
            # Identical rendered prompts need one exact token count. Distinct
            # prompts can be tokenized concurrently without sharing judgments.
            prompt_keys = [digest(m) for m in messages]
            unique_messages = dict(zip(prompt_keys, messages))
            with ThreadPoolExecutor(max_workers=min(self.config.max_workers, len(unique_messages))) as pool:
                unique_counts = dict(zip(unique_messages,
                    pool.map(self.backend.count_tokens, unique_messages.values())))
            token_counts = [unique_counts[key] for key in prompt_keys]
            if any(type(count) is not int or count < 0 for count in token_counts):
                raise BackendError("Invalid backend token count", code="invalid_token_count")
            if any(n + self.config.max_output_tokens > limit for n in token_counts):
                raise BackendError(
                    "Prompt plus output allowance exceeds context budget; choose an explicit shared history window",
                    code="context_budget_exceeded",
                )
        except BackendError as error:
            record["preflight_error"] = {"code": error.code, "message": str(error)}
            record["completed_at"] = utc_now()
            record["latency_seconds"] = time.monotonic() - start
            record["backend"] = self.backend.metadata()
            return record
        record["preflight_seconds"] = time.monotonic() - start
        record["context_limit"] = limit

        def review(index):
            reviewer_id, role = specs[index]
            seed_index = index + 1 if protocol == "identical_monitors" else index
            seed = self._seed(replicate_id, current["step"], seed_index)
            entry = {
                "reviewer_id": reviewer_id, "role": role, "reviewer_index": index,
                "seed": seed, "prompt_sha256": digest(messages[index]),
                "preflight_prompt_tokens": token_counts[index],
                "status": "error", "decision": None, "evidence_signals": [], "attempts": [],
            }
            review_start = time.monotonic()
            try:
                response = self.backend.generate(messages[index], schema, self.config, seed)
                entry["attempts"] = response.attempts
                entry["model"] = response.model
                entry["response_sha256"] = digest(response.content)
                if response.finish_reason != "stop":
                    raise BackendError("Completion did not finish normally", code="incomplete_output")
                decision, signals = parse_response(response.content, context, reviewer_id)
                entry.update(status="ok", decision=decision, evidence_signals=signals)
                if entry["attempts"]:
                    entry["attempts"][-1]["output_validation"] = "ok"
            except BackendError as error:
                if error.attempts:
                    entry["attempts"] = error.attempts
                entry["error"] = {"code": error.code, "message": str(error)}
            except ContractError as error:
                entry["error"] = {"code": "invalid_model_output", "message": str(error)}
            if entry["status"] != "ok" and entry["attempts"]:
                entry["attempts"][-1]["output_validation"] = "error"
            entry["latency_seconds"] = time.monotonic() - review_start
            return entry

        # Workers share no conversation or reviewer outputs. executor.map keeps
        # stable reviewer order independently of completion order.
        with ThreadPoolExecutor(max_workers=min(self.config.max_workers, len(specs))) as pool:
            entries = list(pool.map(review, range(len(specs))))
        record["reviewer_records"] = entries
        record["reviewers"] = [r["decision"] for r in entries if r["status"] == "ok"]
        if all(r["status"] == "ok" for r in entries):
            final = (record["reviewers"][0] if protocol == "general_monitor" else
                     aggregate_decisions(record["reviewers"], self.config.action_priority))
            record.update(
                status="ok", final_decision=final,
                decision=final["decision"],
                human_review_required=any(
                    d["decision"] in self.config.human_review_actions for d in record["reviewers"]
                ),
            )
        # A partial ensemble is never silently scored as the planned ensemble.
        record["completed_at"] = utc_now()
        record["latency_seconds"] = time.monotonic() - start
        record["backend"] = self.backend.metadata()
        return record

    def as_replay_callback(self, protocol: str, *, sink: Callable | None = None,
                           replicate_id=0):
        return ReplayAdapter(self, protocol, sink=sink, replicate_id=replicate_id)


class ReplayAdapter:
    """One instance per protocol/run. Callback output is exactly one decision.

    Every observed step advances history, including failed reviews. Failures
    raise ProtocolExecutionError after recording partial results through sink.
    The harness chooses operational failure handling; it must not call it a
    successful model detection.
    """
    def __init__(self, suite: ProtocolSuite, protocol: str, *, sink=None, replicate_id=0):
        suite._specs(protocol)
        self.suite, self.protocol, self.sink = suite, protocol, sink
        self.replicate_id = replicate_id
        self._history = []
        self.last_result = None

    def __call__(self, timestep: Mapping) -> dict:
        public = public_timestep(timestep)
        if public["step"] != len(self._history):
            raise ContractError("stateful replay callback requires consecutive steps starting at zero")
        result = self.suite.evaluate(self.protocol, public, history=self._history,
                                     replicate_id=self.replicate_id)
        self.last_result = result
        self._history.append(public)
        if self.sink:
            self.sink(result)
        if result["status"] != "ok":
            raise ProtocolExecutionError(result)
        return result["final_decision"]

    def reset(self, replicate_id: int | None = None):
        new_id = self.replicate_id + 1 if replicate_id is None else replicate_id
        if type(new_id) is not int or new_id < 0:
            raise ContractError("replicate_id must be a nonnegative integer")
        self.replicate_id = new_id
        self._history = []
        self.last_result = None
