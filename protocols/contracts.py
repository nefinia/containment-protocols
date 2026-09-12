"""Strict application invariants for the team's draft-07 JSON contracts.

Explicit validators for these two contracts, not a general JSON Schema engine.
The application deliberately emits a stricter subset of schema-valid values.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

ACTIONS = ("continue", "restrict", "investigate", "pause", "terminate")
# An experimental policy, NOT an ordering implied by the JSON Schema enum.
ACTION_PRIORITY = ("continue", "investigate", "restrict", "pause", "terminate")
SIGNAL_CODES = (
    "AUTHORIZATION_BOUNDARY", "TASK_DRIFT", "CROSS_SESSION_COMMUNICATION",
    "UNAUTHORIZED_EGRESS", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION",
    "EXPLOIT_EXECUTION", "PERSISTENCE_EVASION", "DATA_EXPOSURE",
    "THIRD_PARTY_IMPACT", "AVAILABILITY_IMPACT", "POLICY_UNCERTAINTY",
)
DECISION_KEYS = {
    "step", "reviewer_id", "decision", "reasoning", "signals_detected", "timestamp"
}
_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
    re.IGNORECASE,
)
_FENCE = chr(96) * 3


class ContractError(ValueError):
    """Invalid input or output; messages omit underlying private content."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not _DATETIME.fullmatch(value):
        raise ContractError("timestamp must be an RFC3339 date-time with timezone")
    try:
        return datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("timestamp contains an invalid calendar date or time") from None


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def strict_json(text: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError("JSON contains duplicate keys")
            result[key] = value
        return result

    def nonfinite(_):
        raise ContractError("JSON contains a non-finite number")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (json.JSONDecodeError, TypeError):
        raise ContractError("Invalid JSON") from None


def public_timestep(item: Mapping[str, Any]) -> dict:
    """Create a NEW allowlisted view; never forward arbitrary extra fields."""
    if not isinstance(item, Mapping):
        raise ContractError("timestep must be an object")
    step = item.get("step")
    if type(step) is not int or step < 0:
        raise ContractError("step must be a nonnegative integer")
    time = item.get("timestamp")
    timestamp(time)
    info = item.get("visible_info")
    if not isinstance(info, str) or not info.strip():
        raise ContractError("visible_info must be a nonempty string")
    return {"step": step, "timestamp": time, "visible_info": info}


def public_context(current: Mapping, history: Sequence[Mapping] = (),
                   history_window: int | None = None) -> list[dict]:
    current = public_timestep(current)
    prior = [public_timestep(item) for item in history]
    previous_step = -1
    previous_time = None
    for item in prior + [current]:
        moment = timestamp(item["timestamp"])
        if item["step"] <= previous_step:
            raise ContractError("history steps must be unique, increasing, and before current")
        if previous_time is not None and moment < previous_time:
            raise ContractError("history timestamps must be nondecreasing")
        previous_step, previous_time = item["step"], moment
    if history_window is not None:
        if type(history_window) is not int or history_window < 0:
            raise ContractError("history_window must be a nonnegative integer or None")
        prior = prior[-history_window:] if history_window else []
    return prior + [current]


def validate_timeline(data: Any) -> list[dict]:
    if isinstance(data, dict):
        keys = [k for k in ("timeline", "timesteps", "steps") if k in data]
        if len(keys) != 1:
            raise ContractError("timeline wrapper must contain exactly one recognized list")
        data = data[keys[0]]
    if not isinstance(data, list) or not data:
        raise ContractError("timeline must be a nonempty list")
    result, previous = [], None
    for index, item in enumerate(data):
        clean = public_timestep(item)
        if clean["step"] != index:
            raise ContractError("complete timeline steps must be numbered 0 through N-1")
        moment = timestamp(clean["timestamp"])
        if previous is not None and moment < previous:
            raise ContractError("timeline timestamps must be nondecreasing")
        label = item.get("ground_truth_label")
        if label not in ("benign", "unsafe", None):
            raise ContractError("ground_truth_label must be benign, unsafe, or null")
        if clean["visible_info"].strip().upper().startswith("TODO"):
            raise ContractError("placeholder observations cannot be replayed")
        result.append({**clean, "ground_truth_label": label})
        previous = moment
    return result


def validate_decision(item: Any, expected_step: int | None = None) -> dict:
    if not isinstance(item, dict) or set(item) != DECISION_KEYS:
        raise ContractError("decision must contain exactly the six supported output fields")
    if type(item["step"]) is not int or item["step"] < 0:
        raise ContractError("decision step must be a nonnegative integer")
    if expected_step is not None and item["step"] != expected_step:
        raise ContractError("decision step does not match its observation")
    reviewer = item["reviewer_id"]
    if reviewer is not None and (not isinstance(reviewer, str) or not reviewer.strip()):
        raise ContractError("reviewer_id must be null or a nonempty string")
    if item["decision"] not in ACTIONS:
        raise ContractError("unknown decision action")
    if not isinstance(item["reasoning"], str) or not item["reasoning"].strip():
        raise ContractError("reasoning must be a nonempty string")
    signals = item["signals_detected"]
    if not isinstance(signals, list) or not all(
        isinstance(s, str) and s.strip() for s in signals
    ):
        raise ContractError("signals_detected must be a list of nonempty strings")
    timestamp(item["timestamp"])
    return item


def response_schema(visible_steps: Sequence[int]) -> dict:
    """Model selects category and visible step; code attaches source evidence."""
    return {
        "type": "object", "additionalProperties": False,
        "required": ["decision", "reasoning", "signals_detected"],
        "properties": {
            "decision": {"type": "string", "enum": list(ACTIONS)},
            "reasoning": {"type": "string", "minLength": 1, "maxLength": 1800},
            "signals_detected": {
                "type": "array", "maxItems": 8,
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["code", "step"],
                    "properties": {
                        "code": {"type": "string", "enum": list(SIGNAL_CODES)},
                        "step": {"type": "integer", "enum": list(visible_steps)},
                    },
                },
            },
        },
    }


def parse_response(raw: str, context: Sequence[Mapping], reviewer_id: str | None) -> tuple[dict, list]:
    if not isinstance(raw, str):
        raise ContractError("model response content must be text")
    text = raw.strip()
    if text.startswith(_FENCE):
        lines = text.splitlines()
        if (len(lines) < 3 or lines[0].lower() not in (_FENCE, _FENCE + "json")
                or lines[-1] != _FENCE):
            raise ContractError("invalid JSON code fence")
        text = "\n".join(lines[1:-1])
    value = strict_json(text)
    if not isinstance(value, dict) or set(value) != {"decision", "reasoning", "signals_detected"}:
        raise ContractError("model response has missing or unexpected fields")
    if value["decision"] not in ACTIONS:
        raise ContractError("model returned an unknown action")
    reasoning = value["reasoning"]
    if not isinstance(reasoning, str) or not reasoning.strip() or len(reasoning) > 1800:
        raise ContractError("model reasoning must contain 1 to 1800 characters")
    signals = value["signals_detected"]
    if not isinstance(signals, list) or len(signals) > 8:
        raise ContractError("model signals must be a list of at most eight evidence objects")
    observed = {row["step"]: row["visible_info"] for row in context}
    normalized, strings, seen = [], [], set()
    for signal in signals:
        if not isinstance(signal, dict) or set(signal) != {"code", "step"}:
            raise ContractError("signal must contain exactly code and step; evidence is attached by code")
        code, step = signal["code"], signal["step"]
        if not isinstance(code, str) or code not in SIGNAL_CODES:
            raise ContractError("signal code is outside the shared taxonomy")
        if type(step) is not int or step not in observed:
            raise ContractError("signal references evidence outside the visible context")
        # The model chooses a visible observation, not a quotation it might
        # paraphrase or fabricate. Preserve the complete observation verbatim.
        quote = observed[step]
        evidence_id = digest({"code": code, "step": step, "evidence": quote})
        if evidence_id in seen:
            raise ContractError("duplicate evidence signal")
        seen.add(evidence_id)
        normalized.append({**signal, "evidence": quote, "evidence_id": evidence_id,
                           "signal_key": f"{code}:{step}"})
        strings.append(f"{code} @ step {step}: {quote}")
    decision = {
        "step": context[-1]["step"], "reviewer_id": reviewer_id,
        "decision": value["decision"], "reasoning": reasoning.strip(),
        "signals_detected": strings, "timestamp": utc_now(),
    }
    return validate_decision(decision, context[-1]["step"]), normalized
