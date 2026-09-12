"""Replay the incident timeline without leaking future or scoring information."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence


DECISIONS = {"continue", "restrict", "investigate", "pause", "terminate"}
LABELS = {"benign", "unsafe", None}


@dataclass(frozen=True)
class ReplayTimestep:
    """The only per-step object made available to a protocol."""

    step: int
    timestamp: str
    visible_info: str


@dataclass(frozen=True)
class ReplayContext:
    """Label-free prefix visible to a protocol at one point in the replay."""

    current: ReplayTimestep
    history: tuple[ReplayTimestep, ...]

    @property
    def visible_info(self) -> str:
        """Return all observations available through the current timestep."""
        return "\n".join(item.visible_info for item in self.history)


@dataclass(frozen=True)
class ProtocolDecision:
    step: int
    decision: str
    reasoning: str
    timestamp: str
    reviewer_id: str | None = None
    signals_detected: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "step": self.step,
            "decision": self.decision,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp,
        }
        if self.reviewer_id is not None:
            result["reviewer_id"] = self.reviewer_id
        if self.signals_detected:
            result["signals_detected"] = list(self.signals_detected)
        return result


@dataclass(frozen=True)
class ReplayResult:
    decisions: tuple[ProtocolDecision, ...]
    labels: tuple[str | None, ...]

    def scoring_rows(self) -> list[dict[str, Any]]:
        """Join decisions to labels only after the protocol has finished."""
        return [
            {**decision.as_dict(), "ground_truth_label": label}
            for decision, label in zip(self.decisions, self.labels)
        ]


Protocol = Callable[[ReplayContext], ProtocolDecision | dict[str, Any]]


class ReplayEngine:
    """Load a timeline and run a protocol over its label-free prefixes."""

    def __init__(self, timesteps: Sequence[ReplayTimestep], labels: Sequence[str | None]):
        if len(timesteps) != len(labels):
            raise ValueError("Each timestep must have exactly one ground-truth label.")
        self._timesteps = tuple(timesteps)
        self._labels = tuple(labels)

    @classmethod
    def from_json(cls, path: str | Path) -> "ReplayEngine":
        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not load timeline {source}: {exc}") from exc

        if not isinstance(raw, list) or not raw:
            raise ValueError("Timeline must be a non-empty JSON array.")

        timesteps: list[ReplayTimestep] = []
        labels: list[str | None] = []
        expected_step = 0
        previous_timestamp: datetime | None = None

        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("Each timeline entry must be a JSON object.")
            missing = {"step", "timestamp", "visible_info"} - item.keys()
            if missing:
                raise ValueError(f"Timeline entry is missing required fields: {sorted(missing)}")

            step = item["step"]
            timestamp = item["timestamp"]
            visible_info = item["visible_info"]
            label = item.get("ground_truth_label")
            if not isinstance(step, int) or isinstance(step, bool) or step != expected_step:
                raise ValueError(f"Expected 0-indexed step {expected_step}, got {step!r}.")
            if not isinstance(timestamp, str) or not _parse_timestamp(timestamp):
                raise ValueError(f"Invalid ISO 8601 timestamp at step {step}.")
            parsed_timestamp = _parse_timestamp(timestamp)
            if parsed_timestamp.tzinfo is None:
                raise ValueError(f"Timestamp at step {step} must include a timezone.")
            if previous_timestamp is not None and parsed_timestamp < previous_timestamp:
                raise ValueError(f"Timestamps must be non-decreasing at step {step}.")
            if not isinstance(visible_info, str):
                raise ValueError(f"visible_info must be a string at step {step}.")
            if label not in LABELS:
                raise ValueError(f"Invalid ground_truth_label at step {step}: {label!r}.")

            timesteps.append(ReplayTimestep(step, timestamp, visible_info))
            labels.append(label)
            expected_step += 1
            previous_timestamp = parsed_timestamp

        return cls(timesteps, labels)

    def iter_contexts(self) -> Iterator[ReplayContext]:
        history: list[ReplayTimestep] = []
        for timestep in self._timesteps:
            history.append(timestep)
            yield ReplayContext(current=timestep, history=tuple(history))

    def run(self, protocol: Protocol) -> ReplayResult:
        decisions: list[ProtocolDecision] = []
        for context in self.iter_contexts():
            decision = _coerce_decision(protocol(context), context.current)
            decisions.append(decision)
        return ReplayResult(tuple(decisions), self._labels)


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _coerce_decision(value: ProtocolDecision | dict[str, Any], timestep: ReplayTimestep) -> ProtocolDecision:
    if isinstance(value, ProtocolDecision):
        decision = value
    elif isinstance(value, dict):
        decision = ProtocolDecision(
            step=value.get("step", timestep.step),
            decision=value.get("decision", ""),
            reasoning=value.get("reasoning", ""),
            timestamp=value.get("timestamp", timestep.timestamp),
            reviewer_id=value.get("reviewer_id"),
            signals_detected=tuple(value.get("signals_detected", ())),
        )
    else:
        raise TypeError("A protocol must return ProtocolDecision or a decision dictionary.")

    if decision.step != timestep.step or decision.timestamp != timestep.timestamp:
        raise ValueError("Protocol decision must match the timestep it responds to.")
    if decision.decision not in DECISIONS:
        raise ValueError(f"Invalid decision at step {timestep.step}: {decision.decision!r}.")
    if not isinstance(decision.reasoning, str):
        raise ValueError("Protocol reasoning must be a string.")
    return decision


def _continue_protocol(context: ReplayContext) -> ProtocolDecision:
    return ProtocolDecision(
        step=context.current.step,
        decision="continue",
        reasoning="No protocol implementation was supplied.",
        timestamp=context.current.timestamp,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a containment timeline.")
    parser.add_argument("timeline", type=Path, help="Path to a ground-truth timeline JSON file.")
    parser.add_argument("--scored", action="store_true", help="Include labels in output after replay.")
    args = parser.parse_args()

    result = ReplayEngine.from_json(args.timeline).run(_continue_protocol)
    rows = result.scoring_rows() if args.scored else [decision.as_dict() for decision in result.decisions]
    for row in rows:
        print(json.dumps(row, ensure_ascii=True))


if __name__ == "__main__":
    main()