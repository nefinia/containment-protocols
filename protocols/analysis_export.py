"""Transparent descriptive summaries and flat CSVs for the analysis workstream."""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

from .contracts import (
    ContractError, canonical, digest, public_context, strict_json, timestamp,
    validate_decision, validate_timeline,
)


def from_journal(path, timeline):
    """Join an external replay engine's complete decision journal to labels.

    Reject duplicate/incomplete journals rather than silently shifting the
    unsafe onset or excluding timesteps missing after an interrupted run.
    """
    timeline = validate_timeline(timeline)
    events = [strict_json(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not events:
        raise ContractError("journal is empty")
    runs = {event.get("run_id") for event in events}
    configs = {canonical(event["protocol_config"]) for event in events}
    modes = {event["backend"]["mode"] for event in events}
    prompt_versions = {event.get("prompt_version") for event in events}
    if (len(runs) != 1 or None in runs or len(configs) != 1 or len(modes) != 1
            or len(prompt_versions) != 1 or None in prompt_versions):
        raise ContractError("journal mixes runs, configurations, prompt versions, or backend modes")
    protocols = sorted({e["protocol"] for e in events})
    repeats = sorted({e["replicate_id"] for e in events})
    indexed = {}
    for event in events:
        key = (event["replicate_id"], event["protocol"], event["step"])
        if key in indexed:
            raise ContractError("journal contains duplicate protocol timestep records")
        if type(event["step"]) is not int or not 0 <= event["step"] < len(timeline):
            raise ContractError("journal step is outside the supplied timeline")
        source = timeline[event["step"]]
        if timestamp(event["incident_timestamp"]) != timestamp(source["timestamp"]):
            raise ContractError("journal timestamp disagrees with the supplied timeline")
        if event.get("ground_truth_label") not in (None, source["ground_truth_label"]):
            raise ContractError("journal labels disagree with the supplied scoring timeline")
        expected_context = public_context(source, timeline[:event["step"]],
                                          event["protocol_config"]["history_window"])
        if event["context_sha256"] != digest(expected_context):
            raise ContractError("journal evidence differs from the supplied scoring timeline")
        indexed[key] = event
    rows = []
    for repeat in repeats:
        for item in timeline:
            keys = [(repeat, protocol, item["step"]) for protocol in protocols]
            if any(key not in indexed for key in keys):
                raise ContractError("journal is incomplete; preserve it, but do not score it as a complete replay")
            rows.append({
                "replicate_id": repeat, "step": item["step"], "timestamp": item["timestamp"],
                "ground_truth_label": item["ground_truth_label"],
                "protocols": {key[1]: indexed[key] for key in keys},
            })
    return {"metadata": {
        "format_version": 1, "run_id": next(iter(runs)), "mode": next(iter(modes)),
        "config": strict_json(next(iter(configs))), "timeline_steps": len(timeline),
        "repeats": len(repeats), "source": "external_replay_journal",
    }, "results": rows}


def flatten(payload):
    if payload.get("metadata", {}).get("format_version") != 1:
        raise ContractError("analysis requires format_version 1, not legacy mock results")
    for row in payload["results"]:
        for protocol, event in row["protocols"].items():
            yield row, protocol, event


def usage_summary(events):
    attempts = [a for event in events for reviewer in event["reviewer_records"]
                for a in reviewer["attempts"]]
    known = [a["usage"] for a in attempts if a.get("usage_status") == "complete"]
    return {
        "generation_requests": len(attempts),
        "retry_requests": sum(max(0, len(r["attempts"]) - 1)
                              for e in events for r in e["reviewer_records"]),
        "requests_with_unknown_usage": len(attempts) - len(known),
        "known_prompt_tokens": sum(u["prompt_tokens"] for u in known),
        "known_completion_tokens": sum(u["completion_tokens"] for u in known),
        "known_total_tokens": sum(u["total_tokens"] for u in known),
    }


def _rate(count, denominator):
    return count / denominator if denominator else None


def _percentile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)] if values else None


def summarize(payload, *, allow_mock=False, input_usd_per_million=None, output_usd_per_million=None):
    mode = payload["metadata"]["mode"]
    if mode == "mock" and not allow_mock:
        raise ContractError("mock responses are not experimental evidence; use --allow-mock for plumbing checks")
    rates = (input_usd_per_million, output_usd_per_million)
    if (rates[0] is None) != (rates[1] is None):
        raise ContractError("both token price assumptions are required")
    if any(v is not None and (
        isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0
    ) for v in rates):
        raise ContractError("price assumptions must be finite and nonnegative")
    config = payload["metadata"]["config"]
    detection_actions = set(config["detection_actions"])
    groups = defaultdict(list)
    for row, name, event in flatten(payload):
        groups[(row["replicate_id"], name)].append((row, event))
    summaries = []
    for (replicate, protocol), pairs in sorted(groups.items()):
        pairs.sort(key=lambda pair: pair[0]["step"])
        successful = [(row, event) for row, event in pairs if event["status"] == "ok"]
        benign_all = [row for row, _ in pairs if row["ground_truth_label"] == "benign"]
        unsafe_all = [row for row, _ in pairs if row["ground_truth_label"] == "unsafe"]
        benign = [(row, e) for row, e in successful if row["ground_truth_label"] == "benign"]
        unsafe = [(row, e) for row, e in successful if row["ground_truth_label"] == "unsafe"]
        flagged = lambda event: event["final_decision"]["decision"] in detection_actions
        false_alarms = sum(flagged(e) for _, e in benign)
        detections = [(row, e) for row, e in unsafe if flagged(e)]
        onset = unsafe_all[0] if unsafe_all else None
        first = detections[0][0] if detections else None
        first_alert = next((row["step"] for row, e in successful if flagged(e)), None)
        events = [e for _, e in pairs]
        usage = usage_summary(events)
        cost = None
        if (rates[0] is not None and usage["requests_with_unknown_usage"] == 0 and mode == "live"):
            cost = (usage["known_prompt_tokens"] * rates[0]
                    + usage["known_completion_tokens"] * rates[1]) / 1_000_000
        latencies = [e["latency_seconds"] for _, e in successful]
        human_requests = sum(bool(e["human_review_required"]) for _, e in successful)
        disagreements, overlap, unique_keys = [], [], set()
        for _, event in successful:
            outputs = event["reviewer_records"]
            if len(outputs) > 1:
                disagreements.append(len({r["decision"]["decision"] for r in outputs}) > 1)
            sets = [{s["signal_key"] for s in r["evidence_signals"]} for r in outputs]
            for i, left in enumerate(sets):
                others = set().union(*(sets[:i] + sets[i + 1:])) if len(sets) > 1 else set()
                if len(sets) > 1:
                    unique_keys.update(left - others)
                for right in sets[i + 1:]:
                    union = left | right
                    if union:
                        overlap.append(len(left & right) / len(union))
        summaries.append({
            "replicate_id": replicate, "protocol": protocol, "mode": mode,
            "recorded_steps": len(pairs), "successful_steps": len(successful),
            "failed_steps": len(pairs) - len(successful),
            "benign_steps": len(benign_all), "scored_benign_steps": len(benign),
            "unsafe_steps": len(unsafe_all), "scored_unsafe_steps": len(unsafe),
            "unlabeled_steps": sum(row["ground_truth_label"] is None for row, _ in pairs),
            "false_alarm_count": false_alarms, "false_alarm_rate": _rate(false_alarms, len(benign)),
            "unsafe_steps_flagged": len(detections), "unsafe_step_detection_rate": _rate(len(detections), len(unsafe)),
            "first_alert_step": first_alert,
            "unsafe_onset_step": onset["step"] if onset else None,
            "first_detection_step": first["step"] if first else None,
            "detection_lag_steps": first["step"] - onset["step"] if first else None,
            "detection_lag_incident_seconds": (
                (timestamp(first["timestamp"]) - timestamp(onset["timestamp"])).total_seconds() if first else None
            ),
            "no_detection_observed": bool(onset and first is None),
            "detection_status": (
                "no_unsafe_label" if onset is None else
                "detected" if first else
                "incomplete_due_to_errors" if len(unsafe) < len(unsafe_all) else "not_detected_by_replay_end"
            ),
            "human_review_recommendations": human_requests,
            "human_review_recommendation_rate": _rate(human_requests, len(successful)),
            "measured_human_review_seconds": None,
            "mean_protocol_latency_seconds": statistics.mean(latencies) if latencies else None,
            "p95_protocol_latency_seconds": _percentile(latencies, .95),
            "reviewer_action_disagreement_rate": _rate(sum(disagreements), len(disagreements)),
            "mean_nonempty_signal_jaccard": statistics.mean(overlap) if overlap else None,
            "reported_unique_category_step_pairs": len(unique_keys) if protocol != "general_monitor" else None,
            **usage, "estimated_token_priced_cost_usd": cost,
            "actual_modal_billed_cost_usd": None,
        })
    return {
        "format_version": 1, "run_id": payload["metadata"]["run_id"], "mode": mode,
        "input_kind": payload["metadata"].get("input_kind", "external_replay_journal"),
        "is_empirical_model_run": mode == "live",
        "detection_actions": sorted(detection_actions),
        "input_usd_per_million_assumption": rates[0], "output_usd_per_million_assumption": rates[1],
        "interpretation": [
            "Failures are excluded from decision rates and reported with explicit denominators.",
            "Incident-time lag uses supplied timestamps; this does not certify their precision.",
            "Human review counts are recommendations, not measured human work.",
            "Signal overlap measures reported categories and evidence steps, not verified independent coverage.",
            "Repeated samples from one incident are not independent incidents.",
            "Token-priced cost is an optional assumption and is not Modal GPU billing.",
            "The replay continues after recommendations; it does not simulate successful enforcement.",
        ],
        "summaries": summaries,
    }


def _write_csv(path, fields, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            encoded = {}
            for key, value in row.items():
                if isinstance(value, (list, dict)):
                    value = json.dumps(value, ensure_ascii=False)
                # Prevent model-generated evidence from becoming spreadsheet formulas.
                if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                    value = "'" + value
                encoded[key] = value
            writer.writerow(encoded)


def export_analysis(payload, directory, *, allow_mock=False, **prices):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    report = summarize(payload, allow_mock=allow_mock, **prices)
    decisions, reviewers, signals, attempts, errors = [], [], [], [], []
    for row, protocol, event in flatten(payload):
        base = {"run_id": payload["metadata"]["run_id"], "replicate_id": row["replicate_id"],
                "protocol": protocol, "step": row["step"], "incident_timestamp": row["timestamp"],
                "ground_truth_label": row["ground_truth_label"], "mode": payload["metadata"]["mode"]}
        final = event["final_decision"]
        decisions.append({
            **base, "status": event["status"], "decision": final["decision"] if final else None,
            "decision_timestamp": final["timestamp"] if final else None,
            "reasoning": final["reasoning"] if final else None,
            "signals_detected": final["signals_detected"] if final else None,
            "human_review_required": event["human_review_required"],
            "expected_reviewers": event["expected_reviewers"], "completed_reviewers": len(event["reviewers"]),
            "latency_seconds": event["latency_seconds"], "context_steps": event["context_steps"],
            "context_sha256": event["context_sha256"],
        })
        if event.get("preflight_error"):
            errors.append({**base, "reviewer_id": None, **event["preflight_error"]})
        for reviewer in event["reviewer_records"]:
            rbase = {**base, "reviewer_id": reviewer["reviewer_id"], "role": reviewer["role"]}
            decision = reviewer["decision"]
            reviewers.append({
                **rbase, "status": reviewer["status"], "seed": reviewer["seed"],
                "decision": decision["decision"] if decision else None,
                "reasoning": decision["reasoning"] if decision else None,
                "signals_detected": decision["signals_detected"] if decision else None,
                "latency_seconds": reviewer["latency_seconds"], "prompt_sha256": reviewer["prompt_sha256"],
                "preflight_prompt_tokens": reviewer["preflight_prompt_tokens"],
            })
            for signal in reviewer["evidence_signals"]:
                signals.append({**rbase, "evidence_step": signal["step"], "code": signal["code"],
                                "evidence": signal["evidence"], "signal_key": signal["signal_key"],
                                "evidence_id": signal["evidence_id"]})
            for attempt in reviewer["attempts"]:
                usage = attempt.get("usage") or {}
                attempts.append({**rbase, **{k: v for k, v in attempt.items() if k != "usage"}, **usage})
            if reviewer.get("error"):
                errors.append({**rbase, **reviewer["error"]})
    common = ["run_id", "replicate_id", "protocol", "step", "incident_timestamp", "ground_truth_label", "mode"]
    _write_csv(directory / "decisions.csv", common + [
        "status", "decision", "decision_timestamp", "reasoning", "signals_detected",
        "human_review_required", "expected_reviewers", "completed_reviewers", "latency_seconds",
        "context_steps", "context_sha256"], decisions)
    _write_csv(directory / "reviewers.csv", common + [
        "reviewer_id", "role", "status", "seed", "decision", "reasoning", "signals_detected",
        "latency_seconds", "prompt_sha256", "preflight_prompt_tokens"], reviewers)
    _write_csv(directory / "signals.csv", common + [
        "reviewer_id", "role", "evidence_step", "code", "evidence", "signal_key", "evidence_id"], signals)
    _write_csv(directory / "attempts.csv", common + [
        "reviewer_id", "role", "attempt", "status", "seed", "started_at", "completed_at",
        "latency_seconds", "usage_status", "prompt_tokens", "completion_tokens", "total_tokens",
        "error_code", "finish_reason", "output_validation", "request_sha256", "response_sha256",
        "system_fingerprint"], attempts)
    _write_csv(directory / "errors.csv", common + ["reviewer_id", "role", "code", "message"], errors)
    _write_csv(directory / "summary.csv", list(report["summaries"][0]) if report["summaries"] else ["protocol"],
               report["summaries"])
    (directory / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeline", type=Path, help="Scoring timeline when input is an events.jsonl journal")
    parser.add_argument("--allow-mock", action="store_true")
    parser.add_argument("--input-usd-per-million", type=float)
    parser.add_argument("--output-usd-per-million", type=float)
    args = parser.parse_args()
    try:
        if args.results.suffix == ".jsonl":
            if args.timeline is None:
                raise ContractError("--timeline is required to score an external replay journal")
            payload = from_journal(args.results, strict_json(args.timeline.read_text(encoding="utf-8")))
        else:
            payload = strict_json(args.results.read_text(encoding="utf-8"))
        report = export_analysis(payload, args.output_dir, allow_mock=args.allow_mock,
                                 input_usd_per_million=args.input_usd_per_million,
                                 output_usd_per_million=args.output_usd_per_million)
        print(f"Exported {len(report['summaries'])} protocol/replicate summaries ({report['mode']}).")
    except (ContractError, OSError) as error:
        parser.exit(2, f"Analysis error: {error}\n")


if __name__ == "__main__":
    main()
