"""Reference progressive replay runner and append-only decision journal."""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import uuid
from dataclasses import replace
from pathlib import Path

from . import __version__
from .analysis_export import export_analysis
from .backend import BackendError, MockBackend, VLLMBackend
from .config import ProtocolConfig
from .contracts import (
    ContractError, canonical, digest, public_timestep, strict_json, utc_now,
    validate_decision, validate_timeline,
)
from .core import PROTOCOLS, ProtocolSuite
from .prompts import PROMPT_VERSION


def load_timeline(path: Path) -> list[dict]:
    path = Path(path)
    if ".source_summary." in path.name or ".template." in path.name:
        raise ContractError("source summaries and templates are not replay input files")
    return validate_timeline(strict_json(path.read_text(encoding="utf-8")))


def timeline_audit(timeline):
    """Nonblocking dataset cautions; never relabel or rewrite the evidence."""
    notices = []
    benign = sum(row["ground_truth_label"] == "benign" for row in timeline)
    if benign < 10:
        notices.append({"code": "small_benign_denominator", "count": benign})
    for row in timeline:
        text = row["visible_info"].lower()
        if any(phrase in text for phrase in ("following days", "through the day", "throughout the day")):
            notices.append({"code": "check_observation_cutoff", "step": row["step"]})
    notices.append({"code": "source_provenance_and_label_semantics_require_team_review"})
    return notices


def public_config(config):
    return config.public_dict()


def _code_fingerprint():
    root = Path(__file__).resolve().parent
    return digest({path.name: path.read_text(encoding="utf-8") for path in sorted(root.glob("*.py"))})


class RunJournal:
    """Recoverable JSONL records; no endpoint or raw request/response bodies.

    Each event and its label are kept in the journal. Pure schema decisions are
    additionally separated by protocol and replicate for replay consumers.
    """
    def __init__(self, directory, run_id):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.run_id = run_id
        self.stream = (self.directory / "events.jsonl").open("x", encoding="utf-8")

    def write(self, event, label=None):
        wrapped = {"run_id": self.run_id, "ground_truth_label": label, **event}
        self.stream.write(canonical(wrapped) + "\n")
        self.stream.flush()
        os.fsync(self.stream.fileno())
        target = self.directory / f"replicate_{event['replicate_id']:03d}"
        target.mkdir(exist_ok=True)
        protocol = event["protocol"]
        if event["final_decision"] is not None:
            with (target / f"{protocol}.decisions.jsonl").open("a", encoding="utf-8") as output:
                output.write(canonical(event["final_decision"]) + "\n")
        if event["reviewers"]:
            with (target / f"{protocol}.reviewers.jsonl").open("a", encoding="utf-8") as output:
                for decision in event["reviewers"]:
                    output.write(canonical(decision) + "\n")

    def close(self):
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def run_timeline(timeline, *, use_modal=False, identical_count=None, config=None,
                 backend=None, repeats=1, run_id=None, journal=None, progress=None,
                 input_kind="team_timeline"):
    timeline = validate_timeline(timeline)
    if type(repeats) is not int or repeats < 1:
        raise ContractError("repeats must be a positive integer")
    config = config or ProtocolConfig()
    if identical_count is not None:
        config = replace(config, identical_count=identical_count)
    backend = backend or (VLLMBackend() if use_modal else MockBackend())
    run_id = run_id or uuid.uuid4().hex
    if journal is not None and journal.run_id != run_id:
        raise ContractError("journal run_id must match the run")
    backend.prepare()  # Cold-start waiting is measured separately from protocol latency.
    suite = ProtocolSuite(backend, config)
    schema_root = Path(__file__).resolve().parent.parent / "schemas"
    metadata = {
        "format_version": 1, "implementation_version": __version__, "run_id": run_id,
        "started_at": utc_now(), "mode": backend.metadata()["mode"], "input_kind": input_kind,
        "timeline_steps": len(timeline), "repeats": repeats,
        "identical_monitor_count": config.identical_count, "specialist_count": 4,
        "config": public_config(config), "prompt_version": PROMPT_VERSION,
        "code_sha256": _code_fingerprint(),
        "schemas_sha256": {p.name: digest(strict_json(p.read_text(encoding="utf-8")))
                           for p in sorted(schema_root.glob("*.schema.json"))},
        "dataset_sha256": digest(timeline),
        "visible_dataset_sha256": digest([public_timestep(t) for t in timeline]),
        "timeline_audit": timeline_audit(timeline), "backend": backend.metadata(),
        "replay_mode": "observational_complete_timeline",
        "observation_scope": "provided_centralized_stream",
        "ground_truth_exposure": "labels remain in the runner/scorer; model input uses an allowlist",
        "condition_order": "seeded shuffle at each step",
        "policy_text_saved": False,
    }
    results = []
    for repeat in range(repeats):
        # Start a new history for every replicate. Never reuse model answers as evidence.
        history = []
        order_rng = random.Random(config.seed + repeat)
        for item in timeline:
            public = public_timestep(item)
            order = list(PROTOCOLS)
            order_rng.shuffle(order)
            blocks = {}
            for name in order:
                event = suite.evaluate(name, public, history=history, replicate_id=repeat)
                blocks[name] = event
                if journal is not None:
                    journal.write(event, item["ground_truth_label"])
                if progress:
                    progress(repeat, public["step"], name, event["status"])
            results.append({
                "replicate_id": repeat, "step": item["step"], "timestamp": item["timestamp"],
                "ground_truth_label": item["ground_truth_label"],
                "condition_order": order, "protocols": blocks,
            })
            history.append(public)
    metadata["completed_at"] = utc_now()
    metadata["backend"] = backend.metadata()
    metadata["failed_protocol_steps"] = sum(
        e["status"] != "ok" for row in results for e in row["protocols"].values()
    )
    return {"metadata": metadata, "results": results}


def validate_results(payload):
    if payload.get("metadata", {}).get("format_version") != 1:
        raise ContractError("unexpected result format")
    rows = payload.get("results")
    if not isinstance(rows, list) or not rows:
        raise ContractError("run contains no results")
    seen = set()
    for row in rows:
        key = (row["replicate_id"], row["step"])
        if key in seen:
            raise ContractError("duplicate protocol timestep in results")
        seen.add(key)
        if set(row["protocols"]) != set(PROTOCOLS):
            raise ContractError("missing protocol condition")
        for name, event in row["protocols"].items():
            if (event["protocol"] != name or event["step"] != row["step"]
                    or event["replicate_id"] != row["replicate_id"]):
                raise ContractError("result identifiers do not match their containing row")
            for decision in event["reviewers"]:
                validate_decision(decision, row["step"])
            if event["status"] == "ok":
                if len(event["reviewers"]) != event["expected_reviewers"]:
                    raise ContractError("successful ensemble has the wrong reviewer count")
                validate_decision(event["final_decision"], row["step"])
                if event["final_decision"]["reviewer_id"] is not None:
                    raise ContractError("final decisions must have reviewer_id null")
            elif event["status"] != "error" or event["final_decision"] is not None:
                raise ContractError("failed runs cannot carry a final model decision")
    expected = payload["metadata"]["timeline_steps"] * payload["metadata"]["repeats"]
    if len(rows) != expected:
        raise ContractError("run is incomplete; use the journal for partial recovery")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeline", type=Path, default=Path("data/ground_truth_timeline.json"))
    parser.add_argument("--output", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--use-modal", action="store_true")
    mode.add_argument("--mock", action="store_true")
    parser.add_argument("--identical-count", type=int, default=4)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--seed", type=int, default=20260912)
    parser.add_argument("--temperature", type=float, default=.2)
    parser.add_argument("--max-output-tokens", type=int, default=512)
    parser.add_argument("--context-limit", type=int, default=4096)
    parser.add_argument("--history-window", type=int)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--policy-file", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--readiness-timeout", type=float, default=600)
    parser.add_argument("--request-timeout", type=float, default=120)
    parser.add_argument("--input-kind", choices=("team_timeline", "synthetic_fixture"), default="team_timeline")
    args = parser.parse_args()
    run_id = uuid.uuid4().hex
    output = args.output or Path("results") / f"protocol_run_{run_id[:12]}.json"
    try:
        timeline = load_timeline(args.timeline)
        config = ProtocolConfig(
            identical_count=args.identical_count, seed=args.seed, temperature=args.temperature,
            max_output_tokens=args.max_output_tokens, context_limit=args.context_limit,
            history_window=args.history_window, max_workers=args.max_workers,
            policy=args.policy_file.read_text(encoding="utf-8") if args.policy_file else ProtocolConfig().policy,
        )
        backend = VLLMBackend(
            model=args.model, readiness_timeout=args.readiness_timeout,
            request_timeout=args.request_timeout,
        ) if args.use_modal else MockBackend()
        if output.exists():
            raise ContractError("output already exists; select a new output path")
        output.parent.mkdir(parents=True, exist_ok=True)
        artifacts = output.with_suffix(".artifacts")
        print("Mode: " + ("LIVE" if args.use_modal else "MOCK — software verification only"), flush=True)
        with RunJournal(artifacts, run_id) as journal:
            def progress(repeat, step, protocol, status):
                print(f"replicate={repeat} step={step} protocol={protocol} status={status}", flush=True)
            payload = run_timeline(timeline, backend=backend, config=config, repeats=args.repeats,
                                   run_id=run_id, journal=journal, progress=progress,
                                   input_kind=args.input_kind)
            validate_results(payload)
            with output.open("x", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, ensure_ascii=False, allow_nan=False)
            (artifacts / "manifest.json").write_text(
                json.dumps(payload["metadata"], indent=2, allow_nan=False), encoding="utf-8")
            export_analysis(payload, artifacts / "analysis", allow_mock=not args.use_modal)
        failed = payload["metadata"]["failed_protocol_steps"]
        print(f"Finished. Failed protocol steps: {failed}. Results: {output}")
        return 2 if failed else 0
    except (ContractError, BackendError, OSError) as error:
        # Backend errors have safe messages; never print an HTTP request object.
        print(f"Run failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
