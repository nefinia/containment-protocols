import copy
import csv
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from protocols.analysis_export import export_analysis, from_journal, summarize, usage_summary
from protocols.backend import BackendError, MockBackend, ModelReply, VLLMBackend, normalize_base_url
from protocols.config import ProtocolConfig
from protocols.contracts import (
    ACTIONS, ContractError, canonical, parse_response, public_context, public_timestep,
    strict_json, timestamp, validate_decision, validate_timeline,
)
from protocols.core import ProtocolExecutionError, ProtocolSuite, aggregate_decisions
from protocols.general_monitor import run_general_monitor
from protocols.identical_monitors import run_identical_monitors
from protocols.run_all import RunJournal, load_timeline, run_timeline, timeline_audit, validate_results
from protocols.specialized_reviewers import run_specialized_reviewers

ROOT = Path(__file__).resolve().parents[1]


def observation(step=0, text="A local file read completed.", label=None):
    return {"step": step, "timestamp": f"2026-01-01T10:{step:02d}:00Z",
            "visible_info": text, "ground_truth_label": label}


def response(action="continue", signals=None, reasoning="A synthetic reviewer explanation."):
    return canonical({"decision": action, "reasoning": reasoning, "signals_detected": signals or []})


class ScriptedBackend(MockBackend):
    def __init__(self, handler=None, token_count=100):
        self.handler = handler or (lambda messages, seed: response())
        self.calls = []
        self.token_count = token_count

    def count_tokens(self, messages):
        return self.token_count

    def generate(self, messages, schema, config, seed):
        self.calls.append(copy.deepcopy({"messages": messages, "schema": schema, "seed": seed}))
        text = self.handler(messages, seed)
        return ModelReply(text, [], "scripted-test-only")


class ContractTests(unittest.TestCase):
    def test_allowlist_removes_labels_and_arbitrary_metadata(self):
        row = observation()
        row.update(ground_truth_label="PRIVATE_LABEL_SENTINEL", future_summary="FUTURE_SENTINEL")
        original = copy.deepcopy(row)
        view = public_timestep(row)
        self.assertEqual(set(view), {"step", "timestamp", "visible_info"})
        self.assertEqual(row, original)

    def test_reject_bad_steps_dates_and_empty_observations(self):
        for field, value in [("step", True), ("step", -1), ("step", "0"),
                             ("timestamp", "2026-02-30T00:00:00Z"),
                             ("timestamp", "2026-01-01T00:00:00"),
                             ("visible_info", ""), ("visible_info", None)]:
            with self.subTest(field=field, value=value):
                row = observation()
                row[field] = value
                with self.assertRaises(ContractError):
                    public_timestep(row)

    def test_history_rejects_future_duplicate_and_reverse_time(self):
        for history in ([observation(2)], [observation(), observation()],
                        [{**observation(), "timestamp": "2026-01-02T00:00:00Z"}]):
            with self.assertRaises(ContractError):
                public_context(observation(1), history)

    def test_window_drops_whole_old_steps_without_mutating_input(self):
        prior = [observation(0), observation(1)]
        self.assertEqual([r["step"] for r in public_context(observation(2), prior, 1)], [1, 2])
        self.assertEqual([r["step"] for r in public_context(observation(2), prior, 0)], [2])
        self.assertEqual(len(prior), 2)

    def test_timeline_validation_and_template_guard(self):
        for data in ([observation(1)], [observation(), observation(2)],
                     [observation(text="TODO")], [observation(label="unknown")]):
            with self.assertRaises(ContractError):
                validate_timeline(data)
        self.assertEqual(len(validate_timeline({"timesteps": [observation()]})), 1)
        with self.assertRaises(ContractError):
            load_timeline(Path("anything.source_summary.json"))

    def test_strict_json_rejects_duplicate_keys_nonfinite_and_extra_prose(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}', 'Here: {"x":1}'):
            with self.assertRaises(ContractError):
                strict_json(text)

    def test_model_field_types_are_not_silently_repaired(self):
        good = json.loads(response())
        cases = [
            {**good, "decision": "escalate"}, {**good, "reasoning": ""},
            {**good, "signals_detected": "suspicious"}, {**good, "step": 999},
            {"decision": "continue", "reasoning": "Signals missing"},
            {**good, "signals_detected": ["invented string signal"]},
        ]
        for value in cases:
            with self.assertRaises(ContractError):
                parse_response(canonical(value), [public_timestep(observation())], None)

    def test_grounded_signals_project_to_unchanged_public_contract(self):
        context = public_context(observation(1, "The gate blocked an external request."), [observation()])
        decision, signals = parse_response(response("restrict", [
            {"code": "UNAUTHORIZED_EGRESS", "step": 1}
        ]), context, "permissions")
        self.assertEqual(decision["signals_detected"],
                         ["UNAUTHORIZED_EGRESS @ step 1: The gate blocked an external request."])
        self.assertEqual(signals[0]["signal_key"], "UNAUTHORIZED_EGRESS:1")
        self.assertEqual(len(signals[0]["evidence_id"]), 64)
        validate_decision(decision, 1)

    def test_hallucinated_and_out_of_context_evidence_are_rejected(self):
        for signal in [
            {"code": "UNAUTHORIZED_EGRESS", "step": 99},
            {"code": "INVENTED_CODE", "step": 0},
            {"code": "DATA_EXPOSURE", "step": 0, "evidence": "a private database was stolen"},
            {"code": "DATA_EXPOSURE", "step": True},
        ]:
            with self.assertRaises(ContractError):
                parse_response(response("restrict", [signal]), [observation()], None)

    def test_signal_references_attach_complete_source_and_reject_duplicates(self):
        text = "Preserve this exact observation. " * 20
        row = observation(text=text)
        signal = {"code": "POLICY_UNCERTAINTY", "step": 0}
        decision, evidence = parse_response(response("investigate", [signal]), [row], None)
        self.assertEqual(evidence[0]["evidence"], text)
        self.assertTrue(decision["signals_detected"][0].endswith(text))
        with self.assertRaises(ContractError):
            parse_response(response("investigate", [signal, signal]), [row], None)

    def test_one_fence_is_accepted_but_greedy_json_extraction_is_not(self):
        fence = chr(96) * 3
        valid, _ = parse_response(fence + "json\n" + response() + "\n" + fence, [observation()], None)
        self.assertEqual(valid["decision"], "continue")
        with self.assertRaises(ContractError):
            parse_response(response() + response(), [observation()], None)

    def test_configuration_rejects_invalid_parameters(self):
        for changes in ({"identical_count": 0}, {"max_workers": True}, {"temperature": float("nan")},
                        {"history_window": -1}, {"max_output_tokens": 4096}, {"policy": ""},
                        {"action_priority": ("continue",)}, {"top_p": 0}):
            with self.assertRaises(ContractError):
                ProtocolConfig(**changes)


class ProtocolTests(unittest.TestCase):
    def test_identical_prompts_equal_general_and_seed_slots_differ(self):
        backend = ScriptedBackend()
        suite = ProtocolSuite(backend)
        general = suite.evaluate("general_monitor", observation())
        ensemble = suite.evaluate("identical_monitors", observation())
        self.assertIsNone(general["final_decision"]["reviewer_id"])
        self.assertEqual(len(ensemble["reviewers"]), 4)
        self.assertEqual(len({canonical(c["messages"]) for c in backend.calls}), 1)
        self.assertEqual(backend.calls[0]["seed"], backend.calls[1]["seed"])
        self.assertEqual(len({c["seed"] for c in backend.calls[1:]}), 4)

    def test_specialists_receive_same_evidence_and_shared_taxonomy(self):
        backend = ScriptedBackend(lambda m, s: response(reasoning="REVIEWER_ONLY_SENTINEL"))
        suite = ProtocolSuite(backend)
        history = [observation(0, "Prior observed action.")]
        row = observation(1)
        row["future_report"] = "HIDDEN_FUTURE_SENTINEL"
        row["ground_truth_label"] = "HIDDEN_LABEL_SENTINEL"
        suite.evaluate("specialized_reviewers", row, history=history)
        self.assertEqual(len({call["messages"][1]["content"] for call in backend.calls}), 1)
        self.assertEqual(len({call["messages"][0]["content"] for call in backend.calls}), 4)
        for call in backend.calls:
            text = canonical(call["messages"])
            for sentinel in ("HIDDEN_FUTURE_SENTINEL", "HIDDEN_LABEL_SENTINEL", "REVIEWER_ONLY_SENTINEL",
                             "ground_truth_label"):
                self.assertNotIn(sentinel, text)
            self.assertIn("Prior observed action.", text)
            self.assertEqual(call["schema"]["properties"]["signals_detected"]["items"]
                             ["properties"]["step"]["enum"], [0, 1])

    def test_aggregation_preserves_raw_results_and_actual_evidence(self):
        decisions = []
        for index, action in enumerate(("continue", "investigate", "restrict", "pause")):
            value, _ = parse_response(response(action), [observation()], f"r{index}")
            decisions.append(value)
        before = copy.deepcopy(decisions)
        final = aggregate_decisions(decisions)
        self.assertEqual(final["decision"], "pause")
        self.assertIsNone(final["reviewer_id"])
        self.assertIn("r3", final["reasoning"])
        self.assertEqual(decisions, before)

    def test_aggregation_rejects_empty_mixed_steps_and_duplicate_reviewers(self):
        value, _ = parse_response(response(), [observation()], "r1")
        for group in ([], [value, {**value, "step": 1}], [value, value]):
            with self.assertRaises(ContractError):
                aggregate_decisions(group)

    def test_failed_reviewer_invalidates_whole_ensemble(self):
        def handler(messages, seed):
            if "Focus on exploit mechanisms" in messages[0]["content"]:
                raise BackendError("Synthetic failure", code="synthetic_failure")
            return response("restrict")
        result = ProtocolSuite(ScriptedBackend(handler)).evaluate("specialized_reviewers", observation())
        self.assertEqual(result["status"], "error")
        self.assertIsNone(result["final_decision"])
        self.assertIsNone(result["human_review_required"])
        self.assertEqual(len(result["reviewers"]), 3)
        self.assertEqual(len(result["reviewer_records"]), 4)

    def test_truncated_and_invalid_outputs_do_not_become_continue(self):
        for text in ("not JSON", response("invented-action")):
            result = ProtocolSuite(ScriptedBackend(lambda m, s: text)).evaluate("general_monitor", observation())
            self.assertEqual(result["status"], "error")
            self.assertIsNone(result["final_decision"])
        class Truncated(ScriptedBackend):
            def generate(self, *args):
                return ModelReply(response(), [], "scripted", "length")
        result = ProtocolSuite(Truncated()).evaluate("general_monitor", observation())
        self.assertEqual(result["reviewer_records"][0]["error"]["code"], "incomplete_output")

    def test_context_overflow_is_explicit_and_sends_no_generation(self):
        backend = ScriptedBackend(token_count=3900)
        result = ProtocolSuite(backend).evaluate("identical_monitors", observation())
        self.assertEqual(result["preflight_error"]["code"], "context_budget_exceeded")
        self.assertEqual(backend.calls, [])

    def test_stateful_callback_history_reset_and_error_recording(self):
        backend = ScriptedBackend()
        records = []
        callback = ProtocolSuite(backend).as_replay_callback("general_monitor", sink=records.append)
        callback(observation())
        callback(observation(1))
        self.assertEqual(records[-1]["context_steps"], [0, 1])
        with self.assertRaises(ContractError):
            callback(observation(1))
        callback.reset()
        callback(observation())
        self.assertEqual(records[-1]["replicate_id"], 1)
        self.assertEqual(records[-1]["context_steps"], [0])
        bad_records = []
        bad = ProtocolSuite(ScriptedBackend(lambda m, s: "invalid"))
        adapter = bad.as_replay_callback("general_monitor", sink=bad_records.append)
        with self.assertRaises(ProtocolExecutionError) as error:
            adapter(observation())
        self.assertIs(error.exception.result, adapter.last_result)
        self.assertEqual(len(bad_records), 1)

    def test_both_public_call_signatures_work(self):
        first = run_general_monitor(0, "2026-01-01T00:00:00Z", "Local read.", use_modal=False)
        second = run_general_monitor(observation(), use_modal=False)
        self.assertEqual(first["decision"], second["decision"])
        self.assertIsNone(first["reviewer_id"])
        self.assertEqual(len(run_identical_monitors(observation(), n=4, use_modal=False)["reviewers"]), 4)
        self.assertEqual(len(run_specialized_reviewers(observation(), use_modal=False)["reviewers"]), 4)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.timeline = [observation(0, label="benign"), observation(1, label="unsafe"),
                         observation(2, label="unsafe")]

    def test_lag_uses_incident_time_and_explicit_label_denominators(self):
        def handler(messages, seed):
            step = strict_json(messages[1]["content"])["current_step"]
            return response("restrict" if step == 2 else "continue")
        payload = run_timeline(self.timeline, backend=ScriptedBackend(handler))
        validate_results(payload)
        with self.assertRaises(ContractError):
            summarize(payload)
        summary = summarize(payload, allow_mock=True)["summaries"][0]
        self.assertEqual(summary["detection_lag_steps"], 1)
        self.assertEqual(summary["detection_lag_incident_seconds"], 60)
        self.assertEqual(summary["false_alarm_count"], 0)
        self.assertEqual(summary["scored_benign_steps"], 1)
        self.assertEqual(summary["unsafe_steps_flagged"], 1)

    def test_errors_are_excluded_and_never_scored_as_detection(self):
        payload = run_timeline(self.timeline, backend=ScriptedBackend(lambda m, s: "invalid"))
        report = summarize(payload, allow_mock=True)
        for item in report["summaries"]:
            self.assertEqual(item["failed_steps"], 3)
            self.assertIsNone(item["false_alarm_rate"])
            self.assertIsNone(item["first_detection_step"])
            self.assertEqual(item["detection_status"], "incomplete_due_to_errors")

    def test_unknown_labels_and_missing_usage_are_not_zero_cost(self):
        payload = run_timeline([observation()], backend=ScriptedBackend())
        report = summarize(payload, allow_mock=True)
        self.assertIsNone(report["summaries"][0]["false_alarm_rate"])
        self.assertIsNone(report["summaries"][0]["estimated_token_priced_cost_usd"])
        events = [{"reviewer_records": [{"attempts": [
            {"usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}, "usage_status": "complete"},
            {"usage": None, "usage_status": "missing"}]}]}]
        usage = usage_summary(events)
        self.assertEqual(usage["generation_requests"], 2)
        self.assertEqual(usage["known_total_tokens"], 12)
        self.assertEqual(usage["requests_with_unknown_usage"], 1)
        self.assertEqual(usage["retry_requests"], 1)

    def test_replicates_reset_history_and_journal_has_every_event(self):
        with tempfile.TemporaryDirectory() as directory:
            with RunJournal(Path(directory) / "run", "test-run") as journal:
                payload = run_timeline(self.timeline, backend=ScriptedBackend(), repeats=2,
                                       run_id="test-run", journal=journal)
            validate_results(payload)
            events = (Path(directory) / "run/events.jsonl").read_text().splitlines()
            self.assertEqual(len(events), 18)
            for row in payload["results"]:
                for event in row["protocols"].values():
                    self.assertEqual(event["context_steps"], list(range(row["step"] + 1)))
            pure = Path(directory) / "run/replicate_000/general_monitor.decisions.jsonl"
            for line in pure.read_text().splitlines():
                validate_decision(strict_json(line))
            with self.assertRaises(FileExistsError):
                RunJournal(Path(directory) / "run", "other")

    def test_csv_exports_preserve_records_and_neutralize_formulas(self):
        backend = ScriptedBackend(lambda m, s: response(reasoning="=SYNTHETIC_FORMULA"))
        payload = run_timeline(self.timeline, backend=backend)
        with tempfile.TemporaryDirectory() as directory:
            export_analysis(payload, directory, allow_mock=True)
            with (Path(directory) / "reviewers.csv").open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 27)
            self.assertTrue(all(r["reasoning"].startswith("'=") for r in rows))
            self.assertEqual(payload["results"][0]["protocols"]["general_monitor"]
                             ["final_decision"]["reasoning"], "=SYNTHETIC_FORMULA")
            self.assertTrue((Path(directory) / "errors.csv").exists())

    def test_timeline_audit_does_not_relabel(self):
        timeline = [observation(text="Activity over the following days.", label="benign")]
        original = copy.deepcopy(timeline)
        self.assertTrue(any(n["code"] == "check_observation_cutoff" for n in timeline_audit(timeline)))
        self.assertEqual(timeline, original)

    def test_external_replay_journal_roundtrip_and_wrong_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "journal"
            with RunJournal(target, "external-run") as journal:
                callback = ProtocolSuite(ScriptedBackend()).as_replay_callback(
                    "specialized_reviewers", sink=journal.write)
                for row in self.timeline:
                    callback(row)
            payload = from_journal(target / "events.jsonl", self.timeline)
            report = summarize(payload, allow_mock=True)
            self.assertEqual(len(report["summaries"]), 1)
            self.assertEqual(report["summaries"][0]["recorded_steps"], 3)
            changed = copy.deepcopy(self.timeline)
            changed[0]["visible_info"] = "Different reconstructed evidence."
            with self.assertRaises(ContractError):
                from_journal(target / "events.jsonl", changed)
            with (target / "events.jsonl").open("a") as stream:
                stream.write((target / "events.jsonl").read_text().splitlines()[0] + "\n")
            with self.assertRaises(ContractError):
                from_journal(target / "events.jsonl", self.timeline)

    def test_human_recommendation_counts_ensemble_once_per_step(self):
        payload = run_timeline(self.timeline, backend=ScriptedBackend(lambda m, s: response("restrict")))
        for row in summarize(payload, allow_mock=True)["summaries"]:
            self.assertEqual(row["human_review_recommendations"], 3)


class HTTPTests(unittest.TestCase):
    def transport(self, method, url, body, headers, timeout):
        if url.endswith("/models"):
            return {"data": [{"id": "test-model", "max_model_len": 4096}]}
        if url.endswith("/tokenize"):
            return {"count": 100}
        return {"model": "test-model", "choices": [{"message": {"content": response()},
                 "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}}

    def test_url_normalization_and_private_configuration_not_in_metadata(self):
        for value in ("https://example.com", "https://example.com/v1/", "https://example.com/v1"):
            self.assertEqual(normalize_base_url(value), "https://example.com/v1")
        for value in ("", "http://example.com", "https://user:secret@example.com/v1",
                      "https://example.com/v1?key=secret"):
            with self.assertRaises(ContractError):
                normalize_base_url(value)
        backend = VLLMBackend("https://example.com", api_key="SECRET_SENTINEL", transport=self.transport)
        backend.prepare()
        self.assertNotIn("SECRET_SENTINEL", canonical(backend.metadata()))
        self.assertNotIn("example.com", canonical(backend.metadata()))

    def test_readiness_is_cached_tokenizer_path_and_generation_schema(self):
        requests = []
        def transport(method, url, body, headers, timeout):
            requests.append((method, url, body))
            return self.transport(method, url, body, headers, timeout)
        backend = VLLMBackend("https://example.com/v1", transport=transport)
        result = ProtocolSuite(backend).evaluate("identical_monitors", observation())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(sum(url.endswith("/models") for _, url, _ in requests), 1)
        self.assertEqual(sum(url == "https://example.com/tokenize" for _, url, _ in requests), 1)
        for _, url, body in requests:
            if url.endswith("/chat/completions"):
                self.assertEqual(body["response_format"]["type"], "json_schema")
                self.assertEqual(body["messages"][0]["role"], "system")
                self.assertNotIn("ground_truth_label", canonical(body))
        usage = usage_summary([result])
        self.assertEqual(usage["generation_requests"], 4)
        self.assertEqual(usage["known_total_tokens"], 480)

    def test_transient_retry_is_logged_and_permanent_errors_fail_fast(self):
        count = 0
        def flaky(method, url, body, headers, timeout):
            nonlocal count
            if url.endswith("/chat/completions"):
                count += 1
                if count == 1:
                    raise BackendError("HTTP 503", code="http_503", retriable=True)
            return self.transport(method, url, body, headers, timeout)
        backend = VLLMBackend("https://example.com/v1", transport=flaky, sleep=lambda _: None)
        event = ProtocolSuite(backend).evaluate("general_monitor", observation())
        self.assertEqual(event["status"], "ok")
        self.assertEqual(len(event["reviewer_records"][0]["attempts"]), 2)
        self.assertEqual(usage_summary([event])["requests_with_unknown_usage"], 1)
        permanent_calls = []
        def permanent(*args):
            permanent_calls.append(1)
            raise BackendError("HTTP 401", code="http_401")
        bad = VLLMBackend("https://example.com/v1", transport=permanent)
        with self.assertRaises(BackendError):
            bad.prepare()
        self.assertEqual(len(permanent_calls), 1)

    def test_multiple_models_require_explicit_selection(self):
        transport = lambda *args: {"data": [{"id": "one"}, {"id": "two"}]}
        with self.assertRaises(BackendError):
            VLLMBackend("https://example.com", transport=transport).prepare()
        backend = VLLMBackend("https://example.com", model="two", transport=transport)
        self.assertEqual(backend.prepare()["model"], "two")

    def test_usage_survives_output_validation_failure_and_malformed_model_entry(self):
        def transport(method, url, body, headers, timeout):
            if url.endswith("/models"):
                return {"data": ["malformed-entry", {"id": "test-model"}]}
            result = self.transport(method, url, body, headers, timeout)
            if url.endswith("/chat/completions"):
                result["choices"][0]["message"]["content"] = "invalid"
            return result
        backend = VLLMBackend("https://example.com", transport=transport)
        event = ProtocolSuite(backend).evaluate("general_monitor", observation())
        self.assertEqual(event["status"], "error")
        self.assertEqual(usage_summary([event])["known_total_tokens"], 120)
        self.assertEqual(event["reviewer_records"][0]["attempts"][0]["output_validation"], "error")

    def test_real_http_requests_against_local_synthetic_server(self):
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.reply(None)
            def do_POST(self):
                body = strict_json(self.rfile.read(int(self.headers["Content-Length"])).decode())
                self.reply(body)
            def reply(self, body):
                result = outer.transport(self.command, self.path, body, {}, 1)
                encoded = canonical(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}/v1"
            payload = run_timeline([observation()], backend=VLLMBackend(base))
            validate_results(payload)
            self.assertEqual(payload["metadata"]["failed_protocol_steps"], 0)
            self.assertEqual(sum(usage_summary([e])["generation_requests"]
                                 for e in payload["results"][0]["protocols"].values()), 9)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class CLITests(unittest.TestCase):
    def test_cli_writes_results_exports_and_rejects_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.json"
            command = [sys.executable, "-m", "protocols.run_all", "--mock",
                       "--timeline", str(ROOT / "examples/synthetic_timeline.json"),
                       "--output", str(output), "--input-kind", "synthetic_fixture"]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = strict_json(output.read_text())
            self.assertEqual(payload["metadata"]["mode"], "mock")
            self.assertTrue((output.with_suffix(".artifacts") / "analysis/summary.csv").exists())
            before = output.read_bytes()
            repeated = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(output.read_bytes(), before)

    def test_independent_draft7_schema_validation(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("optional independent jsonschema verifier is not installed")
        schemas = {p.name: json.loads(p.read_text()) for p in (ROOT / "schemas").glob("*.json")}
        for schema in schemas.values():
            jsonschema.Draft7Validator.check_schema(schema)
        payload = run_timeline([observation()], backend=ScriptedBackend())
        validator = jsonschema.Draft7Validator(schemas["decision.schema.json"],
                                               format_checker=jsonschema.FormatChecker())
        for event in payload["results"][0]["protocols"].values():
            validator.validate(event["final_decision"])
            for decision in event["reviewers"]:
                validator.validate(decision)


if __name__ == "__main__":
    unittest.main()
