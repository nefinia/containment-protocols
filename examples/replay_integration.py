"""Run from repository root: python -m examples.replay_integration --mock

Replace the timeline iterator with the real replay engine's timestep iterator.
"""
import argparse
from pathlib import Path
from protocols.backend import MockBackend, VLLMBackend
from protocols.core import ProtocolSuite
from protocols.run_all import RunJournal, load_timeline


def main():
    import uuid
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--timeline", type=Path, default=Path("examples/synthetic_timeline.json"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    run_id = uuid.uuid4().hex
    target = args.output_dir or Path("results") / ("callback-" + run_id[:12])
    suite = ProtocolSuite(MockBackend() if args.mock else VLLMBackend())
    with RunJournal(target, run_id) as journal:
        callback = suite.as_replay_callback("specialized_reviewers", sink=journal.write)
        for timestep in load_timeline(args.timeline):
            decision = callback(timestep)
            print(decision["step"], decision["decision"])


if __name__ == "__main__":
    main()
