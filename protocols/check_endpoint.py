"""A small, synthetic live check. Does not run or send an incident timeline."""
import argparse
import json
from .backend import BackendError, VLLMBackend
from .config import ProtocolConfig
from .contracts import ContractError
from .core import ProtocolSuite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--model")
    args = parser.parse_args()
    try:
        backend = VLLMBackend(model=args.model, readiness_timeout=args.timeout,
                              request_timeout=min(60, args.timeout))
        suite = ProtocolSuite(backend, ProtocolConfig(temperature=0))
        event = suite.evaluate("general_monitor", {
            "step": 0, "timestamp": "2026-01-01T00:00:00Z",
            "visible_info": "Synthetic connectivity check: an authorized local file read completed.",
        })
        print(json.dumps({
            "mode": "synthetic_live_check", "status": event["status"],
            "backend": backend.metadata(), "decision": event["final_decision"],
            "preflight_error": event.get("preflight_error"),
            "reviewer_errors": [r.get("error") for r in event["reviewer_records"] if r.get("error")],
        }, indent=2))
        return 0 if event["status"] == "ok" else 2
    except (BackendError, ContractError) as error:
        print(json.dumps({"status": "error", "message": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
