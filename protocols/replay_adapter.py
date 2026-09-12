"""Bridges jambohaku's ReplayEngine (protocols/replay_engine.py) to Muhammad's
ProtocolSuite (protocols/core.py). Neither file imports the other; this module
is the only thing that needs to know both shapes.
"""
from __future__ import annotations

from typing import Any

from protocols.core import ProtocolSuite
from protocols.replay_engine import ReplayContext, ProtocolDecision


def make_protocol(suite: ProtocolSuite, protocol_name: str, *, sink=None):
    """Return a function usable as `protocol` in ReplayEngine.run(protocol).

    jambohaku's engine hands us a ReplayContext (context.current is a
    ReplayTimestep). Muhammad's callback wants a plain
    {step, timestamp, visible_info} mapping and tracks history itself, so we
    only ever forward context.current, never context.history.
    """
    callback = suite.as_replay_callback(protocol_name, sink=sink)

    def protocol(context: ReplayContext) -> dict[str, Any]:
        current = context.current
        timestep = {
            "step": current.step,
            "timestamp": current.timestamp,
            "visible_info": current.visible_info,
        }
        decision = callback(timestep)
        # Muhammad's `timestamp` is decision-emission time (when the model
        # answered), recorded separately from incident time by design
        # (see docs/PROTOCOL_IMPLEMENTATION_README.md, "Outputs for the
        # analysis workstream"). jambohaku's engine requires the returned
        # decision's timestamp to equal the timestep's incident timestamp
        # (replay_engine.py, _coerce_decision). We keep both: the incident
        # timestamp goes where the engine checks it, the real emission time
        # is preserved under a separate key for the analysis workstream.
        return {
            **decision,
            "timestamp": current.timestamp,
            "decision_emitted_at": decision["timestamp"],
        }

    return protocol
