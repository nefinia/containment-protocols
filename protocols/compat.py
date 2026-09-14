"""Compatibility for the supplied modules; dictionary timesteps also work."""
from dataclasses import replace
from typing import Mapping
from .backend import MockBackend, VLLMBackend
from .config import ProtocolConfig
from .contracts import ContractError, public_timestep
from .core import ProtocolExecutionError, ProtocolSuite


def coerce_step(step, timestamp=None, visible_info=None):
    if isinstance(step, Mapping):
        if timestamp is not None or visible_info is not None:
            raise ContractError("pass a timestep object OR three individual fields")
        return public_timestep(step)
    return public_timestep({"step": step, "timestamp": timestamp, "visible_info": visible_info})


def execute(protocol, step, timestamp=None, visible_info=None, *, use_modal=True,
            history=(), suite=None, config=None, num_reviewers=None, replicate_id=0):
    current = coerce_step(step, timestamp, visible_info)
    if suite is not None and config is not None:
        raise ContractError("configuration belongs to the supplied suite")
    if suite is None:
        config = config or ProtocolConfig()
        if num_reviewers is not None:
            config = replace(config, identical_count=num_reviewers)
        suite = ProtocolSuite(VLLMBackend() if use_modal else MockBackend(), config)
    elif num_reviewers is not None and num_reviewers != suite.config.identical_count:
        raise ContractError("reviewer count differs from the supplied suite configuration")
    result = suite.evaluate(protocol, current, history=history, replicate_id=replicate_id)
    if result["status"] != "ok":
        raise ProtocolExecutionError(result)
    return result

