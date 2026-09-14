"""Four specialized reviewers with shared policy, taxonomy, and evidence."""
from .compat import execute
from .core import aggregate_decisions
from .prompts import SPECIALIST_ROLES


def run_specialized_reviewers(step, timestamp=None, visible_info=None, *, use_modal=True,
                              history=(), suite=None, config=None, replicate_id=0):
    return execute("specialized_reviewers", step, timestamp, visible_info, use_modal=use_modal,
                   history=history, suite=suite, config=config,
                   replicate_id=replicate_id)
