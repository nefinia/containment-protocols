"""Independent copies of one prompt, default count four."""
from .compat import execute
from .contracts import ContractError
from .core import aggregate_decisions


def run_identical_monitors(step, timestamp=None, visible_info=None, *, num_reviewers=None,
                           n=None, use_modal=True, history=(), suite=None, config=None,
                           replicate_id=0):
    if n is not None and num_reviewers is not None:
        raise ContractError("use num_reviewers or n, not both")
    return execute("identical_monitors", step, timestamp, visible_info, use_modal=use_modal,
                   history=history, suite=suite, config=config,
                   num_reviewers=n if n is not None else num_reviewers,
                   replicate_id=replicate_id)

