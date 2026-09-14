"""General monitor; compatible with the supplied three-field call signature."""
from .compat import execute


def run_general_monitor(step, timestamp=None, visible_info=None, *, use_modal=True,
                        history=(), suite=None, config=None, replicate_id=0):
    return execute("general_monitor", step, timestamp, visible_info, use_modal=use_modal,
                   history=history, suite=suite, config=config,
                   replicate_id=replicate_id)["final_decision"]

