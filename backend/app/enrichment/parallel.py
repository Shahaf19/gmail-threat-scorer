"""Runs several lookups at once under one overall time limit, on one shared and bounded set of threads."""

from collections.abc import Callable, Hashable, Sequence
from concurrent.futures import ThreadPoolExecutor, wait
from typing import TypeVar

OVERALL_DEADLINE_SECONDS = 5
# One pool for the whole process: concurrent requests queue for these threads instead of each request
# starting its own, so a burst of slow outside services can't multiply threads until memory runs out.
MAX_LOOKUP_THREADS = 16

_POOL = ThreadPoolExecutor(max_workers=MAX_LOOKUP_THREADS, thread_name_prefix="lookup")

Item = TypeVar("Item", bound=Hashable)
Result = TypeVar("Result")


def run_parallel(function: Callable[[Item], Result], items: Sequence[Item]) -> dict[Item, Result | Exception]:
    """Each item maps to its result, or to the error it raised (a lookup that misses the deadline counts as one)."""
    futures = {_POOL.submit(function, item): item for item in items}
    wait(futures, timeout=OVERALL_DEADLINE_SECONDS)
    outcomes: dict[Item, Result | Exception] = {}
    for future, item in futures.items():
        if future.done():
            outcomes[item] = future.exception() or future.result()
        else:
            # A queued lookup is dropped; one already running ends on its own request timeout.
            future.cancel()
            outcomes[item] = TimeoutError("lookup missed the deadline")
    return outcomes
