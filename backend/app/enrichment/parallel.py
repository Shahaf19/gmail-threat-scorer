"""Runs several lookups at once under one overall time limit."""

from collections.abc import Callable, Hashable, Sequence
from concurrent.futures import ThreadPoolExecutor, wait
from typing import TypeVar

OVERALL_DEADLINE_SECONDS = 5

Item = TypeVar("Item", bound=Hashable)
Result = TypeVar("Result")


def run_parallel(function: Callable[[Item], Result], items: Sequence[Item]) -> dict[Item, Result | Exception]:
    """Each item maps to its result, or to the error it raised (a lookup that misses the deadline counts as one)."""
    if not items:
        return {}
    pool = ThreadPoolExecutor(max_workers=len(items))
    futures = {pool.submit(function, item): item for item in items}
    wait(futures, timeout=OVERALL_DEADLINE_SECONDS)
    # Not waiting for stragglers: every request already has its own timeout, so they end on their own.
    pool.shutdown(wait=False, cancel_futures=True)
    outcomes: dict[Item, Result | Exception] = {}
    for future, item in futures.items():
        if not future.done():
            outcomes[item] = TimeoutError("lookup missed the deadline")
        else:
            outcomes[item] = future.exception() or future.result()
    return outcomes
