"""
Denial-of-service defence (section 2.7, Advanced).

The problem: model inference is CPU work. FastAPI runs `async def`
endpoints on one event loop, so CPU work done there blocks every other
request until it finishes. One expensive request (a batch of long URLs)
freezes the whole server, and a flood of requests queues forever.

The defence has three parts:
1. Inference runs in a fixed pool of worker threads, never on the event
   loop, so the server keeps accepting and answering requests.
2. Admission control: at most `workers + queue` inference jobs may be in
   the system. Any request beyond that is refused at once with HTTP 503
   and a Retry-After header, instead of piling up.
3. A timeout: a job that runs longer than the limit returns HTTP 503 so
   one slow request cannot hold a client connection indefinitely.

Request size limits (body size, URL length, batch size) cap how expensive
a single request can be in the first place.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable


class ServerBusyError(Exception):
    """Raised when admission control rejects a request."""

    def __init__(self, reason: str, retry_after: int = 1):
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


class InferenceGuard:
    def __init__(self, workers: int, queue: int, timeout: float, enabled: bool = True):
        self.enabled = enabled
        self.timeout = timeout
        self.capacity = workers + queue
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="inference")
        self._slots = asyncio.Semaphore(self.capacity)
        self.rejected = 0

    async def run(self, func: Callable[..., Any], *args: Any) -> Any:
        if not self.enabled:
            # Vulnerable behaviour, used only to demonstrate the attack:
            # the CPU work runs directly on the event loop.
            return func(*args)

        # Admission control: never wait for a slot; refuse when full.
        if self._slots.locked():
            self.rejected += 1
            raise ServerBusyError("The server is handling too many checks right now.", retry_after=2)
        await self._slots.acquire()
        loop = asyncio.get_running_loop()
        job = self._executor.submit(func, *args)
        # Free the slot only when the worker has really finished. A job
        # that timed out keeps its slot until its thread is done, so
        # timed-out work can never pile up beyond the capacity.
        job.add_done_callback(lambda _: loop.call_soon_threadsafe(self._slots.release))
        try:
            return await asyncio.wait_for(asyncio.wrap_future(job), timeout=self.timeout)
        except asyncio.TimeoutError:
            job.cancel()
            raise ServerBusyError("The check took too long and was stopped.", retry_after=5) from None

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
