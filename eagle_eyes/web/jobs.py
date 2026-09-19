"""A small in-process job queue, so a model call is not an HTTP request.

A deep analysis takes seconds. A batch takes minutes. Doing that inside the
request means a page that hangs, a proxy that times out somewhere in the middle,
and a user who retries -- which starts a second paid call for the same failure.

Deliberately in-process and deliberately small. A real deployment would use a
broker; this one is a single container and a queue that lives in it is honest
about that. What it must NOT do is pretend to be durable: a job in flight is
lost on restart, and `docs/PRODUCTION_MIGRATION.md` §4.6 records that rather
than leaving a status page saying "running" forever for work nothing is doing.

Threads, not asyncio: the work is a blocking SDK call and a SQLite write, and
running it on the event loop would block every other request on the worker.
"""

from __future__ import annotations

import queue
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

QUEUED, RUNNING, DONE, FAILED = "queued", "running", "done", "failed"

# Bounded on purpose. An unbounded queue under load turns into unbounded memory
# and a wait nobody can see the end of; a full queue is a clear "come back
# later" the UI can actually show.
MAX_PENDING = 100

# Jobs are kept after they finish so the page that submitted one can read the
# result, then discarded oldest-first. Without this the dict grows forever.
MAX_REMEMBERED = 500


@dataclass
class Job:
    id: str
    kind: str
    actor: str
    status: str = QUEUED
    result: Any = None
    error: str = ""
    # What this job is doing RIGHT NOW, for the waiting page. Real progress,
    # not a scripted sequence of reassuring stage names -- a spinner that
    # claims "Triaging with Haiku..." while the queue has not started yet is
    # telling the user something that is not true.
    note: str = ""
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    @property
    def done(self) -> bool:
        return self.status in (DONE, FAILED)

    def as_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status,
                "error": self.error, "result": self.result, "note": self.note}


class JobQueue:
    def __init__(self, workers: int = 2) -> None:
        self._q: queue.Queue = queue.Queue(maxsize=MAX_PENDING)
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()
        for i in range(max(1, workers)):
            t = threading.Thread(target=self._run, name=f"eagle-eyes-worker-{i}",
                                 daemon=True)
            t.start()
            self._threads.append(t)

    # -- submission ----------------------------------------------------

    def submit(self, kind: str, actor: str, fn: Callable[["Job"], Any]) -> Job:
        """`fn` is handed the Job so it can report progress as it goes.

        It takes the job rather than closing over it because the job does not
        exist until this method creates it -- and a status page that cannot say
        which of forty failures it is on is a spinner, not progress.
        """
        job = Job(id=uuid.uuid4().hex, kind=kind, actor=actor)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._forget_old()
        try:
            self._q.put_nowait((job, fn))
        except queue.Full:
            job.status = FAILED
            job.error = ("the analysis queue is full. Nothing was charged and "
                         "nothing was lost -- submit it again in a moment.")
            job.finished_at = datetime.now(timezone.utc)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def for_actor(self, actor: str) -> list[Job]:
        with self._lock:
            return [j for j in self._jobs.values() if j.actor == actor]

    @property
    def pending(self) -> int:
        return self._q.qsize()

    # -- worker --------------------------------------------------------

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                item = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            job, fn = item
            job.status = RUNNING
            try:
                job.result = fn(job)
                job.status = DONE
            except Exception as exc:
                # The message reaches a user, so it carries the exception text
                # and not the traceback -- a traceback in a browser is a map of
                # the filesystem. The full trace goes to the log.
                job.status = FAILED
                job.error = str(exc) or exc.__class__.__name__
                traceback.print_exc()
            finally:
                job.finished_at = datetime.now(timezone.utc)
                self._q.task_done()

    def _forget_old(self) -> None:
        while len(self._order) > MAX_REMEMBERED:
            oldest = self._order.pop(0)
            self._jobs.pop(oldest, None)

    def drain(self, timeout: float = 30.0) -> bool:
        """Wait for the queue to empty. For tests and for a clean shutdown."""
        deadline = datetime.now(timezone.utc).timestamp() + timeout
        while datetime.now(timezone.utc).timestamp() < deadline:
            if self._q.unfinished_tasks == 0:
                return True
            threading.Event().wait(0.02)
        return False

    def stop(self) -> None:
        self._stopping.set()
        for t in self._threads:
            t.join(timeout=2.0)
