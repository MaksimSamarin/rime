"""Bound and coalesce asynchronous lifecycle work before allocating workers."""
import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Lock


class NodeJobs:
    def __init__(self, workers=4, executor=None, logger=None):
        self._executor = executor or ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="node-job")
        self._logger = logger or logging.getLogger(__name__)
        self._lock = Lock()
        self._running = set()
        self._pending = {}

    def submit(self, node_id, kind, function, *args, replace_connect=False, **kwargs):
        if kind not in ("connect", "restart"):
            raise ValueError("Unsupported node operation")
        job = (kind, function, args, kwargs)
        with self._lock:
            if node_id in self._running:
                # Health checks do not enqueue another connect behind a stalled
                # connect. An explicit restart retains only its latest config.
                if kind == "restart":
                    self._pending[node_id] = job
                elif replace_connect and self._pending.get(node_id, (None,))[0] != "restart":
                    # A changed entry keeps one latest reconnect after the old
                    # endpoint's in-flight work has released the node.
                    self._pending[node_id] = job
                return False
            self._running.add(node_id)
        try:
            self._executor.submit(self._run, node_id, job)
        except BaseException:
            with self._lock:
                self._running.discard(node_id)
                self._pending.pop(node_id, None)
            raise
        return True

    def _run(self, node_id, job):
        finished = False
        try:
            while job is not None:
                kind, function, args, kwargs = job
                try:
                    function(*args, **kwargs)
                except Exception as error:
                    self._logger.error("Node %s %s failed (%s)",
                                       node_id, kind, type(error).__name__)
                with self._lock:
                    job = self._pending.pop(node_id, None)
                    if job is None:
                        self._running.discard(node_id)
                        finished = True
        finally:
            if not finished:
                with self._lock:
                    self._running.discard(node_id)
                    self._pending.pop(node_id, None)

    def shutdown(self):
        self._executor.shutdown(wait=True)
