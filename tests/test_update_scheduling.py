from pathlib import Path
import tempfile
import threading
import time
import unittest

from update_runtime.leases import hold
from update_runtime.scheduling import CoordinatedScheduler


class UpdateSchedulingTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory=Path(temporary.name)/'updates'
        self.scheduler=CoordinatedScheduler(directory=self.directory,timezone='UTC')

    def test_periodic_destructive_read_is_skipped_during_update(self):
        counters={'remote':100,'saved':0}
        def consume():
            counters['saved']+=counters['remote'];counters['remote']=0
        job=self.scheduler.add_job(consume,'interval',seconds=60)
        with hold(self.directory,exclusive=True):
            job.func()
            self.assertEqual(counters,{'remote':100,'saved':0})
        job.func()
        self.assertEqual(counters,{'remote':0,'saved':100})

    def test_shared_job_prevents_cutover_until_its_work_is_committed(self):
        def consume():
            with self.assertRaises(BlockingIOError):
                with hold(self.directory,exclusive=True):pass
        self.scheduler.add_job(consume,'interval',seconds=60).func()
        with hold(self.directory,exclusive=True):pass

    def test_startup_job_is_rescheduled_instead_of_lost(self):
        called=threading.Event()
        with hold(self.directory,exclusive=True):
            job=self.scheduler.add_job(called.set,'date',id='fixture-startup')
            job.func()
            self.assertFalse(called.is_set())
        self.scheduler.start()
        try:
            self.assertTrue(called.wait(3))
            # Event.set runs in the executor before the scheduler removes the
            # date job. Let that removal finish before stopping the fixture;
            # APScheduler 3.9.1 changes state before acquiring its store lock.
            deadline=time.monotonic()+2
            while self.scheduler.get_job('fixture-startup') is not None and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertIsNone(self.scheduler.get_job('fixture-startup'))
            self.assertTrue(self.scheduler.running)
            self.assertTrue(self.scheduler._thread.is_alive())
        finally:self.scheduler.shutdown()
