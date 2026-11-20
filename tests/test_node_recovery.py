"""Concurrency and failure-path checks without starting the panel or touching a node."""
import ast
import concurrent.futures
import importlib.util
import logging
from pathlib import Path
import socket
import ssl
import threading
import time
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("node_jobs_checked", ROOT / 'app/utils/node_jobs.py')
jobs_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jobs_module)


def load_function(path, name, namespace, class_name=None):
    namespace.setdefault("_control_timeout", lambda address, default, *args, **kwargs: default)
    namespace.setdefault("_defer_health_recovery", lambda node: False)
    namespace.setdefault("_node_endpoint_matches", lambda node, dbnode: True)
    tree = ast.parse(path.read_text())
    parent = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name) if class_name else tree
    function = next(n for n in parent.body if isinstance(n, ast.FunctionDef) and n.name == name)
    function.decorator_list = []
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), str(path), 'exec'), namespace)
    return namespace[name]


class NodeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.log = logging.getLogger('node-tests')
        self.log.disabled = True
        self.jobs = jobs_module.NodeJobs(workers=2, logger=self.log)
        self.release = threading.Event()
        self.addCleanup(self.jobs.shutdown)
        self.addCleanup(self.release.set)

    def test_ten_thousand_duplicate_connects_do_not_queue(self):
        entered = threading.Event()
        calls = []
        def blocked():
            calls.append(1);entered.set();self.release.wait(3)
        self.assertTrue(self.jobs.submit(6, 'connect', blocked))
        self.assertTrue(entered.wait(1))
        for _ in range(10000):
            self.assertFalse(self.jobs.submit(6, 'connect', blocked))
        self.release.set();self.jobs.shutdown()
        self.assertEqual(calls, [1])

    def test_distinct_nodes_can_progress(self):
        entered = threading.Event();other = threading.Event()
        self.jobs.submit(5, 'connect', lambda: (entered.set(), self.release.wait(3)))
        self.assertTrue(entered.wait(1))
        self.jobs.submit(3, 'connect', other.set)
        self.assertTrue(other.wait(1))

    def test_only_latest_restart_config_is_kept(self):
        entered = threading.Event();calls = []
        self.jobs.submit(6, 'connect', lambda: (entered.set(), self.release.wait(3)))
        self.assertTrue(entered.wait(1))
        for i in range(1000):self.jobs.submit(6, 'restart', calls.append, i)
        self.release.set();self.jobs.shutdown()
        self.assertEqual(calls, [999])

    def test_connect_cannot_replace_pending_restart(self):
        entered = threading.Event();calls = []
        self.jobs.submit(6, 'connect', lambda: (entered.set(), self.release.wait(3)))
        self.assertTrue(entered.wait(1))
        self.jobs.submit(6, 'restart', calls.append, 'latest')
        for _ in range(100):self.jobs.submit(6, 'connect', calls.append, 'unwanted')
        self.release.set();self.jobs.shutdown();self.assertEqual(calls, ['latest'])

    def test_worker_limit_is_global(self):
        lock = threading.Lock();active = [0];maximum = [0]
        def work():
            with lock:active[0] += 1;maximum[0] = max(maximum[0], active[0])
            self.release.wait(1)
            with lock:active[0] -= 1
        for key in range(20):self.jobs.submit(key, 'connect', work)
        self.release.set();self.jobs.shutdown();self.assertLessEqual(maximum[0], 2)

    def test_failed_callback_does_not_pin_node(self):
        done = threading.Event()
        def fail():done.set();raise ConnectionError('simulated')
        self.jobs.submit(6, 'connect', fail);self.assertTrue(done.wait(1))
        self.jobs.shutdown()
        self.assertNotIn(6, self.jobs._running)

    def test_executor_failure_does_not_pin_node(self):
        executor = types.SimpleNamespace(submit=lambda *a: (_ for _ in ()).throw(RuntimeError('cannot start')))
        jobs = jobs_module.NodeJobs(executor=executor, logger=self.log)
        with self.assertRaises(RuntimeError):jobs.submit(6, 'connect', lambda: None)
        self.assertNotIn(6, jobs._running)

    def test_completion_resubmission_never_overlaps_same_node(self):
        lock = threading.Lock();active = [0];overlap = [False];calls = [0]
        def work():
            with lock:
                active[0] += 1;overlap[0] |= active[0] > 1;calls[0] += 1
            time.sleep(.0001)
            with lock:active[0] -= 1
        def submit():
            for _ in range(2000):self.jobs.submit(6, 'connect', work)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(lambda _:submit(), range(8)))
        self.jobs.shutdown();self.assertFalse(overlap[0]);self.assertGreater(calls[0], 0)

    def test_tls_prefetch_has_real_socket_deadline(self):
        listener = socket.socket();listener.bind(('127.0.0.1', 0));listener.listen(1)
        accepted = [];stop = threading.Event()
        def server():
            conn, _ = listener.accept();accepted.append(conn);stop.wait(2);conn.close()
        thread = threading.Thread(target=server, daemon=True);thread.start()
        namespace={'ssl':ssl,'NODE_CONNECT_TIMEOUT':.15}
        load_function(ROOT/'app/xray/node.py','verified_node_certificate',namespace)
        method = load_function(ROOT/'app/xray/node.py', 'connect', namespace, 'ReSTXRayNode')
        obj = types.SimpleNamespace(address='127.0.0.1', port=listener.getsockname()[1])
        start = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):method(obj)
            self.assertLess(time.monotonic()-start, .8)
        finally:stop.set();listener.close();thread.join(2)

    def test_disabled_node_does_not_reconnect(self):
        class DB:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        env={'_connecting_nodes':{},'GetDB':DB,'crud':types.SimpleNamespace(get_node_by_id=lambda db,id:types.SimpleNamespace(status='disabled')),
             'NodeStatus':types.SimpleNamespace(disabled='disabled')}
        fn=load_function(ROOT/'app/xray/operations.py','_connect_node',env)
        self.assertIsNone(fn(6))

    def test_restart_reconnects_in_same_worker(self):
        class DB:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        calls=[]
        env={'GetDB':DB,'crud':types.SimpleNamespace(get_node_by_id=lambda db,id:types.SimpleNamespace(status='error',id=id)),
             'NodeStatus':types.SimpleNamespace(disabled='disabled'),'xray':types.SimpleNamespace(nodes={6:types.SimpleNamespace(connected=False)}),
             '_connect_node':lambda *args:calls.append(args)}
        fn=load_function(ROOT/'app/xray/operations.py','_restart_node',env);fn(6,{'latest':True})
        self.assertEqual(calls,[(6,{'latest':True})])

    def test_one_node_failure_does_not_skip_other_nodes(self):
        calls=[]
        class Broken:
            @property
            def connected(self):raise ConnectionError('simulated node outage')
        healthy=types.SimpleNamespace(connected=True,started=True,api=types.SimpleNamespace(get_sys_stats=lambda timeout:calls.append('healthy')))
        xray=types.SimpleNamespace(core=types.SimpleNamespace(started=True),nodes={5:Broken(),3:healthy},
          operations=types.SimpleNamespace(connect_node=lambda *args:calls.append('retry'),restart_node=lambda *args:None))
        env={'xray':xray,'logger':self.log,'xray_exc':types.SimpleNamespace(XrayError=RuntimeError)}
        fn=load_function(ROOT/'app/jobs/0_xray_core.py','core_health_check',env);fn()
        self.assertEqual(calls,['retry','healthy'])


if __name__ == '__main__':unittest.main()
