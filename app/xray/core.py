import atexit
import re
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager

from app import logger
from app.xray.config import XRayConfig
from app.xray.api_security import hub_api_endpoint
from config import DEBUG


class XRayCore:
    def __init__(self,
                 executable_path: str = "/usr/bin/xray",
                 assets_path: str = "/usr/share/xray"):
        self.executable_path = executable_path
        self.assets_path = assets_path

        self.version = self.get_version()
        self.process = None
        self.restarting = False

        self._logs_buffer = deque(maxlen=100)
        self._temp_log_buffers = {}
        self._on_start_funcs = []
        self._on_stop_funcs = []
        self._env = {
            "XRAY_LOCATION_ASSET": assets_path
        }

        atexit.register(lambda: self.stop() if self.started else None)

    def get_version(self):
        cmd = [self.executable_path, "version"]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8')
        m = re.match(r'^Xray (\d+\.\d+\.\d+)', output)
        if m:
            return m.groups()[0]

    def get_x25519(self, private_key: str = None):
        from base64 import b64decode, urlsafe_b64encode
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        if private_key:
            try:
                raw=b64decode(private_key+'='*(-len(private_key)%4),altchars=b'-_',validate=True)
                key=X25519PrivateKey.from_private_bytes(raw)
            except (ValueError,TypeError) as error:
                raise ValueError('Invalid REALITY private key') from error
        else:
            key=X25519PrivateKey.generate()
        private=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
        public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        return {'private_key':urlsafe_b64encode(private).decode().rstrip('='),
                'public_key':urlsafe_b64encode(public).decode().rstrip('=')}

    def __capture_process_logs(self):
        process = self.process
        def capture_and_debug_log():
            while process:
                output = process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)
                    logger.debug(output)

                elif process.poll() is not None:
                    break

        def capture_only():
            while process:
                output = process.stdout.readline()
                if output:
                    output = output.strip()
                    self._logs_buffer.append(output)
                    for buf in list(self._temp_log_buffers.values()):
                        buf.append(output)

                elif process.poll() is not None:
                    break

        if DEBUG:
            threading.Thread(target=capture_and_debug_log).start()
        else:
            threading.Thread(target=capture_only).start()

    @contextmanager
    def get_logs(self):
        buf = deque(self._logs_buffer, maxlen=100)
        buf_id = id(buf)
        try:
            self._temp_log_buffers[buf_id] = buf
            yield buf
        finally:
            del self._temp_log_buffers[buf_id]
            del buf

    @property
    def started(self):
        if not self.process:
            return False

        if self.process.poll() is None:
            return True

        return False

    def start(self, config: XRayConfig):
        from hy2bridge.access import filter_config
        config = filter_config(config, 'xray:local')
        if self.started is True:
            raise RuntimeError("Xray is started already")

        hub_api_endpoint().prepare()

        if config.get('log', {}).get('logLevel') in ('none', 'error'):
            config['log']['logLevel'] = 'warning'

        cmd = [
            self.executable_path,
            "run",
            '-config',
            'stdin:'
        ]
        self.process = subprocess.Popen(
            cmd,
            env=self._env,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True
        )
        self.process.stdin.write(config.to_json())
        self.process.stdin.flush()
        self.process.stdin.close()
        # Older cores can accept a Unix-listener configuration but start no
        # listener. Never report success with an unavailable protected API.
        deadline = time.monotonic()+5
        while not hub_api_endpoint().path.exists():
            if self.process.poll() is not None or time.monotonic()>=deadline:
                self.stop()
                raise RuntimeError('The protected Unix API did not start; use the qualified Xray runtime')
            time.sleep(.05)
        logger.warning(f"Xray core {self.version} started")

        self.__capture_process_logs()

        # execute on start functions
        for func in self._on_start_funcs:
            threading.Thread(target=func).start()

    def stop(self):
        if not self.started:
            return

        process = self.process
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if self.process is process:
            self.process = None
        logger.warning("Xray core stopped")

        # execute on stop functions
        for func in self._on_stop_funcs:
            threading.Thread(target=func).start()

    def restart(self, config: XRayConfig):
        if self.restarting is True:
            return

        try:
            self.restarting = True
            logger.warning("Restarting Xray core...")
            self.stop()
            self.start(config)
        finally:
            self.restarting = False

    def on_start(self, func: callable):
        self._on_start_funcs.append(func)
        return func

    def on_stop(self, func: callable):
        self._on_stop_funcs.append(func)
        return func
