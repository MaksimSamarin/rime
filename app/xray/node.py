import socket
import hashlib
import json
import os
import re
import ssl
import tempfile
import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import List

import grpc
import requests
import rpyc
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from websocket import WebSocketConnectionClosedException, WebSocketTimeoutException, create_connection

from app.xray.config import XRayConfig
from xray_api.routing import protect_balancers as _protect_balancers
from xray_api import XRay as XRayAPI
from xray_api.base import control_lock
from hy2bridge.native_trust import match_certificate

NODE_CONNECT_TIMEOUT = 5
NODE_RPC_TIMEOUT = 15


def _node_control_options(address):
    try:
        options = json.loads(os.environ.get("RIME_NODE_CONTROL_OVERRIDES", "{}"))
    except (TypeError, ValueError):
        return {}
    if not isinstance(options, dict):
        return {}
    value = options.get(address, {})
    return value if isinstance(value, dict) else {}


def _control_timeout(address, default, key="timeout"):
    options = _node_control_options(address)
    value = options.get(key, options.get("timeout", default))
    if type(value) not in (int, float) or not 1 <= value <= 60:
        return default
    return max(default, value)


def _control_failure_threshold(address):
    value = _node_control_options(address).get("health_failures", 1)
    return value if type(value) is int and 1 <= value <= 10 else 1



def string_to_temp_file(content: str):
    file = tempfile.NamedTemporaryFile(mode='w+t')
    file.write(content)
    file.flush()
    return file


def verified_node_certificate(node):
    observed=ssl.get_server_certificate((node.address,node.port),
        timeout=_control_timeout(getattr(node,'control_address',node.address),NODE_CONNECT_TIMEOUT))
    verifier=getattr(node,'_certificate_verifier',None)
    if verifier is not None:
        return verifier(observed)
    return match_certificate(getattr(node,'_trusted_server_certificate',None),observed)


def initialize_api_transport(node,mutual_tls):
    """Reuse the physical API transport while its endpoint and identity are stable."""
    physical=(getattr(node,'control_address',node.address),getattr(node,'control_api_port',node.api_port))
    def digest(value):
        value=value.encode() if isinstance(value,str) else value
        return hashlib.sha256(value or b'').hexdigest()
    identity=(node.address,node.api_port,physical,bool(mutual_tls),digest(node._node_cert),
              digest(node.ssl_key) if mutual_tls else None,digest(node.ssl_cert) if mutual_tls else None)
    with control_lock(*physical):
        previous=getattr(node,'_api',None)
        if (previous is not None and not getattr(previous,'retired',False)
                and getattr(node,'_api_transport_identity',None)==identity):
            try:previous.get_sys_stats(timeout=_control_timeout(physical[0],2))
            except Exception:pass
            else:return previous
        if previous is not None:
            previous.retired=True
            previous.usage_epoch=None
            try:previous._channel.close()
            finally:
                node._api=None
                node._api_transport_identity=None
        options={}
        if mutual_tls:options.update(ssl_key=node.ssl_key.encode(),client_cert=node.ssl_cert.encode())
        api=XRayAPI(address=node.address,port=node.api_port,ssl_cert=node._node_cert.encode(),
                    ssl_target_name='Gozargah',control_identity=physical,**options)
        node._api=api
        node._api_transport_identity=identity
        return api


class SANIgnoringAdaptor(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       assert_hostname=False)


class NodeAPIError(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail


def close_control_client(node):
    identity = (getattr(node, 'control_address', node.address),
                getattr(node, 'control_api_port', node.api_port))
    with control_lock(*identity):
        node._closed = True
        api = getattr(node, '_api', None)
        if api is not None:
            api.retired = True
        try:
            node.disconnect()
        finally:
            if api is not None:
                api.usage_epoch = None
                api._channel.close()
                node._api = None
            queues = getattr(node, '_logs_queues', None)
            if queues is not None:
                queues.clear()
            session = getattr(node, 'session', None)
            if session is not None:
                session.close()
            for name in ('_keyfile', '_certfile', '_node_certfile'):
                stream = getattr(node, name, None)
                if stream is not None:
                    stream.close()


class ReSTXRayNode:
    def __init__(self,
                 address: str,
                 port: int,
                 api_port: int,
                 ssl_key: str,
                 ssl_cert: str,
                 usage_coefficient: float = 1,
                 control_address: str | None = None,
                 control_api_port: int | None = None,
                 server_certificate: str | None = None,
                 certificate_verifier=None):

        self.address = address
        self.control_address = control_address or address
        self.control_api_port = control_api_port or api_port
        self._closed = False
        self._trusted_server_certificate = server_certificate
        self._certificate_verifier = certificate_verifier
        self.health_check_timeout = _control_timeout(getattr(self,"control_address",self.address), 2, "health_timeout")
        self.health_failure_threshold = _control_failure_threshold(self.control_address)
        self._health_failure_count = 0
        self.port = port
        self.api_port = api_port
        self.ssl_key = ssl_key
        self.ssl_cert = ssl_cert
        self.usage_coefficient = usage_coefficient

        self._keyfile = string_to_temp_file(ssl_key)
        self._certfile = string_to_temp_file(ssl_cert)

        self.session = requests.Session()
        self.session.trust_env = False
        self.session.mount('https://', SANIgnoringAdaptor())
        self.session.cert = (self._certfile.name, self._keyfile.name)

        self._session_id = None
        self._rest_api_url = f"https://{self.address.strip('/')}:{self.port}"

        self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_REQUIRED
        self._ssl_context.load_cert_chain(certfile=self.session.cert[0], keyfile=self.session.cert[1])
        self._logs_ws_url = f"wss://{self.address.strip('/')}:{self.port}/logs"
        self._logs_queues = []
        self._logs_bg_thread = threading.Thread(target=self._bg_fetch_logs, daemon=True)

        self._api = None
        self._started = False
        self._user_reconcile = False
        self._user_tags = []
        self._api_mtls = False
        self._api_direct = False
        self._management_sources = False
        self._stats_epoch = None

    def _prepare_config(self, config: XRayConfig):
        if not getattr(self,'_api_direct',False):
            _protect_balancers(config.setdefault('routing',{}),config.get('outbounds',[]))
        for inbound in config.get("inbounds", []):
            streamSettings = inbound.get("streamSettings") or {}
            tlsSettings = streamSettings.get("tlsSettings") or {}
            certificates = tlsSettings.get("certificates") or []
            for certificate in certificates:
                if certificate.get("certificateFile"):
                    with open(certificate['certificateFile']) as file:
                        certificate['certificate'] = [
                            line.strip() for line in file.readlines()
                        ]
                        del certificate['certificateFile']

                if certificate.get("keyFile"):
                    with open(certificate['keyFile']) as file:
                        certificate['key'] = [
                            line.strip() for line in file.readlines()
                        ]
                        del certificate['keyFile']

        return config

    def make_request(self, path: str, timeout: int, **params):
        timeout = _control_timeout(getattr(self,"control_address",self.address), timeout)
        try:
            res = self.session.post(self._rest_api_url + path, timeout=timeout,
                                    json={"session_id": self._session_id, **params})
            data = res.json()
        except Exception as e:
            exc = NodeAPIError(0, str(e))
            raise exc

        if res.status_code == 200:
            return data
        else:
            exc = NodeAPIError(res.status_code, data['detail'])
            raise exc

    @property
    def connected(self):
        if getattr(self, '_closed', False):
            return False
        if not self._session_id:
            return False
        try:
            self.make_request("/ping", timeout=3)
            return True
        except NodeAPIError:
            return False

    @property
    def started(self):
        res = self.make_request("/", timeout=3)
        return res.get('started', False)

    @property
    def api(self):
        if getattr(self, '_closed', False):
            raise ConnectionError('Node client has been retired')
        if not self._session_id:
            raise ConnectionError("Node is not connected")

        if not self._api:
            if self._started is True:
                self._api = initialize_api_transport(self,True)
            else:
                raise ConnectionError("Node is not started")

        self._api.usage_epoch = self._usage_epoch if self._api_mtls and self._stats_epoch is not None else None
        return self._api

    def _usage_epoch(self):
        status = self.make_request('/', timeout=3)
        epoch = status.get('stats_epoch')
        if status.get('api_mtls') != 1 or not isinstance(epoch, str) or not 1 <= len(epoch) <= 128:
            return None
        return epoch

    def connect(self):
        if getattr(self, '_closed', False):
            raise ConnectionError('Node client has been retired')
        self._node_cert = verified_node_certificate(self)
        previous=getattr(self,'_node_certfile',None)
        if previous is not None:previous.close()
        self._node_certfile = string_to_temp_file(self._node_cert)
        self.session.verify = self._node_certfile.name
        self._ssl_context.load_verify_locations(cadata=self._node_cert)

        res = self.make_request("/connect", timeout=3)
        self._session_id = res['session_id']
        self._started = res.get('started') is True
        self._user_reconcile = res.get('user_reconcile') == 1
        self._user_tags = res.get('user_tags', [])
        self._api_mtls = res.get('api_mtls') == 1
        self._api_direct = res.get('api_direct') == 1
        self._management_sources = res.get('management_sources') == 1
        self._stats_epoch = res.get('stats_epoch')

    def disconnect(self):
        self.make_request("/disconnect", timeout=3)
        self._session_id = None

    def close(self):
        close_control_client(self)

    def get_version(self):
        res = self.make_request("/", timeout=3)
        return res.get('core_version')

    def start(self, config: XRayConfig):
        lock=control_lock(getattr(self,'control_address',self.address),getattr(self,'control_api_port',self.api_port))
        if not lock.acquire(timeout=2):
            raise ConnectionError('Node user synchronization is busy; retry connection later')
        try:
            return self._start_locked(config)
        finally:
            lock.release()

    def _start_locked(self, config: XRayConfig):
        if not self.connected:
            self.connect()

        config = self._prepare_config(config)
        json_config = config.to_json()

        verified=False
        if self._user_reconcile:
            self._started=self.started
        if self._user_reconcile and self._started:
            from hy2bridge.native_users import reconcile
            from xray_api.types.account import VLESSAccount
            verified=reconcile(self.api,config,self._user_tags,VLESSAccount)
            if not verified:
                return self.restart(config)

        try:
            res = self.make_request("/start", timeout=10, config=json_config, users_verified=verified)
        except NodeAPIError as exc:
            if exc.detail == 'Xray is started already':
                return self.restart(config)
            else:
                raise exc

        self._started = True
        self._user_reconcile = res.get('user_reconcile') == 1
        self._user_tags = res.get('user_tags', [])
        self._api_mtls = res.get('api_mtls') == 1
        self._api_direct = res.get('api_direct') == 1
        self._management_sources = res.get('management_sources') == 1
        self._stats_epoch = res.get('stats_epoch')

        self._api = initialize_api_transport(self,True)
        self._api.usage_epoch = self._usage_epoch if self._api_mtls and self._stats_epoch is not None else None

        try:
            grpc.channel_ready_future(self._api._channel).result(timeout=_control_timeout(getattr(self,"control_address",self.address), 5))
            self._api.get_sys_stats(timeout=_control_timeout(getattr(self,'control_address',self.address),5))
        except grpc.FutureTimeoutError:
            raise ConnectionError('Failed to connect to node\'s API')

        return res

    def stop(self):
        if not self.connected:
            self.connect()

        self.make_request('/stop', timeout=5)
        self._api = None
        self._started = False

    def restart(self, config: XRayConfig):
        lock=control_lock(getattr(self,'control_address',self.address),getattr(self,'control_api_port',self.api_port))
        if not lock.acquire(timeout=2):
            raise ConnectionError('Node user synchronization is busy; retry restart later')
        try:
            return self._restart_locked(config)
        finally:
            lock.release()

    def _restart_locked(self, config: XRayConfig):
        if not self.connected:
            self.connect()

        config = self._prepare_config(config)
        json_config = config.to_json()

        res = self.make_request("/restart", timeout=10, config=json_config)

        self._started = True
        self._user_reconcile = res.get('user_reconcile') == 1
        self._user_tags = res.get('user_tags', [])
        self._api_mtls = res.get('api_mtls') == 1
        self._api_direct = res.get('api_direct') == 1
        self._management_sources = res.get('management_sources') == 1
        self._stats_epoch = res.get('stats_epoch')

        self._api = initialize_api_transport(self,True)
        self._api.usage_epoch = self._usage_epoch if self._api_mtls and self._stats_epoch is not None else None

        try:
            grpc.channel_ready_future(self._api._channel).result(timeout=_control_timeout(getattr(self,"control_address",self.address), 5))
            self._api.get_sys_stats(timeout=_control_timeout(getattr(self,'control_address',self.address),5))
        except grpc.FutureTimeoutError:
            raise ConnectionError('Failed to connect to node\'s API')

        return res

    def _bg_fetch_logs(self):
        while self._logs_queues:
            try:
                websocket_url = f"{self._logs_ws_url}?session_id={self._session_id}&interval=0.7"
                self._ssl_context.load_verify_locations(self.session.verify)
                ws = create_connection(websocket_url, sslopt={"context": self._ssl_context}, timeout=2,
                                       http_no_proxy=['*'])
                while self._logs_queues:
                    try:
                        logs = ws.recv()
                        for buf in self._logs_queues:
                            buf.append(logs)
                    except WebSocketConnectionClosedException:
                        break
                    except WebSocketTimeoutException:
                        pass
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(2)

    @contextmanager
    def get_logs(self):
        try:
            buf = deque(maxlen=100)
            self._logs_queues.append(buf)

            if not self._logs_bg_thread.is_alive():
                try:
                    self._logs_bg_thread.start()
                except RuntimeError:
                    self._logs_bg_thread = threading.Thread(target=self._bg_fetch_logs, daemon=True)
                    self._logs_bg_thread.start()

            yield buf

        finally:
            try:
                self._logs_queues.remove(buf)
            except ValueError:
                pass
            del buf


class RPyCXRayNode:
    def __init__(self,
                 address: str,
                 port: int,
                 api_port: int,
                 ssl_key: str,
                 ssl_cert: str,
                 usage_coefficient: float = 1,
                 control_address: str | None = None,
                 control_api_port: int | None = None,
                 server_certificate: str | None = None,
                 certificate_verifier=None):

        class Service(rpyc.Service):
            def __init__(self,
                         on_start_funcs: List[callable] | None = None,
                         on_stop_funcs: List[callable] | None = None):
                self.on_start_funcs = list(on_start_funcs or [])
                self.on_stop_funcs = list(on_stop_funcs or [])

            def exposed_on_start(self):
                for func in self.on_start_funcs:
                    threading.Thread(target=func).start()

            def exposed_on_stop(self):
                for func in self.on_stop_funcs:
                    threading.Thread(target=func).start()

            def add_startup_func(self, func):
                self.on_start_funcs.append(func)

            def add_shutdown_func(self, func):
                self.on_stop_funcs.append(func)

            def on_connect(self, conn):
                pass

            def on_disconnect(self, conn):
                pass

        self.address = address
        self.control_address = control_address or address
        self.control_api_port = control_api_port or api_port
        self.health_check_timeout = _control_timeout(getattr(self,"control_address",self.address), 2, "health_timeout")
        self.health_failure_threshold = _control_failure_threshold(self.control_address)
        self._health_failure_count = 0
        self.port = port
        self.api_port = api_port
        self.ssl_key = ssl_key
        self.ssl_cert = ssl_cert
        self.usage_coefficient = usage_coefficient

        self._closed = False
        self._trusted_server_certificate = server_certificate
        self._certificate_verifier = certificate_verifier
        self.started = False

        self._keyfile = string_to_temp_file(ssl_key)
        self._certfile = string_to_temp_file(ssl_cert)

        self._service = Service()
        self._api = None
        self._user_reconcile = False
        self._user_tags = []
        self._api_mtls = False
        self._api_direct = False
        self._management_sources = False
        self._stats_epoch = None

    def disconnect(self):
        if getattr(self, '_closed', False):
            connection = self.__dict__.pop('connection', None)
            if connection is not None:
                connection._channel.close()
            return
        try:
            self.connection.close()
            del self.connection
        except AttributeError:
            pass

    def close(self):
        close_control_client(self)

    def connect(self):
        if getattr(self, '_closed', False):
            raise ConnectionError('Node client has been retired')
        self.disconnect()

        tries = 0
        while True:
            tries += 1
            self._node_cert = verified_node_certificate(self)
            previous=getattr(self,'_node_certfile',None)
            if previous is not None:previous.close()
            self._node_certfile = string_to_temp_file(self._node_cert)
            stream = rpyc.SocketStream.ssl_connect(
                self.address, self.port,
                {"keyfile": self._keyfile.name,
                 "certfile": self._certfile.name,
                 "ca_certs": self._node_certfile.name,
                 "cert_reqs": ssl.CERT_REQUIRED,
                 "check_hostname": False},
                keepalive=True, timeout=_control_timeout(getattr(self,"control_address",self.address), NODE_CONNECT_TIMEOUT))
            try:
                conn = rpyc.connect_stream(
                    stream, service=self._service,
                    config={"sync_request_timeout": NODE_RPC_TIMEOUT})
            except BaseException:
                stream.close()
                raise
            try:
                conn.ping()
                self.connection = conn
                break
            except EOFError as exc:
                if tries <= 3:
                    continue
                raise exc

    @property
    def connected(self):
        if getattr(self, '_closed', False):
            return False
        try:
            self.connection.ping()
            return (not self.connection.closed)
        except (AttributeError, EOFError, TimeoutError):
            self.disconnect()
            return False

    @property
    def remote(self):
        if not self.connected:
            self.connect()
        return self.connection.root

    @property
    def api(self):
        if getattr(self, '_closed', False):
            raise ConnectionError('Node client has been retired')
        if not self.connected:
            raise ConnectionError("Node is not connected")

        if not self.started:
            raise ConnectionError("Node is not started")

        return self._api

    def get_version(self):
        return self.remote.fetch_xray_version()

    def _prepare_config(self, config: XRayConfig):
        if not getattr(self,'_api_direct',False):
            _protect_balancers(config.setdefault('routing',{}),config.get('outbounds',[]))
        for inbound in config.get("inbounds", []):
            streamSettings = inbound.get("streamSettings") or {}
            tlsSettings = streamSettings.get("tlsSettings") or {}
            certificates = tlsSettings.get("certificates") or []
            for certificate in certificates:
                if certificate.get("certificateFile"):
                    with open(certificate['certificateFile']) as file:
                        certificate['certificate'] = [
                            line.strip() for line in file.readlines()
                        ]
                        del certificate['certificateFile']

                if certificate.get("keyFile"):
                    with open(certificate['keyFile']) as file:
                        certificate['key'] = [
                            line.strip() for line in file.readlines()
                        ]
                        del certificate['keyFile']

        return config

    def start(self, config: XRayConfig):
        lock=control_lock(self.control_address,self.control_api_port)
        if not lock.acquire(timeout=2):
            raise ConnectionError('Node user synchronization is busy; retry connection later')
        try:
            return self._start_locked(config)
        finally:
            lock.release()

    def _start_locked(self, config: XRayConfig):
        capabilities = self._capabilities()
        config = self._prepare_config(config)
        json_config = config.to_json()
        if capabilities.get('user_reconcile') == 1:
            self.remote.claim(capabilities.get('owner'))
        verified = False
        if capabilities.get('started') and capabilities.get('user_reconcile') == 1:
            self.started = True
            self._initialize_api(capabilities)
            grpc.channel_ready_future(self._api._channel).result(
                timeout=_control_timeout(self.control_address, 5))
            self._api.get_sys_stats(timeout=_control_timeout(getattr(self,'control_address',self.address),5))
            from hy2bridge.native_users import reconcile
            from xray_api.types.account import VLESSAccount
            verified = reconcile(self.api, config, capabilities.get('user_tags', []), VLESSAccount)
            if not verified:
                self.remote.restart(json_config)
        if verified:
            self.remote.start(json_config, users_verified=True)
        elif not capabilities.get('started') or capabilities.get('user_reconcile') != 1:
            self.remote.start(json_config)
        self.started = True
        capabilities = self._capabilities()
        self._user_reconcile = capabilities.get('user_reconcile') == 1
        self._user_tags = capabilities.get('user_tags', [])
        self._initialize_api(capabilities)
        try:
            grpc.channel_ready_future(self._api._channel).result(timeout=_control_timeout(getattr(self,"control_address",self.address), 5))
            self._api.get_sys_stats(timeout=_control_timeout(getattr(self,'control_address',self.address),5))
        except grpc.FutureTimeoutError:

            start_time = time.time()
            end_time = start_time + 3  # check logs for 3 seconds
            last_log = ''
            with self.get_logs() as logs:
                while time.time() < end_time:
                    if logs:
                        last_log = logs[-1].strip().split('\n')[-1]
                    time.sleep(0.1)

            self.disconnect()

            if re.search(r'[Ff]ailed', last_log):
                raise RuntimeError(last_log)

            raise ConnectionError('Failed to connect to node\'s API')

    def _capabilities(self):
        try:
            method = self.remote.capabilities
        except AttributeError:
            self._api_mtls = False
            self._api_direct = False
            self._management_sources = False
            self._stats_epoch = None
            return {}
        raw = method()
        if not isinstance(raw, str) or len(raw) > 1024 * 1024:
            raise ConnectionError('Node capability response is invalid')
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            raise ConnectionError('Node capability response is invalid') from None
        if not isinstance(value, dict):
            raise ConnectionError('Node capability response is invalid')
        self._api_mtls = value.get('api_mtls') == 1
        self._api_direct = value.get('api_direct') == 1
        self._management_sources = value.get('management_sources') == 1
        epoch = value.get('stats_epoch')
        self._stats_epoch = epoch if isinstance(epoch,str) and 1 <= len(epoch) <= 128 else None
        return value

    def _usage_epoch(self):
        self._capabilities()
        return self._stats_epoch

    def _initialize_api(self, capabilities):
        options = {}
        if capabilities.get('api_mtls') == 1:
            options.update(ssl_key=self.ssl_key.encode(), client_cert=self.ssl_cert.encode())
        self._api = initialize_api_transport(self,capabilities.get('api_mtls') == 1)
        self._api.usage_epoch = self._usage_epoch if self._stats_epoch is not None else None

    def stop(self):
        self.remote.stop()
        self.started = False
        self._api = None

    def restart(self, config: XRayConfig):
        lock=control_lock(self.control_address,self.control_api_port)
        if not lock.acquire(timeout=2):
            raise ConnectionError('Node user synchronization is busy; retry restart later')
        try:
            return self._restart_locked(config)
        finally:
            lock.release()

    def _restart_locked(self, config: XRayConfig):
        capabilities = self._capabilities()
        config = self._prepare_config(config)
        json_config = config.to_json()
        if capabilities.get('user_reconcile') == 1:
            self.remote.claim(capabilities.get('owner'))
        self.remote.restart(json_config)
        self.started = True
        self._initialize_api(self._capabilities())
        try:
            grpc.channel_ready_future(self._api._channel).result(timeout=_control_timeout(self.control_address,5))
            self._api.get_sys_stats(timeout=_control_timeout(getattr(self,'control_address',self.address),5))
        except grpc.FutureTimeoutError:
            raise ConnectionError("Failed to reconnect to the restarted node's API") from None

    @contextmanager
    def get_logs(self):
        if not self.connected:
            raise ConnectionError("Node is not connected")

        try:
            self.__curr_logs
        except AttributeError:
            self.__curr_logs = 0

        try:
            buf = deque(maxlen=100)

            if self.__curr_logs <= 0:
                self.__curr_logs = 1
                self.__bgsrv = rpyc.BgServingThread(self.connection)
            else:
                if not self.__bgsrv._active:
                    self.__bgsrv = rpyc.BgServingThread(self.connection)
                self.__curr_logs += 1

            logs = self.remote.fetch_logs(buf.append)
            yield buf

        finally:
            if self.__curr_logs <= 1:
                self.__curr_logs = 0
                self.__bgsrv.stop()
            else:
                if not self.__bgsrv._active:
                    self.__bgsrv = rpyc.BgServingThread(self.connection)
                self.__curr_logs -= 1

            if logs:
                logs.stop()

    def on_start(self, func: callable):
        self._service.add_startup_func(func)
        return func

    def on_stop(self, func: callable):
        self._service.add_shutdown_func(func)
        return func


class XRayNode:
    def __new__(self,
                address: str,
                port: int,
                api_port: int,
                ssl_key: str,
                ssl_cert: str,
                usage_coefficient: float = 1,
                protocol: str | None = None,
                control_address: str | None = None,
                control_api_port: int | None = None,
                server_certificate: str | None = None,
                certificate_verifier=None):

        protocol = protocol or _node_control_options(control_address or address).get("protocol")
        if protocol in ("rest", "rpyc"):
            implementation = ReSTXRayNode if protocol == "rest" else RPyCXRayNode
            return implementation(address=address, port=port, api_port=api_port,
                                  ssl_key=ssl_key, ssl_cert=ssl_cert,
                                  usage_coefficient=usage_coefficient,control_address=control_address,
                                  control_api_port=control_api_port,server_certificate=server_certificate,
                                  certificate_verifier=certificate_verifier)

        # trying to detect what's the server of node
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((address, port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            s.recv(1024)
            s.close()
            # it might be uvicorn
            return ReSTXRayNode(
                address=address,
                port=port,
                api_port=api_port,
                ssl_key=ssl_key,
                ssl_cert=ssl_cert,
                usage_coefficient=usage_coefficient,
                control_address=control_address,
                control_api_port=control_api_port,server_certificate=server_certificate,
                certificate_verifier=certificate_verifier
            )
        except Exception:
            # if might be rpyc
            return RPyCXRayNode(
                address=address,
                port=port,
                api_port=api_port,
                ssl_key=ssl_key,
                ssl_cert=ssl_cert,
                usage_coefficient=usage_coefficient,
                control_address=control_address,
                control_api_port=control_api_port,server_certificate=server_certificate,
                certificate_verifier=certificate_verifier
            )
