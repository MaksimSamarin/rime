from functools import lru_cache
import threading
from typing import TYPE_CHECKING

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text

from app import logger, xray
from app.db import GetDB, crud
from app.models.node import NodeStatus
from app.models.user import UserResponse
from app.utils.concurrency import threaded_function
from app.utils.node_jobs import NodeJobs
from app.xray.node import XRayNode, ReSTXRayNode, RPyCXRayNode, _node_control_options
from xray_api import XRay as XRayAPI
from xray_api.types.account import Account, XTLSFlows
from hy2bridge.access import allows, filter_config
from hy2bridge.native_users import supports_inbound

if TYPE_CHECKING:
    from app.db import User as DBUser
    from app.db.models import Node as DBNode

NODE_LIFECYCLE_LOCK=threading.RLock()
_node_jobs = NodeJobs(logger=logger)


@lru_cache(maxsize=None)
def get_tls():
    from app.db import GetDB, get_tls_certificate
    with GetDB() as db:
        tls = get_tls_certificate(db)
        return {
            "key": tls.key,
            "certificate": tls.certificate
        }


@threaded_function
def _add_user_to_inbound(api: XRayAPI, inbound_tag: str, account: Account):
    with api.control_lock:
        if getattr(api, 'retired', False):
            return
        try:
            api.add_inbound_user(tag=inbound_tag, user=account, timeout=30)
        except (xray.exc.EmailExistsError, xray.exc.ConnectionError):
            pass


@threaded_function
def _remove_user_from_inbound(api: XRayAPI, inbound_tag: str, email: str):
    with api.control_lock:
        if getattr(api, 'retired', False):
            return
        try:
            api.remove_inbound_user(tag=inbound_tag, email=email, timeout=30)
        except (xray.exc.EmailNotFoundError, xray.exc.ConnectionError):
            pass


@threaded_function
def _alter_inbound_user(api: XRayAPI, inbound_tag: str, account: Account):
    with api.control_lock:
        if getattr(api, 'retired', False):
            return
        try:
            api.remove_inbound_user(tag=inbound_tag, email=account.email, timeout=30)
        except (xray.exc.EmailNotFoundError, xray.exc.ConnectionError):
            pass
        try:
            api.add_inbound_user(tag=inbound_tag, user=account, timeout=30)
        except (xray.exc.EmailExistsError, xray.exc.ConnectionError):
            pass


def add_user(dbuser: "DBUser"):
    user = UserResponse.model_validate(dbuser)
    email = f"{dbuser.id}.{dbuser.username}"

    for proxy_type, inbound_tags in user.inbounds.items():
        for inbound_tag in inbound_tags:
            inbound = xray.config.inbounds_by_tag.get(inbound_tag, {})

            try:
                proxy_settings = user.proxies[proxy_type].dict(no_obj=True)
            except KeyError:
                pass
            account = proxy_type.account_model(email=email, **proxy_settings)

            # XTLS currently only supports transmission methods of TCP and mKCP
            if getattr(account, 'flow', None) and (
                inbound.get('network', 'tcp') not in ('tcp', 'kcp')
                or
                (
                    inbound.get('network', 'tcp') in ('tcp', 'kcp')
                    and
                    inbound.get('tls') not in ('tls', 'reality')
                )
                or
                inbound.get('header_type') == 'http'
            ):
                account.flow = XTLSFlows.NONE

            if allows(dbuser.id, 'xray:local'):
                _add_user_to_inbound(xray.api, inbound_tag, account)
            for node_id, node in list(xray.nodes.items()):
                if node.connected and node.started and supports_inbound(node, inbound_tag) and allows(dbuser.id, 'xray:'+str(node_id)):
                    _add_user_to_inbound(node.api, inbound_tag, account)


def remove_user(dbuser: "DBUser"):
    email = f"{dbuser.id}.{dbuser.username}"

    for inbound_tag in xray.config.inbounds_by_tag:
        _remove_user_from_inbound(xray.api, inbound_tag, email)
        for node in list(xray.nodes.values()):
            if node.connected and node.started and supports_inbound(node, inbound_tag):
                _remove_user_from_inbound(node.api, inbound_tag, email)


def update_user(dbuser: "DBUser"):
    user = UserResponse.model_validate(dbuser)
    email = f"{dbuser.id}.{dbuser.username}"

    active_inbounds = []
    for proxy_type, inbound_tags in user.inbounds.items():
        for inbound_tag in inbound_tags:
            active_inbounds.append(inbound_tag)
            inbound = xray.config.inbounds_by_tag.get(inbound_tag, {})

            try:
                proxy_settings = user.proxies[proxy_type].dict(no_obj=True)
            except KeyError:
                pass
            account = proxy_type.account_model(email=email, **proxy_settings)

            # XTLS currently only supports transmission methods of TCP and mKCP
            if getattr(account, 'flow', None) and (
                inbound.get('network', 'tcp') not in ('tcp', 'kcp')
                or
                (
                    inbound.get('network', 'tcp') in ('tcp', 'kcp')
                    and
                    inbound.get('tls') not in ('tls', 'reality')
                )
                or
                inbound.get('header_type') == 'http'
            ):
                account.flow = XTLSFlows.NONE

            if allows(dbuser.id, 'xray:local'):
                _alter_inbound_user(xray.api, inbound_tag, account)
            else:
                _remove_user_from_inbound(xray.api, inbound_tag, email)
            for node_id, node in list(xray.nodes.items()):
                if node.connected and node.started and supports_inbound(node, inbound_tag):
                    if allows(dbuser.id, 'xray:'+str(node_id)):
                        _alter_inbound_user(node.api, inbound_tag, account)
                    else:
                        _remove_user_from_inbound(node.api, inbound_tag, email)

    for inbound_tag in xray.config.inbounds_by_tag:
        if inbound_tag in active_inbounds:
            continue
        # remove disabled inbounds
        _remove_user_from_inbound(xray.api, inbound_tag, email)
        for node in list(xray.nodes.values()):
            if node.connected and node.started and supports_inbound(node, inbound_tag):
                _remove_user_from_inbound(node.api, inbound_tag, email)


def remove_node(node_id: int, stop=True):
    with NODE_LIFECYCLE_LOCK:return _remove_node(node_id, stop=stop)


def _remove_node(node_id: int, stop=True):
    if node_id in xray.nodes:
        if stop:
            try:xray.nodes[node_id].stop()
            except Exception:pass
        try:
            node = xray.nodes[node_id]
            close = getattr(node, 'close', node.disconnect)
            close()
        except Exception:
            pass
        finally:
            try:
                del xray.nodes[node_id]
            except KeyError:
                pass


def add_node(dbnode: "DBNode"):
    previous=xray.nodes.get(dbnode.id)
    protocol=None
    if previous:
        if isinstance(previous,ReSTXRayNode):protocol='rest'
        elif isinstance(previous,RPyCXRayNode):protocol='rpyc'
    tls = get_tls()
    try:
        with GetDB() as db:
            managed = db.execute(text('SELECT 1 FROM fleet_managed WHERE native_id=:node_id'),
                                 {'node_id': dbnode.id}).first() is not None
    except SQLAlchemyError:
        managed = False
    configured=_node_control_options(dbnode.address).get('protocol')
    options = {'protocol': configured or ('rest' if managed else protocol)}
    address, service_port, api_port = _management_endpoint(dbnode)
    from hy2bridge.native_trust import client_options
    options.update(client_options(dbnode))
    remove_node(dbnode.id, stop=False)
    xray.nodes[dbnode.id] = XRayNode(address=address,
                                     port=service_port,
                                     api_port=api_port,
                                     ssl_key=tls['key'],
                                     ssl_cert=tls['certificate'],
                                     usage_coefficient=dbnode.usage_coefficient,control_address=dbnode.address,
                                     control_api_port=dbnode.api_port, **options)

    return xray.nodes[dbnode.id]


def _management_endpoint(dbnode):
    from hy2bridge.relay_routes import management
    return management('xray:' + str(dbnode.id), dbnode.address, dbnode.port, dbnode.api_port)


def _node_endpoint_matches(node, dbnode):
    current = (getattr(node, 'address', None), getattr(node, 'port', None), getattr(node, 'api_port', None))
    identity = (getattr(node, 'control_address', dbnode.address),
                getattr(node, 'control_api_port', dbnode.api_port), node.usage_coefficient)
    expected_identity = (dbnode.address, dbnode.api_port, dbnode.usage_coefficient)
    return current == _management_endpoint(dbnode) and identity == expected_identity


def _change_node_status(node_id: int, status: NodeStatus, message: str = None, version: str = None):
    with GetDB() as db:
        try:
            dbnode = crud.get_node_by_id(db, node_id)
            if not dbnode:
                return

            if dbnode.status == NodeStatus.disabled:
                remove_node(dbnode.id)
                return

            crud.update_node_status(db, dbnode, status, message, version)
        except SQLAlchemyError:
            db.rollback()


global _connecting_nodes
_connecting_nodes = {}


def connect_node(node_id, config=None, refresh_endpoint=False):
    return _node_jobs.submit(node_id, "connect", _connect_node_locked, node_id, config,
                             replace_connect=refresh_endpoint)


def _connect_node_locked(node_id, config=None):
    with NODE_LIFECYCLE_LOCK:
        return _connect_node(node_id, config)


def _connect_node(node_id, config=None):
    global _connecting_nodes

    if _connecting_nodes.get(node_id):
        return

    with GetDB() as db:
        dbnode = crud.get_node_by_id(db, node_id)

    if not dbnode or dbnode.status == NodeStatus.disabled:
        return

    try:
        node = xray.nodes[dbnode.id]
        if not _node_endpoint_matches(node, dbnode):
            raise ConnectionError('Node management endpoint changed')
        assert node.connected
    except (KeyError, AssertionError, ConnectionError, TimeoutError, OSError):
        try:node = xray.operations.add_node(dbnode)
        except Exception as error:
            _change_node_status(node_id,NodeStatus.error,message=str(error))
            logger.info(f'Unable to establish trusted management of node {node_id}')
            return

    try:
        _connecting_nodes[node_id] = True

        _change_node_status(node_id, NodeStatus.connecting)
        logger.info(f"Connecting to \"{dbnode.name}\" node")

        refresh_users = config is None
        if config is None:
            config = xray.config.include_db_users()

        node.start(filter_config(config, 'xray:'+str(node_id)))
        if refresh_users and getattr(node, '_user_reconcile', False):
            # User changes committed while the replacement was starting may
            # have skipped its unavailable API. Re-read after it is usable.
            with node.api.control_lock:
                node.start(filter_config(xray.config.include_db_users(), 'xray:'+str(node_id)))
        import time
        node.observed_health = (time.monotonic(), True)
        version = node.get_version()
        _change_node_status(node_id, NodeStatus.connected, version=version)
        logger.info(f"Connected to \"{dbnode.name}\" node, xray run on v{version}")

    except Exception as e:
        _change_node_status(node_id, NodeStatus.error, message=str(e))
        logger.info(f"Unable to connect to \"{dbnode.name}\" node")

    finally:
        try:
            del _connecting_nodes[node_id]
        except KeyError:
            pass


def restart_node(node_id, config=None):
    return _node_jobs.submit(node_id, "restart", _restart_node_locked, node_id, config)


def _restart_node_locked(node_id, config=None):
    with NODE_LIFECYCLE_LOCK:
        return _restart_node(node_id, config)


def _restart_node(node_id, config=None):
    with GetDB() as db:
        dbnode = crud.get_node_by_id(db, node_id)

    if not dbnode or dbnode.status == NodeStatus.disabled:
        return

    try:
        node = xray.nodes[dbnode.id]
        if not _node_endpoint_matches(node, dbnode):
            raise ConnectionError('Node management endpoint changed')
    except (KeyError, ConnectionError):
        try:node = xray.operations.add_node(dbnode)
        except Exception as error:
            _change_node_status(node_id,NodeStatus.error,message=str(error))
            logger.info(f'Unable to establish trusted management of node {node_id}')
            return

    if not node.connected:
        return _connect_node(node_id, config)

    try:
        logger.info(f"Restarting Xray core of \"{dbnode.name}\" node")

        if config is None:
            config = xray.config.include_db_users()

        node.restart(filter_config(config, 'xray:'+str(node_id)))
        if getattr(node,'_user_reconcile',False):
            with node.api.control_lock:
                # Callers pass an already populated startup snapshot. Read the
                # current base again, including commits made during restart.
                latest=xray.config.include_db_users()
                node.start(filter_config(latest,'xray:'+str(node_id)))
        logger.info(f"Xray core of \"{dbnode.name}\" node restarted")
    except Exception as e:
        _change_node_status(node_id, NodeStatus.error, message=str(e))
        logger.info(f"Unable to restart node {node_id}")
        try:
            node.disconnect()
        except Exception:
            pass


__all__ = [
    "add_user",
    "remove_user",
    "add_node",
    "remove_node",
    "connect_node",
    "restart_node",
]
