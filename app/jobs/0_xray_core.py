import time
import traceback

from app import app, logger, scheduler, xray
from app.db import GetDB, crud
from app.models.node import NodeStatus
from config import JOB_CORE_HEALTH_CHECK_INTERVAL
from xray_api import exc as xray_exc


def _defer_health_recovery(node):
    threshold = getattr(node, "health_failure_threshold", 1)
    node._health_failure_count = getattr(node, "_health_failure_count", 0) + 1
    if node._health_failure_count < threshold:
        return True
    node._health_failure_count = 0
    return False


def core_health_check():
    import time
    config = None

    # main core
    if not xray.core.started:
        if not config:
            config = xray.config.include_db_users()
        xray.core.restart(config)

    # One unavailable node must not prevent health checks of the others.
    for node_id, node in list(xray.nodes.items()):
        try:
            connected = node.connected
            if connected:
                try:
                    assert node.started
                    node.api.get_sys_stats(timeout=getattr(node, "health_check_timeout", 2))
                    node._health_failure_count = 0
                    node.observed_health = (time.monotonic(), True)
                except (ConnectionError, xray_exc.XrayError, AssertionError) as error:
                    node.observed_health = (time.monotonic(), False)
                    if not isinstance(error, AssertionError) and _defer_health_recovery(node):
                        logger.warning("Node %s health check deferred after %s", node_id, type(error).__name__)
                        continue
                    if config is None:
                        config = xray.config.include_db_users()
                    # Only a confirmed stopped engine justifies automatic start.
                    # Missing controller RPC must never restart a live VPN core.
                    if isinstance(error, AssertionError):
                        xray.operations.restart_node(node_id, config)
                    else:
                        xray.operations.connect_node(node_id, config)
            else:
                node.observed_health = (time.monotonic(), False)
                if _defer_health_recovery(node):
                    logger.warning("Node %s connection check deferred", node_id)
                    continue
                if config is None:
                    config = xray.config.include_db_users()
                xray.operations.connect_node(node_id, config)
        except Exception as error:
            node.observed_health = (time.monotonic(), False)
            if _defer_health_recovery(node):
                logger.warning("Node %s health check deferred after %s", node_id, type(error).__name__)
                continue
            logger.warning("Node %s health check failed (%s)", node_id, type(error).__name__)
            xray.operations.connect_node(node_id, config)


@app.on_event("startup")
def start_core():
    logger.info("Generating Xray core config")

    start_time = time.time()
    config = xray.config.include_db_users()
    logger.info(f"Xray core config generated in {(time.time() - start_time):.2f} seconds")

    # main core
    logger.info("Starting main Xray core")
    try:
        xray.core.start(config)
    except Exception:
        traceback.print_exc()

    # nodes' core
    logger.info("Starting nodes Xray core")
    with GetDB() as db:
        dbnodes = crud.get_nodes(db=db, enabled=True)
        node_ids = [dbnode.id for dbnode in dbnodes]
        for dbnode in dbnodes:
            crud.update_node_status(db, dbnode, NodeStatus.connecting)

    for node_id in node_ids:
        xray.operations.connect_node(node_id, config)

    scheduler.add_job(core_health_check, 'interval',
                      seconds=JOB_CORE_HEALTH_CHECK_INTERVAL,
                      coalesce=True, max_instances=1)


@app.on_event("shutdown")
def app_shutdown():
    logger.info("Stopping main Xray core")
    xray.core.stop()

    # Remote VPN engines belong to their node, not the controller process.
    # Explicit disable/delete operations retain their own stop semantics.
    logger.info("Leaving remote Xray engines running")
