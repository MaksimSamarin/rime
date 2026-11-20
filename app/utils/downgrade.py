"""Explicit maintenance handover from cumulative to reset-based metering."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from update_runtime.leases import hold,set_barrier,clear_barrier
from update_runtime.releases import version_key,UpdateError


def _epoch(api):
    value=api.usage_epoch
    value=value() if callable(value) else value
    if not isinstance(value,str) or not value:raise UpdateError('native_epoch_unavailable')
    return value


def handover(nodes,collect,restart,progress=None):
    """Collect once, restart each qualified core, and verify its new epoch."""
    result=[]
    with ExitStack() as locks:
        for ident,node in sorted(nodes.items()):locks.enter_context(node.api.control_lock)
        for ident,node in sorted(nodes.items()):
            api=node.api
            previous=_epoch(api)
            collect(api,ident,'users',getattr(node,'usage_coefficient',1))
            collect(api,ident,'outbound',getattr(node,'usage_coefficient',1))
            restart(ident,node)
            deadline=time.monotonic()+15
            while True:
                try:
                    current=_epoch(node.api)
                    if current!=previous:break
                except Exception:
                    if time.monotonic()>=deadline:raise
                if time.monotonic()>=deadline:raise UpdateError('native_restart_unverified')
                time.sleep(.2)
            result.append({'node_id':ident,'old_epoch':previous,'new_epoch':current})
            if progress is not None:progress(list(result))
    return result


def _write(path,value):
    temporary=path.with_name('.downgrade-'+uuid.uuid4().hex)
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(descriptor,'w') as output:
            json.dump(value,output);output.flush();os.fsync(output.fileno())
        temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)


def prepare(target,directory):
    if version_key(target)>=version_key('0.9.0'):raise UpdateError('invalid_downgrade_target')
    from app import xray
    from app.db import GetDB
    from app.db.models import Node
    from app.utils.native_usage import record_native_usage,uses_cumulative_usage
    from app.xray.operations import NODE_LIFECYCLE_LOCK
    from hy2bridge.access import filter_config
    directory=Path(directory)
    identity='downgrade-'+uuid.uuid4().hex
    path=directory/'.downgrade.json'
    with hold(directory,exclusive=True),NODE_LIFECYCLE_LOCK:
        if (directory/'.cutover.json').exists():raise UpdateError('update_running')
        with GetDB() as db:
            active={node.id for node in db.query(Node).all() if str(getattr(node.status,'value',node.status))!='disabled'}
            from sqlalchemy import text,inspect
            cursor_ids={row[0] for row in db.execute(text('SELECT DISTINCT node_id FROM fleet_native_usage_cursors'))} \
                if inspect(db.get_bind()).has_table('fleet_native_usage_cursors') else set()
        nodes={ident:node for ident,node in list(xray.nodes.items())
               if ident in active and uses_cumulative_usage(node.api)}
        if not cursor_ids.intersection(active)<=set(nodes):raise UpdateError('native_node_unavailable')
        value={'id':identity,'target':target,'state':'preparing','created_at':time.time()}
        _write(path,value);set_barrier(directory,identity)
        try:
            configuration=xray.config.include_db_users()
            def progress(rows):
                value['nodes']=rows;_write(path,value)
            result=handover(nodes,record_native_usage,
                lambda ident,node:node.restart(filter_config(configuration,'xray:'+str(ident))),progress)
            value.update(state='prepared',nodes=result,prepared_at=time.time())
            _write(path,value)
            # The record is in the same persistent SQLite database used by a
            # planned handover, without modifying any user or signing value.
            with GetDB() as db:
                from sqlalchemy import text
                db.execute(text('CREATE TABLE IF NOT EXISTS fleet_native_downgrade (id INTEGER PRIMARY KEY,payload TEXT NOT NULL)'))
                db.execute(text('DELETE FROM fleet_native_downgrade'))
                db.execute(text('INSERT INTO fleet_native_downgrade(id,payload) VALUES(1,:payload)'),{'payload':json.dumps(value)})
                db.commit()
        except BaseException:
            value.update(state='failed',failed_at=time.time());_write(path,value)
            # Keep maintenance active after a partial restart; an operator must
            # inspect it and explicitly cancel or finish the handover.
            raise
    return {'state':value['state'],'target':target,'nodes':len(value['nodes']),
            'maintenance':True,'controller_compatibility_required':True}


def cancel(directory):
    directory=Path(directory);path=directory/'.downgrade.json'
    with hold(directory,exclusive=True):
        if path.is_symlink():raise UpdateError('invalid_update_request')
        value=json.loads(path.read_text())
        if not str(value.get('id','')).startswith('downgrade-'):raise UpdateError('invalid_update_request')
        value.update(state='cancelled',cancelled_at=time.time());_write(path,value)
        from app.db import GetDB
        from sqlalchemy import inspect,text
        with GetDB() as db:
            if inspect(db.get_bind()).has_table('fleet_native_downgrade'):
                db.execute(text('UPDATE fleet_native_downgrade SET payload=:payload WHERE id=1'),{'payload':json.dumps(value)})
                db.commit()
        clear_barrier(directory,value['id'])
    return {'state':'cancelled','maintenance':False}
