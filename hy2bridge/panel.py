"""Explicit, opt-in FastAPI extension; no modification of existing subscriptions."""
import hmac
import json
import os
from typing import Annotated, Literal
from datetime import datetime, timedelta, timezone
import csv
import io
from pathlib import Path

from fastapi import Depends, Header, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StrictInt

from .store import Store, Conflict
from .operations import Operations
from .registry import Registry
from .provision import Provisioner,ProvisionError
from .periods import Periods


class Counts(BaseModel):
    tx: Annotated[StrictInt, Field(ge=0, le=2**60)]
    rx: Annotated[StrictInt, Field(ge=0, le=2**60)]


class Batch(BaseModel):
    spool: str = Field(min_length=16,max_length=64)
    seq: Annotated[StrictInt, Field(ge=1,le=2**60)]
    totals: dict[str, Counts] = Field(max_length=10000)


class Health(BaseModel):
    error: Literal['accounting_failed','stats_unavailable','ledger_failed','control_expired','counter_reset'] | None = None
    uptime_seconds: Annotated[StrictInt,Field(ge=0)] = 0
    online_users: Annotated[StrictInt,Field(ge=0)] | None = None
    online_connections: Annotated[StrictInt,Field(ge=0)] | None = None
    mem_available_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    disk_free_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    cpu_load1: float | None = Field(default=None,ge=0,allow_inf_nan=False)
    accounting_durable: bool = False
    core_version: str = Field(default='unknown',max_length=80)
    kick_attempts: Annotated[StrictInt,Field(ge=0)] = 0


class SSHAddress(BaseModel):
    host: str=Field(min_length=1,max_length=253)
    ssh_port: Annotated[StrictInt,Field(ge=1,le=65535)]=22


class ProvisionRequest(SSHAddress):
    name: str=Field(min_length=1,max_length=64)
    protocol: Literal['hysteria2','vless']
    vpn_port: Annotated[StrictInt,Field(ge=1,le=65535)]
    username: str=Field(min_length=1,max_length=64)
    private_key: str=Field(default='',max_length=16384)
    password: str=Field(default='',max_length=1024)
    key_passphrase: str=Field(default='',max_length=1024)
    fingerprint: str=Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')
    domain: str=Field(min_length=1,max_length=253)
    certificate: str=Field(min_length=1,max_length=32768)
    certificate_key: str=Field(min_length=1,max_length=16384)


class DeployRequest(BaseModel):
    plan_id: str=Field(pattern=r'^[a-f0-9]{32}$')

class BarrierAck(BaseModel):
    id: str=Field(pattern=r'^[a-f0-9]{32}$')
    seq: Annotated[StrictInt,Field(ge=1)]


def install(app):
    from app.models.admin import Admin
    from config import SQLALCHEMY_DATABASE_URL
    if getattr(app.state, 'rime_installed', False):
        return
    config_path = os.environ.get('RIME_FLEET_CONFIG') or os.environ.get('HY2_PANEL_CONFIG')
    config = json.loads(Path(config_path).read_text()) if config_path else {}
    if not SQLALCHEMY_DATABASE_URL.startswith('sqlite:///'):
        raise RuntimeError('Rime traffic accounting requires SQLite')
    store = Store(SQLALCHEMY_DATABASE_URL[len('sqlite:///'):])
    # Refuse multiple workers: reset barriers and SSH plans have one owner.
    import fcntl
    controller_lock=open(store.path+'.fleet.lock','a')
    try:fcntl.flock(controller_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError:
        controller_lock.close();raise RuntimeError('Fleet requires one panel worker per SQLite database') from None
    app.state.fleet_controller_lock=controller_lock
    store.initialize()
    operations=Operations(store)
    registry=Registry(store)
    registry.install_links()
    periods=Periods(store)
    periods.recover_after_controller_restart()
    if config.get('safe_period_reset',False):periods.install()
    from app import xray
    operations.native_probe=lambda node_id: (bool(xray.nodes[node_id].connected and xray.nodes[node_id].started)
                                           if node_id in xray.nodes else None)
    tokens = config.get('node_tokens',{})
    if not isinstance(tokens,dict) or any(not isinstance(v,str) or len(v) < 32 for v in tokens.values()) or len(set(tokens.values()))!=len(tokens):
        raise ValueError('Each Hy2 node must have a separate token of at least 32 characters')
    for node in tokens:
        operations.ensure_node(node)
    def current_hy2_nodes():
        with store.connection() as db:
            managed={r['id'] for r in db.execute("SELECT id FROM fleet_managed WHERE protocol='hysteria2'")}
        return set(tokens)|managed
    periods.node_ids=current_hy2_nodes

    def authorize(node: str, authorization: str = Header(default='')):
        token = tokens.get(node)
        if not ((token is not None and hmac.compare_digest(authorization, 'Bearer ' + token)) or registry.authorize(node,authorization)):
            raise HTTPException(401, 'Invalid node credential')
        return node

    @app.get('/api/hy2/nodes/{node}/policy', tags=['Hysteria2'])
    def policy(node: str = Depends(authorize)):
        try:
            return store.policy(node)
        except Conflict as e:
            raise HTTPException(409,str(e))

    @app.post('/api/hy2/nodes/{node}/usage', tags=['Hysteria2'])
    def usage(batch: Batch, node: str = Depends(authorize)):
        try:
            return store.ingest(node,batch.model_dump())
        except Conflict as e:
            raise HTTPException(409,str(e))

    @app.post('/api/hy2/nodes/{node}/barrier',tags=['Hysteria2'])
    def barrier(data:BarrierAck,node:str=Depends(authorize)):
        try:return periods.ack(node,data.id,data.seq)
        except Conflict as e:raise HTTPException(409,str(e))

    @app.get('/api/hy2/report', tags=['Hysteria2'])
    def report(admin: Admin = Depends(Admin.check_sudo_admin)):
        return store.report()

    @app.post('/api/hy2/nodes/{node}/health', tags=['Fleet'])
    def health(health: Health,node: str = Depends(authorize)):
        return operations.heartbeat(node,health.model_dump())

    @app.get('/api/fleet/overview',tags=['Fleet'])
    def overview(admin: Admin=Depends(Admin.check_sudo_admin)):
        nodes=operations.nodes()
        return {'nodes':nodes,'events':operations.events(50),'generated_at':datetime.now(timezone.utc).isoformat(),
                'summary':{state:sum(n['state']==state for n in nodes) for state in ('healthy','degraded','offline','unknown')}}

    @app.get('/api/fleet/events',tags=['Fleet'])
    def events(admin: Admin=Depends(Admin.check_sudo_admin)):
        return operations.events(250)

    def filtered_report(start,end,protocol,node,username):
        end=end or datetime.now(timezone.utc)
        start=start or end-timedelta(days=7)
        if start.tzinfo is None:start=start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:end=end.replace(tzinfo=timezone.utc)
        try:return operations.traffic(start.astimezone(timezone.utc),end.astimezone(timezone.utc),protocol,node,username)
        except ValueError as e:raise HTTPException(422,str(e))

    @app.get('/api/fleet/traffic',tags=['Fleet'])
    def traffic(start: datetime|None=None,end: datetime|None=None,protocol: Literal['hysteria2','xray']|None=None,
                node: str|None=None,username: str|None=None,admin: Admin=Depends(Admin.check_sudo_admin)):
        return filtered_report(start,end,protocol,node,username)

    @app.get('/api/fleet/traffic.csv',tags=['Fleet'])
    def export(start: datetime|None=None,end: datetime|None=None,protocol: Literal['hysteria2','xray']|None=None,
               node: str|None=None,username: str|None=None,admin: Admin=Depends(Admin.check_sudo_admin)):
        report=filtered_report(start,end,protocol,node,username)
        output=io.StringIO();writer=csv.writer(output)
        fields=('hour','node','username','protocol','tx','rx','total');writer.writerow(fields)
        for row in report['rows']:
            def safe(value):
                if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@','\t','\r')):return "'"+value
                return value
            writer.writerow([safe(row.get(f)) for f in fields])
        return Response('\ufeff'+output.getvalue(),media_type='text/csv',headers={
            'Content-Disposition':'attachment; filename="traffic.csv"','Cache-Control':'no-store'})

    provision_settings=config.get('provision',{})
    if provision_settings.get('vless_template'):
        from app.db import GetDB,crud
        with GetDB() as db:provision_settings['vless_template']['client_certificate']=crud.get_tls_certificate(db).certificate
    provision=Provisioner(store,provision_settings,*registry.callbacks(operations,provision_settings))
    def provision_call(call,*args):
        try:return call(*args)
        except ProvisionError as e:raise HTTPException(409,str(e))
        except Exception:raise HTTPException(503,'Операция недоступна; проверьте конфигурацию установщика') from None

    @app.post('/api/fleet/provision/host-key',tags=['Fleet'])
    def host_key(data:SSHAddress,admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision_call(provision.scan,data.host,data.ssh_port)

    @app.post('/api/fleet/provision/preflight',tags=['Fleet'])
    def preflight(data:ProvisionRequest,admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision_call(provision.preflight,data.model_dump())

    @app.post('/api/fleet/provision/deploy',tags=['Fleet'])
    def deploy(data:DeployRequest,admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision_call(provision.deploy,data.plan_id)

    @app.get('/api/fleet/provision/jobs/{job}',tags=['Fleet'])
    def job(job:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision_call(provision.job,job)

    app.state.rime_installed = True
    web=Path(__file__).with_name('web')
    app.mount('/fleet/assets',StaticFiles(directory=web),name='fleet-assets')
    @app.get('/fleet',include_in_schema=False)
    @app.get('/fleet/',include_in_schema=False)
    def fleet_page():
        return FileResponse(web/'index.html',headers={'Cache-Control':'no-store',
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            'X-Content-Type-Options':'nosniff'})
