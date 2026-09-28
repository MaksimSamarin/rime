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
from fastapi.responses import FileResponse, Response, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StrictInt, model_validator

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


class MeterBatch(Batch):
    source_epoch: str = Field(pattern=r'^[a-f0-9]{64}$')
    source_at: float = Field(ge=0,allow_inf_nan=False)
    counter_started_at: float | None = Field(default=None,ge=0,allow_inf_nan=False)


class ConnectionGroup(BaseModel):
    key: str = Field(pattern=r'^[a-f0-9]{12}$')
    count: Annotated[StrictInt,Field(ge=1)]
    family: Literal['ipv4','ipv6','account']


class ConnectionDetails(BaseModel):
    kind: Literal['tcp_established','hy2_client_instances']
    observed_at: float = Field(ge=0,allow_inf_nan=False)
    total: Annotated[StrictInt,Field(ge=0)]
    local_port: int | None = Field(default=None,ge=1,le=65535)
    unique_source_ips: Annotated[StrictInt,Field(ge=0)] | None = None
    authenticated_users: Annotated[StrictInt,Field(ge=0)] | None = None
    confirmed_core_sockets: Annotated[StrictInt,Field(ge=0)] | None = None
    unverified_owner_sockets: Annotated[StrictInt,Field(ge=0)] | None = None
    groups: list[ConnectionGroup] = Field(default_factory=list,max_length=50)
    other_connections: Annotated[StrictInt,Field(ge=0)] = 0


class Health(BaseModel):
    error: Literal['accounting_failed','stats_unavailable','ledger_failed','control_expired','counter_reset'] | None = None
    uptime_seconds: Annotated[StrictInt,Field(ge=0)] = 0
    online_users: Annotated[StrictInt,Field(ge=0)] | None = None
    online_connections: Annotated[StrictInt,Field(ge=0)] | None = None
    mem_available_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    disk_free_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    cpu_load1: float | None = Field(default=None,ge=0,allow_inf_nan=False)
    cpu_percent: float | None = Field(default=None,ge=0,le=100,allow_inf_nan=False)
    accounting_durable: bool = False
    core_version: str = Field(default='unknown',max_length=80)
    kick_attempts: Annotated[StrictInt,Field(ge=0)] = 0
    mem_total_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    disk_total_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    swap_total_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    swap_free_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    net_rx_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    net_tx_bytes: Annotated[StrictInt,Field(ge=0)] | None = None
    service_healthy: bool | None = None
    traffic_healthy: bool | None = None
    traffic_checked_at: float | None = Field(default=None,ge=0,allow_inf_nan=False)
    traffic_latency_ms: float | None = Field(default=None,ge=0,allow_inf_nan=False)
    traffic_error: str | None = Field(default=None,max_length=300)
    check: dict | None = None
    connection_metric_state: Literal['available','unavailable','not_configured'] | None = None
    connection_details: ConnectionDetails | None = None

    @model_validator(mode='after')
    def consistent_connections(self):
        detail=self.connection_details
        if detail and (self.online_connections!=detail.total or sum(g.count for g in detail.groups)+detail.other_connections!=detail.total):
            raise ValueError('Connection summary does not match its total')
        return self


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


class DeleteNodeRequest(BaseModel):
    name: str = Field(min_length=1,max_length=256)
    confirmation: str = Field(pattern=r'^[a-f0-9]{64}$')
    acknowledge_remote_retained: bool

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
    store.require_registered_nodes=True
    operations.require_registered_nodes=True
    from .observers import Observers
    observers=Observers(store,config.get('observers'))
    operations.observers=observers
    from .meter import Meters
    meters=Meters(store,config.get('meters',[]))
    operations.meters=meters
    from app import scheduler
    scheduler.add_job(meters.check_health,'interval',seconds=10,id='rime_meter_health',replace_existing=True)
    from . import quotas
    quotas.current=quotas.NodeQuotas(store)
    operations.quotas=quotas.current
    from . import access
    access.current=access.Access(store)
    from .console import install as install_console
    install_console(app,store,operations,access.current)
    registry.install_links()
    periods=Periods(store)
    periods.recover_after_controller_restart()
    if config.get('safe_period_reset',False):periods.install()
    quotas.current.install(app)
    from app import xray
    operations.native_probe=lambda node_id: (bool(xray.nodes[node_id].connected and xray.nodes[node_id].started)
                                           if node_id in xray.nodes else None)
    local_state={'outage':None}
    import psutil
    from .telemetry import HostResources, PanelRuntime
    from app import __version__
    host_resources=HostResources(psutil, str(Path(store.path).resolve().parent))
    panel_runtime=PanelRuntime(psutil,__version__)
    def local_node():
        import psutil,time
        if xray.core.started:local_state['outage']=None
        elif local_state['outage'] is None:local_state['outage']=time.time()
        return {'id':'xray:local','name':'Сервер панели','protocol':'xray','address':'Панель Rime',
            'role':'panel','panel':panel_runtime.snapshot(),
            'state':'healthy' if xray.core.started else 'offline','seen_at':time.time(),
            'outage_since':local_state['outage'],'age_seconds':0,
            'status_source':'local','metrics':{'core_version':xray.core.version,
            **host_resources.snapshot(), 'service_healthy':bool(xray.core.started),
            'cpu_load1':os.getloadavg()[0]}}
    operations.local_probe=local_node
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
            result=store.policy(node)
            result['check']=operations.claim_check(node)
            return result
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
        try:return operations.heartbeat(node,health.model_dump())
        except ValueError as error:raise HTTPException(409,str(error))

    @app.post('/api/fleet/telemetry/{node}',tags=['Fleet'])
    def resource_telemetry(node:str,health:Health,authorization:str=Header(default='')):
        if not observers.authorize(node,authorization):raise HTTPException(401,'Invalid telemetry credential')
        if health.connection_details and health.connection_details.kind!=('tcp_established' if node.startswith('xray:') else 'hy2_client_instances'):
            raise HTTPException(422,'Connection metric does not match the node protocol')
        # Resource-only credentials cannot acknowledge traffic barriers, report
        # usage or claim that the legacy collector has durable accounting.
        data=health.model_dump(exclude={'check','accounting_durable','kick_attempts','error','traffic_healthy','traffic_checked_at','traffic_latency_ms','traffic_error'})
        data['resource_observer']=True
        try:return operations.heartbeat(node,data)
        except ValueError as error:raise HTTPException(409,str(error))

    @app.post('/api/fleet/meters/{node}/usage',tags=['Fleet'])
    def meter_usage(node:str,batch:MeterBatch,authorization:str=Header(default='')):
        if not meters.authorize(node,authorization):raise HTTPException(401,'Invalid meter credential')
        try:return meters.ingest(node,batch.model_dump(include={'spool','seq','totals'}),batch.source_at,batch.source_epoch,batch.counter_started_at)
        except (Conflict,ValueError) as error:raise HTTPException(409,str(error))

    @app.get('/api/fleet/overview',tags=['Fleet'])
    def overview(admin: Admin=Depends(Admin.check_sudo_admin)):
        nodes=operations.nodes()
        return {'nodes':nodes,'events':operations.events(50),'generated_at':datetime.now(timezone.utc).isoformat(),
                'summary':{state:sum(n['state']==state for n in nodes) for state in ('healthy','degraded','offline','unknown')}}

    @app.get('/api/fleet/events',tags=['Fleet'])
    def events(admin: Admin=Depends(Admin.check_sudo_admin)):
        return operations.events(250)

    def filtered_report(start,end,protocol,node,username,tag=None):
        end=end or datetime.now(timezone.utc)
        start=start or end-timedelta(days=7)
        if start.tzinfo is None:start=start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:end=end.replace(tzinfo=timezone.utc)
        try:return operations.traffic(start.astimezone(timezone.utc),end.astimezone(timezone.utc),protocol,node,username,tag)
        except ValueError as e:raise HTTPException(422,str(e))

    @app.get('/api/fleet/traffic',tags=['Fleet'])
    def traffic(start: datetime|None=None,end: datetime|None=None,protocol: Literal['hysteria2','xray']|None=None,
                node: str|None=None,username: str|None=None,tag: str|None=None,admin: Admin=Depends(Admin.check_sudo_admin)):
        return filtered_report(start,end,protocol,node,username,tag)

    @app.get('/api/fleet/traffic.csv',tags=['Fleet'])
    def export(start: datetime|None=None,end: datetime|None=None,protocol: Literal['hysteria2','xray']|None=None,
               node: str|None=None,username: str|None=None,tag: str|None=None,admin: Admin=Depends(Admin.check_sudo_admin)):
        report=filtered_report(start,end,protocol,node,username,tag)
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
    from .lifecycle import Lifecycle,DeleteConflict
    lifecycle=Lifecycle(store);lifecycle.install_runtime(scheduler,xray,quotas.current,provision)
    app.state.node_lifecycle=lifecycle
    original_begin=periods.begin
    def guarded_begin(*args,**kwargs):
        with lifecycle.guard:return original_begin(*args,**kwargs)
    periods.begin=guarded_begin

    @app.get('/api/fleet/nodes/{node}/delete-preview',tags=['Fleet'])
    def delete_preview(node:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        if node in tokens:raise HTTPException(409,'Нода задана статической конфигурацией: сначала перенесите её регистрацию в панель')
        try:result=lifecycle.plan(node)
        except DeleteConflict as error:raise HTTPException(409,str(error))
        if result is None:raise HTTPException(404,'Нода не найдена')
        return result

    @app.delete('/api/fleet/nodes/{node}',tags=['Fleet'])
    def delete_node(node:str,data:DeleteNodeRequest,admin:Admin=Depends(Admin.check_sudo_admin)):
        if node in tokens:raise HTTPException(409,'Нода задана статической конфигурацией')
        try:return lifecycle.delete(node,data.name,data.confirmation,data.acknowledge_remote_retained)
        except DeleteConflict as error:raise HTTPException(409,str(error))
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
    class NoCacheStatic(StaticFiles):
        async def get_response(self,path,scope):
            response=await super().get_response(path,scope)
            response.headers['Cache-Control']='no-store, max-age=0'
            response.headers['Pragma']='no-cache'
            return response
    app.mount('/fleet/assets',NoCacheStatic(directory=web),name='fleet-assets')
    @app.get('/fleet',include_in_schema=False)
    @app.get('/fleet/',include_in_schema=False)
    def fleet_page():
        headers={'Cache-Control':'no-store',
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            'X-Content-Type-Options':'nosniff'}
        if os.environ.get('RIME_DEMO')=='1':
            return HTMLResponse((web/'index.html').read_text().replace('<body>','<body><div class="demo-label">DEMO · Тестовые пользователи и условные ноды · Прод не подключён</div>'),headers=headers)
        return FileResponse(web/'index.html',headers=headers)
