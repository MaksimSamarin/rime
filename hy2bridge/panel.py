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
from pydantic import BaseModel, Field, StrictInt, StrictBool, model_validator

from .store import Store, Conflict
from .operations import Operations
from .registry import Registry
from .provision import Provisioner,ProvisionError
from .periods import Periods


class Counts(BaseModel):
    tx: Annotated[StrictInt, Field(ge=0, le=2**60)]
    rx: Annotated[StrictInt, Field(ge=0, le=2**60)]


class ClientProbe(BaseModel):
    checked_at: float = Field(ge=0,allow_inf_nan=False)
    passed: StrictBool
    target_ip: str = Field(min_length=2,max_length=45)
    stage: Literal['payload','client','connect','configuration','route']
    latency_ms: float | None = Field(default=None,ge=0,le=120000,allow_inf_nan=False)
    error: str | None = Field(default=None,max_length=160)


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
    management_policy_ack: dict | None = Field(default=None,max_length=3)
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
    move_node: str | None = Field(default=None,max_length=64,pattern=r'^[a-zA-Z0-9:_-]+$')
    address: str | None = Field(default=None,max_length=45)
    cleanup_job: str | None = Field(default=None,pattern=r'^[a-f0-9]{32}$')
    name: str=Field(min_length=1,max_length=256)
    protocol: Literal['hysteria2','vless']
    vpn_port: Annotated[StrictInt,Field(ge=1,le=65535)]
    username: str=Field(min_length=1,max_length=64)
    private_key: str=Field(default='',max_length=16384)
    password: str=Field(default='',max_length=1024)
    key_passphrase: str=Field(default='',max_length=1024)
    fingerprint: str=Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')
    domain: str=Field(min_length=1,max_length=253)
    certificate: str=Field(default='',max_length=32768)
    certificate_key: str=Field(default='',max_length=16384)

    @model_validator(mode='after')
    def node_name_length(self):
        if not self.move_node and len(self.name)>64:
            raise ValueError('Название новой ноды не длиннее 64 символов')
        return self


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
    from .reachability import Reachability
    operations.reachability=Reachability(store,config.get('client_probes',[]))
    from .http import FleetGZipMiddleware
    app.add_middleware(FleetGZipMiddleware,minimum_size=1024,compresslevel=5)
    from app import scheduler
    scheduler.add_job(meters.check_health,'interval',seconds=10,id='rime_meter_health',replace_existing=True)
    scheduler.add_job(operations.prune,'interval',hours=1,id='rime_diagnostic_retention',replace_existing=True,max_instances=1)
    scheduler.add_job(operations.expire_checks,'interval',seconds=30,id='rime_check_timeouts',replace_existing=True,max_instances=1,coalesce=True)
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
    # HTTP handlers read observations; remote RPC belongs to the health worker.
    def observed_native(node_id):
        import time
        value=getattr(xray.nodes.get(node_id),'observed_health',None)
        return value[1] if value and time.monotonic()-value[0]<120 else None
    operations.native_probe=observed_native
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
        with store.connection() as db:
            if db.execute('SELECT 1 FROM fleet_legacy_retired WHERE node=?',(node,)).fetchone():continue
        operations.ensure_node(node)
    def current_hy2_nodes():
        with store.connection() as db:
            managed={r['id'] for r in db.execute("SELECT id FROM fleet_managed WHERE protocol='hysteria2'")}
            retired={r['node'] for r in db.execute('SELECT node FROM fleet_legacy_retired')}
        return (set(tokens)-retired)|managed
    periods.node_ids=current_hy2_nodes

    def valid_node_credential(node,authorization,db):
        if db.execute("SELECT 1 FROM fleet_managed WHERE id=? AND protocol='hysteria2'",(node,)).fetchone():
            return registry.authorize(node,authorization,db)
        if db.execute('SELECT 1 FROM fleet_legacy_retired WHERE node=?',(node,)).fetchone():return False
        token=tokens.get(node)
        return token is not None and hmac.compare_digest(authorization,'Bearer '+token)

    def authorize(node: str, authorization: str = Header(default='')):
        with store.connection() as db:valid=valid_node_credential(node,authorization,db)
        if not valid:
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
    def usage(batch: Batch, node: str = Depends(authorize),authorization:str=Header(default='')):
        def credential_guard(db,added):
            if not valid_node_credential(node,authorization,db):
                raise HTTPException(401,'Node credential changed')
        try:
            return store.ingest(node,batch.model_dump(),commit_hook=credential_guard)
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
        data=health.model_dump(exclude={'check','accounting_durable','kick_attempts','error','traffic_healthy','traffic_checked_at','traffic_latency_ms','traffic_error','management_policy_ack'})
        data['resource_observer']=True
        try:
            result=operations.heartbeat(node,data)
            from .native_sources import current
            if current is not None and node.startswith('xray:'):
                policy=current.response(node,health.management_policy_ack)
                if policy is not None:result['management_policy']=policy
            return result
        except ValueError as error:raise HTTPException(409,str(error))

    @app.post('/api/fleet/meters/{node}/usage',tags=['Fleet'])
    def meter_usage(node:str,batch:MeterBatch,authorization:str=Header(default='')):
        if not meters.authorize(node,authorization):raise HTTPException(401,'Invalid meter credential')
        try:return meters.ingest(node,batch.model_dump(include={'spool','seq','totals'}),batch.source_at,batch.source_epoch,batch.counter_started_at)
        except (Conflict,ValueError) as error:raise HTTPException(409,str(error))

    @app.get('/api/fleet/meters/{node}/policy',tags=['Fleet'])
    def legacy_policy(node:str,authorization:str=Header(default='')):
        if not meters.authorize(node,authorization):raise HTTPException(401,'Invalid meter credential')
        try:
            result=store.policy(node)
            return {k:v for k,v in result.items() if k!='barriers'}
        except Conflict as error:raise HTTPException(409,str(error))

    @app.get('/api/fleet/overview',tags=['Fleet'])
    def overview(admin: Admin=Depends(Admin.check_sudo_admin)):
        nodes=operations.nodes()
        return {'nodes':nodes,'events':operations.events(250,nodes=nodes),'generated_at':datetime.now(timezone.utc).isoformat(),
                'summary':{state:sum(n['state']==state for n in nodes) for state in ('healthy','degraded','offline','unknown')}}

    @app.post('/api/fleet/client-probes/{probe}/{node}',tags=['Fleet'])
    def client_probe(probe:str,node:str,data:ClientProbe,authorization:str=Header(default='')):
        if not operations.reachability.authorize(probe,node,authorization):raise HTTPException(401,'Invalid client-probe credential')
        try:return operations.reachability.ingest(probe,node,data.model_dump())
        except ValueError as error:raise HTTPException(422,str(error))

    @app.get('/api/fleet/events',tags=['Fleet'])
    def events(admin: Admin=Depends(Admin.check_sudo_admin)):
        return operations.events(250)

    def filtered_report(start,end,protocol,node,username,tag=None,detail=True,group_by='protocol'):
        end=end or datetime.now(timezone.utc)
        start=start or end-timedelta(days=7)
        if start.tzinfo is None:start=start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:end=end.replace(tzinfo=timezone.utc)
        try:return operations.traffic(start.astimezone(timezone.utc),end.astimezone(timezone.utc),protocol,node,username,tag,detail=detail,group_by=group_by)
        except ValueError as e:raise HTTPException(422,str(e))

    @app.get('/api/fleet/traffic',tags=['Fleet'])
    def traffic(start: datetime|None=None,end: datetime|None=None,protocol: Literal['hysteria2','xray']|None=None,
                node: str|None=None,username: str|None=None,tag: str|None=None,detail:bool=True,
                group_by:Literal['protocol','node','tag','user']='protocol',admin: Admin=Depends(Admin.check_sudo_admin)):
        return filtered_report(start,end,protocol,node,username,tag,detail,group_by)

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
    from .provision_probe import ProvisionProbe
    provision_probe=ProvisionProbe(store,provision_settings,operations.reachability,xray)
    provision=Provisioner(store,provision_settings,*registry.callbacks(operations,provision_settings),
                          verify=provision_probe.run if provision_settings.get('probe_username') else None)
    app.state.fleet_provisioner=provision
    from .proxy_service import install as install_proxy
    proxies=install_proxy(app,store,provision)
    from . import native_trust
    native_trust.current=native_trust.NativeTrust(store,proxies.recovery)
    from . import native_sources
    native_sources.current=native_sources.ManagementSources(store,provision_settings)
    def capture_node(job,data,configuration,registration):
        if data['protocol']=='vless':
            from .recovery import vless_profile
            template=provision_settings['vless_template']
            certificates={template['certificate_path'].lstrip('/'):configuration['files']['cert.pem'],
                          template['key_path'].lstrip('/'):configuration['files']['key.pem']}
            vpn=vless_profile(dict(xray.config),[{'inbound_tag':template['inbound_tag'],'port':data['vpn_port']}],certificates)
        else:
            vpn={'protocol':'hysteria2','config':json.loads(configuration['files']['hysteria.json']),
                 'certificate':configuration['files']['cert.pem'],'certificate_key':configuration['files']['key.pem']}
        if registration.get('management_tls'):vpn['management_tls']=registration['management_tls']
        if registration.get('management_auth'):
            vpn['management_auth']=registration['management_auth']
            vpn['management_protocol']=configuration.get('env',{}).get('SERVICE_PROTOCOL','rest')
        proxies.recovery.remember_vpn(registration['node'],vpn)
    provision.capture=capture_node
    from .client_checks import install as install_client_checks
    install_client_checks(app,store,provision_settings,operations.reachability,provision_probe.active_target)
    if provision_settings.get('probe_username'):
        scheduler.add_job(provision_probe.run_active,'interval',seconds=60,id='rime_managed_client_checks',
                          replace_existing=True,max_instances=1,coalesce=True)
    from .lifecycle import Lifecycle,DeleteConflict
    lifecycle=Lifecycle(store);lifecycle.install_runtime(scheduler,xray,quotas.current,provision)
    app.state.node_lifecycle=lifecycle
    from .transfer import NodeTransfer
    transfer=NodeTransfer(provision,operations,provision_probe,lifecycle,recovery=proxies.recovery,proxies=proxies)
    app.state.node_transfer=transfer
    provision_probe.transfer=transfer
    if provision_settings.get('relay_enabled',False):
        from .relays import Relays
        from .relay_api import install as install_relays
        from . import relay_routes
        relay_routes.current=Relays(provision,transfer,proxies)
        operations.relays=relay_routes.current
        proxies.relays=relay_routes.current
        proxies.deletion.relays=relay_routes.current
        install_relays(app,relay_routes.current)
        scheduler.add_job(relay_routes.current.prune,'interval',hours=1,id='rime_relay_retention',replace_existing=True)
        scheduler.add_job(relay_routes.current.check_active,'interval',seconds=60,id='rime_relay_payload_checks',replace_existing=True,max_instances=1,coalesce=True)
        scheduler.add_job(relay_routes.current.changes.recover,'date',id='rime_relay_operation_recovery',replace_existing=True)
        scheduler.add_job(relay_routes.current.changes.recover,'interval',seconds=60,id='rime_relay_operation_retries',replace_existing=True,max_instances=1,coalesce=True)
    from .recovery_api import install as install_recovery
    install_recovery(app,transfer)
    original_begin=periods.begin
    def guarded_begin(*args,**kwargs):
        with lifecycle.guard:
            with store.connection() as db:
                if db.execute("SELECT 1 FROM fleet_node_transfers WHERE state='switched'").fetchone():
                    raise Conflict('Сброс расхода отложен до завершения переноса ноды')
            return original_begin(*args,**kwargs)
    periods.begin=guarded_begin

    @app.get('/api/fleet/nodes/{node}/delete-preview',tags=['Fleet'])
    def delete_preview(node:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        with store.connection() as db:retired=db.execute('SELECT 1 FROM fleet_legacy_retired WHERE node=?',(node,)).fetchone()
        if node in tokens and not retired:raise HTTPException(409,'Нода задана статической конфигурацией: сначала перенесите её регистрацию в панель')
        try:result=lifecycle.plan(node)
        except DeleteConflict as error:raise HTTPException(409,str(error))
        if result is None:raise HTTPException(404,'Нода не найдена')
        return result

    @app.delete('/api/fleet/nodes/{node}',tags=['Fleet'])
    def delete_node(node:str,data:DeleteNodeRequest,admin:Admin=Depends(Admin.check_sudo_admin)):
        with store.connection() as db:retired=db.execute('SELECT 1 FROM fleet_legacy_retired WHERE node=?',(node,)).fetchone()
        if node in tokens and not retired:raise HTTPException(409,'Нода задана статической конфигурацией')
        try:return lifecycle.delete(node,data.name,data.confirmation,data.acknowledge_remote_retained)
        except DeleteConflict as error:raise HTTPException(409,str(error))
    def provision_call(call,*args):
        try:return call(*args)
        except ProvisionError as e:raise HTTPException(409,str(e))
        except Exception:raise HTTPException(503,'Операция недоступна; проверьте конфигурацию установщика') from None

    @app.get('/api/fleet/provision/options',tags=['Fleet'])
    def provision_options(admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision.options()

    @app.post('/api/fleet/provision/host-key',tags=['Fleet'])
    def host_key(data:SSHAddress,admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision_call(provision.scan,data.host,data.ssh_port)

    @app.post('/api/fleet/provision/preflight',tags=['Fleet'])
    def preflight(data:ProvisionRequest,admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision_call(transfer.preflight if data.move_node else provision.preflight,data.model_dump())

    @app.get('/api/fleet/provision/transfer/{node}',tags=['Fleet'])
    def transfer_options(node:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        return provision_call(transfer.options_for,node)

    @app.post('/api/fleet/provision/deploy',tags=['Fleet'])
    def deploy(data:DeployRequest,admin:Admin=Depends(Admin.check_sudo_admin)):
        with provision.lock:
            record=provision.plans.get(data.plan_id)
            moving=bool(record and record['data'].get('move_node'))
        return provision_call(transfer.deploy if moving else provision.deploy,data.plan_id)

    @app.get('/api/fleet/provision/jobs/{job}',tags=['Fleet'])
    def job(job:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        try:return provision.job(job)
        except ProvisionError as error:raise HTTPException(404,str(error)) from None

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
