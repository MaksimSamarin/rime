"""Sudo administration and separately authenticated entry observations."""
from typing import Literal

from fastapi import Depends, Header, HTTPException
from pydantic import BaseModel, Field, StrictBool, StrictInt

from .provision import ProvisionError
from .proxy_service import ProxyReconcile, ProxyDeploy
from .relay_accounting import UnknownRelayService


class EntryRequest(ProxyReconcile):
    name: str = Field(min_length=1,max_length=64)
    domain: str = Field(min_length=1,max_length=253,pattern=r'^[A-Za-z0-9][A-Za-z0-9.-]*$')
    control_port: StrictInt = Field(default=62080,ge=1024,le=65535)
    metrics_port: StrictInt = Field(default=62081,ge=1024,le=65535)
    api_port: StrictInt = Field(default=62082,ge=1024,le=65535)


class RouteRequest(BaseModel):
    node: str = Field(min_length=1,max_length=128,pattern=r'^[A-Za-z0-9_.:-]+$')
    entry: str = Field(pattern=r'^[a-f0-9]{32}$')
    origin: str = Field(default='',max_length=253,pattern=r'^[A-Za-z0-9.:-]*$')
    include_proxies: StrictBool = True
    management: StrictBool = True
    ssh_port: StrictInt | None = Field(default=None,ge=1,le=65535)


class RouteSwitchRequest(BaseModel):
    entry: str = Field(pattern=r'^[a-f0-9]{32}$')
    grace_seconds: StrictInt | None = Field(default=None,ge=0,le=72*3600)


class ExplicitConfirmation(BaseModel):
    confirmation: str = Field(min_length=1,max_length=253)


class TransportCount(BaseModel):
    rx: StrictInt = Field(ge=0,le=2**60)
    tx: StrictInt = Field(ge=0,le=2**60)
    epoch: str = Field(min_length=8,max_length=128,pattern=r'^[A-Za-z0-9_-]+$')


class EntryHealth(BaseModel):
    cpu_percent: float | None = Field(default=None,ge=0,le=100,allow_inf_nan=False)
    cpu_count: StrictInt | None = Field(default=None,ge=1,le=65536)
    load_1m: float | None = Field(default=None,ge=0,allow_inf_nan=False)
    mem_total_bytes: StrictInt = Field(ge=0,le=2**60)
    mem_available_bytes: StrictInt = Field(ge=0,le=2**60)
    disk_total_bytes: StrictInt = Field(ge=0,le=2**60)
    disk_free_bytes: StrictInt = Field(ge=0,le=2**60)
    listeners: list[tuple[StrictInt,Literal['tcp','udp']]] = Field(default_factory=list,max_length=2048)
    quarantined_packets: StrictInt = Field(default=0,ge=0,le=256)


class EntryPacket(BaseModel):
    spool: str = Field(min_length=16,max_length=64,pattern=r'^[a-zA-Z0-9_-]+$')
    epoch: str = Field(min_length=8,max_length=128,pattern=r'^[A-Za-z0-9_-]+$')
    seq: StrictInt = Field(ge=1,le=2**60)
    observed_at: float = Field(ge=0,allow_inf_nan=False)
    totals: dict[str,TransportCount] = Field(max_length=2048)
    health: EntryHealth | None = None


def install(app, service):
    from app.models.admin import Admin

    def call(function,*args):
        try:return function(*args)
        except ProvisionError as error:raise HTTPException(409,str(error)) from None
        except Exception:raise HTTPException(503,'Операция туннеля недоступна. Проверьте связь с входным сервером') from None

    @app.get('/api/fleet/relays',tags=['Fleet'])
    def catalog(admin=Depends(Admin.check_sudo_admin)):
        return {'enabled':True,**call(service.catalog)}

    @app.post('/api/fleet/relays/entry/plan',tags=['Fleet'])
    def entry(data:EntryRequest,admin=Depends(Admin.check_sudo_admin)):
        return call(service.plan_entry,data.model_dump())

    @app.post('/api/fleet/relays/route/plan',tags=['Fleet'])
    def route(data:RouteRequest,admin=Depends(Admin.check_sudo_admin)):
        return call(service.plan_route,data.model_dump())

    @app.post('/api/fleet/relays/routes/{identity}/switch/plan',tags=['Fleet'])
    def switch_route(identity:str,data:RouteSwitchRequest,admin=Depends(Admin.check_sudo_admin)):
        return call(service.switches.plan,identity,data.entry, data.grace_seconds) if data.grace_seconds is not None else call(service.switches.plan,identity,data.entry)

    @app.post('/api/fleet/relays/entry/{identity}/remove/plan',tags=['Fleet'])
    def remove_entry(identity:str,data:ProxyReconcile,admin=Depends(Admin.check_sudo_admin)):
        return call(service.plan_entry_remove,identity,data.model_dump())

    @app.post('/api/fleet/relays/entry/{identity}/check',tags=['Fleet'])
    def check_entry(identity:str,admin=Depends(Admin.check_sudo_admin)):
        return call(service.reconcile_entry,identity)

    @app.post('/api/fleet/relays/routes/{identity}/detach',tags=['Fleet'])
    def detach_route(identity:str,data:ExplicitConfirmation,admin=Depends(Admin.check_sudo_admin)):
        return call(service.detach_route,identity,data.confirmation)

    @app.post('/api/fleet/relays/entry/{identity}/forget',tags=['Fleet'])
    def forget_entry(identity:str,data:ExplicitConfirmation,admin=Depends(Admin.check_sudo_admin)):
        return call(service.forget_entry,identity,data.confirmation)

    @app.post('/api/fleet/relays/deploy',tags=['Fleet'])
    def deploy(data:ProxyDeploy,admin=Depends(Admin.check_sudo_admin)):
        return call(service.deploy,data.plan_id)

    @app.get('/api/fleet/relays/jobs/{identity}',tags=['Fleet'])
    def job(identity:str,admin=Depends(Admin.check_sudo_admin)):
        return call(service.job,identity)

    @app.delete('/api/fleet/relays/routes/{identity}',tags=['Fleet'])
    def remove(identity:str,admin=Depends(Admin.check_sudo_admin)):
        return call(service.remove_route,identity)

    @app.post('/api/fleet/relays/routes/{identity}/check',tags=['Fleet'])
    def check_route(identity:str,admin=Depends(Admin.check_sudo_admin)):
        return call(service.recheck_route,identity)

    @app.post('/api/fleet/relays/{identity}/telemetry',tags=['Fleet'])
    def telemetry(identity:str,data:EntryPacket,authorization:str=Header(default='')):
        try:return service.ingest(identity,authorization,data.model_dump(exclude_none=True))
        except PermissionError:raise HTTPException(401,'Токен входного сервера отклонён') from None
        except UnknownRelayService:
            raise HTTPException(409,{'code':'relay_service_unregistered',
                'message':'Служба наблюдения отсутствует в регистрации входного сервера'}) from None
        except (ProvisionError,ValueError):raise HTTPException(409,'Наблюдение не принято. Проверьте регистрацию входного сервера') from None
