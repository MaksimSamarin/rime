"""Unified administrative console: users, tags, node details and incident workflow."""
import json
import time
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError


class UserEdit(BaseModel):
    tags: list[str] = Field(default_factory=list, max_length=20)
    nodes: list[str] | None = None
    data_limit: int = Field(default=0,ge=0,le=2**60)
    expire: int = Field(default=0,ge=0)
    note: str = Field(default='',max_length=500)
    status: Literal['active','disabled','on_hold','limited','expired'] = 'active'


class UserNew(UserEdit):
    username: str = Field(pattern=r'^[a-z0-9_]{3,32}$')


class IncidentEdit(BaseModel):
    acknowledged: bool = True
    note: str = Field(default='',max_length=1000)


class NodeEdit(BaseModel):
    name: str = Field(min_length=1,max_length=64)
    host_ids: list[int] | None = None
    address: str | None = Field(default=None,min_length=1,max_length=253)
    port: int | None = Field(default=None,ge=1,le=65535)
    api_port: int | None = Field(default=None,ge=1,le=65535)
    vpn_port: int | None = Field(default=None,ge=1,le=65535)
    usage_coefficient: float | None = Field(default=None,gt=0,le=100)
    enabled: bool | None = None
    active: bool | None = None


class NodeQuotaEdit(BaseModel):
    limit_bytes: int = Field(ge=0,le=2**60)
    direction: Literal['outgoing','total'] = 'total'
    period: Literal['none','daily','weekly','monthly'] = 'monthly'
    reset_date: date | None = None
    action: Literal['warn','stop'] = 'warn'


def install(app,store,operations,access):
    from app import scheduler,xray
    from app.db import GetDB,crud
    from app.db.models import User
    from app.models.admin import Admin
    from app.models.user import UserCreate,UserModify,UserResponse,NextPlanModel
    from app.models.node import NodeModify,NodeStatus

    with store.connection(write=True) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS fleet_event_actions(
            event_key TEXT PRIMARY KEY, acknowledged INTEGER NOT NULL,note TEXT NOT NULL,
            actor TEXT NOT NULL,updated_at REAL NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS fleet_health_history(
            node TEXT NOT NULL,minute INTEGER NOT NULL,state TEXT NOT NULL,metrics TEXT NOT NULL,
            PRIMARY KEY(node,minute))''')

    def sample():
        minute=int(time.time())//60*60
        nodes=operations.nodes()
        with store.connection(write=True) as db:
            for node in nodes:
                exists=(node['id']=='xray:local' or (db.execute('SELECT 1 FROM nodes WHERE id=?',(int(node['id'][5:]),)).fetchone() if node['id'].startswith('xray:') else db.execute('SELECT 1 FROM fleet_inventory WHERE id=?',(node['id'],)).fetchone()))
                if not exists:continue
                history_metrics=dict(node['metrics'])
                if history_metrics.get('connection_details'):
                    history_metrics['connection_details']={k:v for k,v in history_metrics['connection_details'].items() if k not in ('groups','other_connections')}
                db.execute('INSERT OR REPLACE INTO fleet_health_history VALUES(?,?,?,?)',
                    (node['id'],minute,node['state'],json.dumps(history_metrics)))
                if node.get('status_source') in ('marzban','local'):
                    existing=db.execute("SELECT id FROM fleet_events WHERE node=? AND code='native_unavailable' AND resolved_at IS NULL",(node['id'],)).fetchone()
                    if node['state']=='offline':
                        if existing:db.execute('UPDATE fleet_events SET last_at=?,occurrences=occurrences+1 WHERE id=?',(time.time(),existing['id']))
                        else:db.execute("INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,'native_unavailable','error',?,?)",(node['id'],time.time(),time.time()))
                    elif node['state']=='healthy' and existing:db.execute('UPDATE fleet_events SET resolved_at=? WHERE id=?',(time.time(),existing['id']))
            db.execute('DELETE FROM fleet_health_history WHERE minute<?',(minute-7*86400,))
    scheduler.add_job(sample,'interval',seconds=60,id='rime_health_history',replace_existing=True)
    app.add_event_handler('startup',sample)

    def node_by_id(node):
        found=next((n for n in operations.nodes() if n['id']==node),None)
        if found is None:raise HTTPException(404,'Нода не найдена')
        return found

    def validate(data):
        tags=[t.strip() for t in data.tags if t.strip()]
        if any(len(t)>40 for t in tags):raise HTTPException(422,'Тег не длиннее 40 символов')
        if data.nodes is not None:
            if any(n.get('monitoring_only') for n in operations.nodes()):
                raise HTTPException(409,'Выбор нод станет доступен после подключения управления существующих Hy2-нод. Сейчас используйте «Все ноды».')
            valid={n['id'] for n in operations.nodes()}|{'xray:local'}
            if not data.nodes or not set(data.nodes)<=valid:
                raise HTTPException(422,'Выберите хотя бы одну существующую ноду или «Все ноды»')

    def serialize(user):
        value=UserResponse.model_validate(user).model_dump(mode='json')
        value.update(access.metadata(user.id))
        return value

    @app.get('/api/fleet/users',tags=['Fleet'])
    def users(q:str='',tag:str='',offset:int=Query(0,ge=0),limit:int=Query(30,ge=1,le=100),
              admin:Admin=Depends(Admin.check_sudo_admin)):
        with GetDB() as db:
            query=db.query(User)
            if q:query=query.filter(User.username.contains(q,autoescape=True))
            if tag:
                with store.connection() as conn:
                    ids=[r['user_id'] for r in conn.execute('''SELECT m.user_id FROM fleet_user_meta m
                        JOIN users u ON u.id=m.user_id AND u.created_at=m.user_created, json_each(m.tags) t WHERE t.value=?''',(tag,))]
                query=query.filter(User.id.in_(ids))
            return {'total':query.count(),'users':[serialize(u) for u in query.order_by(User.username).offset(offset).limit(limit)]}

    @app.get('/api/fleet/tags',tags=['Fleet'])
    def tags(admin:Admin=Depends(Admin.check_sudo_admin)):
        with store.connection() as db:
            return [dict(r) for r in db.execute('''SELECT t.value AS tag,COUNT(*) AS users FROM fleet_user_meta m
                JOIN users u ON u.id=m.user_id AND u.created_at=m.user_created,json_each(m.tags) t
                GROUP BY t.value ORDER BY t.value COLLATE NOCASE''')]

    @app.get('/api/fleet/users/{username}',tags=['Fleet'])
    def user(username:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        with GetDB() as db:
            user=crud.get_user(db,username)
            if not user:raise HTTPException(404,'Пользователь не найден')
            return serialize(user)

    @app.post('/api/fleet/users',tags=['Fleet'])
    def create(data:UserNew,bg:BackgroundTasks,admin:Admin=Depends(Admin.check_sudo_admin)):
        validate(data)
        if data.status not in ('active','disabled'):raise HTTPException(422,'Начальный статус: active или disabled')
        if 'vless' not in xray.config.inbounds_by_protocol:raise HTTPException(409,'Сначала настройте VLESS inbound для выдачи идентификаторов пользователей')
        with GetDB() as db:
            try:
                # Explicit input runs UserCreate's inbound expansion validator;
                # an omitted Pydantic default would exclude every VLESS inbound.
                initial=UserCreate(username=data.username,proxies={'vless':{}},inbounds={},status='active').model_copy(update={'status':'disabled'})
                user=crud.create_user(db,initial,
                    admin=crud.get_admin(db,admin.username))
            except IntegrityError:
                db.rollback();raise HTTPException(409,'Такое имя уже существует')
            # Start disabled: a selected-node account is never briefly granted all nodes.
            access.save(user.id,data.tags,data.nodes)
            user=crud.update_user(db,user,UserModify(**data.model_dump(exclude={'username','tags','nodes'})))
            if data.status=='active':bg.add_task(xray.operations.add_user,user)
            return serialize(user)

    @app.put('/api/fleet/users/{username}',tags=['Fleet'])
    def edit(username:str,data:UserEdit,bg:BackgroundTasks,admin:Admin=Depends(Admin.check_sudo_admin)):
        validate(data)
        with GetDB() as db:
            user=crud.get_user(db,username)
            if not user:raise HTTPException(404,'Пользователь не найден')
            payload=data.model_dump(exclude={'tags','nodes'})
            if data.status in ('limited','expired','on_hold'):
                if data.status!=user.status:raise HTTPException(422,'Этот статус назначается автоматически')
                payload.pop('status')
            if user.next_plan:
                payload['next_plan']=NextPlanModel(**{k:getattr(user.next_plan,k) for k in
                    ('data_limit','expire','add_remaining_traffic','fire_on_either')})
            modified=UserModify(**payload)
            access.save(user.id,data.tags,data.nodes)
            user=crud.update_user(db,user,modified)
            bg.add_task(xray.operations.update_user if user.status in ('active','on_hold') else xray.operations.remove_user,user)
            return serialize(user)

    @app.get('/api/fleet/monitoring',tags=['Fleet'])
    def monitoring(node:str|None=None,hours:int=Query(24,ge=1,le=168),admin:Admin=Depends(Admin.check_sudo_admin)):
        nodes=operations.nodes()
        with store.connection() as db:
            sql='SELECT * FROM fleet_health_history WHERE minute>=?';params=[time.time()-hours*3600]
            if node:sql+=' AND node=?';params.append(node)
            rows=[{**dict(r),'metrics':json.loads(r['metrics'])} for r in db.execute(sql+' ORDER BY minute',params)]
        return {'nodes':[n for n in nodes if not node or n['id']==node],'history':rows,'retention_days':7,
                'sample_seconds':60,'generated_at':time.time()}

    @app.get('/api/fleet/nodes/{node}',tags=['Fleet'])
    def detail(node:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        result=node_by_id(node)
        with store.connection() as db:
            managed=db.execute('''SELECT id,domain,port AS vpn_port,active,native_id,host_id FROM fleet_managed
                WHERE id=? OR ('xray:'||native_id)=?''',(node,node)).fetchone()
            result['settings']=dict(managed) if managed else {}
            if result.get('monitoring_only'):
                observer=db.execute('SELECT domain,port FROM fleet_observers WHERE node=?',(node,)).fetchone()
                result['settings']={'domain':observer['domain'],'vpn_port':observer['port']}
            if node.startswith('xray:') and node!='xray:local':
                row=db.execute('SELECT port,api_port,usage_coefficient,status FROM nodes WHERE id=?',(int(node[5:]),)).fetchone()
                if row:result['settings'].update(dict(row))
            result['hosts']=[dict(r) for r in db.execute('''SELECT h.id,h.remark,h.address,
                COALESCE(m.node,'xray:'||f.native_id) AS node FROM hosts h
                LEFT JOIN fleet_host_nodes m ON m.host_id=h.id LEFT JOIN fleet_managed f ON f.host_id=h.id
                ORDER BY h.id''')] if result['protocol']!='hysteria2' else []
            if node=='xray:local':
                # Preserve any real local VPN mappings, but do not offer every
                # remote subscription endpoint as a hub configuration option.
                result['local_vpn_hosts']=[h for h in result['hosts'] if h['node']==node]
                result['hosts']=[]
        result['events']=[e for e in operations.events(250) if e['node']==node]
        result['checks']=operations.checks(node)
        now=datetime.now(timezone.utc)
        result['traffic']=operations.traffic(now-timedelta(days=7),now,node=node)
        return result

    @app.get('/api/fleet/nodes/{node}/connections',tags=['Fleet'])
    def connection_detail(node:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        result=node_by_id(node)
        return {'node':node,'name':result['name'],'protocol':result['protocol'],'received_at':result['seen_at'],
            'state':result['metrics'].get('connection_metric_state','unavailable'),'count':result['metrics'].get('online_connections'),
            'details':result['metrics'].get('connection_details')}

    @app.put('/api/fleet/nodes/{node}',tags=['Fleet'])
    def node_edit(node:str,data:NodeEdit,bg:BackgroundTasks,admin:Admin=Depends(Admin.check_sudo_admin)):
        found=node_by_id(node)
        if found.get('monitoring_only') and any(getattr(data,key) is not None for key in
                ('host_ids','address','port','api_port','vpn_port','usage_coefficient','enabled','active')):
            raise HTTPException(409,'Эта Hy2-нода подключена только к мониторингу. Изменение VPN требует переноса управления.')
        if node=='xray:local' and any(getattr(data,key) is not None for key in
                ('host_ids','address','port','api_port','vpn_port','usage_coefficient','enabled','active')):
            raise HTTPException(422,'У хаба нет настроек выходной ноды. Локальные VPN-привязки сохраняются отдельно.')
        with store.connection(write=True) as db:
            db.execute('INSERT OR REPLACE INTO fleet_node_labels VALUES(?,?)',(node,data.name))
            if data.host_ids is not None:
                valid={r['id'] for r in db.execute('SELECT id FROM hosts')}
                if found['protocol']=='hysteria2' or not set(data.host_ids)<=valid:raise HTTPException(422,'Некорректные адреса подписки')
                occupied={r['host_id'] for r in db.execute('SELECT host_id FROM fleet_host_nodes WHERE node<>?',(node,))}
                if occupied & set(data.host_ids):raise HTTPException(409,'Адрес уже привязан к другой ноде')
                db.execute('DELETE FROM fleet_host_nodes WHERE node=?',(node,))
                for hid in data.host_ids:db.execute('INSERT INTO fleet_host_nodes VALUES(?,?)',(hid,node))
            db.execute('UPDATE fleet_inventory SET name=? WHERE id=?',(data.name,node))
            if data.address is not None:db.execute('UPDATE fleet_inventory SET address=? WHERE id=?',(data.address,node))
            if data.enabled is not None:db.execute('UPDATE fleet_inventory SET enabled=? WHERE id=?',(int(data.enabled),node))
            db.execute("UPDATE fleet_managed SET name=? WHERE id=? OR ('xray:'||native_id)=?",(data.name,node,node))
            managed=db.execute("SELECT id,protocol FROM fleet_managed WHERE id=? OR ('xray:'||native_id)=?",(node,node)).fetchone()
            if managed:
                if data.address is not None:db.execute('UPDATE fleet_managed SET domain=? WHERE id=?',(data.address,managed['id']))
                if data.vpn_port is not None:db.execute('UPDATE fleet_managed SET port=? WHERE id=?',(data.vpn_port,managed['id']))
                if data.active is not None:db.execute('UPDATE fleet_managed SET active=? WHERE id=?',(int(data.active),managed['id']))
        if node.startswith('xray:') and node!='xray:local':
            with GetDB() as db:
                dbnode=crud.get_node_by_id(db,int(node[5:]))
                if not dbnode:raise HTTPException(404,'Нода не найдена')
                modify=NodeModify(name=data.name,address=data.address,port=data.port,api_port=data.api_port,
                    usage_coefficient=data.usage_coefficient,status=(NodeStatus.connected if data.enabled is not False else NodeStatus.disabled))
                updated=crud.update_node(db,dbnode,modify)
                xray.operations.remove_node(updated.id)
                if updated.status!=NodeStatus.disabled:bg.add_task(xray.operations.connect_node,node_id=updated.id)
        return {'saved':True,'reconnect_scheduled':node.startswith('xray:') and node!='xray:local' and data.enabled is not False}

    @app.post('/api/fleet/nodes/{node}/checks',tags=['Fleet'])
    def node_check(node:str,admin:Admin=Depends(Admin.check_sudo_admin)):
        node_by_id(node)
        try:return operations.request_check(node)
        except ValueError as exc:raise HTTPException(409,str(exc))

    @app.put('/api/fleet/nodes/{node}/quota',tags=['Fleet'])
    def quota_edit(node:str,data:NodeQuotaEdit,bg:BackgroundTasks,admin:Admin=Depends(Admin.check_sudo_admin)):
        if node_by_id(node).get('monitoring_only'):
            raise HTTPException(409,'Учёт и лимиты этой Hy2-ноды ещё обслуживает прежний мост')
        from .quotas import current
        from config import DISABLE_RECORDING_NODE_USAGE
        if node.startswith('xray:') and data.limit_bytes and DISABLE_RECORDING_NODE_USAGE:
            raise HTTPException(409,'Для лимитов Xray включите запись расхода нод')
        settings=data.model_dump(exclude={'reset_date'})
        settings['reset_at']=datetime.combine(data.reset_date,datetime.min.time(),tzinfo=timezone.utc).timestamp() if data.reset_date else None
        try:result=current.save(node,settings,admin.username)
        except ValueError as exc:raise HTTPException(422,str(exc))
        bg.add_task(current.reconcile)
        return result

    @app.post('/api/fleet/nodes/{node}/quota/reset',tags=['Fleet'])
    def quota_reset(node:str,bg:BackgroundTasks,admin:Admin=Depends(Admin.check_sudo_admin)):
        if node_by_id(node).get('monitoring_only'):
            raise HTTPException(409,'Учёт и лимиты этой Hy2-ноды ещё обслуживает прежний мост')
        from .quotas import current
        try:result=current.reset(node,admin.username)
        except ValueError as exc:raise HTTPException(409,str(exc))
        bg.add_task(current.reconcile)
        return result

    @app.put('/api/fleet/events/{event_key}/action',tags=['Fleet'])
    def action(event_key:str,data:IncidentEdit,admin:Admin=Depends(Admin.check_sudo_admin)):
        event=next((e for e in operations.events(1000) if str(e['id'])==event_key),None)
        if not event:raise HTTPException(404,'Событие не найдено; обновите список')
        with store.connection(write=True) as db:
            db.execute('INSERT OR REPLACE INTO fleet_event_actions VALUES(?,?,?,?,?)',
                (event_key,int(data.acknowledged),data.note,admin.username,time.time()))
        return {'saved':True}
