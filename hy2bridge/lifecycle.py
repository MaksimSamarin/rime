"""Scoped node removal from the active panel database; no remote host wipe."""
import hashlib
import json
import threading
from functools import wraps


class DeleteConflict(ValueError):
    pass


class Lifecycle:
    def __init__(self,store):
        self.store=store;self.guard=threading.RLock()
        self.disconnect=lambda native_id:None
        self.invalidate=lambda aliases:None
        self.restore=lambda native_id:None
        self.quota_guard=None

    @staticmethod
    def exists(db,table):
        return db.execute('SELECT 1 FROM sqlite_master WHERE type="table" AND name=?',(table,)).fetchone() is not None

    def plan(self,node,db=None):
        if node=='xray:local':raise DeleteConflict('Сервер самой панели удаляется отдельной процедурой')
        if db is None:
            with self.store.connection() as connection:return self.plan(node,connection)
        native_id=None
        if node.startswith('xray:'):
            try:native_id=int(node[5:])
            except ValueError:raise DeleteConflict('Некорректный идентификатор ноды')
            row=db.execute('SELECT id,name,address,port,api_port,created_at FROM nodes WHERE id=?',(native_id,)).fetchone()
        else:row=db.execute('SELECT id,name,address,protocol,created_at FROM fleet_inventory WHERE id=?',(node,)).fetchone()
        if row is None:return None
        identity=dict(row);aliases={node};jobs=[];hosts=set();managed=[]
        if self.exists(db,'fleet_managed'):
            managed=db.execute("SELECT * FROM fleet_managed WHERE id=? OR ('xray:'||native_id)=?",(node,node)).fetchall()
            for item in managed:
                aliases.add(item['id']);jobs.append(item['id'])
                if item['host_id'] is not None:hosts.add(item['host_id'])
        if self.exists(db,'fleet_host_nodes'):
            for item in db.execute('SELECT host_id,node FROM fleet_host_nodes').fetchall():
                if item['node'] in aliases:hosts.add(item['host_id'])
        if self.exists(db,'fleet_managed'):
            if any(item['host_id'] in hosts and item['id'] not in aliases for item in db.execute('SELECT id,host_id FROM fleet_managed').fetchall()):
                raise DeleteConflict('Подписочный адрес используется другой нодой; сначала разделите привязки')
        if native_id is not None and not hosts:
            raise DeleteConflict('Сначала свяжите адреса подписок с этой нодой; безопасно определить их автоматически не удалось')
        external=[]
        if self.exists(db,'fleet_external_links'):
            external=[dict(r) for r in db.execute('SELECT * FROM fleet_external_links WHERE node=?',(node,)).fetchall()]
        observer=None
        if self.exists(db,'fleet_observers'):
            r=db.execute('SELECT * FROM fleet_observers WHERE node=?',(node,)).fetchone();observer=dict(r) if r else None
            if observer and observer['kind']=='legacy_hy2' and not external:
                raise DeleteConflict('Адрес этой Hy2-ноды ещё задан внешней добавкой подписки. Сначала перенесите адрес в управляемый реестр.')
        if self.exists(db,'fleet_barriers'):
            for barrier in db.execute('SELECT targets FROM fleet_barriers').fetchall():
                if aliases.intersection(json.loads(barrier['targets'])):raise DeleteConflict('Идёт безопасный сброс расхода; дождитесь его завершения')
        if self.exists(db,'fleet_jobs'):
            for job in jobs:
                row=db.execute('SELECT state FROM fleet_jobs WHERE id=?',(job,)).fetchone()
                if row and row['state']=='running':raise DeleteConflict('Установка ноды ещё выполняется')
        labels={}
        if self.exists(db,'fleet_node_labels'):
            labels={r['node']:r['name'] for r in db.execute('SELECT node,name FROM fleet_node_labels').fetchall()}
        name=labels.get(node,managed[0]['name'] if managed else identity['name'])
        endpoints=[dict(r) for hid in sorted(hosts) for r in db.execute('SELECT id,remark,address,port FROM hosts WHERE id=?',(hid,)).fetchall()]
        affected=0
        if self.exists(db,'fleet_user_meta'):
            affected=sum(bool(aliases.intersection(json.loads(r['nodes']))) for r in db.execute('SELECT nodes FROM fleet_user_meta WHERE nodes IS NOT NULL').fetchall())
        stable={'identity':identity,'aliases':sorted(aliases),'hosts':endpoints,'external':external,'observer':observer,'name':name}
        revision=hashlib.sha256(json.dumps(stable,sort_keys=True,default=str).encode()).hexdigest()
        return {'node':node,'name':name,'address':identity['address'],'native_id':native_id,'aliases':sorted(aliases),'jobs':jobs,
                'host_ids':sorted(hosts),'subscription_addresses':endpoints,'external_endpoints':len(external),
                'restricted_user_links':affected,'confirmation':revision,
                'effects':['Запись ноды и её доступы в панели','Связанные адреса из новых ответов подписки','История, метрики, события, проверки и квоты этой ноды','Связи этой ноды в выборе пользователей']+(['Xray этой ноды отключится от панели; активные подключения на ней прервутся'] if native_id is not None else []),
                'retained':['Общие пользователи, UUID, лимиты и общий расход','Другие ноды и их данные','Существующие резервные копии и внешние журналы','VPS, DNS и службы удалённого сервера; их очистка выполняется отдельно']}

    def delete(self,node,name,confirmation,acknowledge_remote):
        if not acknowledge_remote:raise DeleteConflict('Подтвердите границы удаления: удалённый сервер и резервные копии остаются')
        with self.guard:
            if self.quota_guard and not self.quota_guard.acquire(blocking=False):raise DeleteConflict('Идёт применение квоты; повторите после завершения')
            try:return self._delete(node,name,confirmation)
            finally:
                if self.quota_guard:self.quota_guard.release()

    def _delete(self,node,name,confirmation):
            preview=self.plan(node)
            if preview is None:return {'deleted':True,'already_absent':True}
            if name!=preview['name'] or confirmation!=preview['confirmation']:raise DeleteConflict('Нода изменилась или имя не совпало; заново откройте подтверждение')
            # Native accounting and health jobs use the same guard. No network
            # call is performed while a SQLite read/write transaction is open.
            if preview['native_id'] is not None:self.disconnect(preview['native_id'])
            try:
                self._purge(node,confirmation,preview)
            except BaseException:
                if preview['native_id'] is not None:self.restore(preview['native_id'])
                raise
            self.invalidate(preview['aliases'])
            return {'deleted':True,'already_absent':False,'users_deleted':0,'remote_files_erased':False,'provider_instance_deleted':False,'backup_archives_changed':False}

    def _purge(self,node,confirmation,preview):
            with self.store.connection(write=True) as db:
                current=self.plan(node,db)
                if not current or current['confirmation']!=confirmation:raise DeleteConflict('Нода изменилась во время удаления')
                aliases=current['aliases'];marks=','.join('?' for _ in aliases)
                auths=set()
                for table in ('hy2_totals','hy2_hourly'):
                    if self.exists(db,table):auths.update(r['auth'] for r in db.execute('SELECT DISTINCT auth FROM '+table+' WHERE node IN ('+marks+')',aliases).fetchall())
                if self.exists(db,'fleet_events') and self.exists(db,'fleet_event_actions'):
                    ids={str(r['id']) for r in db.execute('SELECT id FROM fleet_events WHERE node IN ('+marks+')',aliases).fetchall()}
                    keys=[r['event_key'] for r in db.execute('SELECT event_key FROM fleet_event_actions').fetchall()]
                    for key in keys:
                        if key in ids or key in {'job:'+j for j in current['jobs']} or any(key.startswith('offline:'+a+':') for a in aliases):
                            db.execute('DELETE FROM fleet_event_actions WHERE event_key=?',(key,))
                for table,column in [('fleet_health','node'),('fleet_health_history','node'),('fleet_events','node'),('fleet_checks','node'),
                    ('fleet_xray_hourly','node'),('fleet_node_traffic','node'),('fleet_node_quotas','node'),('fleet_quota_audit','node'),
                    ('fleet_node_labels','node'),('fleet_host_nodes','node'),('fleet_observers','node'),('fleet_observer_sources','node'),('fleet_meters','node'),
                    ('fleet_external_links','node'),('fleet_meter_state','node'),('fleet_meter_samples','node'),('fleet_meter_gaps','node'),
                    ('hy2_nodes','node'),('hy2_totals','node'),('hy2_hourly','node'),('hy2_samples','node'),('fleet_managed','id'),('fleet_inventory','id')]:
                    if self.exists(db,table):db.execute('DELETE FROM '+table+' WHERE '+column+' IN ('+marks+')',aliases)
                if self.exists(db,'fleet_jobs'):
                    for job in current['jobs']:db.execute('DELETE FROM fleet_jobs WHERE id=?',(job,))
                if self.exists(db,'fleet_user_meta'):
                    for row in db.execute('SELECT user_id,nodes FROM fleet_user_meta WHERE nodes IS NOT NULL').fetchall():
                        selected=json.loads(row['nodes']);remaining=[n for n in selected if n not in aliases]
                        if remaining!=selected:db.execute('UPDATE fleet_user_meta SET nodes=? WHERE user_id=?',(json.dumps(remaining),row['user_id']))
                for auth in auths:
                    if not db.execute('SELECT 1 FROM hy2_totals WHERE auth=? UNION SELECT 1 FROM hy2_hourly WHERE auth=?',(auth,auth)).fetchone():
                        db.execute('DELETE FROM hy2_identities WHERE auth=?',(auth,))
                for hid in current['host_ids']:
                    if self.exists(db,'fleet_host_nodes'):db.execute('DELETE FROM fleet_host_nodes WHERE host_id=?',(hid,))
                    db.execute('DELETE FROM hosts WHERE id=?',(hid,))
                if current['native_id'] is not None:
                    for table in ('node_user_usages','node_usages'):
                        if self.exists(db,table):db.execute('DELETE FROM '+table+' WHERE node_id=?',(current['native_id'],))
                    db.execute('DELETE FROM nodes WHERE id=?',(current['native_id'],))

    def install_runtime(self,scheduler,xray,quotas,provisioner):
        from app.db import GetDB,crud
        from app.models.node import NodeStatus
        self.guard=xray.operations.NODE_LIFECYCLE_LOCK
        self.quota_guard=quotas.lock
        self.disconnect=xray.operations.remove_node
        def restore(node_id):
            with GetDB() as db:
                row=crud.get_node_by_id(db,node_id)
                enabled=row is not None and row.status!=NodeStatus.disabled
            if enabled:xray.operations.connect_node(node_id)
        self.restore=restore
        def invalidate(aliases):
            for node in aliases:quotas.enforced.pop(node,None);quotas.configured.pop(node,None)
            with provisioner.lock:
                for node in aliases:
                    plan=provisioner.plans.pop(node,None)
                    if plan:plan['data'].clear()
            xray.hosts.update()
        self.invalidate=invalidate
        # Collection can remain concurrent. Serialize only per-node persistence
        # with deletion and skip snapshots belonging to an already removed node.
        for job in scheduler.get_jobs():
            if job.func.__name__ not in ('record_user_usages','record_node_usages'):continue
            function=job.func
            while hasattr(function,'__wrapped__'):function=function.__wrapped__
            namespace=function.__globals__
            for name in ('record_user_stats','record_node_stats'):
                original=namespace.get(name)
                if not original or getattr(original,'_rime_lifecycle_guard',False):continue
                def guarded(fn):
                    @wraps(fn)
                    def call(params,node_id,*args,**kwargs):
                        with self.guard:
                            if node_id is not None:
                                with self.store.connection() as db:
                                    if not db.execute('SELECT 1 FROM nodes WHERE id=?',(node_id,)).fetchone():return
                            return fn(params,node_id,*args,**kwargs)
                    call._rime_lifecycle_guard=True;return call
                namespace[name]=guarded(original)
