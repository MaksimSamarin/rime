"""Transactional removal of one managed proxy and its associated relay rules."""
import json
import os
from pathlib import Path
import secrets
import threading
import time
from copy import deepcopy

from .provision import ProvisionError
from .proxy_service import ProxyReconcile, ProxyDeploy


class ProxyDeletion:
    def __init__(self, proxy):
        self.proxy = proxy
        self.store = proxy.store
        self.plans = {}
        self.relays = None
        with self.store.connection(write=True) as database:
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_proxy_deletions(
                service TEXT PRIMARY KEY,job TEXT NOT NULL,phase TEXT NOT NULL,
                snapshot TEXT NOT NULL,updated_at REAL NOT NULL)''')

    def options(self, identity):
        with self.store.connection() as database:
            row = database.execute('SELECT * FROM fleet_proxy_services WHERE id=?', (identity,)).fetchone()
            if row is None:
                raise ProvisionError('Прокси не найден')
            node = row['node']
            if hasattr(self.proxy,'access_metadata'):
                result=self.proxy.access_metadata(node)
                return {**result,'node':node,'http_port':row['http_port'],'https_port':row['https_port']}
            host = self.proxy.node_reference(database, node)[0]
            managed = database.execute("SELECT id FROM fleet_managed WHERE id=? OR 'xray:'||native_id=?", (node,node)).fetchone()
            context = {}
            if managed:
                job = database.execute('SELECT context FROM fleet_jobs WHERE id=?',(managed['id'],)).fetchone()
                if job:context=json.loads(job['context'])
            result = {'node':node,'host':host,'ssh_port':context.get('ssh_port',22),
                      'username':context.get('username','root'),'fingerprint':context.get('fingerprint'),
                      'http_port':row['http_port'],'https_port':row['https_port']}
        if self.relays and self.relays.has_origin_route(node):
            result.update(self.relays.origin_access(node))
        return result

    def connect(self, node, access):
        if hasattr(self.proxy,'connect'):return self.proxy.connect(access,node)
        return self.proxy.provision.connect(access)

    def plan(self, identity, access):
        with self.store.connection(write=True) as database:
            row = database.execute('SELECT * FROM fleet_proxy_services WHERE id=?', (identity,)).fetchone()
            if row is None:
                raise ProvisionError('Прокси не найден')
            source = dict(row)
            pending = database.execute('SELECT * FROM fleet_proxy_deletions WHERE service=?', (identity,)).fetchone()
            cleanup = not source['active'] and pending and pending['phase'] == 'cleanup_pending'
            if not source['active'] and not cleanup:
                raise ProvisionError('Прокси уже удалён или заменён')
            expected_host, generation = self.proxy.node_identity(source['node'], database)
        self.proxy.require_stable_node(source['node'])
        if hasattr(self.proxy,'validate_access'):
            self.proxy.validate_access(source['node'],access)
        else:
            self.proxy.provision.target(access['host'], access['ssh_port'])
            actual = set(self.proxy.provision.resolve(access['host'], access['ssh_port']))
            expected = set(self.proxy.provision.resolve(expected_host, access['ssh_port']))
            if not actual & expected:
                raise ProvisionError('SSH-адрес должен принадлежать выбранной ноде')
        job = secrets.token_hex(16)
        runtime = source['runtime_id'] or source['id']
        snapshot = None
        if not cleanup:
            with self.connect(source['node'], access) as client:
                snapshot = self.proxy.remote(client, {'id':job,'action':'managed-snapshot',
                    'replace_service':identity,'legacy_managed':bool(source['legacy_squid'])})
        routes = self.relays.proxy_routes(identity) if self.relays else []
        recovery_proxy = deepcopy(self.proxy.recovery.load(source['node'])['proxies'].get(identity))
        public = {'id':job,'ready':True,'expires_at':time.time()+600,'service':identity,
                  'node':source['node'],'operation':'delete','routes':routes,
                  'summary':{'HTTP':source['http_port'],'HTTPS':source['https_port'],'Туннельных правил':len(routes)}}
        record = {'plan':public,'access':access,'source':source,'generation':generation,
                  'snapshot':snapshot,'runtime':runtime,'cleanup':bool(cleanup),'recovery_proxy':recovery_proxy,
                  'delete_job':pending['job'] if cleanup else job}
        with self.proxy.provision.lock:
            expired = [key for key,value in self.plans.items() if value['plan']['expires_at'] < time.time()]
            for key in expired:
                self.plans.pop(key)['access'].clear()
            self.plans[job] = record
        return public

    def deploy(self, job):
        with self.proxy.provision.lock:
            record = self.plans.get(job)
            if not record or record['plan']['expires_at'] < time.time():
                try:
                    self.proxy.job(job)
                    return {'id':job}
                except (ProvisionError,AttributeError):pass
                raise ProvisionError('План удаления истёк. Повторите проверку')
            address = record['access'].get('address') or record['access']['host']
            if address in self.proxy.provision.running:
                raise ProvisionError('На сервере выполняется другая операция')
            try:
                from update_runtime.leases import acquire
                record['_operation_lease'] = acquire(Path(self.store.path).parent / '.updates')
            except BlockingIOError:
                raise ProvisionError('Панель обновляется. Повторите удаление после завершения обновления') from None
            try:
                if self.relays:
                    record['_relay_desired']=self.relays.changes.prepare_proxy_delete(job,record['source']['node'],record['source']['id'])
            except Exception:
                os.close(record.pop('_operation_lease'))
                raise
            self.proxy.provision.running.add(address)
            self.plans.pop(job)
        context = {key:record['access'].get(key) for key in ['host','address','ssh_port','username']}
        context.update(operation='delete',service=record['source']['id'])
        self.proxy.update(job,record['source']['node'],'running','Проверка доступа к серверу',context)
        try:
            threading.Thread(target=self.worker,args=(record,address),daemon=True).start()
        except Exception:
            record['access'].clear()
            with self.proxy.provision.lock:
                self.proxy.provision.running.discard(address)
            os.close(record.pop('_operation_lease'))
            if self.relays and record.get('_relay_desired') is not None:
                self.relays.changes.finish(job,False)
            if self.relays:self.relays.release_entry(record.get('_relay_entry'))
            self.proxy.update(job,record['source']['node'],'failed','Удаление не запущено. Повторите проверку доступа')
            raise
        return {'id':job}

    def worker(self, record, address):
        job = record['plan']['id']
        source = record['source']
        node = source['node']
        stopped = committed = False
        checkpoint=record.get('delete_job',job)
        route_snapshot = None
        final = None
        try:
            self.proxy.require_stable_node(node)
            with self.connect(node, record['access']) as client:
                if not record['cleanup']:
                    self.proxy.update(job,node,'running','Сохранение конфигурации и остановка выбранного прокси')
                    self.proxy.remote(client, {'id':job,'action':'managed-stop','replace_service':source['id'],
                        'legacy_managed':bool(source['legacy_squid']),'managed_fingerprint':record['snapshot']['fingerprint']})
                    stopped = True
                    if self.relays and record.get('_relay_desired') is not None:
                        self.proxy.update(job,node,'running','Удаление связанных правил туннелирования')
                        self.relays.changes.apply(job,record['_relay_desired'])
                    with self.store.connection(write=True) as database:
                        current = database.execute('SELECT * FROM fleet_proxy_services WHERE id=?',(source['id'],)).fetchone()
                        if not current or dict(current) != source or self.proxy.current_generation(database,node) != record['generation']:
                            raise ProvisionError('Прокси или нода изменились во время удаления')
                        if self.relays and record.get('_relay_desired') is not None:
                            self.relays.changes.publish(job,database=database)
                        database.execute('UPDATE fleet_proxy_services SET active=0 WHERE id=?',(source['id'],))
                        profile = self.proxy.recovery.load(node,database)
                        profile['proxies'].pop(source['id'],None)
                        self.proxy.recovery.save(node,profile,database)
                        database.execute('INSERT OR REPLACE INTO fleet_proxy_deletions VALUES(?,?,?,?,?)',
                            (source['id'],job,'cleanup_pending',json.dumps(source),time.time()))
                    self.proxy.remote(client, {'id':job,'action':'managed-delete-commit','replace_service':source['id']})
                    committed = True
                else:
                    result=self.proxy.remote(client,{'id':checkpoint,'action':'managed-delete-resume',
                        'replace_service':source['id'],'legacy_managed':bool(source['legacy_squid'])})
                    if result.get('committed') is not True:
                        raise ProvisionError('Исходная точка удаления прокси не подтверждена')
                    committed=True
                self.proxy.update(job,node,'running','Удаление контейнера и проверка результата')
                result = self.proxy.remote(client, {'id':checkpoint,'action':'managed-delete-finalize',
                    'replace_service':source['id'],'legacy_managed':bool(source['legacy_squid'])})
                if not result.get('removed'):
                    raise ProvisionError('Удаление контейнера не подтверждено')
                with self.store.connection(write=True) as database:
                    database.execute("UPDATE fleet_proxy_deletions SET phase='deleted',updated_at=? WHERE service=?",(time.time(),source['id']))
                final=('succeeded','Прокси и связанные правила туннелирования удалены')
        except Exception:
            restored = False
            if stopped and not committed:
                try:
                    with self.connect(node,record['access']) as client:
                        result = self.proxy.remote(client, {'id':job,'action':'managed-restore','force':True,
                            'replace_service':source['id'],'legacy_managed':bool(source['legacy_squid'])})
                        restored = bool(result.get('restored'))
                    if self.relays and record.get('_relay_desired') is not None:
                        self.relays.changes.rollback(job)
                    if restored:
                        with self.store.connection(write=True) as database:
                            database.execute('UPDATE fleet_proxy_services SET active=1 WHERE id=?',(source['id'],))
                            database.execute('DELETE FROM fleet_proxy_deletions WHERE service=?',(source['id'],))
                            if record['recovery_proxy']:
                                profile = self.proxy.recovery.load(node,database)
                                profile['proxies'][source['id']] = record['recovery_proxy']
                                self.proxy.recovery.save(node,profile,database)
                except Exception:
                    restored = False
            final=('rolled_back' if restored else 'failed',
                'Удаление отменено, предыдущая установка восстановлена' if restored else 'Операция удаления требует сверки. Повторите проверку')
        finally:
            if self.relays and record.get('_relay_desired') is not None:
                try:self.relays.changes.finish(job,committed)
                except Exception:
                    final=('failed','Служба обработана, восстановление правил входа требует сверки')
            if self.relays:self.relays.release_entry(record.get('_relay_entry'))
            record['access'].clear()
            with self.proxy.provision.lock:
                self.proxy.provision.running.discard(address)
            lease = record.pop('_operation_lease', None)
            if lease is not None:os.close(lease)
        if final:self.proxy.update(job,node,*final)


def install(app, proxy):
    from fastapi import Depends, HTTPException
    from app.models.admin import Admin
    deletion = ProxyDeletion(proxy)

    @app.get('/api/fleet/proxy/{identity}/delete/options',tags=['Fleet'])
    def options(identity:str,admin=Depends(Admin.check_sudo_admin)):
        try:return deletion.options(identity)
        except ProvisionError as error:raise HTTPException(404,str(error)) from None

    @app.post('/api/fleet/proxy/{identity}/delete/plan',tags=['Fleet'])
    def plan(identity:str,access:ProxyReconcile,admin=Depends(Admin.check_sudo_admin)):
        try:return deletion.plan(identity,access.model_dump())
        except ProvisionError as error:raise HTTPException(409,str(error)) from None

    @app.post('/api/fleet/proxy/delete/deploy',tags=['Fleet'])
    def deploy(data:ProxyDeploy,admin=Depends(Admin.check_sudo_admin)):
        try:return deletion.deploy(data.plan_id)
        except ProvisionError as error:raise HTTPException(409,str(error)) from None

    return deletion
