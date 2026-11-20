"""Recoverable forwarding changes coordinated with node and proxy operations."""
from copy import deepcopy
import json
import secrets
import time

from .provision import ProvisionError
from .relay_control import RelayPortConflict, allocate_ports, certificate_covers, forwarding_service, canonical_service


class RelayChanges:
    def __init__(self, relays):
        self.relays = relays
        self.store = relays.store
        self.suspended_management = set()
        with self.store.connection(write=True) as database:
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_changes(
                id TEXT PRIMARY KEY,kind TEXT NOT NULL,node TEXT NOT NULL,entry TEXT NOT NULL,
                before TEXT NOT NULL,after TEXT,phase TEXT NOT NULL,updated_at REAL NOT NULL)''')
            database.execute('CREATE TABLE IF NOT EXISTS fleet_relay_edits(id TEXT PRIMARY KEY,node TEXT NOT NULL,state TEXT NOT NULL)')
            database.execute("UPDATE fleet_tunnels SET state='needs_reconcile' WHERE id IN (SELECT json_extract(before,'$.tunnel.id') FROM fleet_relay_changes WHERE phase IN ('applying','applied','needs_reconcile'))")

    def read(self, identity):
        with self.store.connection() as database:
            row = database.execute('SELECT * FROM fleet_relay_changes WHERE id=?',(identity,)).fetchone()
        return dict(row) if row else None

    def pending(self, identity):
        row=self.read(identity)
        return row if row and row['phase'] not in ('committed','rolled_back','abandoned') else None

    def prepare(self, identity, node, kind):
        with self.relays.lock:
            previous=self.read(identity)
            if previous and previous['phase']=='abandoned':
                if previous['node']!=node:raise ProvisionError('Изменился владелец прежней операции')
                return None
            if previous and (previous['node']!=node or previous['phase'] not in ['committed','rolled_back']):
                raise ProvisionError('Предыдущее изменение маршрута требует завершения сверки')
            before=self.snapshot(node)
            if before is None:return None
            route=before['tunnel']
            if route['entry'] in self.relays.busy:
                raise ProvisionError('Дождитесь завершения другой операции на входном сервере')
            with self.store.connection(write=True) as database:
                database.execute('INSERT OR REPLACE INTO fleet_relay_changes VALUES(?,?,?,?,?,?,?,?)',
                    (identity,kind,node,route['entry'],json.dumps(before),None,'prepared',time.time()))
            self.relays.busy.add(route['entry'])
            return before

    def snapshot(self, node):
        with self.store.connection() as database:
            route=database.execute("SELECT * FROM fleet_tunnels WHERE node=? AND state='active'",(node,)).fetchone()
            if route is None:return None
            services=[dict(row) for row in database.execute("SELECT * FROM fleet_tunnel_services WHERE tunnel=? AND state='active' ORDER BY id",(route['id'],))]
        return {'tunnel':dict(route),'services':services}

    def proxy_snapshot(self, before, identity, data):
        if before is None or json.loads(before['tunnel']['flags']).get('include_proxies') is False:return None
        desired=deepcopy(before)
        entry=self.relays.entry(before['tunnel']['entry'])
        if data.get('https_port') and not certificate_covers(data['certificate'],entry['domain']):
            raise ProvisionError('Сертификат HTTPS-прокси не покрывает имя выбранного входа')
        previous=data.get('_replace') or {}
        old=[service for service in before['services'] if service['kind']=='proxy' and service['proxy'] in {data.get('replace_service'),identity}]
        desired['services']=[service for service in desired['services'] if service not in old]
        old_names={self.configuration(service)['name'] for service in old}
        occupied={(entry[field],'tcp') for field in ['control_port','metrics_port','api_port','ssh_port'] if field in entry}
        for port,protocol in json.loads(entry.get('health','{}')).get('listeners',[]):occupied.add((port,protocol))
        for service in old:occupied.discard((service['public_port'],service['protocol']))
        for config in self.relays.control(entry).services():
            if config['name'] not in old_names:
                occupied.add((int(config['addr'].rsplit(':',1)[1]),'udp' if config.get('listener',{}).get('type')=='udp' else 'tcp'))
        for mode in ['http','https']:
            port=data.get(mode+'_port')
            if port is None:continue
            original=next((service for service in old if service['origin_port']==(data.get(mode+'_port') if service['proxy']==identity else previous.get(mode+'_port'))),None)
            if original:
                value=deepcopy(original)
                if value['origin_port']!=port:
                    value['origin_port']=port
                    value['config']=json.dumps(forwarding_service(value['id']+'-'+secrets.token_hex(4),value['public_port'],before['tunnel']['origin'],port,'tcp'))
            else:
                public=allocate_ports([{'origin_port':port,'protocol':'tcp'}],occupied)[0]['public_port']
                key=secrets.token_hex(16)
                value={'id':key,'tunnel':before['tunnel']['id'],'entry':entry['id'],'kind':'proxy','protocol':'tcp',
                    'origin_port':port,'public_port':public,'state':'active',
                    'config':json.dumps(forwarding_service(key+'-'+secrets.token_hex(4),public,before['tunnel']['origin'],port,'tcp'))}
            value['proxy']=identity
            occupied.add((value['public_port'],'tcp'))
            desired['services'].append(value)
        desired['tunnel'].update(checked_at=None,result='{}')
        return desired

    @staticmethod
    def proxy_ports(snapshot, identity):
        if snapshot is None:return {}
        return {str(service['origin_port']):service['public_port'] for service in snapshot['services'] if service['proxy']==identity}

    def preview_proxy(self, data, identity):
        return self.proxy_snapshot(self.snapshot(data['node']),identity,data)

    def prepare_proxy(self, data, identity):
        before=self.prepare(identity,data['node'],'proxy')
        if before is None:return None
        try:
            after=self.proxy_snapshot(before,identity,data)
            expected=data.get('_relay_preview')
            if expected is not None and self.proxy_ports(after,identity)!=expected:
                raise ProvisionError('Публичные порты входа изменились после проверки. Подготовьте новый план')
            return after
        except Exception:
            self.finish(identity,False)
            raise

    def prepare_proxy_delete(self, job, node, proxy):
        with self.relays.lock:
            before=self.snapshot(node)
            if before is None or not any(row['proxy']==proxy for row in before['services']):return None
            before=self.prepare(job,node,'proxy-delete')
        if before is None:return None
        desired=deepcopy(before)
        desired['services']=[row for row in desired['services'] if row['proxy']!=proxy]
        desired['tunnel'].update(checked_at=None,result='{}')
        return desired

    def pending_proxy_endpoint(self, identity, port):
        change=self.read(identity)
        if not change or not change['after'] or change['phase'] not in ['applying','applied']:return None
        after=json.loads(change['after'])
        service=next((value for value in after['services'] if value['proxy']==identity and value['origin_port']==port),None)
        if service is None:return None
        return {**service,**{key:self.relays.entry(change['entry'])[key] for key in ['address','domain']}}

    @staticmethod
    def configuration(service):
        return json.loads(service['config'])

    def replace_remote(self, change, desired):
        if change.get('id') and not self.pending(change['id']):
            raise ProvisionError('Изменение маршрута уже завершено или отменено оператором')
        before = json.loads(change['before'])
        after = json.loads(change['after']) if change['after'] else before
        control = self.relays.control(self.relays.entry(change['entry']))
        actual = {value['name']:value for value in control.services()}
        owned = {}
        for snapshot in [before,after]:
            for service in snapshot['services']:
                config=self.configuration(service)
                owned.setdefault(config['name'],[]).append(canonical_service(config))
        wanted = {self.configuration(service)['name']:self.configuration(service) for service in desired['services']}
        # Verify the complete set before the first remote mutation. A name
        # alone never grants ownership after an operator edits that service.
        for name in actual.keys() & owned.keys():
            if canonical_service(actual[name]) not in owned[name]:
                raise ProvisionError('Правило входного сервера изменено вне текущего плана')
        for name in actual.keys() & wanted.keys():
            if canonical_service(actual[name]) != canonical_service(wanted[name]):
                raise ProvisionError('Правила входного сервера изменились вне текущего плана')
        for name in sorted(owned.keys()-wanted.keys()):
            if name in actual:control.remove(name)
        for name,config in wanted.items():
            if name not in actual:
                control.add(config)
                continue
        control.save()

    def write_snapshot(self, database, change, desired):
        row=database.execute('SELECT phase FROM fleet_relay_changes WHERE id=?',(change['id'],)).fetchone()
        if row and row['phase']=='abandoned':
            raise ProvisionError('Маршрут снят оператором. Прежняя публикация не восстанавливается')
        before = json.loads(change['before'])
        after = json.loads(change['after']) if change['after'] else before
        known = {service['id'] for snapshot in [before,after] for service in snapshot['services']}
        for identity in known:
            database.execute("UPDATE fleet_tunnel_services SET state='deleted' WHERE id=?",(identity,))
        fields = ['id','tunnel','entry','kind','proxy','protocol','origin_port','public_port','config','state']
        for service in desired['services']:
            database.execute('INSERT OR REPLACE INTO fleet_tunnel_services('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',
                [service[field] for field in fields])
        route = desired['tunnel']
        database.execute('UPDATE fleet_tunnels SET origin=?,state=?,checked_at=?,result=? WHERE id=?',
            (route['origin'],route['state'],route['checked_at'],route['result'],route['id']))

    def apply(self, identity, desired):
        change = self.read(identity)
        if change is None:return
        if change['phase']=='abandoned':raise ProvisionError('Изменение маршрута отменено оператором')
        with self.store.connection(write=True) as database:
            database.execute("UPDATE fleet_relay_changes SET after=?,phase='applying',updated_at=? WHERE id=?",(json.dumps(desired),time.time(),identity))
            for service in desired['services']:
                # The sender may observe a new service before publication.
                database.execute('''INSERT OR IGNORE INTO fleet_tunnel_services
                    (id,tunnel,entry,kind,proxy,protocol,origin_port,public_port,config,state) VALUES(?,?,?,?,?,?,?,?,?,'preparing')''',
                    [service[field] for field in ['id','tunnel','entry','kind','proxy','protocol','origin_port','public_port','config']])
        change = self.read(identity)
        try:
            original={service['id'] for service in json.loads(change['before'])['services']}
            blocked=set()
            for attempt in range(16):
                try:
                    self.replace_remote(change,desired)
                    break
                except RelayPortConflict as error:
                    service=next((value for value in desired['services'] if self.configuration(value)['name']==error.service),None)
                    if service is None or service['id'] in original or attempt==15:raise
                    blocked.add((service['public_port'],service['protocol']))
                    used=blocked|{(value['public_port'],value['protocol']) for value in desired['services']}
                    control=self.relays.control(self.relays.entry(change['entry']))
                    used.update((int(value['addr'].rsplit(':',1)[1]),'udp' if value.get('listener',{}).get('type')=='udp' else 'tcp') for value in control.services())
                    port=allocate_ports([{'origin_port':10443,'protocol':service['protocol']}],used)[0]['public_port']
                    config=self.configuration(service)
                    config['addr']='0.0.0.0:'+str(port)
                    service.update(public_port=port,config=json.dumps(config))
                    with self.store.connection(write=True) as database:
                        database.execute('UPDATE fleet_relay_changes SET after=? WHERE id=?',(json.dumps(desired),identity))
                        database.execute('UPDATE fleet_tunnel_services SET public_port=?,config=? WHERE id=?',(port,service['config'],service['id']))
                    change=self.read(identity)
        except Exception:
            self.rollback(identity)
            raise
        with self.store.connection(write=True) as database:
            database.execute("UPDATE fleet_relay_changes SET phase='applied',updated_at=? WHERE id=?",(time.time(),identity))

    def publish(self, identity, result=None, database=None):
        if database is None:
            with self.store.connection(write=True) as connection:return self.publish(identity,result,connection)
        row = database.execute('SELECT * FROM fleet_relay_changes WHERE id=?',(identity,)).fetchone()
        if row is None:return
        change = dict(row)
        if change['phase']!='applied':raise ProvisionError('Изменение маршрута не подтверждено входным сервером')
        desired = json.loads(change['after'])
        if result is not None:
            desired['tunnel'].update(result=json.dumps(result),checked_at=time.time())
        self.write_snapshot(database,change,desired)
        database.execute('UPDATE fleet_relay_changes SET after=? WHERE id=?',(json.dumps(desired),identity))

    def rollback(self, identity):
        change = self.read(identity)
        if change is None or change['phase'] in ['rolled_back','committed','abandoned']:return
        before = json.loads(change['before'])
        before['tunnel'].update(checked_at=None,result='{}')
        try:
            if change['after']:self.replace_remote(change,before)
            with self.store.connection(write=True) as database:
                self.write_snapshot(database,change,before)
                database.execute("UPDATE fleet_relay_changes SET phase='rolled_back',updated_at=? WHERE id=?",(time.time(),identity))
        except Exception:
            with self.store.connection(write=True) as database:
                database.execute("UPDATE fleet_relay_changes SET phase='needs_reconcile',updated_at=? WHERE id=? AND phase<>'abandoned'",(time.time(),identity))
                if database.execute("SELECT 1 FROM fleet_relay_changes WHERE id=? AND phase<>'abandoned'",(identity,)).fetchone():
                    database.execute("UPDATE fleet_tunnels SET state='needs_reconcile' WHERE id=?",(before['tunnel']['id'],))
            raise

    def finish(self, identity, accepted, recheck=False):
        change = self.read(identity)
        if change is None or change['phase']=='abandoned':return
        try:
            if accepted:
                desired=json.loads(change['after']) if change['after'] else json.loads(change['before'])
                if recheck:
                    self.replace_remote(change,desired)
                    source,profile=self.relays.source(change['node'])
                    result=self.relays.verify_route(source,profile,self.relays.entry(change['entry']),desired['tunnel']['origin'],desired['services'])
                    desired['tunnel'].update(checked_at=time.time(),result=json.dumps(result))
                with self.store.connection(write=True) as database:
                    self.write_snapshot(database,change,desired)
                    database.execute("UPDATE fleet_relay_changes SET phase='committed',updated_at=? WHERE id=?",(time.time(),identity))
            else:self.rollback(identity)
        finally:
            with self.relays.lock:
                self.relays.busy.discard(change['entry'])
                self.suspended_management.discard(change['node'])
            if change['kind']=='transfer':self.relays.reconnect(change['node'])

    def retarget(self, identity, data):
        change = self.read(identity)
        if change is None:return
        if change['phase']=='abandoned':raise ProvisionError('Изменение маршрута отменено оператором')
        desired = deepcopy(json.loads(change['before']))
        desired['tunnel']['origin'] = data['address']
        source = data['_source']
        for service in desired['services']:
            if service['kind']=='management' and source['native']:
                field = 'service_port' if service['origin_port']==source['native']['port'] else 'api_port'
                service['origin_port'] = data.get('_management_ports',self.relays.settings.get('vless_template',{}))[field]
            if service['kind']=='ssh' and data.get('ssh_port'):service['origin_port'] = data['ssh_port']
            if service['kind']=='vpn' and source['protocol']=='hysteria2' and data.get('vpn_port'):
                service['origin_port']=data['vpn_port']
            old=self.configuration(service)
            target=data['address']+':'+str(service['origin_port'])
            if old['forwarder']['nodes'][0]['addr']!=target:
                service['config'] = json.dumps(forwarding_service(service['id']+'-'+secrets.token_hex(4),service['public_port'],
                    data['address'],service['origin_port'],service['protocol']))
        self.apply(identity,desired)
        result = self.relays.verify_route(source,data['_profile'],self.relays.entry(change['entry']),data['address'],desired['services'])
        self.publish(identity,result)

    def recover(self):
        if getattr(self.relays, 'switches', None):
            self.relays.switches.recover()
        if getattr(self.relays, 'retirements', None):
            self.relays.retirements.recover()
        with self.store.connection() as database:
            changes = [dict(row) for row in database.execute("SELECT * FROM fleet_relay_changes WHERE phase NOT IN ('committed','rolled_back','abandoned')")]
        for change in changes:
            with self.relays.lock:
                if change['entry'] in self.relays.busy:continue
                self.relays.busy.add(change['entry'])
            try:
                current=self.pending(change['id'])
                if current is None:continue
                change=current
                with self.store.connection() as database:
                    table = {'transfer':'fleet_node_transfers','proxy':'fleet_proxy_jobs','proxy-delete':'fleet_proxy_jobs','native-edit':'fleet_relay_edits','inventory-edit':'fleet_relay_edits'}[change['kind']]
                    row = database.execute('SELECT state FROM '+table+' WHERE id=?',(change['id'],)).fetchone()
                accepted=bool(row and row['state']=='succeeded')
                if change['kind']=='proxy-delete':
                    with self.store.connection() as database:
                        exists=database.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_proxy_deletions'").fetchone()
                        committed=database.execute("SELECT 1 FROM fleet_proxy_deletions d JOIN fleet_proxy_services p ON p.id=d.service WHERE d.job=? AND d.phase IN ('cleanup_pending','deleted') AND p.active=0",(change['id'],)).fetchone() if exists else None
                    accepted=accepted or bool(committed)
                self.finish(change['id'],accepted,recheck=accepted)
                if accepted and change['kind']=='transfer':
                    self.relays.provision.update(change['id'],'succeeded','Нода и её входной маршрут перенесены. Прежние доступы сохранены')
            except Exception:
                with self.relays.lock:self.relays.busy.discard(change['entry'])
            finally:
                with self.relays.lock:self.relays.busy.discard(change['entry'])
