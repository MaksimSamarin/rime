"""Prepare a replacement entry before atomically publishing its verified route."""
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import time

from .provision import ProvisionError
from .relay_control import RelayPortConflict, allocate_ports, certificate_covers, forwarding_service, canonical_service


class RelaySwitches:
    phases = (
        ('selection', 'Проверка выбранного входа'),
        ('preparation', 'Подготовка нового маршрута'),
        ('rules', 'Создание правил нового входа'),
        ('payload', 'Проверка VPN и прокси через новый вход'),
        ('publication', 'Публикация проверенного маршрута'),
        ('cleanup', 'Очистка прежнего входа'),
        ('complete', 'Смена входа завершена'),
    )

    def __init__(self, relays):
        self.relays = relays
        self.store = relays.store
        with self.store.connection(write=True) as database:
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_switches(
                id TEXT PRIMARY KEY,tunnel TEXT NOT NULL,node TEXT NOT NULL,
                old_entry TEXT NOT NULL,new_entry TEXT NOT NULL,before TEXT NOT NULL,
                after TEXT NOT NULL,phase TEXT NOT NULL,updated_at REAL NOT NULL,
                retry_at REAL NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '')''')

    def read(self, identity):
        with self.store.connection() as database:
            row = database.execute('SELECT * FROM fleet_relay_switches WHERE id=?', (identity,)).fetchone()
        return dict(row) if row else None

    @staticmethod
    def stable(snapshot):
        value = deepcopy(snapshot)
        for key in ('checked_at', 'result'):
            value['tunnel'].pop(key, None)
        return value

    def snapshot(self, identity, database=None):
        if database is None:
            with self.store.connection() as connection:
                return self.snapshot(identity, connection)
        row = database.execute("SELECT * FROM fleet_tunnels WHERE id=? AND state IN ('active','needs_reconcile')", (identity,)).fetchone()
        if row is None:
            raise ProvisionError('Маршрут не найден или его установка ещё выполняется')
        route = dict(row)
        rows = database.execute('''SELECT * FROM fleet_tunnel_services WHERE tunnel=? AND entry=?
            AND state IN ('active','needs_reconcile') ORDER BY id''', (identity, route['entry'])).fetchall()
        if not rows:
            raise ProvisionError('Состав прежнего маршрута требует сверки')
        return {'tunnel': route, 'services': [dict(item) for item in rows]}

    def require_idle(self, node, database):
        pending = database.execute("SELECT 1 FROM fleet_relay_switches WHERE node=? AND phase IN ('prepared','installing','verified','published')", (node,)).fetchone()
        change = database.execute("SELECT 1 FROM fleet_relay_changes WHERE node=? AND phase NOT IN ('committed','rolled_back','abandoned')", (node,)).fetchone()
        transfer = None
        if database.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_node_transfers'").fetchone():
            transfer = database.execute("SELECT 1 FROM fleet_node_transfers WHERE node=? AND state='switched'", (node,)).fetchone()
        if pending or change or transfer:
            raise ProvisionError('Дождитесь завершения текущего изменения ноды')

    def occupied(self, entry, control):
        used = {(entry[key], 'tcp') for key in ('control_port', 'metrics_port', 'api_port', 'ssh_port') if key in entry}
        used.update((port, protocol) for port, protocol in json.loads(entry.get('health', '{}')).get('listeners', []))
        used.update((int(value['addr'].rsplit(':', 1)[1]), 'udp' if value.get('listener', {}).get('type') == 'udp' else 'tcp') for value in control.services())
        with self.store.connection() as database:
            for row in database.execute("SELECT public_port,protocol FROM fleet_tunnel_services WHERE entry=? AND state IN ('active','preparing','needs_reconcile')", (entry['id'],)):
                used.add((row['public_port'], row['protocol']))
        return used

    def validate_proxies(self, services, profile, entry):
        modes = {}
        for identity in {service['proxy'] for service in services if service['kind'] == 'proxy'}:
            with self.store.connection() as database:
                row = database.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND active=1', (identity,)).fetchone()
            if row is None or identity not in profile['proxies']:
                raise ProvisionError('Прокси исходного маршрута изменился. Повторите проверку')
            self.relays.proxies.clear_password(dict(row))
            modes[identity] = {row[field]: mode for mode, field in [('http','http_port'),('https','https_port')] if row[field] is not None}
            proxy = profile['proxies'][identity]
            https = any(service['proxy'] == identity and service['origin_port'] == row['https_port'] for service in services)
            if https and not certificate_covers(proxy['files']['cert.pem'], entry['domain']):
                raise ProvisionError('Сертификат HTTPS-прокси не покрывает имя нового входного сервера')
        return modes

    def verify_entry_dns(self, entry):
        addresses = self.relays.provision.resolve(entry['domain'], entry.get('ssh_port',22))
        if set(addresses) != {entry['address']}:
            raise ProvisionError('DNS нового входа должен указывать только на его проверенный IPv4')

    def plan(self, identity, entry_id, grace_seconds=None):
        grace_seconds=self.configured_grace(grace_seconds)
        before = self.snapshot(identity)
        route = before['tunnel']
        if route['entry'] == entry_id:
            raise ProvisionError('Этот вход уже используется маршрутом')
        with self.store.connection() as database:
            self.require_idle(route['node'], database)
        entry = self.relays.entry(entry_id)
        previous = self.relays.entry(route['entry'])
        if entry['state'] != 'active' or not entry.get('seen_at') or time.time() - entry['seen_at'] > 60:
            raise ProvisionError('Новый вход должен быть готов и передавать свежие метрики')
        if entry['address'] == route['origin']:
            raise ProvisionError('Входной сервер совпадает с выходной нодой')
        with self.relays.lock:
            if {route['entry'], entry_id} & self.relays.busy:
                raise ProvisionError('На одном из входных серверов выполняется другая операция')
        source, profile = self.relays.source(route['node'])
        if str(source['identity']['created_at']) != route['generation']:
            raise ProvisionError('Экземпляр выходной ноды изменился. Сначала сверьте её регистрацию')
        modes = self.validate_proxies(before['services'], profile, entry)
        self.verify_entry_dns(entry)
        used = self.occupied(entry, self.relays.control(entry))
        services = []
        for old in before['services']:
            preferred = {key: old[key] for key in ('kind', 'proxy', 'protocol', 'origin_port')}
            if old['kind'] == 'proxy':
                preferred['mode'] = modes[old['proxy']][old['origin_port']]
            selected = allocate_ports([{**preferred, 'origin_port': old['public_port']}], used)[0]['public_port']
            used.add((selected, old['protocol']))
            services.append({**preferred, 'public_port': selected, 'previous_public_port': old['public_port']})
        brief = lambda value: {key: value[key] for key in ('id', 'name', 'domain')}
        public = {'kind': 'route-switch', 'route_id': identity, 'node': route['node'], 'name': source['name'],
                  'from_entry': brief(previous), 'to_entry': brief(entry), 'services': services,
                  'domain': entry['domain'], 'origin': route['origin'], 'subscription_refresh_required': True,
                  'grace_seconds':grace_seconds,
                  'message': 'Новый вход проверяется до переключения. Ключи и URL подписок сохраняются. После смены обновите подписку в клиенте.'}
        record = {'kind': 'route-switch', 'entry': entry, 'previous_entry': previous, 'before': before,
                  'source_digest': self.relays.transfer.digest(source),
                  'profile_digest': self.relays.transfer.digest(profile), 'services': services}
        record['grace_seconds']=grace_seconds
        return self.relays.remember_plan(record, public)

    def context(self, record, completed, pending=False):
        phase, label = self.phases[min(completed, 6)]
        return {'operation': 'route-switch', 'route_id': record['tunnel'], 'node': record['node'],
                'from_entry': record['old_entry'], 'to_entry': record['new_entry'],
                'old_cleanup_pending': pending,
                'grace_until': record['retry_at'] if record['phase']=='grace_pending' else None,
                'progress': {'completed': completed, 'total': 7, 'phase': phase, 'label': label}}

    def progress(self, identity, completed, message=None):
        row = self.read(identity)
        context = self.context(row, completed, row['phase'] == 'cleanup_pending')
        self.relays.update(identity, 'running', message or context['progress']['label'], context)

    def save_phase(self, identity, phase, after=None, error='', retry_at=0):
        with self.store.connection(write=True) as database:
            database.execute('UPDATE fleet_relay_switches SET phase=?,after=COALESCE(?,after),updated_at=?,retry_at=?,error=? WHERE id=?',
                             (phase, json.dumps(after) if after is not None else None, time.time(), retry_at, error, identity))

    def start(self, identity, record):
        return self.relays.launch(identity, record['entry']['id'], self.worker, record,
                                  related_entries=(record['previous_entry']['id'],))

    def worker(self, identity, record):
        before = record['before']
        route = before['tunnel']
        entry = self.relays.entry(record['entry']['id'])
        source, profile = self.relays.source(route['node'])
        with self.store.connection() as database:
            self.require_idle(route['node'], database)
            if self.stable(self.snapshot(route['id'], database)) != self.stable(before):
                raise ProvisionError('Прежний маршрут изменился. Повторите выбор нового входа')
        if entry['state'] != 'active' or not entry.get('seen_at') or time.time() - entry['seen_at'] > 60:
            raise ProvisionError('Новый вход перестал передавать свежие метрики')
        if any(entry.get(key) != record['entry'].get(key) for key in ('address', 'domain', 'credential')):
            raise ProvisionError('Настройки нового входа изменились. Повторите проверку')
        if self.relays.transfer.digest(source) != record['source_digest'] or self.relays.transfer.digest(profile) != record['profile_digest']:
            raise ProvisionError('Конфигурация выходной ноды или прокси изменилась')
        self.validate_proxies(before['services'], profile, entry)
        self.verify_entry_dns(entry)
        services = []
        for planned in record['services']:
            key = secrets.token_hex(16)
            config = forwarding_service(key + '-' + secrets.token_hex(4), planned['public_port'], route['origin'], planned['origin_port'], planned['protocol'])
            services.append({key: value for key, value in planned.items() if key != 'previous_public_port'} |
                            {'id': key, 'tunnel': route['id'], 'entry': entry['id'], 'config': json.dumps(config), 'state': 'preparing'})
        after = {'tunnel': {**route, 'entry': entry['id'], 'state': 'active'}, 'services': services,
                 'grace_seconds':self.configured_grace(record.get('grace_seconds'))}
        with self.store.connection(write=True) as database:
            self.require_idle(route['node'], database)
            if self.stable(self.snapshot(route['id'], database)) != self.stable(before):
                raise ProvisionError('Маршрут изменился после проверки')
            database.execute('INSERT INTO fleet_relay_switches(id,tunnel,node,old_entry,new_entry,before,after,phase,updated_at) VALUES(?,?,?,?,?,?,?,?,?)',
                             (identity, route['id'], route['node'], route['entry'], entry['id'], json.dumps(before), json.dumps(after), 'prepared', time.time()))
            for service in services:
                database.execute('INSERT INTO fleet_tunnel_services VALUES(?,?,?,?,?,?,?,?,?,?)',
                                 tuple(service[key] for key in ('id','tunnel','entry','kind','proxy','protocol','origin_port','public_port','config','state')))
        try:
            self.progress(identity, 1)
            control = self.relays.control(entry)
            self.save_phase(identity, 'installing')
            self.install(identity, control, after)
            self.progress(identity, 3)
            result = self.relays.verify_route(source, profile, entry, route['origin'], after['services'])
            if not result.get('passed'):
                raise ProvisionError('Новый вход не подтвердил передачу VPN и прокси')
            after['tunnel'].update(checked_at=time.time(), result=json.dumps(result))
            self.save_phase(identity, 'verified', after)
            self.progress(identity, 4)
            self.publish(identity, source, profile)
        except Exception as error:
            row = self.read(identity)
            if row['phase'] in ('published', 'cleanup_pending', 'complete'):
                raise
            restored = self.rollback(identity)
            message = str(error) if isinstance(error, ProvisionError) else 'Проверка нового входа не завершена'
            if not restored:
                message += '. Подготовленные правила будут очищены после восстановления связи'
            self.relays.update(identity, 'rolled_back' if restored else 'failed', message, self.context(self.read(identity), 3))
            return
        self.progress(identity, 5)
        self.relays.reconnect(route['node'])
        grace=self.grace_seconds(record['previous_entry'],after['grace_seconds'])
        if grace:
            self.save_phase(identity,'grace_pending',retry_at=time.time()+grace)
            cleaned=False
        else:
            cleaned = self.cleanup(identity)
        from .native_management import refresh_management_sources
        refresh_management_sources(self.relays,route['node'])
        self.progress(identity, 6)
        row = self.read(identity)
        message = 'Входной сервер изменён. Обновите подписку в клиенте'
        if row['phase']=='grace_pending':
            message += '. Прежний вход сохранён на льготный период обновления подписок'
        elif not cleaned:
            message += '. Очистка прежнего входа продолжится после восстановления связи'
        self.relays.update(identity, 'succeeded', message, self.context(row, 7, not cleaned))

    def configured_grace(self, value=None):
        if value is None:value=self.relays.settings.get('relay_switch_grace_seconds',86400)
        if type(value) is not int or not 0<=value<=72*3600:
            raise ProvisionError('Льготный период смены входа должен быть от 0 до 72 часов')
        return value

    def grace_seconds(self, entry, value=None):
        value=self.configured_grace(value)
        # Planning and payload verification may exceed a telemetry interval.
        # Decide planned/emergency behavior from the current observation.
        entry=self.relays.entry(entry['id'])
        if not value or entry.get('state')!='active' or not entry.get('seen_at') or time.time()-entry['seen_at']>60:
            return 0
        try:
            control=self.relays.control(entry)
            if hasattr(control,'timeout'):control.timeout=3
            control.services()
        except Exception:return 0
        return value

    def install(self, identity, control, after):
        self.progress(identity, 2)
        for service in after['services']:
            blocked = set()
            for attempt in range(16):
                try:
                    control.add(json.loads(service['config']))
                    break
                except RelayPortConflict:
                    if attempt == 15:
                        raise
                    blocked.add((service['public_port'], service['protocol']))
                    used = blocked | {(value['public_port'], value['protocol']) for value in after['services']}
                    used.update((int(value['addr'].rsplit(':',1)[1]), 'udp' if value.get('listener',{}).get('type') == 'udp' else 'tcp') for value in control.services())
                    port = allocate_ports([{'origin_port':10443,'protocol':service['protocol']}], used)[0]['public_port']
                    config = json.loads(service['config'])
                    config['addr'] = '0.0.0.0:' + str(port)
                    service.update(public_port=port, config=json.dumps(config))
                    with self.store.connection(write=True) as database:
                        database.execute('UPDATE fleet_tunnel_services SET public_port=?,config=? WHERE id=?', (port,service['config'],service['id']))
                        database.execute('UPDATE fleet_relay_switches SET after=?,updated_at=? WHERE id=?', (json.dumps(after),time.time(),identity))
        control.save()

    def publish(self, identity, source, profile):
        row = self.read(identity)
        before, after = json.loads(row['before']), json.loads(row['after'])
        current_source, current_profile = self.relays.source(row['node'])
        self.verify_entry_dns(self.relays.entry(row['new_entry']))
        if self.relays.transfer.digest(current_source) != self.relays.transfer.digest(source) or self.relays.transfer.digest(current_profile) != self.relays.transfer.digest(profile):
            raise ProvisionError('Конфигурация ноды изменилась во время проверки')
        with self.store.connection(write=True) as database:
            current = self.snapshot(row['tunnel'], database)
            if self.stable(current) != self.stable(before):
                raise ProvisionError('Прежний маршрут изменился во время проверки')
            database.execute("UPDATE fleet_tunnel_services SET state='retired' WHERE tunnel=? AND entry=? AND state IN ('active','needs_reconcile')", (row['tunnel'],row['old_entry']))
            database.execute("UPDATE fleet_tunnel_services SET state='active' WHERE id IN (SELECT json_extract(value,'$.id') FROM json_each(?))", (json.dumps(after['services']),))
            route = after['tunnel']
            database.execute("UPDATE fleet_tunnels SET entry=?,state='active',checked_at=?,result=? WHERE id=?", (row['new_entry'],route['checked_at'],route['result'],row['tunnel']))
            database.execute("UPDATE fleet_relay_switches SET phase='published',updated_at=? WHERE id=?", (time.time(),identity))

    def remove_owned(self, entry_id, services):
        entry = self.relays.entry(entry_id)
        control = self.relays.control(entry)
        deadline = time.monotonic() + 10
        if hasattr(control, 'timeout'):
            control.timeout = 3
        actual = {value['name']: {key:item for key,item in value.items() if key != 'status'} for value in control.services()}
        owned={}
        for service in services:
            config=json.loads(service['config'])
            owned.setdefault(config['name'],[]).append(config)
        for name,configs in owned.items():
            if name in actual and not any(canonical_service(actual[name])==canonical_service(config) for config in configs):
                raise ProvisionError('Правило прежнего входа изменено отдельно от панели')
        for name in owned:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProvisionError('Очистка правил продолжится при следующей сверке')
            if hasattr(control, 'timeout'):
                control.timeout = min(3,remaining)
            if name not in actual:
                continue
            control.remove(name)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProvisionError('Сохранение очистки продолжится при следующей сверке')
        if hasattr(control, 'timeout'):
            control.timeout = min(3,remaining)
        control.save()

    @staticmethod
    def comparable_configuration(value):
        return canonical_service(value)

    def cleanup(self, identity):
        row = self.read(identity)
        if row['phase']=='abandoned':return True
        try:
            self.remove_owned(row['old_entry'], json.loads(row['before'])['services'])
        except Exception:
            self.save_phase(identity, 'cleanup_pending', error='Прежний вход недоступен или его правила требуют сверки', retry_at=time.time()+60)
            return False
        with self.store.connection(write=True) as database:
            for service in json.loads(row['before'])['services']:
                database.execute("UPDATE fleet_tunnel_services SET state='deleted' WHERE id=? AND state='retired'", (service['id'],))
            database.execute("UPDATE fleet_relay_switches SET phase='complete',updated_at=?,retry_at=0,error='' WHERE id=?", (time.time(),identity))
        from .native_management import refresh_management_sources
        refresh_management_sources(self.relays,row['node'])
        return True

    def rollback(self, identity):
        row = self.read(identity)
        if row['phase'] in ('published','cleanup_pending','grace_pending','complete','abandoned'):
            return False
        try:
            self.remove_owned(row['new_entry'], json.loads(row['after'])['services'])
        except Exception:
            self.save_phase(identity, 'rollback_pending', error='Новый вход недоступен для очистки', retry_at=time.time()+60)
            return False
        with self.store.connection(write=True) as database:
            for service in json.loads(row['after'])['services']:
                database.execute("UPDATE fleet_tunnel_services SET state='deleted' WHERE id=? AND state='preparing'", (service['id'],))
            database.execute("UPDATE fleet_relay_switches SET phase='rolled_back',updated_at=?,retry_at=0,error='' WHERE id=?", (time.time(),identity))
        from .native_management import refresh_management_sources
        refresh_management_sources(self.relays,row['node'])
        return True

    def recover(self):
        with self.store.connection() as database:
            rows = [dict(row) for row in database.execute("SELECT * FROM fleet_relay_switches WHERE phase NOT IN ('complete','rolled_back','abandoned') AND retry_at<=? ORDER BY updated_at LIMIT 4", (time.time(),))]
        if not rows:
            return
        from update_runtime.leases import acquire
        for row in rows:
            owners = {row['old_entry'],row['new_entry']}
            with self.relays.lock:
                if owners & self.relays.busy:
                    continue
                try:
                    lease = acquire(Path(self.store.path).parent / '.updates')
                except BlockingIOError:
                    continue
                self.relays.busy.update(owners)
            published = row['phase'] in ('published','cleanup_pending','grace_pending')
            try:
                latest=self.read(row['id'])
                if latest is None or latest['phase'] in ('complete','rolled_back','abandoned'):continue
                row=latest
                published=row['phase'] in ('published','cleanup_pending','grace_pending')
                if published:
                    if row['phase'] == 'published':
                        self.relays.reconnect(row['node'])
                        after=json.loads(row['after'])
                        grace=self.grace_seconds(self.relays.entry(row['old_entry']),after.get('grace_seconds'))
                        until=row['updated_at']+grace
                        if grace and until>time.time():
                            self.save_phase(row['id'],'grace_pending',retry_at=until)
                            self.relays.update(row['id'],'succeeded','Новый вход работает. Прежний сохранён на льготный период',self.context(self.read(row['id']),7,True))
                            continue
                    cleaned = self.cleanup(row['id'])
                    message = 'Смена входа восстановлена после перезапуска'
                    if not cleaned:
                        message += '. Очистка прежнего входа ожидает связи'
                    final = ('succeeded',message,self.context(self.read(row['id']),7,not cleaned))
                else:
                    restored = self.rollback(row['id'])
                    final = ('rolled_back' if restored else 'failed','Прерванная смена отменена. Прежний маршрут сохранён',self.context(self.read(row['id']),3))
            except Exception:
                self.save_phase(row['id'], row['phase'], error='Сверка смены входа будет повторена', retry_at=time.time()+60)
                final = None
            finally:
                with self.relays.lock:
                    self.relays.busy.difference_update(owners)
                os.close(lease)
            if final:
                self.relays.update(row['id'],*final)

    def catalog(self, tunnel, database=None):
        if database is None:
            with self.store.connection() as connection:
                return self.catalog(tunnel, connection)
        rows = database.execute("SELECT id,old_entry,new_entry,phase,retry_at FROM fleet_relay_switches WHERE tunnel=? ORDER BY rowid DESC", (tunnel,)).fetchall()
        pending = sum(row['phase'] == 'cleanup_pending' for row in rows)
        latest = dict(rows[0]) if rows else None
        grace=max((row['retry_at'] for row in rows if row['phase']=='grace_pending'),default=None)
        return {'old_cleanup_pending': bool(pending), 'pending_cleanup_count': pending, 'grace_until':grace,'switch': latest}

    def prune(self):
        with self.store.connection(write=True) as database:
            database.execute("DELETE FROM fleet_relay_switches WHERE phase IN ('complete','rolled_back','abandoned') AND updated_at<?", (time.time()-90*86400,))

    def pending_entry(self, entry):
        with self.store.connection() as database:
            return database.execute('''SELECT count(*) FROM fleet_relay_switches WHERE
                (phase IN ('cleanup_pending','grace_pending') AND old_entry=?) OR
                (phase='rollback_pending' AND new_entry=?) OR
                (phase IN ('prepared','installing','verified','published') AND (old_entry=? OR new_entry=?))''',
                (entry,entry,entry,entry)).fetchone()[0]
