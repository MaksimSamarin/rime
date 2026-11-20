"""Managed entry servers and reversible routes for existing VPN and proxy nodes."""
import base64
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from .provision import ProvisionError
from .relay_accounting import RelayAccounting
from .relay_control import RelayControl, RelayPortConflict, allocate_ports, credentials, forwarding_service, initial_configuration
from .relay_routes import outbound


class Relays:
    def __init__(self, provision, transfer, proxies):
        self.provision = provision
        self.transfer = transfer
        self.proxies = proxies
        self.store = provision.store
        self.settings = provision.settings
        self.plans = {}
        self.lock = threading.RLock()
        self.busy = set()
        self.worker_state = threading.local()
        self.runtime = Path(self.settings.get('relay_binary', '/opt/rime-relay/gost'))
        with self.store.connection(write=True) as database:
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_entries(
                id TEXT PRIMARY KEY,name TEXT NOT NULL,host TEXT NOT NULL,address TEXT NOT NULL,
                domain TEXT NOT NULL,control_port INTEGER NOT NULL,metrics_port INTEGER NOT NULL,
                api_port INTEGER NOT NULL,credential TEXT NOT NULL,ssh_port INTEGER NOT NULL,
                username TEXT NOT NULL,fingerprint TEXT NOT NULL,state TEXT NOT NULL,
                created_at REAL NOT NULL,seen_at REAL,health TEXT NOT NULL DEFAULT '{}')''')
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_tunnels(
                id TEXT PRIMARY KEY,node TEXT NOT NULL,entry TEXT NOT NULL,origin TEXT NOT NULL,
                generation TEXT NOT NULL,state TEXT NOT NULL,created_at REAL NOT NULL,
                checked_at REAL,result TEXT NOT NULL DEFAULT '{}',snapshot TEXT NOT NULL)''')
            database.execute("CREATE UNIQUE INDEX IF NOT EXISTS fleet_relay_active_address ON fleet_relay_entries(address) WHERE state<>'deleted'")
            database.execute("CREATE UNIQUE INDEX IF NOT EXISTS fleet_tunnel_active_node ON fleet_tunnels(node) WHERE state IN ('preparing','active','needs_reconcile')")
            if 'flags' not in {row['name'] for row in database.execute('PRAGMA table_info(fleet_tunnels)')}:
                database.execute("ALTER TABLE fleet_tunnels ADD COLUMN flags TEXT NOT NULL DEFAULT '{}' ")
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_tunnel_services(
                id TEXT PRIMARY KEY,tunnel TEXT NOT NULL,entry TEXT NOT NULL,kind TEXT NOT NULL,
                proxy TEXT,protocol TEXT NOT NULL,origin_port INTEGER NOT NULL,public_port INTEGER NOT NULL,
                config TEXT NOT NULL,state TEXT NOT NULL)''')
            database.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_jobs(
                id TEXT PRIMARY KEY,state TEXT NOT NULL,message TEXT NOT NULL,
                steps TEXT NOT NULL,context TEXT NOT NULL,updated_at REAL NOT NULL)''')
            database.execute("UPDATE fleet_relay_jobs SET state='failed',message='Операция прервана перезапуском. Выполните сверку входного сервера' WHERE state='running'")
            database.execute("UPDATE fleet_tunnels SET state='needs_reconcile' WHERE state='preparing'")
            database.execute("UPDATE fleet_relay_entries SET state='needs_reconcile' WHERE state='preparing'")
        self.accounting = RelayAccounting(self.store)
        from .relay_changes import RelayChanges
        self.changes = RelayChanges(self)
        from .relay_edit import RelayEdits
        self.edits=RelayEdits(self)
        from .relay_switch import RelaySwitches
        self.switches = RelaySwitches(self)
        from .relay_retire import RelayRetirements
        self.retirements = RelayRetirements(self)

    def entry(self, identity):
        with self.store.connection() as database:
            row = database.execute('SELECT * FROM fleet_relay_entries WHERE id=?', (identity,)).fetchone()
        if row is None:
            raise ProvisionError('Входной сервер не найден')
        return dict(row)

    def control(self, entry):
        raw = self.proxies.secrets.decrypt('relay/' + entry['id'], entry['credential'])
        return RelayControl(entry['host'], entry['address'], entry['control_port'], json.loads(raw))

    def catalog(self):
        with self.store.connection() as database:
            entries = [dict(row) for row in database.execute('SELECT * FROM fleet_relay_entries ORDER BY created_at')]
            tunnels = [dict(row) for row in database.execute("SELECT t.*,e.name AS entry_name,e.domain AS entry_domain FROM fleet_tunnels t JOIN fleet_relay_entries e ON e.id=t.entry WHERE t.state<>'deleted' ORDER BY t.created_at")]
            totals = {row['service']: dict(row) for row in database.execute('SELECT * FROM fleet_relay_totals')}
            proxy_modes = {}
            if database.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_proxy_services'").fetchone():
                proxy_modes = {row['id']: {row[field]:mode for mode,field in [('http','http_port'),('https','https_port')] if row[field] is not None}
                               for row in database.execute('SELECT id,http_port,https_port FROM fleet_proxy_services')}
            for tunnel in tunnels:
                history = list(database.execute('SELECT * FROM fleet_tunnel_services WHERE tunnel=? ORDER BY kind,origin_port', (tunnel['id'],)))
                traffic = {}
                for row in history:
                    key = (row['kind'], row['proxy'], row['protocol'], row['origin_port'])
                    aggregate = traffic.setdefault(key, {'rx':0,'tx':0})
                    count = totals.get(row['id'], {})
                    for direction in ('rx', 'tx'):
                        aggregate[direction] += count.get(direction, 0)
                tunnel['services'] = [{key: row[key] for key in ['id','kind','proxy','protocol','origin_port','public_port','state']}
                    | {'traffic': traffic[(row['kind'],row['proxy'],row['protocol'],row['origin_port'])],
                       'mode':proxy_modes.get(row['proxy'],{}).get(row['origin_port'])}
                    for row in history if row['entry'] == tunnel['entry'] and row['state'] in ('active','preparing','needs_reconcile')]
                tunnel['traffic'] = {direction:sum(totals.get(row['id'],{}).get(direction,0) for row in history) for direction in ('rx','tx')}
                tunnel['result'] = json.loads(tunnel['result'])
                tunnel.pop('snapshot')
                tunnel.pop('generation')
                tunnel.update(self.switches.catalog(tunnel['id'], database))
        for entry in entries:
            entry.pop('credential')
            entry['health'] = json.loads(entry['health'])
            entry['fresh'] = bool(entry['seen_at'] and time.time() - entry['seen_at'] < 60)
            entry['pending_cleanup_count'] = self.switches.pending_entry(entry['id'])+self.retirements.pending_entry(entry['id'])
        return {'entries': entries, 'tunnels': tunnels, 'runtime_available': self.runtime.is_file()}

    def remote(self, client, data):
        code = base64.b64encode(Path(__file__).with_name('port_check.py').read_bytes()+b'\n'+Path(__file__).with_name('relay_install.py').read_bytes()).decode()
        incoming, output, errors = client.exec_command("python3 -c \"import base64;exec(base64.b64decode('" + code + "'))\"", timeout=60)
        incoming.write(json.dumps(data))
        incoming.flush()
        incoming.channel.shutdown_write()
        raw = output.read(1024 * 1024)
        if output.channel.recv_exit_status():
            raise ProvisionError('Служба входного сервера не подтвердила операцию')
        return json.loads(raw)

    def remember_plan(self, record, public):
        with self.lock:
            for key, value in list(self.plans.items()):
                if value['public']['expires_at'] < time.time():
                    value.get('access', {}).clear()
                    del self.plans[key]
            while len(self.plans)>=32:
                oldest=next(iter(self.plans))
                self.plans.pop(oldest).get('access',{}).clear()
            public.update(id=secrets.token_hex(16), expires_at=time.time()+600, ready=True)
            record['public'] = public
            self.plans[public['id']] = record
        return public

    def plan_entry(self, data):
        if not self.runtime.is_file():
            raise ProvisionError('Проверенная сборка туннеля отсутствует в этом образе панели')
        self.provision.target(data['host'], data['ssh_port'])
        address = self.provision.resolve(data['host'], data['ssh_port'])[0]
        if data.get('address') != address:
            raise ProvisionError('Повторите проверку SSH-ключа входного сервера')
        if address not in self.provision.resolve(data['domain'], data['ssh_port']):
            raise ProvisionError('DNS входного сервера должен указывать на выбранный IPv4')
        with self.store.connection() as database:
            if database.execute("SELECT 1 FROM fleet_relay_entries WHERE address=? AND state<>'deleted'", (address,)).fetchone():
                raise ProvisionError('Этот входной сервер уже зарегистрирован. Выберите его для следующей ноды')
        from .bootstrap import inspect
        ports = [[data['control_port'],'tcp'],[data['metrics_port'],'tcp'],[data['api_port'],'tcp']]
        if len({value[0] for value in ports}) != 3 or data['ssh_port'] in {value[0] for value in ports}:
            raise ProvisionError('Укажите три разных служебных порта, свободных от SSH и VPN')
        with self.provision.connect(data) as client:
            runtime = inspect(client, ports)
            if not runtime['python_available']:
                raise ProvisionError('На входном сервере требуется Python 3')
            incoming, output, errors = client.exec_command('test -d /run/systemd/system && test "$(id -u)" = 0', timeout=10)
            if output.channel.recv_exit_status():
                raise ProvisionError('Для установки входного сервера нужен root-доступ и systemd')
            # Use the same live socket inspection as the node wizard.
            result = self.remote(client, {'id':secrets.token_hex(16),'action':'preflight','ports':ports})
            if any(not check['passed'] for check in result['checks']):
                raise ProvisionError('Один из служебных портов входного сервера занят')
        return self.remember_plan({'kind':'entry','access':data}, {'kind':'entry','name':data['name'],
            'address':address,'domain':data['domain'],'ports':[value[0] for value in ports],
            'message':'Будет установлена отдельная служба TCP/UDP. Существующие VPN и прокси продолжают работать'})

    def source(self, node):
        self.proxies.require_stable_node(node)
        profile = self.transfer.prepare_profile(node)
        with self.store.connection() as database:
            source = self.transfer.snapshot(node, database)
        if source.get('native'):
            from .native_management import cached_node, protocol_for
            current = cached_node(source)
            if getattr(current, '_api_mtls', False) is True:
                vpn = profile['vpn']
                metadata = {'management_auth':'controller-mtls-v1',
                            'management_protocol':protocol_for(source, profile, current)}
                if getattr(current,'_management_sources',False) is True:
                    metadata['management_source_policy']=1
                if not vpn.get('management_tls') and getattr(current, '_node_cert', None):
                    metadata['management_server_certificate'] = current._node_cert
                    if getattr(current,'_trusted_server_certificate',None):
                        metadata['management_certificate_verified']=True
                if any(vpn.get(key) != value for key,value in metadata.items()):
                    vpn.update(metadata)
                    self.proxies.recovery.save(node, profile)
                    with self.store.connection() as database:
                        source = self.transfer.snapshot(node, database)
        return source, profile

    def services_for(self, source, profile, include_proxies, management, ssh_port):
        services = []
        vpn = profile['vpn']
        publish = vpn.get('publish') or [[source['vpn_port'],24443,'udp']]
        for outside, inside, protocol in publish:
            services.append({'kind':'vpn','proxy':None,'origin_port':outside,'protocol':protocol})
        if include_proxies:
            for identity, proxy in profile['proxies'].items():
                for outside, inside in proxy['publish']:
                    services.append({'kind':'proxy','proxy':identity,'origin_port':outside,'protocol':'tcp',
                                     'mode':'http' if inside==3128 else 'https'})
        if management and source['native']:
            for port in [source['native']['port'], source['native']['api_port']]:
                services.append({'kind':'management','proxy':None,'origin_port':port,'protocol':'tcp'})
        if ssh_port:
            services.append({'kind':'ssh','proxy':None,'origin_port':ssh_port,'protocol':'tcp'})
        unique = {}
        for service in services:
            key = (service['origin_port'], service['protocol'])
            if key in unique:
                raise ProvisionError('В комплекте выходной ноды пересекаются порты разных служб')
            unique[key] = service
        return list(unique.values())

    def plan_route(self, data):
        entry = self.entry(data['entry'])
        if entry['state'] != 'active':
            raise ProvisionError('Входной сервер требует завершения установки или сверки')
        if not entry['seen_at'] or time.time()-entry['seen_at'] > 60:
            raise ProvisionError('Нет свежих ресурсов входного сервера. Дождитесь связи его агента с панелью')
        with self.store.connection() as database:
            if database.execute("SELECT 1 FROM fleet_tunnels WHERE node=? AND state<>'deleted'", (data['node'],)).fetchone():
                raise ProvisionError('Для этой ноды уже создан туннель. Сначала удалите прежний маршрут')
        source, profile = self.source(data['node'])
        origin = self.provision.resolve(data.get('origin') or source['identity']['address'],22)[0]
        if origin == entry['address']:
            raise ProvisionError('Входной и выходной сервер должны отличаться')
        control = self.control(entry)
        occupied = set()
        occupied.update((port,protocol) for port,protocol in json.loads(entry['health']).get('listeners',[]))
        occupied.update((entry[field],'tcp') for field in ['control_port','api_port','metrics_port','ssh_port'])
        for service in control.services():
            port = int(service['addr'].rsplit(':',1)[1])
            protocol = 'udp' if service.get('listener',{}).get('type')=='udp' else 'tcp'
            occupied.add((port,protocol))
        # Existing VPN/proxy ports of a panel-managed entry are reserved too.
        with self.store.connection() as database:
            for proxy in database.execute('SELECT http_port,https_port FROM fleet_proxy_services WHERE address=? AND active=1',(entry['address'],)):
                occupied.update((port,'tcp') for port in proxy if port)
            for row in database.execute('SELECT m.port,m.protocol FROM fleet_managed m LEFT JOIN nodes n ON n.id=m.native_id WHERE n.address=? OR m.domain=?',(entry['address'],entry['domain'])):
                occupied.add((row['port'],'udp' if row['protocol']=='hysteria2' else 'tcp'))
        services = allocate_ports(self.services_for(source,profile,data['include_proxies'],data['management'],data.get('ssh_port')),occupied)
        for identity in {service['proxy'] for service in services if service['kind']=='proxy'}:
            with self.store.connection() as database:
                proxy = database.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND active=1',(identity,)).fetchone()
            if proxy is None:raise ProvisionError('Прокси исходной ноды изменился. Повторите проверку')
            self.proxies.clear_password(dict(proxy))
        # HTTPS endpoint names must be covered by the unchanged exit certificate.
        from cryptography import x509
        for service in services:
            if service.get('mode') == 'https':
                proxy = profile['proxies'][service['proxy']]
                certificate = x509.load_pem_x509_certificate(proxy['files']['cert.pem'].encode())
                san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                names = san.get_values_for_type(x509.DNSName) + [str(value) for value in san.get_values_for_type(x509.IPAddress)]
                domain = entry['domain'].lower()
                if not any(domain == name.lower() or (name.startswith('*.') and domain.count('.')==name.count('.') and domain.endswith(name[1:].lower())) for name in names):
                    raise ProvisionError('Прежний сертификат HTTPS-прокси не покрывает имя входного сервера. Выберите вход с подходящим доменом')
        return self.remember_plan({'kind':'route','source':source,'profile':profile,'entry':entry,'origin':origin,'services':services,
                                  'flags':{'include_proxies':data['include_proxies']}},
            {'kind':'route','node':source['node'],'name':source['name'],'entry':entry['id'],'entry_name':entry['name'],
             'domain':entry['domain'],'origin':origin,'services':services,
             'message':'Ключи и URL подписок сохраняются. После включения обновите прежнюю подписку в клиенте для получения входного адреса'})

    def plan_entry_remove(self, identity, access):
        entry = self.entry(identity)
        if self.switches.pending_entry(identity) or self.retirements.pending_entry(identity):
            raise ProvisionError('Очистка правил после смены входа ещё не завершена. Дождитесь связи или выполните сверку входного сервера')
        with self.store.connection() as database:
            if database.execute("SELECT 1 FROM fleet_tunnels WHERE entry=? AND state<>'deleted'",(identity,)).fetchone():
                raise ProvisionError('Сначала удалите маршруты этого входного сервера')
        if access['host'] not in {entry['host'],entry['address']} or access['ssh_port'] != entry['ssh_port']:
            raise ProvisionError('Используйте зарегистрированный прямой SSH-доступ входного сервера')
        if access['fingerprint'] != entry['fingerprint']:
            raise ProvisionError('SSH-ключ входного сервера изменился. Требуется сверка его регистрации')
        with self.provision.connect(access):pass
        return self.remember_plan({'kind':'entry-remove','entry':entry,'access':access},
            {'kind':'entry-remove','name':entry['name'],'domain':entry['domain'],'address':entry['address'],
             'message':'Будут удалены служба туннеля, сборщик и их приватный каталог на входном сервере'})

    def update(self, identity, state, message, context=None):
        if getattr(self.worker_state,'identity',None)==identity:
            if state=='succeeded':
                self.worker_state.success=(message,context)
                state='running'
                message='Завершение операции'
                if context and context.get('operation') == 'route-switch':
                    context = deepcopy(context)
                    context['progress'] = {**context['progress'], 'completed':6, 'phase':'complete', 'label':'Освобождение операции'}
            elif state in ['failed','rolled_back']:
                self.worker_state.success=None
        with self.store.connection(write=True) as database:
            row = database.execute('SELECT steps,context FROM fleet_relay_jobs WHERE id=?',(identity,)).fetchone()
            steps = json.loads(row['steps']) if row else []
            if not steps or steps[-1] != message:
                steps.append(message)
            context = context if context is not None else json.loads(row['context']) if row else {}
            database.execute('INSERT OR REPLACE INTO fleet_relay_jobs VALUES(?,?,?,?,?,?)',
                (identity,state,message,json.dumps(steps[-30:]),json.dumps(context),time.time()))

    def job(self, identity):
        with self.store.connection() as database:
            row = database.execute('SELECT * FROM fleet_relay_jobs WHERE id=?',(identity,)).fetchone()
        if row is None:
            raise ProvisionError('Задача туннеля не найдена')
        return {**dict(row),'steps':json.loads(row['steps']),'context':json.loads(row['context'])}

    def launch(self, identity, entry, function, *arguments, related_entries=()):
        from update_runtime.leases import acquire
        owners = {entry, *related_entries}
        with self.lock:
            if owners & self.busy:
                raise ProvisionError('На входном сервере выполняется другая операция')
            try:
                lease = acquire(Path(self.store.path).parent / '.updates')
            except BlockingIOError:
                raise ProvisionError('Дождитесь завершения обновления панели') from None
            self.busy.update(owners)
            self.update(identity,'running','Проверка конфигурации туннеля',{'entry':entry})
        def worker():
            self.worker_state.identity=identity
            self.worker_state.owners=owners
            self.worker_state.success=None
            try:
                function(identity,*arguments)
            except Exception as error:
                self.update(identity,'failed',str(error) if isinstance(error,ProvisionError) else 'Операция не завершена. Проверьте состояние входного сервера и повторите сверку')
            finally:
                with self.lock:self.busy.difference_update(owners)
                os.close(lease)
                successful=self.worker_state.success
                self.worker_state.identity=None
                self.worker_state.owners=set()
                if successful:self.update(identity,'succeeded',successful[0],successful[1])
        try:
            threading.Thread(target=worker,daemon=True).start()
        except Exception:
            with self.lock:self.busy.difference_update(owners)
            os.close(lease)
            self.update(identity,'failed','Задача не запущена. Повторите подтверждение плана')
            raise
        return {'id':identity}

    def deploy(self, identity):
        with self.lock:
            record = self.plans.get(identity)
            if not record or record['public']['expires_at'] < time.time():
                with self.store.connection() as database:
                    existing=database.execute('SELECT id FROM fleet_relay_jobs WHERE id=?',(identity,)).fetchone()
                if existing:return {'id':identity}
                raise ProvisionError('План туннеля истёк. Повторите проверку')
            if record['kind'] == 'route-switch':
                result = self.switches.start(identity, record)
                del self.plans[identity]
                return result
            owner = record['entry']['id'] if record['kind'] in ['route','entry-remove'] else record['access']['address']
            action = {'entry':self.install_entry,'route':self.install_route,'entry-remove':self.remove_entry_worker}[record['kind']]
            result = self.launch(identity,owner,action,record)
            del self.plans[identity]
        return result

    def remove_entry_worker(self, identity, record):
        entry = record['entry']
        access = record['access']
        try:
            if self.switches.pending_entry(entry['id']) or self.retirements.pending_entry(entry['id']):
                raise ProvisionError('После проверки появилась отложенная очистка. Повторите сверку входа')
            with self.store.connection() as database:
                if database.execute("SELECT 1 FROM fleet_tunnels WHERE entry=? AND state<>'deleted'",(entry['id'],)).fetchone():
                    raise ProvisionError('После подготовки плана на входе появился маршрут. Удаление отменено')
            self.update(identity,'running','Остановка службы туннеля и сборщика')
            with self.provision.connect(access) as client:
                result = self.remote(client,{'id':entry['id'],'action':'remove'})
                if not result.get('removed'):raise ProvisionError('Входной сервер не подтвердил удаление')
            with self.store.connection(write=True) as database:
                database.execute("UPDATE fleet_relay_entries SET state='deleted',health='{}',credential='' WHERE id=?",(entry['id'],))
            self.update(identity,'succeeded','Входной сервер удалён. Другие службы сервера сохранены')
        finally:
            access.clear()

    def install_entry(self, identity, record):
        data = record['access']
        created = False
        try:
            credential = credentials(data['host'],data['address'])
            envelope = self.proxies.secrets.encrypt('relay/'+identity,json.dumps(credential),create=True)
            directory = '/var/lib/rime-relay/' + identity
            config = initial_configuration(credential,data['control_port'],data['metrics_port'],directory,data['api_port'])
            observer = {'id':identity,'directory':directory,'metrics_port':data['metrics_port'],
                        'panel_url':self.settings['panel_url'],'token':credential['meter_token'],
                        'observer_token':credential['observer_token']}
            files = {'gost.json':json.dumps(config),'control-cert.pem':credential['certificate'],
                     'control-key.pem':credential['key'],'observer.json':json.dumps(observer)}
            if self.settings.get('panel_ca_file'):
                files['panel-ca.pem'] = Path(self.settings['panel_ca_file']).read_text()
                observer['panel_ca_file'] = directory+'/panel-ca.pem'
                files['observer.json'] = json.dumps(observer)
            root = Path(__file__).resolve().parents[1] / 'relay-runtime'
            scripts = {name:(root/name).read_text() for name in ['launch.py','observer.py']}
            with self.store.connection(write=True) as database:
                database.execute('''INSERT INTO fleet_relay_entries(id,name,host,address,domain,control_port,metrics_port,
                    api_port,credential,ssh_port,username,fingerprint,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (identity,data['name'],data['host'],data['address'],data['domain'],data['control_port'],data['metrics_port'],
                     data['api_port'],envelope,data['ssh_port'],data['username'],data['fingerprint'],'preparing',time.time()))
            with self.provision.connect(data) as client:
                self.update(identity,'running','Передача проверенного ядра туннеля')
                with client.open_sftp() as sftp:
                    home = sftp.normalize('.')
                uploaded = self.provision.upload(client,str(self.runtime),identity,'.gost',home)
                created = True
                self.update(identity,'running','Установка отдельной службы входного сервера')
                self.remote(client,{'id':identity,'action':'install','binary':uploaded,
                    'binary_sha256':hashlib.sha256(self.runtime.read_bytes()).hexdigest(),'files':files,'scripts':scripts})
                entry = {**data,'id':identity}
                controller = RelayControl(data['host'],data['address'],data['control_port'],credential)
                deadline = time.monotonic()+15
                while True:
                    try:
                        controller.services()
                        break
                    except ProvisionError:
                        if time.monotonic() >= deadline:raise
                        time.sleep(.5)
                with self.store.connection(write=True) as database:
                    database.execute("UPDATE fleet_relay_entries SET state='active' WHERE id=?",(identity,))
            self.update(identity,'succeeded','Входной сервер готов. Можно подключать выходные ноды')
        except Exception as error:
            import logging
            logging.getLogger('fleet').warning('Entry installation failed (%s)',type(error).__name__)
            restored = not created
            if created:
                try:
                    with self.provision.connect(data) as client:self.remote(client,{'id':identity,'action':'remove'})
                    restored = True
                except Exception:pass
            with self.store.connection(write=True) as database:
                database.execute('UPDATE fleet_relay_entries SET state=? WHERE id=?',('deleted' if restored else 'needs_reconcile',identity))
            self.update(identity,'rolled_back' if restored else 'failed',
                (str(error)+'. ' if isinstance(error,ProvisionError) else '')+
                ('Установка отменена, существующие службы сохранены' if restored else 'Требуется сверка частичной установки входного сервера'))
        finally:
            data.clear()

    def install_route(self, identity, record):
        entry = record['entry']
        control = self.control(entry)
        installed = []
        try:
            source, profile = self.source(record['source']['node'])
            if self.transfer.digest(source) != self.transfer.digest(record['source']):
                raise ProvisionError('Исходная нода изменилась. Повторите планирование туннеля')
            self.update(identity,'running','Сохранение исходных адресов и правил')
            services = []
            with self.store.connection(write=True) as database:
                database.execute('INSERT INTO fleet_tunnels(id,node,entry,origin,generation,state,created_at,snapshot) VALUES(?,?,?,?,?,?,?,?)',
                    (identity,source['node'],entry['id'],record['origin'],str(source['identity']['created_at']),'preparing',time.time(),json.dumps(source)))
                database.execute('UPDATE fleet_tunnels SET flags=? WHERE id=?',(json.dumps(record.get('flags',{})),identity))
                for service in record['services']:
                    key = secrets.token_hex(16)
                    config = forwarding_service(key+'-'+secrets.token_hex(4),service['public_port'],record['origin'],service['origin_port'],service['protocol'])
                    value = {**service,'id':key,'config':config}
                    services.append(value)
                    database.execute('INSERT INTO fleet_tunnel_services VALUES(?,?,?,?,?,?,?,?,?,?)',
                        (key,identity,entry['id'],service['kind'],service['proxy'],service['protocol'],service['origin_port'],service['public_port'],json.dumps(config),'preparing'))
            self.update(identity,'running','Создание независимых TCP/UDP-маршрутов')
            for service in services:
                blocked=set()
                for attempt in range(16):
                    try:
                        control.add(service['config'])
                        break
                    except RelayPortConflict:
                        if attempt==15:raise
                        blocked.add((service['public_port'],service['protocol']))
                        used=blocked|{(value['public_port'],value['protocol']) for value in services}
                        used.update((int(value['addr'].rsplit(':',1)[1]),'udp' if value.get('listener',{}).get('type')=='udp' else 'tcp') for value in control.services())
                        port=allocate_ports([{'origin_port':10443,'protocol':service['protocol']}],used)[0]['public_port']
                        self.update(identity,'running','Занятый порт входа заменён на '+str(port)+'/'+service['protocol'].upper())
                        service['public_port']=port
                        service['config']['addr']='0.0.0.0:'+str(port)
                        with self.store.connection(write=True) as database:
                            database.execute('UPDATE fleet_tunnel_services SET public_port=?,config=? WHERE id=?',
                                (port,json.dumps(service['config']),service['id']))
                installed.append(service)
            control.save()
            self.update(identity,'running','Проверка VPN-трафика и прокси через входной сервер')
            result = self.verify_route(source,profile,entry,record['origin'],services)
            with self.store.connection(write=True) as database:
                if self.transfer.digest(self.transfer.snapshot(source['node'],database)) != self.transfer.digest(source):
                    raise ProvisionError('Исходная нода изменилась во время проверки')
                database.execute("UPDATE fleet_tunnel_services SET state='active' WHERE tunnel=?",(identity,))
                database.execute("UPDATE fleet_tunnels SET state='active',checked_at=?,result=? WHERE id=?",(time.time(),json.dumps(result),identity))
            self.reconnect(source['node'])
            self.update(identity,'succeeded','Туннель включён. Ключи и URL подписок сохранены')
        except Exception as error:
            restored = True
            for service in reversed(installed):
                try:control.remove(service['config']['name'])
                except Exception:restored = False
            try:control.save()
            except Exception:restored = False
            with self.store.connection(write=True) as database:
                database.execute("UPDATE fleet_tunnels SET state=? WHERE id=?",('deleted' if restored else 'needs_reconcile',identity))
                database.execute("UPDATE fleet_tunnel_services SET state=? WHERE tunnel=?",('deleted' if restored else 'needs_reconcile',identity))
            reason = str(error) if isinstance(error,ProvisionError) else 'Проверка туннеля не завершена'
            self.update(identity,'rolled_back' if restored else 'failed',reason+'. '+('Прежние адреса сохранены' if restored else 'Требуется сверка правил входного сервера'))

    def verify_route(self, source, profile, entry, origin, services, required=True):
        from .native_management import ensure_management_sources
        ensure_management_sources(self,source,profile,entry,services)
        from .client_probe import probe, xray_probe_binary
        targets=self.transfer.probe.transfer_targets(source,profile,{'address':origin})
        if required and not targets:raise ProvisionError('Нет клиентских конфигураций для проверки VPN')
        vpn={service['origin_port']:service for service in services if service['kind']=='vpn'}
        results=[]
        vpn_results=[]
        proxy_results=[]
        ssh_results=[]
        def record(service,result):
            results.append({'kind':service['kind'],'origin_port':service['origin_port'],
                'public_port':service['public_port'],'passed':result['passed'],'stage':result.get('stage')})
        for target in targets:
            config=target['config']
            port=int(config['server'].rsplit(':',1)[1]) if config.get('_kind')=='hy2' else config['outbounds'][0]['settings']['vnext'][0]['port']
            service=vpn.get(port)
            if service is None:raise ProvisionError('Туннель не содержит один из сохранённых VPN-входов')
            config=outbound(config,service,entry['address'])
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0))
                local_port=listener.getsockname()[1]
            result=probe({**target,'config':config,'resolved_ip':entry['address'],'expected_egress_ip':origin},
                {**self.settings.get('relay_probe',{}),'direct_targets':[entry['address']],
                 'xray_binary':xray_probe_binary(self.settings),
                 'hysteria_binary':self.settings.get('hysteria_binary','')},local_port)
            known=result['stage'] not in ['configuration','route']
            vpn_results.append(result['passed'] if known else None)
            record(service,result)
            if required and not result['passed']:raise ProvisionError('Трафик через входной сервер не прошёл. Этап '+result['stage'])
        from .proxy_probe import probe as proxy_probe
        for proxy_id in {service['proxy'] for service in services if service['kind']=='proxy'}:
            with self.store.connection() as database:
                row=database.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND active=1',(proxy_id,)).fetchone()
            password=None
            try:
                if row is None:raise ProvisionError('Прокси был удалён во время проверки')
                row=dict(row)
                password=self.proxies.clear_password(row)
            except ProvisionError:
                if required:raise
            for service in services:
                if service['proxy']!=proxy_id:continue
                if password is None:result={'passed':False,'stage':'credentials'}
                else:
                    mode='http' if service['origin_port']==row['http_port'] else 'https'
                    try:result=proxy_probe(entry['address'],entry['domain'],service['public_port'],mode=='https',row['username'],password,
                        {**self.proxies.settings,'expected_egress_ip':origin})
                    except (OSError,ValueError):result={'passed':False,'stage':'configuration'}
                proxy_results.append(result['passed'])
                record(service,result)
                if required and not result['passed']:raise ProvisionError('Прокси через входной сервер не передал контрольные данные')
        for service in services:
            if service['kind']!='ssh':continue
            try:
                self.provision.scan(entry['address'],service['public_port'])
                result={'passed':True,'stage':'ssh'}
            except ProvisionError:
                result={'passed':False,'stage':'ssh'}
            ssh_results.append(result['passed'])
            record(service,result)
            if required and not result['passed']:raise ProvisionError('SSH-порт выхода недоступен через выбранный вход')
        from .native_management import probe_management
        management = probe_management(source,profile,entry,services,getattr(self,'management_credentials',None))
        results.extend(management['services'])
        if required and not management['passed']:
            raise ProvisionError(management['message'])
        vpn_passed=all(vpn_results) if vpn_results and None not in vpn_results else None
        return {'passed':bool(vpn_passed) and all(proxy_results) and all(ssh_results) and management['passed'],'vpn_passed':vpn_passed,
                'proxies_passed':all(proxy_results),'ssh_passed':all(ssh_results),
                'management_passed':management['management_passed'],
                'origin':'Сервер панели → '+entry['name'],'target_ip':entry['address'],'egress_ip':origin,
                'checked_at':time.time(),'checks':len(results),'services':results}

    def endpoint_map(self, node):
        with self.store.connection() as database:
            rows = database.execute('''SELECT s.*,e.domain,e.address,e.name AS entry_name FROM fleet_tunnel_services s
                JOIN fleet_tunnels t ON t.id=s.tunnel JOIN fleet_relay_entries e ON e.id=s.entry
                WHERE t.node=? AND t.state='active' AND s.state='active' ''',(node,)).fetchall()
        return {(row['kind'],row['origin_port'],row['protocol']):dict(row) for row in rows}

    def direct_target(self, node):
        with self.store.connection() as database:
            row=database.execute("SELECT origin FROM fleet_tunnels WHERE node=? AND state<>'deleted'",(node,)).fetchone()
        return row['origin'] if row else None

    def published_host(self, node, value, inbound):
        service = self.endpoint_map(node).get(('vpn',value.get('port') or inbound['port'],'tcp'))
        if service is None:return value
        result = deepcopy(value)
        if not result.get('sni') and inbound.get('tls'):
            result['sni'] = inbound.get('sni') or value['address']
        result.update(address=[service['domain']],port=service['public_port'])
        return result

    def published_link(self, node, value):
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            return value
        service = self.endpoint_map(node).get(('vpn',port,'udp'))
        if service is None:return value
        user = parsed.netloc.rsplit('@',1)[0]
        return urlunsplit((parsed.scheme,user+'@'+service['domain']+':'+str(service['public_port']),parsed.path,parsed.query,parsed.fragment))

    def proxy_endpoint(self, identity, mode, port):
        with self.store.connection() as database:
            row = database.execute('''SELECT s.*,e.domain,e.address,e.name AS entry_name FROM fleet_tunnel_services s
                JOIN fleet_tunnels t ON t.id=s.tunnel JOIN fleet_relay_entries e ON e.id=s.entry
                WHERE s.proxy=? AND s.origin_port=? AND t.state='active' AND s.state='active' ''',(identity,port)).fetchone()
        return dict(row) if row else None

    def has_origin_route(self, node):
        return any(key[0]=='ssh' for key in self.endpoint_map(node))

    def origin_access(self, node):
        service = next((value for key,value in self.endpoint_map(node).items() if key[0]=='ssh'),None)
        if service is None:raise ProvisionError('SSH-маршрут через вход не настроен')
        return {'host':service['address'],'ssh_port':service['public_port'],'via_entry':True,'entry_name':service['entry_name']}

    def connect_origin(self, node, access):
        expected = self.origin_access(node)
        if access.get('address') != expected['host'] or access['ssh_port'] != expected['ssh_port']:
            raise ProvisionError('Используйте показанный SSH-маршрут выбранного туннеля')
        return self.provision.connect(access)

    def proxy_routes(self, identity):
        with self.store.connection() as database:
            return [dict(row) for row in database.execute("SELECT * FROM fleet_tunnel_services WHERE proxy=? AND state='active' ORDER BY id",(identity,))]

    def reserve_node(self, node):
        with self.lock:
            with self.store.connection() as database:
                row=database.execute("SELECT entry FROM fleet_tunnels WHERE node=? AND state<>'deleted'",(node,)).fetchone()
            if row is None:return None
            if row['entry'] in self.busy:raise ProvisionError('На входном сервере выполняется другая операция')
            self.busy.add(row['entry'])
            return row['entry']

    def release_entry(self, entry):
        if entry:
            with self.lock:self.busy.discard(entry)

    def restore_proxy_routes(self, rows, access=None):
        for row in rows:
            control = self.control(self.entry(row['entry']))
            names = {value['name'] for value in control.services()}
            value = json.loads(row['config'])
            if value['name'] not in names:control.add(value)
            control.save()
        with self.store.connection(write=True) as database:
            for row in rows:database.execute("UPDATE fleet_tunnel_services SET state='active' WHERE id=?",(row['id'],))

    def remove_route(self, identity):
        with self.store.connection() as database:
            row = database.execute("SELECT * FROM fleet_tunnels WHERE id=? AND state<>'deleted'",(identity,)).fetchone()
        if row is None:raise ProvisionError('Туннель не найден')
        return self.launch(secrets.token_hex(16),row['entry'],self.remove_route_worker,dict(row))

    def detach_route(self, identity, confirmation):
        if confirmation != identity:
            raise ProvisionError('Подтвердите возврат выбранного маршрута на прямые адреса')
        with self.lock:
            route=self.switches.snapshot(identity)['tunnel']
            entries=self.retirements.entries_for_node(route['node'])
            return self.launch(secrets.token_hex(16),route['entry'],self.retirements.detach,route,related_entries=entries)

    def forget_entry(self, identity, confirmation):
        entry=self.entry(identity)
        if confirmation!=entry['domain']:
            raise ProvisionError('Для подтверждения введите точный домен входного сервера')
        with self.lock,self.store.connection(write=True) as db:
            nodes=[row[0] for row in db.execute('SELECT DISTINCT t.node FROM fleet_tunnels t JOIN fleet_tunnel_services s ON s.tunnel=t.id WHERE s.entry=?',(identity,))]
            if identity in self.busy:
                raise ProvisionError('Дождитесь завершения операции входного сервера')
            if db.execute("SELECT 1 FROM fleet_tunnels WHERE entry=? AND state<>'deleted'",(identity,)).fetchone():
                raise ProvisionError('Сначала верните маршруты на прямые адреса или смените их вход')
            if db.execute("SELECT 1 FROM fleet_relay_switches WHERE phase IN ('prepared','installing','verified','published') AND (old_entry=? OR new_entry=?)",(identity,identity)).fetchone():
                raise ProvisionError('Смена входа ещё выполняется')
            if db.execute("SELECT 1 FROM fleet_relay_changes WHERE entry=? AND phase NOT IN ('committed','rolled_back','abandoned')",(identity,)).fetchone():
                raise ProvisionError('Изменение маршрута требует восстановления')
            db.execute("UPDATE fleet_relay_switches SET phase='abandoned',retry_at=0,updated_at=? WHERE (phase IN ('cleanup_pending','grace_pending') AND old_entry=?) OR (phase='rollback_pending' AND new_entry=?)",(time.time(),identity,identity))
            db.execute("UPDATE fleet_relay_retirements SET phase='abandoned',retry_at=0,updated_at=? WHERE entry=? AND phase='cleanup_pending'",(time.time(),identity))
            db.execute("UPDATE fleet_tunnel_services SET state='deleted' WHERE entry=? AND state IN ('retired','preparing','needs_reconcile')",(identity,))
            db.execute("UPDATE fleet_relay_entries SET state='deleted',credential='',health='{}' WHERE id=?",(identity,))
        from .native_management import refresh_management_sources
        for node in nodes:refresh_management_sources(self,node)
        return {'forgotten':True,'remote_cleanup_performed':False}

    def remove_route_worker(self, job, route):
        with self.store.connection() as database:
            self.switches.require_idle(route['node'],database)
            if not self.route_matches(database, route):
                raise ProvisionError('Маршрут изменился. Повторите удаление текущего входа')
        entry = self.entry(route['entry'])
        control = self.control(entry)
        with self.store.connection() as database:
            rows = [dict(row) for row in database.execute("SELECT * FROM fleet_tunnel_services WHERE tunnel=? AND entry=? AND state IN ('active','needs_reconcile')",(route['id'],route['entry']))]
        route['_services'] = rows
        removed = []
        try:
            self.update(job,'running','Удаление выбранных правил с входного сервера')
            for row in rows:
                control.remove(json.loads(row['config'])['name'])
                removed.append(row)
            control.save()
            with self.store.connection(write=True) as database:
                if not self.route_matches(database, route):
                    raise ProvisionError('Маршрут изменился во время удаления. Повторите проверку')
                database.execute("UPDATE fleet_tunnels SET state='deleted' WHERE id=?",(route['id'],))
                database.execute("UPDATE fleet_tunnel_services SET state='deleted' WHERE tunnel=?",(route['id'],))
                if database.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_events'").fetchone():
                    database.execute("UPDATE fleet_events SET resolved_at=?,last_at=? WHERE node=? AND code IN ('relay_client_unreachable','relay_proxy_unreachable') AND resolved_at IS NULL",(time.time(),time.time(),route['node']))
            self.reconnect(route['node'])
            from .native_management import refresh_management_sources
            refresh_management_sources(self,route['node'])
            self.update(job,'succeeded','Туннель удалён. Подписка снова выдаёт прямые адреса ноды')
        except Exception:
            self.restore_proxy_routes(removed)
            self.update(job,'rolled_back','Удаление отменено. Правила туннеля восстановлены')

    def reconnect(self, node):
        if node.startswith('xray:') and node[5:].isdigit():
            from app import xray
            xray.operations.connect_node(int(node[5:]), refresh_endpoint=True)

    def summary(self, database, node):
        row = database.execute('''SELECT t.id,t.state,t.checked_at,t.result,e.name,e.domain
            FROM fleet_tunnels t JOIN fleet_relay_entries e ON e.id=t.entry
            WHERE t.node=? AND t.state<>'deleted' ''',(node,)).fetchone()
        if row is None:return None
        value = json.loads(row['result'])
        fresh = bool(row['checked_at'] and time.time()-row['checked_at']<=180)
        management = database.execute("SELECT 1 FROM fleet_tunnel_services WHERE tunnel=? AND kind='management' AND state='active'",(row['id'],)).fetchone() is not None
        return {**value,'id':row['id'],'active':row['state']=='active','fresh':fresh,
            'state':('available' if value.get('vpn_passed',value.get('passed')) else 'unavailable') if fresh and value.get('vpn_passed',value.get('passed')) is not None else 'unknown',
            'entry_name':row['name'],'domain':row['domain'],'checked_at':row['checked_at'],'management':management,
            'origin':database.execute('SELECT origin FROM fleet_tunnels WHERE id=?',(row['id'],)).fetchone()['origin']}

    def check_active(self):
        with self.store.connection() as database:
            routes = [dict(row) for row in database.execute("SELECT * FROM fleet_tunnels WHERE state='active'")]
        for route in routes:
            with self.lock:
                if route['entry'] in self.busy:continue
            try:
                entry = self.entry(route['entry'])
                source,profile = self.source(route['node'])
                services = list(self.endpoint_map(route['node']).values())
                route['_services'] = services
                result = self.verify_route(source,profile,entry,route['origin'],services,False)
            except Exception as error:
                result = {'passed':False,'vpn_passed':None,'proxies_passed':None,'checked_at':time.time(),'error':type(error).__name__,
                    'origin':'Сервер панели → выбранный вход'}
            self.record_check(route,result)

    def record_check(self,route,result,owned=False):
        with self.lock,self.store.connection(write=True) as database:
            if route['entry'] in self.busy and not owned:return
            if not self.route_matches(database, route):return
            condition="state<>'deleted'" if owned else "state='active'"
            database.execute("UPDATE fleet_tunnels SET checked_at=?,result=? WHERE id=? AND "+condition,
                (time.time(),json.dumps(result),route['id']))
            if database.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_events'").fetchone():
                for code,field in [('relay_client_unreachable','vpn_passed'),('relay_proxy_unreachable','proxies_passed')]:
                    incident=database.execute('SELECT id FROM fleet_events WHERE node=? AND code=? AND resolved_at IS NULL',(route['node'],code)).fetchone()
                    if result.get(field) is True and incident:
                        database.execute('UPDATE fleet_events SET resolved_at=?,last_at=? WHERE id=?',(time.time(),time.time(),incident['id']))
                    elif result.get(field) is False:
                        if incident:database.execute('UPDATE fleet_events SET last_at=?,occurrences=occurrences+1 WHERE id=?',(time.time(),incident['id']))
                        else:database.execute('INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,?,\'error\',?,?)',(route['node'],code,time.time(),time.time()))

    @staticmethod
    def route_matches(database, route):
        current = database.execute("SELECT * FROM fleet_tunnels WHERE id=? AND state<>'deleted'", (route['id'],)).fetchone()
        if current is None or any(current[key] != route[key] for key in ('node','entry','origin','generation')):
            return False
        if '_services' in route:
            fields = ('id','entry','kind','proxy','protocol','origin_port','public_port','config','state')
            expected = sorted(tuple(value[key] for key in fields) for value in route['_services'])
            actual = sorted(tuple(value[key] for key in fields) for value in database.execute(
                "SELECT * FROM fleet_tunnel_services WHERE tunnel=? AND entry=? AND state IN ('active','needs_reconcile')", (route['id'],route['entry'])))
            if expected != actual:return False
        return True



    def reconcile_entry(self, identity):
        entry = self.entry(identity)
        return self.launch(secrets.token_hex(16),identity,self.reconcile_entry_worker,entry)

    def recheck_route(self, identity):
        self.changes.recover()
        with self.store.connection() as database:
            row=database.execute("SELECT * FROM fleet_tunnels WHERE id=? AND state<>'deleted'",(identity,)).fetchone()
        if row is None:raise ProvisionError('Туннель не найден')
        return self.launch(secrets.token_hex(16),row['entry'],self.recheck_route_worker,dict(row))

    def recheck_route_worker(self, identity, route):
        with self.store.connection() as database:
            if not self.route_matches(database, route):
                raise ProvisionError('Вход маршрута изменился. Повторите проверку текущего входа')
        entry=self.entry(route['entry'])
        source,profile=self.source(route['node'])
        if str(source['identity']['created_at'])!=route['generation']:
            raise ProvisionError('Экземпляр выходной ноды изменился. Удалите прежний маршрут и создайте его для текущей ноды')
        self.update(identity,'running','Сверка правил выбранного входного маршрута')
        control=self.control(entry)
        actual={value['name']:{key:item for key,item in value.items() if key!='status'} for value in control.services()}
        with self.store.connection() as database:
            services=[dict(row) for row in database.execute("SELECT * FROM fleet_tunnel_services WHERE tunnel=? AND entry=? AND state IN ('active','needs_reconcile')",(route['id'],route['entry']))]
        for service in services:
            config=json.loads(service['config'])
            if config['name'] not in actual:
                prefix='rime-'+service['id']+'-'
                matching=None
                for name,value in actual.items():
                    if name.startswith(prefix) and {**value,'name':config['name']}==config:
                        matching=value
                        break
                if matching:
                    config=matching
                else:
                    config['name']=prefix+secrets.token_hex(4)
                service['config']=json.dumps(config)
                with self.store.connection(write=True) as database:
                    database.execute('UPDATE fleet_tunnel_services SET config=? WHERE id=?',(service['config'],service['id']))
                    database.execute("UPDATE fleet_tunnels SET checked_at=NULL,result='{}' WHERE id=?",(route['id'],))
                if matching is None:control.add(config)
            elif actual[config['name']]!=config:raise ProvisionError('Правило входа изменено отдельно от панели. Удалите этот маршрут и создайте его заново')
        control.save()
        self.update(identity,'running','Проверка VPN, прокси и SSH через выбранный вход')
        route['_services'] = services
        result=self.verify_route(source,profile,entry,route['origin'],services,False)
        self.record_check(route,result,owned=True)
        if result['passed']:
            with self.store.connection(write=True) as database:
                if not self.route_matches(database, route):
                    raise ProvisionError('Маршрут изменился во время проверки')
                database.execute("UPDATE fleet_tunnels SET state='active' WHERE id=?",(route['id'],))
                database.execute("UPDATE fleet_tunnel_services SET state='active' WHERE tunnel=? AND entry=? AND state IN ('active','needs_reconcile')",(route['id'],route['entry']))
            self.reconnect(route['node'])
            self.update(identity,'succeeded','Передача данных и доступные службы выбранного маршрута подтверждены')
        else:
            message='VPN передаёт трафик. Проверка дополнительных служб завершилась ошибкой' if result.get('vpn_passed') else 'VPN через выбранный вход не прошёл проверку'
            self.update(identity,'failed',message)

    def reconcile_entry_worker(self, identity, entry):
        self.update(identity,'running','Проверка защищённого управления и метрик входного сервера')
        self.control(entry).services()
        current = self.entry(entry['id'])
        if not current['seen_at'] or time.time()-current['seen_at']>60:
            raise ProvisionError('Нет свежей телеметрии входного сервера')
        with self.store.connection(write=True) as database:
            database.execute("UPDATE fleet_relay_entries SET state='active' WHERE id=? AND state<>'deleted'",(entry['id'],))
        self.update(identity,'succeeded','Управление входным сервером и свежие метрики подтверждены')

    def ingest(self, identity, header, packet):
        entry = self.entry(identity)
        if entry['state']=='deleted':raise PermissionError()
        credential = json.loads(self.proxies.secrets.decrypt('relay/'+identity,entry['credential']))
        if not header.isascii() or not hmac.compare_digest(header,'Bearer '+credential['meter_token']):
            raise PermissionError()
        result = self.accounting.ingest(identity,packet)
        if not result.get('duplicate') and packet.get('health'):
            with self.store.connection(write=True) as database:
                previous = database.execute('SELECT seen_at FROM fleet_relay_entries WHERE id=?',(identity,)).fetchone()['seen_at']
                if previous is None or packet['observed_at'] > previous:
                    database.execute('UPDATE fleet_relay_entries SET seen_at=?,health=? WHERE id=?',
                        (packet['observed_at'],json.dumps(packet.get('health',{})),identity))
        return result

    def prune(self):
        self.accounting.prune()
        self.switches.prune()
        self.retirements.prune()
        with self.store.connection(write=True) as database:
            database.execute("DELETE FROM fleet_relay_jobs WHERE state<>'running' AND updated_at<?",(time.time()-90*86400,))
            database.execute("DELETE FROM fleet_relay_changes WHERE phase IN ('committed','rolled_back','abandoned') AND updated_at<?",(time.time()-90*86400,))
