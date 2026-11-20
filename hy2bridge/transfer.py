"""Restore a panel-managed node on a fresh server while retaining its identity."""
import hashlib
import json
import os
import time
from copy import deepcopy
import secrets
import socket
import ipaddress
from urllib.parse import quote,urlsplit

from .provision import Provisioner, ProvisionError
from .native_trust import NativeTrust

MANAGEMENT_PROFILE_KEYS=('management_server_certificate','management_certificate_verified',
                         'management_auth','management_source_policy','management_api_direct')


class NodeTransfer(Provisioner):
    def __init__(self, provision, operations, probe, lifecycle, recovery=None, proxies=None):
        self.relay_success_pending=set()
        super().__init__(provision.store, provision.settings, self.register_node, self.restore_node,
                         self.node_ready, self.accept_node, self.verify_node)
        self.plans = provision.plans
        self.lock = provision.lock
        self.running = provision.running
        self.operations = operations
        self.probe = probe
        self.lifecycle = lifecycle
        self.recovery = recovery
        self.proxies = proxies
        with self.store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_node_transfers(
                id TEXT PRIMARY KEY,node TEXT NOT NULL,snapshot TEXT NOT NULL,
                installed TEXT NOT NULL DEFAULT '{}',state TEXT NOT NULL,created_at REAL NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_transfer_components(
                transfer_id TEXT NOT NULL,kind TEXT NOT NULL,remote_id TEXT NOT NULL,
                PRIMARY KEY(transfer_id,kind,remote_id))''')
            pending = [dict(row) for row in db.execute("SELECT * FROM fleet_node_transfers WHERE state='switched'")]
        for row in pending:
            try:
                self.restore_node(row['id'], {}, reconnect=False)
                self.update(row['id'], 'failed', 'Перенос прерван перезапуском панели. Регистрация восстановлена; новый сервер требует SSH-сверки')
            except Exception:
                self.update(row['id'], 'failed', 'Перенос прерван. Регистрация изменилась и требует ручной сверки')
        with self.store.connection() as db:
            completed = [row['id'] for row in db.execute("SELECT t.id FROM fleet_node_transfers t JOIN fleet_jobs j ON j.id=t.id WHERE t.state='succeeded' AND j.state<>'succeeded'")]
        for job in completed:
            with self.store.connection() as db:
                pending=db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_relay_changes'").fetchone() and db.execute("SELECT 1 FROM fleet_relay_changes WHERE id=? AND phase NOT IN ('committed','abandoned')",(job,)).fetchone()
            if pending:continue
            self.update(job, 'succeeded', 'Перенос завершён; подтверждение задачи восстановлено после перезапуска')

    @staticmethod
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    def update(self, job, state, message, context=None):
        relays=getattr(getattr(self,'proxies',None),'relays',None)
        if state in ['failed','rolled_back']:self.relay_success_pending.discard(job)
        if state=='succeeded' and relays:
            change=relays.changes.read(job)
            if change and change['phase'] not in ['committed','rolled_back','abandoned']:
                self.relay_success_pending.add(job)
                return super().update(job,'running','Нода проверена. Завершение переноса её входного маршрута',context)
        if state=='succeeded':self.relay_success_pending.discard(job)
        if state=='succeeded' and self.recovery:
            with self.store.connection() as db:count=db.execute("SELECT COUNT(*) FROM fleet_transfer_components WHERE transfer_id=? AND kind='proxy'",(job,)).fetchone()[0]
            message=('Нода и прокси перенесены' if count else 'Нода перенесена')+'. Прежние доступы и подписки сохранены'
        if state == 'failed':
            with self.store.connection(write=True) as db:
                db.execute("UPDATE fleet_node_transfers SET state='needs_reconcile' WHERE id=? AND state='switched'", (job,))
                row = db.execute("SELECT 1 FROM fleet_node_transfers WHERE id=? AND state='needs_reconcile'", (job,)).fetchone()
            if row:
                message += '. Сверьте регистрацию в карточке ноды и контейнер на новом сервере. Они сохранены для проверки'
        super().update(job, state, message, context)

    def snapshot(self, node, db):
        if node == 'xray:local':
            raise ProvisionError('Перенос сервера панели выполняется отдельной процедурой')
        managed = db.execute("SELECT * FROM fleet_managed WHERE id=? OR ('xray:'||native_id)=?", (node, node)).fetchone()
        observer = db.execute('SELECT * FROM fleet_observers WHERE node=?', (node,)).fetchone()
        source = db.execute('SELECT * FROM fleet_observer_sources WHERE node=?', (node,)).fetchone()
        if node.startswith('xray:') and node[5:].isdigit():
            native = db.execute('SELECT id,name,address,port,api_port,created_at FROM nodes WHERE id=?', (int(node[5:]),)).fetchone()
            if not native:
                raise ProvisionError('Исходная нода отсутствует')
            try:
                scope = self.lifecycle.plan(node, db)
            except ValueError as error:
                raise ProvisionError(str(error)) from None
            host_ids = scope['host_ids']
            hosts = [dict(row) for row in db.execute('SELECT * FROM hosts WHERE id IN (' + ','.join('?' for _ in host_ids) + ') ORDER BY id', host_ids)]
            if not hosts:
                raise ProvisionError('Сначала свяжите адреса подписок с исходной нодой в её настройках')
            template = self.settings.get('vless_template', {})
            if not self.recovery and any(host['inbound_tag'] != template.get('inbound_tag') for host in hosts):
                raise ProvisionError('У ноды есть адреса другого VLESS-шаблона. Для сохранения этих конфигураций требуется отдельный профиль восстановления')
            fallback={}
            if self.recovery and any(not host['port'] for host in hosts):
                recovered=self.recovery.load(node,db).get('vpn') or {}
                config=recovered.get('config') or dict(self.probe.xray.config)
                fallback={value['tag']:value['port'] for value in config.get('inbounds',[])}
            endpoints = {(host['address'].split(',')[0].strip(), host['port'] or fallback.get(host['inbound_tag'])) for host in hosts}
            if not self.recovery and len(endpoints) != 1:
                raise ProvisionError('Нода использует несколько адресов или портов. Требуется профиль восстановления всех адресов')
            domain, port = sorted(endpoints)[0]
            if not self.recovery and any(host.get('path') or host.get('host') or
                   host.get('sni') not in (None, '', domain) or
                   host.get('security') not in (None, 'inbound_default', 'tls') for host in hosts):
                raise ProvisionError('У адресов ноды есть собственные SNI, путь или параметры транспорта. Требуется отдельная проверка прежних клиентских конфигураций')
            identity = dict(native)
            protocol = 'vless'
        else:
            native = None
            hosts = []
            if not managed and not (self.recovery and observer and observer['kind']=='legacy_hy2'):
                raise ProvisionError('Для этой Hy2-ноды требуется импорт прежней конфигурации. Одних метрик недостаточно для восстановления ключей')
            if managed and managed['protocol']!='hysteria2':raise ProvisionError('Протокол ноды не совпадает с реестром')
            identity_row = db.execute('SELECT id,name,address,created_at FROM fleet_inventory WHERE id=?', (node,)).fetchone()
            if not identity_row:
                raise ProvisionError('Исходная нода отсутствует')
            identity = dict(identity_row)
            domain, port = (managed['domain'], managed['port']) if managed else (observer['domain'],observer['port'])
            protocol = 'hysteria2'
        if not domain or not port or (not self.recovery and domain.replace('.', '').isdigit()):
            raise ProvisionError('Сохранение адреса в подписке требует прежнего DNS-имени ноды')
        proxy_rows=[dict(row) for row in db.execute('SELECT * FROM fleet_proxy_services WHERE node=? AND active=1 ORDER BY id',(node,))]
        if proxy_rows and not self.recovery:
            raise ProvisionError('Автоматический перенос VPN вместе с HTTP/HTTPS-прокси пока не поддерживается. Требуется отдельное восстановление прокси с сохранением доступов')
        result={'node': node, 'native': dict(native) if native else None, 'identity': identity,
                'managed': dict(managed) if managed else None, 'observer': dict(observer) if observer else None,
                'observer_source': dict(source) if source else None, 'hosts': hosts,
                'name': managed['name'] if managed else identity['name'],
                'protocol': protocol, 'domain': domain, 'vpn_port': port}
        if native and db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_native_trust'").fetchone():
            result['management_trust']=NativeTrust.snapshot(db,node)
            if self.recovery:
                vpn=self.recovery.load(node,db).get('vpn') or {}
                result['management_profile']={key:deepcopy(vpn[key]) for key in MANAGEMENT_PROFILE_KEYS if key in vpn}
        if self.recovery:
            row=db.execute('SELECT digest FROM fleet_recovery_profiles WHERE node=?',(node,)).fetchone()
            result.update(proxies=proxy_rows,recovery_digest=row['digest'] if row else None,
                          external=[dict(value) for value in db.execute('SELECT * FROM fleet_external_links WHERE node=? ORDER BY position',(node,))])
        return result

    def options_for(self, node):
        profile=self.prepare_profile(node) if self.recovery else None
        with self.store.connection() as db:
            source = self.snapshot(node, db)
        result={key: source[key] for key in ['node', 'name', 'protocol', 'domain', 'vpn_port']} | {
            'old_address': source['identity']['address'],
            'instructions': 'Создайте новый сервер и направьте прежнее DNS-имя на его IPv4. Укажите прямой SSH-доступ. Сохраняются пользователи, ключи, адреса подписок и история ноды.'}
        if self.recovery:
            result['recovery']=self.recovery.summary(node)
            vpn=profile['vpn']
            inbounds={value['port']:value for value in vpn['config'].get('inbounds',[])}
            services=[]
            for outside,inside,protocol in vpn.get('publish',[[source['vpn_port'],24443,'udp']]):
                stream=inbounds.get(inside,{}).get('streamSettings',{})
                title=('VLESS '+stream.get('network','').upper()+' '+stream.get('security','').upper()).strip() if source['protocol']=='vless' else 'Hysteria2'
                services.append(title+' · '+str(outside)+'/'+protocol.upper())
            for proxy in profile['proxies'].values():
                services.extend(('HTTP' if inside==3128 else 'HTTPS')+'-прокси · '+str(outside)+'/TCP' for outside,inside in proxy['publish'])
            result['services']=services
            with self.store.connection() as db:
                failed=db.execute("SELECT id,context FROM fleet_jobs WHERE state='failed' ORDER BY created_at DESC LIMIT 200").fetchall()
            for row in failed:
                context=json.loads(row['context'])
                if context.get('move_node')==node:
                    result['retry_job']={'id':row['id'],'host':context.get('host')}
                    break
        return result

    def validate(self, data):
        if self.recovery:data['_profile']=self.prepare_profile(data['move_node'])
        with self.store.connection() as db:
            source = self.snapshot(data['move_node'], db)
            busy = db.execute("SELECT 1 FROM fleet_node_transfers WHERE node=? AND state='switched'", (data['move_node'],)).fetchone()
        if busy:
            raise ProvisionError('Для этой ноды уже выполняется перенос')
        if data.get('_source') and self.digest(source) != self.digest(data['_source']):
            raise ProvisionError('Исходная нода или её адреса изменились. Повторите проверку переноса')
        data['_source'] = source
        for key in ['name', 'protocol', 'domain', 'vpn_port']:
            data[key] = source[key]
        super().validate(data)
        if (data.get('address') or data['host']) == source['identity']['address']:
            raise ProvisionError('Для переноса требуется другой сервер. Текущая нода на месте не переустанавливается')
        if not self.probe.settings.get('probe_username'):
            raise ProvisionError('Для переноса обязательна настроенная проверка настоящего VPN-трафика')

    def validate_connection(self,data):
        if not self.recovery:return super().validate_connection(data)
        self.target(data['host'],data['ssh_port'])
        addresses=self.resolve(data['host'],data['ssh_port'])
        address=data.get('address') or addresses[0]
        if address not in addresses:raise ProvisionError('Адрес нового сервера изменился. Повторите проверку SSH-ключа')
        data['address']=address
        if data['protocol']=='hysteria2' and literal_ip(data['_source']['domain']):
            data['_profile']['vpn'].setdefault('sni',data['_source']['domain'])
        for proxy in data['_profile']['proxies'].values():
            if literal_ip(proxy['domain']):
                if any(inside==8443 for outside,inside in proxy['publish']):
                    from cryptography import x509
                    certificate=x509.load_pem_x509_certificate(proxy['files']['cert.pem'].encode())
                    names=certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)
                    if ipaddress.ip_address(address) not in names:
                        raise ProvisionError('HTTPS-прокси использует сертификат прежнего IP. Для нового IP нужен действующий сертификат или прежнее DNS-имя')
                proxy['domain']=address
        data['_targets']=self.probe.transfer_targets(data['_source'],data['_profile'],data)
        domains={target['config']['_hostname'] for target in data['_targets']}
        domains.update(value['domain'] for value in data['_profile']['proxies'].values())
        for domain in domains:
            resolved={item[4][0] for item in socket.getaddrinfo(domain,None,socket.AF_INET,socket.SOCK_STREAM)}
            if not self.settings.get('lab_network') and resolved!={address}:
                raise ProvisionError('Каждый прежний DNS-адрес VPN и прокси должен указывать на новый IPv4. Не совпадает '+domain)
        vpn=data['_profile']['vpn']
        data['certificate']=vpn.get('certificate','')
        data['certificate_key']=vpn.get('certificate_key','')
        data['_custom_tls']=False

    def prepare_profile(self,node):
        from .recovery import proxy_runtime_config
        with self.store.connection() as db:
            source=self.snapshot(node,db)
        profile=self.recovery.load(node)
        if source['protocol']=='vless':
            from .recovery import vless_profile
            saved=(profile.get('vpn') or {}).get('config')
            config=saved or dict(self.probe.xray.config)
            profile['vpn']={**(profile.get('vpn') or {}),**vless_profile(config,source['hosts'],profile.get('originals'),include_all=bool(saved),published=(profile.get('vpn') or {}).get('publish'))}
        elif not profile.get('vpn'):
            raise ProvisionError('Сохранённая конфигурация Hysteria2 отсутствует. Импортируйте резерв ноды один раз перед переносом')
        active={row['id'] for row in source.get('proxies',[])}
        with self.store.connection() as db:
            registered={row['id'] for row in db.execute('SELECT id FROM fleet_proxy_services WHERE node=?',(node,))}
        profile['proxies']={key:value for key,value in profile['proxies'].items() if key in active or key not in registered}
        for proxy in profile['proxies'].values():
            proxy['files']['squid.conf']=proxy_runtime_config(proxy['files']['squid.conf'])
        missing=active-profile['proxies'].keys()
        if missing:raise ProvisionError('В резерве отсутствуют TLS или настройки установленного прокси. Обновите комплект со старой ноды либо импортируйте архив')
        for row in source.get('proxies',[]):
            proxy=profile['proxies'][row['id']]
            accounts=[line.split(':',1) for line in proxy['files']['passwd'].splitlines() if line]
            if row['username'] not in {value[0] for value in accounts}:
                raise ProvisionError('Резерв прокси не содержит текущий логин панели. Обновите конфигурационный комплект')
            proxy['files']['passwd']='\n'.join(user+':'+(row['password_hash'] if user==row['username'] else hashed) for user,hashed in accounts)+'\n'
        if profile['proxies'] and (not self.proxies or not self.proxies.options()['enabled']):
            raise ProvisionError('Для переноса HTTP/HTTPS-прокси подготовьте его проверенный образ на панели')
        self.recovery.save(node,profile)
        return profile

    def required_ports(self,data):
        if not self.recovery:return super().required_ports(data)
        vpn=data['_profile']['vpn']
        ports=[(outside,protocol) for outside,inside,protocol in vpn.get('publish',[[data['vpn_port'],24443,'udp']])]
        if data['protocol']=='vless':ports += [(self.settings['vless_template']['service_port'],'tcp'),(self.settings['vless_template']['api_port'],'tcp')]
        for proxy in data['_profile']['proxies'].values():ports += [(outside,'tcp') for outside,inside in proxy['publish']]
        if len(set(ports))!=len(ports):raise ProvisionError('VPN и прокси в резерве используют один TCP/UDP-порт. Перенос требует отдельных IP или исправления исходной конфигурации')
        return ports

    def preflight(self, data):
        plan = super().preflight(data)
        plan['summary'].update({'Операция': 'Перенос существующей ноды', 'Сохраняется': 'ID ноды, пользователи, ключи, подписки, ограничения и история',
                                'Учёт': 'Учтённый расход сохраняется. Непереданные данные погибшего сервера восстанавливаются только из его журнала или резерва',
                                'DNS': 'Прежнее имя должно указывать на новый сервер',
                                'Старый сервер': 'Данные и службы старого сервера сохраняются',
                                'Откат': 'Прежняя регистрация восстанавливается. DNS возвращается владельцем отдельно'})
        if self.recovery:
            ports=self.required_ports(data)
            plan['summary']['Службы']=' · '.join(str(port)+'/'+protocol.upper() for port,protocol in ports if port not in [self.settings.get('vless_template',{}).get('service_port'),self.settings.get('vless_template',{}).get('api_port')])
            if any(literal_ip(host['address']) for host in data['_source']['hosts']) or literal_ip(data['_source']['domain']):
                plan['summary']['Адреса по IP']='Прежний URL подписки сохраняется. Клиентам с адресом по IP нужно обновить её содержимое после переноса'
        return plan

    def configuration(self, job, data, token):
        config = super().configuration(job, data, token)
        if data['protocol'] == 'hysteria2':
            agent = json.loads(config['files']['agent.json'])
            agent['panel_url'] = self.settings['panel_url'].rstrip('/') + '/api/hy2/nodes/' + data['move_node']
            config['files']['agent.json'] = json.dumps(agent)
        if self.recovery:
            vpn=data['_profile']['vpn']
            if data['protocol']=='vless':
                config['files']['node-profile.json']=json.dumps(vpn['config'])
                config['publish']=[tuple(value) for value in vpn['publish']]+config['publish'][-2:]
                config['env']['INBOUNDS']=','.join(value['tag'] for value in vpn['config']['inbounds'])
                config['env']['RIME_NODE_PROFILE']='/state/node-profile.json'
                if vpn.get('management_tls'):
                    config['files']['node-cert.pem']=vpn['management_tls']['certificate']
                    config['files']['node-key.pem']=vpn['management_tls']['key']
                config['env'].pop('RIME_NODE_CERTIFICATE',None);config['env'].pop('RIME_NODE_CERTIFICATE_KEY',None)
            else:
                current=json.loads(config['files']['hysteria.json'])
                restored=deepcopy(vpn['config'])
                if restored.get('auth',{}).get('type')!='http':
                    raise ProvisionError('Для прежних статических Hy2-доступов требуется сохранённое соответствие пользователям панели')
                restored.update(listen=current['listen'],auth=current['auth'],trafficStats=current['trafficStats'])
                restored.setdefault('tls',{}).update(cert='/state/cert.pem',key='/state/key.pem')
                config['files']['hysteria.json']=json.dumps(restored)
                config['publish']=[tuple(value) for value in vpn.get('publish',config['publish'])]
        return config

    def observer_configuration(self, job, data, token, registration):
        configuration = super().observer_configuration(job, data, token, registration)
        if self.recovery and data['protocol'] == 'vless':
            ports = [inside for outside, inside, protocol in data['_profile']['vpn']['publish']
                     if outside == data['vpn_port'] and protocol == 'tcp']
            if len(ports) != 1:
                raise ProvisionError('В резерве не найден однозначный внутренний порт VPN для проверки готовности')
            observer = json.loads(configuration['files']['config.json'])
            observer['vpn_port'] = ports[0]
            configuration['files']['config.json'] = json.dumps(observer)
        return configuration

    def worker(self,record):
        data=record['data'];job=record['plan']['id']
        relays=getattr(self.proxies,'relays',None)
        relay_prepared=False
        try:
            if relays:
                relay_prepared=relays.changes.prepare(job,data['move_node'],'transfer') is not None
            if self.recovery:
                data['_transfer_job']=job
                with self.store.connection(write=True) as db:
                    db.execute("INSERT INTO fleet_transfer_components VALUES(?,'vpn',?)",(job,job))
                    for identity in data['_profile']['proxies']:
                        runtime=hashlib.sha256((job+'/'+identity).encode()).hexdigest()[:32]
                        db.execute("INSERT INTO fleet_transfer_components VALUES(?,'proxy',?)",(job,runtime))
        except Exception:
            try:self.update(job,'failed','Не удалось сохранить состав переноса. Установка не начиналась')
            finally:
                with self.lock:self.running.discard(data.get('address') or data.get('host'))
                data.clear()
                lease = record.pop('_operation_lease', None)
                if lease is not None:os.close(lease)
                if relay_prepared:relays.changes.finish(job,False)
            return
        try:
            super().worker(record)
        finally:
            if relay_prepared:
                with self.store.connection() as db:
                    row=db.execute('SELECT state FROM fleet_node_transfers WHERE id=?',(job,)).fetchone()
                try:relays.changes.finish(job,bool(row and row['state']=='succeeded'))
                except Exception:self.update(job,'failed','Правила входного сервера требуют сверки. Откройте раздел туннелей')
                if job in self.relay_success_pending:
                    self.update(job,'succeeded','Нода и её входной маршрут перенесены')

    def remote(self,client,config):
        if self.recovery and config.get('action')=='preflight' and config.get('cleanup_job'):
            with self.store.connection() as db:
                children=[row['remote_id'] for row in db.execute("SELECT remote_id FROM fleet_transfer_components WHERE transfer_id=? AND kind='proxy'",(config['cleanup_job'],))]
            config={**config,'cleanup_proxy_ids':children}
        if self.recovery and config.get('action')=='rollback':
            with self.store.connection() as db:
                children=[row['remote_id'] for row in db.execute("SELECT remote_id FROM fleet_transfer_components WHERE transfer_id=? AND kind='proxy'",(config['id'],))]
            for identity in children:
                self.proxies.remote(client,{'id':identity,'action':'rollback','transfer_id':config['id']})
        return super().remote(client,config)

    def install_proxies(self,job,data):
        if not self.recovery:return
        data['_proxy_probes']={}
        if not data['_profile']['proxies']:return
        with self.connect(data) as client:
            from .bootstrap import inspect
            runtime=inspect(client,[])
            if runtime['uid']!=0:raise ProvisionError('Для переноса HTTP/HTTPS-прокси нужен прямой SSH-доступ root')
            for identity,proxy in data['_profile']['proxies'].items():
                runtime_id=hashlib.sha256((job+'/'+identity).encode()).hexdigest()[:32]
                password=secrets.token_urlsafe(32)
                username=proxy['files']['passwd'].splitlines()[0].split(':',1)[0]
                import bcrypt
                files=deepcopy(proxy['files'])
                probe_hash=bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()
                files['passwd']='\n'.join(username+':'+probe_hash if line.split(':',1)[0]==username else line for line in files['passwd'].splitlines())+'\n'
                config={'id':runtime_id,'node':data['move_node'],'action':'install','transfer_id':job,'source_service':identity,
                        'image':self.proxies.settings['image'],'publish':proxy['publish'],'files':files,
                        'restore_passwd_sha256':hashlib.sha256(proxy['files']['passwd'].encode()).hexdigest()}
                self.update(job,'running','Восстановление HTTP/HTTPS-прокси с прежними пользователями')
                self.proxies.upload_image(client,{'remote':runtime},config)
                self.proxies.remote(client,config)
                data['_proxy_probes'][identity]={'username':username,'password':password,'runtime_id':runtime_id}

    def register_node(self, job, data, token):
        source = data['_source']
        node = data['move_node']
        address = data.get('_registration_address') or data['address']
        managed = dict(source['managed']) if source['managed'] else {
            'id': job, 'protocol': data['protocol'], 'name': data['name'], 'domain': data['domain'],
            'port': data['vpn_port'], 'active': 1, 'native_id': source['native']['id'] if source['native'] else None, 'host_id': None}
        managed['token_hash'] = hashlib.sha256(token.encode()).hexdigest()
        if literal_ip(managed['domain']):managed['domain']=address
        if not source['native']:managed['id']=node
        self.install_proxies(job,data)
        with self.lifecycle.guard, self.store.connection(write=True) as db:
            if self.digest(self.snapshot(node, db)) != self.digest(source):
                raise ProvisionError('Исходная нода изменилась во время подготовки нового сервера')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_barriers'").fetchone() and db.execute('SELECT 1 FROM fleet_barriers').fetchone():
                raise ProvisionError('Дождитесь завершения безопасного сброса расхода')
            native = dict(source['native']) if source['native'] else None
            if native:
                template = self.settings['vless_template']
                native.update(address=address, port=template['service_port'], api_port=template['api_port'])
            installed = {'managed': managed, 'native': native, 'address': address}
            if native and 'management_trust' in source:
                certificate=data.get('_management_server_certificate')
                if not certificate:raise ProvisionError('Новый сервер не передал проверенный SSH-сертификат управления')
                installed['management_trust']=NativeTrust.enroll_verified_transfer(db,node,certificate,source['management_trust'])
            saved = dict(source)
            if not native:
                saved['accounting'] = {table: [dict(row) for row in db.execute('SELECT * FROM ' + table + ' WHERE node=?', (node,))]
                                       for table in ['hy2_nodes', 'hy2_totals']}
                if self.recovery and db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_meters'").fetchone():
                    saved['legacy_meter']=dict(db.execute('SELECT * FROM fleet_meters WHERE node=?',(node,)).fetchone() or {})
                if self.recovery:saved['retired']=dict(db.execute('SELECT * FROM fleet_legacy_retired WHERE node=?',(node,)).fetchone() or {})
            db.execute("INSERT INTO fleet_node_transfers VALUES(?,?,?,?,'switched',?)",
                       (job, node, json.dumps(saved), json.dumps(installed), time.time()))
            if native:
                db.execute('UPDATE nodes SET address=?,port=?,api_port=? WHERE id=?', (native['address'], native['port'], native['api_port'], native['id']))
            else:
                db.execute('UPDATE fleet_inventory SET address=? WHERE id=?', (address, node))
                db.execute('DELETE FROM hy2_nodes WHERE node=?', (node,))
                db.execute('DELETE FROM hy2_totals WHERE node=?', (node,))
                if self.recovery:
                    db.execute('INSERT OR REPLACE INTO fleet_legacy_retired VALUES(?,?)',(node,job))
                    db.execute('DELETE FROM fleet_observers WHERE node=?',(node,))
                    db.execute('DELETE FROM fleet_observer_sources WHERE node=?',(node,))
                    if 'legacy_meter' in saved:db.execute('DELETE FROM fleet_meters WHERE node=?',(node,))
            self.write_managed(db, managed)
            if self.recovery:
                security={value['tag']:value.get('streamSettings',{}).get('security') for value in data['_profile']['vpn']['config'].get('inbounds',[])}
                for host in source['hosts']:
                    values=[address if literal_ip(value.strip()) else value.strip() for value in host['address'].split(',')]
                    sni=host.get('sni')
                    if not sni and security.get(host['inbound_tag'])=='tls' and literal_ip(host['address'].split(',')[0].strip()):sni=host['address'].split(',')[0].strip()
                    if ','.join(values)!=host['address'] or sni!=host.get('sni'):
                        db.execute('UPDATE hosts SET address=?,sni=? WHERE id=?',(','.join(values),sni,host['id']))
                installed['hosts']=[dict(db.execute('SELECT * FROM hosts WHERE id=?',(host['id'],)).fetchone()) for host in source['hosts']]
                for external in source['external']:
                    marker='rime-transfer-auth'
                    link=external['prefix']+marker+external['suffix']
                    parsed=urlsplit(link)
                    if literal_ip(parsed.hostname or ''):
                        old='['+parsed.hostname+']' if ':' in parsed.hostname else parsed.hostname
                        changed=parsed._replace(netloc=parsed.netloc.replace('@'+old+':','@'+address+':')).geturl()
                        prefix,suffix=changed.split(marker,1)
                        db.execute('UPDATE fleet_external_links SET prefix=?,suffix=? WHERE node=?',(prefix,suffix,node))
                if data['protocol']=='hysteria2' and literal_ip(source['domain']) and not source['external']:
                    suffix='@'+address+':'+str(data['vpn_port'])+'/?sni='+quote(data['_profile']['vpn'].get('sni',source['domain']),safe='')+'#'+quote(data['name'],safe='')
                    position=db.execute('SELECT COALESCE(MAX(position),0)+1 FROM fleet_external_links').fetchone()[0]
                    db.execute('INSERT INTO fleet_external_links VALUES(?,?,?,?)',(node,'hysteria2://',suffix,position))
                installed['external']=[dict(row) for row in db.execute('SELECT * FROM fleet_external_links WHERE node=?',(node,))]
                saved['proxies']=source.get('proxies',[])
                saved['proxy_generation']=dict(db.execute('SELECT * FROM fleet_proxy_node_generations WHERE node=?',(node,)).fetchone() or {})
                _,generation=self.proxies.node_identity(node,db)
                installed['proxies']=[]
                existing={row['id']:row for row in source.get('proxies',[])}
                created=[]
                for identity,proxy in data['_profile']['proxies'].items():
                    row=deepcopy(existing.get(identity) or self.legacy_proxy_row(identity,proxy,data))
                    row.update(host=data['host'],address=address,domain=proxy['domain'],node_generation=generation,legacy_squid=0,checked_at=0,runtime_id=data['_proxy_probes'][identity]['runtime_id'],
                               result=json.dumps({'passed':False,'origin':self.settings.get('probe_origin','Сервер панели'),'checks':[]}))
                    columns=list(row)
                    db.execute('INSERT OR REPLACE INTO fleet_proxy_services('+','.join(columns)+') VALUES('+','.join('?' for _ in columns)+')',list(row.values()))
                    installed['proxies'].append(row)
                    if identity not in existing:
                        self.proxies.write_job(db,identity,node,'running','Перенос прежнего прокси',{'transfer':job})
                        created.append(identity)
                installed['created_proxy_jobs']=created
                db.execute('UPDATE fleet_node_transfers SET snapshot=?,installed=? WHERE id=?',(json.dumps(saved),json.dumps(installed),job))
            db.execute('DELETE FROM fleet_health WHERE node=?', (node,))
            db.execute('DELETE FROM fleet_client_probes WHERE node=?', (node,))
        data['_cutover_at'] = time.time()
        data['_registration_id']=managed['id']
        if native:
            relays=getattr(self.proxies,'relays',None)
            if relays and relays.changes.pending(job):relays.changes.suspended_management.add(node)
            self.operations.observers.register_native(node, token, data['domain'], data['vpn_port'])
            self.reconnect(native['id'])
        return {'node': node, 'native_id': native['id'] if native else None}

    def legacy_proxy_row(self,identity,proxy,data):
        accounts=[line.split(':',1) for line in proxy['files']['passwd'].splitlines() if line]
        ports={inside:outside for outside,inside in proxy['publish']}
        return {'id':identity,'node':data['move_node'],'host':data['_source']['identity']['address'],
                'address':data['_source']['identity']['address'],'domain':proxy['domain'],
                'http_port':ports.get(3128),'https_port':ports.get(8443),'username':accounts[0][0],
                'password_hash':accounts[0][1],'created_at':time.time(),'checked_at':0,'result':'{}',
                'active':1,'node_generation':'',
                'password_secret':self.proxies.encrypted_password(identity,proxy['known_password']) if proxy.get('known_password') else '',
                'legacy_squid':0,'runtime_id':''}

    @staticmethod
    def write_managed(db, value):
        columns = ['id', 'protocol', 'token_hash', 'name', 'domain', 'port', 'active', 'native_id', 'host_id']
        db.execute('INSERT OR REPLACE INTO fleet_managed(' + ','.join(columns) + ') VALUES(' + ','.join('?' for _ in columns) + ')', [value[key] for key in columns])

    def reconnect(self, native_id):
        from app import xray
        with xray.operations.NODE_LIFECYCLE_LOCK:
            xray.nodes.pop(native_id,None)
        xray.operations.connect_node(native_id)

    def node_ready(self, job, data):
        from .telemetry import complete_resources
        with self.store.connection() as db:
            row = db.execute('SELECT seen_at,data FROM fleet_health WHERE node=?', (data['move_node'],)).fetchone()
        if not row or row['seen_at'] < data['_cutover_at']:
            return False
        metrics = json.loads(row['data'])
        node = {'seen_at': row['seen_at'], 'metrics': metrics}
        if not complete_resources(node) or metrics.get('error') or metrics.get('mem_total_bytes') != data['_expected_memory']:
            return False
        if data['protocol'] == 'hysteria2':
            return metrics.get('accounting_durable') is True
        return self.operations.native_probe(data['_source']['native']['id']) is True

    def verify_node(self, job, data):
        if self.recovery:
            self.probe.run_targets(data['_targets'],data['_registration_id'])
            self.verify_proxies(job,data)
            relays=getattr(self.proxies,'relays',None)
            if relays and relays.changes.pending(job):
                self.update(job,'running','Перенос правил входного сервера и проверка туннеля')
                relays.changes.retarget(job,data)
            return
        self.probe.run(data['_source']['managed']['id'] if data['_source']['managed'] else job, data)

    def verify_proxies(self,job,data):
        data['_proxy_results']={}
        if not data['_profile']['proxies']:return
        with self.connect(data) as client:
            for identity,proxy in data['_profile']['proxies'].items():
                self.update(job,'running','Проверка HTTP/HTTPS-прокси и возврат прежних паролей')
                credentials=data['_proxy_probes'][identity]
                ports={inside:outside for outside,inside in proxy['publish']}
                request={'address':data['address'],'domain':proxy['domain'],'http_port':ports.get(3128),'https_port':ports.get(8443),
                         'proxy_username':credentials['username'],'proxy_password':credentials['password']}
                result=self.proxies.check(request)
                if not result['passed']:raise ProvisionError('HTTP/HTTPS-прокси не передал проверочный трафик')
                self.proxies.remote(client,{'id':credentials['runtime_id'],'action':'transfer-finalize','transfer_id':job,
                                            'passwd':proxy['files']['passwd']})
                from .proxy_probe import connect
                import ssl
                context=ssl.create_default_context(cafile=self.settings.get('panel_ca_file'))
                for mode,port in [('http',ports.get(3128)),('https',ports.get(8443))]:
                    if port is None:continue
                    deadline=time.monotonic()+15
                    while True:
                        try:
                            connection,status=connect(data['address'],port,proxy['domain'],mode=='https',context,
                                                      self.proxies.settings.get('probe_host','api.ipify.org'),self.proxies.settings.get('probe_port',443),
                                                      credentials['username']+':'+credentials['password'],deadline)
                            break
                        except OSError:
                            if time.monotonic()>=deadline:raise ProvisionError('Прокси не ответил после восстановления исходного файла пользователей') from None
                            time.sleep(.2)
                    connection.close()
                    if status!=407:raise ProvisionError('Временная проверочная запись прокси не отозвана')
                data['_proxy_results'][identity]=result

    def accept_node(self, job, data):
        with self.lifecycle.guard, self.store.connection(write=True) as db:
            row = db.execute('SELECT * FROM fleet_node_transfers WHERE id=?', (job,)).fetchone()
            if not row or row['state'] != 'switched' or not self.owns_registration(db, row):
                raise ProvisionError('Регистрация изменилась во время переноса. Требуется сверка')
            db.execute("UPDATE fleet_node_transfers SET state='succeeded' WHERE id=?", (job,))
            if self.recovery:
                if data['_source'].get('native'):
                    stored=self.recovery.load(data['move_node'],db).get('vpn') or {}
                    for key in MANAGEMENT_PROFILE_KEYS:
                        if key in ('management_server_certificate','management_certificate_verified'):continue
                        if key=='management_auth' and data['_profile']['vpn'].get('management_auth'):continue
                        if key in stored:data['_profile']['vpn'][key]=deepcopy(stored[key])
                    certificate=(data['_profile']['vpn'].get('management_tls') or {}).get('certificate')
                    if certificate:
                        data['_profile']['vpn'].update(management_server_certificate=certificate,management_certificate_verified=True)
                for identity,result in data['_proxy_results'].items():
                    db.execute('UPDATE fleet_proxy_services SET result=?,checked_at=? WHERE id=?',(json.dumps(result),time.time(),identity))
                    self.proxies.write_job(db,identity,data['move_node'],'succeeded','VPN и прокси перенесены, прежние доступы сохранены')
                self.recovery.save(data['move_node'],data['_profile'],db)
                if data['protocol']=='hysteria2':
                    db.execute("UPDATE fleet_events SET resolved_at=?,last_at=? WHERE node=? AND code='meter_unavailable' AND resolved_at IS NULL",(time.time(),time.time(),data['move_node']))
            data['_transfer_accepted'] = True

    def owns_registration(self, db, row):
        installed = json.loads(row['installed'])
        current = db.execute('SELECT * FROM fleet_managed WHERE id=?', (installed['managed']['id'],)).fetchone()
        if not current or dict(current) != installed['managed']:
            return False
        for host in installed.get('hosts',[]):
            current=db.execute('SELECT * FROM hosts WHERE id=?',(host['id'],)).fetchone()
            if not current or dict(current)!=host:return False
        if 'external' in installed:
            current_links=[dict(value) for value in db.execute('SELECT * FROM fleet_external_links WHERE node=?',(row['node'],))]
            if current_links!=installed['external']:return False
        for proxy in installed.get('proxies',[]):
            current=db.execute('SELECT * FROM fleet_proxy_services WHERE id=?',(proxy['id'],)).fetchone()
            if not current or dict(current)!=proxy:return False
        native = installed['native']
        if native:
            if 'management_trust' in installed and NativeTrust.snapshot(db,row['node'])!=installed['management_trust']:
                return False
            current = db.execute('SELECT id,name,address,port,api_port,created_at FROM nodes WHERE id=?', (native['id'],)).fetchone()
            return current is not None and dict(current) == native
        current = db.execute('SELECT address FROM fleet_inventory WHERE id=?', (row['node'],)).fetchone()
        return current is not None and current['address'] == installed['address']

    def restore_node(self, job, data, reconnect=True):
        native_id = None
        with self.lifecycle.guard, self.store.connection(write=True) as db:
            row = db.execute('SELECT * FROM fleet_node_transfers WHERE id=?', (job,)).fetchone()
            if not row or row['state'] == 'rolled_back':
                return
            if row['state'] != 'switched' or not self.owns_registration(db, row):
                raise ProvisionError('Регистрация изменилась. Автоматический откат остановлен для сверки')
            source = json.loads(row['snapshot'])
            installed = json.loads(row['installed'])
            if source['native']:
                if 'management_trust' in installed:
                    NativeTrust.restore_transfer(db,source['node'],installed['management_trust'],source.get('management_trust'))
                if self.recovery and 'management_profile' in source:
                    profile=self.recovery.load(source['node'],db)
                    vpn=profile.get('vpn') or {}
                    for key in MANAGEMENT_PROFILE_KEYS:
                        if key in source['management_profile']:vpn[key]=deepcopy(source['management_profile'][key])
                        else:vpn.pop(key,None)
                    self.recovery.save(source['node'],profile,db)
                native = source['native']
                native_id = native['id']
                db.execute('UPDATE nodes SET address=?,port=?,api_port=? WHERE id=?', (native['address'], native['port'], native['api_port'], native_id))
            else:
                db.execute('UPDATE fleet_inventory SET address=? WHERE id=?', (source['identity']['address'], source['node']))
                if self.recovery and 'legacy_meter' in source:
                    db.execute('DELETE FROM fleet_meters WHERE node=?',(source['node'],))
                    meter=source['legacy_meter']
                    if meter:db.execute('INSERT INTO fleet_meters('+','.join(meter)+') VALUES('+','.join('?' for _ in meter)+')',list(meter.values()))
                if self.recovery and 'retired' in source:
                    db.execute('DELETE FROM fleet_legacy_retired WHERE node=?',(source['node'],))
                    if source['retired']:db.execute('INSERT INTO fleet_legacy_retired VALUES(?,?)',(source['retired']['node'],source['retired']['transfer_id']))
                traffic = None
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_node_traffic'").fetchone():
                    traffic = [tuple(row) for row in db.execute('SELECT node,hour,incoming,outgoing FROM fleet_node_traffic WHERE node=?', (source['node'],))]
                for table, rows in source.get('accounting', {}).items():
                    if table not in ['hy2_nodes', 'hy2_totals']:
                        raise ProvisionError('Некорректный снимок учёта ноды')
                    db.execute('DELETE FROM ' + table + ' WHERE node=?', (source['node'],))
                    for value in rows:
                        db.execute('INSERT INTO ' + table + '(' + ','.join(value) + ') VALUES(' + ','.join('?' for _ in value) + ')', list(value.values()))
                if traffic is not None:
                    # Restoring the old cumulative baseline fires insert accounting
                    # triggers. Retain the actual old and candidate traffic exactly.
                    db.execute('DELETE FROM fleet_node_traffic WHERE node=?', (source['node'],))
                    db.executemany('INSERT INTO fleet_node_traffic VALUES(?,?,?,?)', traffic)
            if source['managed']:
                self.write_managed(db, source['managed'])
            else:
                db.execute('DELETE FROM fleet_managed WHERE id=?', (installed['managed']['id'],))
            if self.recovery:
                for host in source['hosts']:
                    if 'sni' in host:db.execute('UPDATE hosts SET address=?,sni=? WHERE id=?',(host['address'],host['sni'],host['id']))
                    else:db.execute('UPDATE hosts SET address=? WHERE id=?',(host['address'],host['id']))
                db.execute('DELETE FROM fleet_external_links WHERE node=?',(source['node'],))
                for external in source.get('external',[]):db.execute('INSERT INTO fleet_external_links VALUES(?,?,?,?)',(external['node'],external['prefix'],external['suffix'],external['position']))
                for proxy in installed.get('proxies',[]):db.execute('DELETE FROM fleet_proxy_services WHERE id=?',(proxy['id'],))
                for proxy in source.get('proxies',[]):
                    db.execute('INSERT INTO fleet_proxy_services('+','.join(proxy)+') VALUES('+','.join('?' for _ in proxy)+')',list(proxy.values()))
                for identity in installed.get('created_proxy_jobs',[]):db.execute('DELETE FROM fleet_proxy_jobs WHERE id=?',(identity,))
                db.execute('DELETE FROM fleet_proxy_node_generations WHERE node=?',(source['node'],))
                generation=source.get('proxy_generation')
                if generation:db.execute('INSERT INTO fleet_proxy_node_generations VALUES(?,?,?)',(generation['node'],generation['source_stamp'],generation['generation']))
            for table, key in [('fleet_observers', 'observer'), ('fleet_observer_sources', 'observer_source')]:
                db.execute('DELETE FROM ' + table + ' WHERE node=?', (source['node'],))
                value = source[key]
                if value:
                    db.execute('INSERT INTO ' + table + '(' + ','.join(value) + ') VALUES(' + ','.join('?' for _ in value) + ')', list(value.values()))
            db.execute('DELETE FROM fleet_health WHERE node=?', (source['node'],))
            db.execute('DELETE FROM fleet_client_probes WHERE node=?', (source['node'],))
            db.execute("UPDATE fleet_node_transfers SET state='rolled_back' WHERE id=?", (job,))
        if native_id and reconnect:
            self.reconnect(native_id)


def literal_ip(value):
    try:ipaddress.ip_address(value);return True
    except ValueError:return False
