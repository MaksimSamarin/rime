"""Payload acceptance and ongoing checks for nodes created by the SSH wizard."""
import copy
import ipaddress
import json
import logging
import socket
import threading
import time
from pathlib import Path

from .client_probe import probe, xray_probe_binary
from .provision import ProvisionError


class ProvisionProbe:
    def __init__(self, store, settings, reachability, xray):
        self.store = store
        self.settings = settings
        self.reachability = reachability
        self.xray = xray
        self.lock = threading.Lock()

    def transfer_targets(self,source,profile,data):
        with self.store.connection() as db:
            account=next(((auth,user) for auth,user in self.store.users(db).items()
                          if user['username']==self.settings.get('probe_username')),None)
        if not account or not self.store.allowed(account[1]):
            raise ProvisionError('Активная учётная запись проверки не настроена')
        auth,user=account
        address=data['address']
        if source['protocol']=='hysteria2':
            hostname=source['domain']
            try:ipaddress.ip_address(hostname);hostname=address
            except ValueError:pass
            tls={'sni':profile['vpn'].get('sni',source['domain'])}
            if self.settings.get('panel_ca_file'):tls['ca']=self.settings['panel_ca_file']
            config={'_kind':'hy2','_hostname':hostname,'server':address+':'+str(source['vpn_port']),'auth':auth,'tls':tls}
            if profile['vpn']['config'].get('obfs'):config['obfs']=copy.deepcopy(profile['vpn']['config']['obfs'])
            return [{'node':source['node'],'expected_ip':address,'config':config}]
        from app.db import GetDB,crud
        from app.models.user import UserResponse
        from app.subscription.share import generate_v2ray_json_subscription
        active_hosts=[host for host in source['hosts'] if not host.get('is_disabled')]
        if not active_hosts:raise ProvisionError('Нет включённых адресов VPN для клиентской проверки')
        wanted={host['id'] for host in active_hosts}
        active_tags={host['inbound_tag'] for host in active_hosts}
        disabled_tags={host['inbound_tag'] for host in source['hosts'] if host.get('is_disabled')}-active_tags
        selected={tag:[copy.deepcopy(host) for host in self.xray.hosts.get(tag,[]) if host.get('id') in wanted]
                  for tag in active_tags}
        selected={tag:hosts for tag,hosts in selected.items() if hosts}
        if {host['id'] for hosts in selected.values() for host in hosts}!=wanted:
            raise ProvisionError('Часть прежних адресов недоступна в подписках. Сверьте привязки перед переносом')
        from app.xray.config import XRayConfig
        recovered=XRayConfig(profile['vpn']['config'])
        first=next(host for hosts in selected.values() for host in hosts)
        for inbound in profile['vpn']['config']['inbounds']:
            if inbound['tag'] in selected or inbound['tag'] in disabled_tags:continue
            selected[inbound['tag']]=[]
            for outside,inside,protocol in profile['vpn'].get('publish') or [(inbound['port'],inbound['port'],'tcp')]:
                if inside!=inbound['port']:continue
                host=copy.deepcopy(first)
                host.update(address=[source['domain']],port=outside,tls=None,sni=None,host=None,path=None,
                            fingerprint=None,allowinsecure=False,mux_enable=False,fragment_setting=None,noise_setting=None,
                            random_user_agent=False,remark='Recovery '+inbound['tag'])
                selected[inbound['tag']].append(host)
        with GetDB() as db:
            account=UserResponse.model_validate(crud.get_user(db,user['username']))
        granted={tag for tags in account.inbounds.values() for tag in tags}
        if not set(selected)<=granted:
            raise ProvisionError('Проверочная учётная запись не имеет доступа ко всем прежним VLESS-входам')
        configs=json.loads(generate_v2ray_json_subscription(account.proxies,account.inbounds,account.model_dump(),False,hosts=selected,inbound_config=recovered))
        result=[]
        for config in configs:
            outbound=next((value for value in config.get('outbounds',[]) if value.get('protocol')=='vless'),None)
            if not outbound:continue
            host=outbound['settings']['vnext'][0]['address']
            try:
                ipaddress.ip_address(host)
                stream=outbound.get('streamSettings',{})
                if stream.get('security')=='tls' and not stream.get('tlsSettings',{}).get('serverName'):
                    stream.setdefault('tlsSettings',{})['serverName']=host
                host=address
            except ValueError:pass
            config={'_hostname':host,'inbounds':[{'listen':'127.0.0.1','port':0,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
                    'outbounds':[outbound,*[value for value in config['outbounds'] if value is not outbound]]}
            ca_file=self.settings.get('panel_ca_file')
            if ca_file and outbound.get('streamSettings',{}).get('security')=='tls':
                outbound['streamSettings'].setdefault('tlsSettings',{})['certificates']=[{'certificateFile':ca_file,'usage':'verify'}]
            result.append({'node':source['node'],'expected_ip':address,'config':config})
        if len(result)<len(active_hosts):raise ProvisionError('Не удалось построить клиентские конфигурации всех включённых адресов ноды')
        return result

    def run_targets(self,targets,job):
        for target in targets:
            settings={'direct_targets':[target['expected_ip']],'xray_binary':xray_probe_binary(self.settings),
                      'hysteria_binary':self.settings.get('hysteria_binary','')}
            with self.lock:
                for attempt in range(3):
                    with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
                    result=probe(target,settings,port)
                    self.reachability.ingest_local(target['node'],result,self.settings.get('probe_origin','Сервер панели'),job=job)
                    if result['passed']:break
                    if attempt<2:time.sleep(1)
                else:raise ProvisionError('Прежняя клиентская конфигурация не передала трафик. Этап '+result['stage'])

    def target(self, job, data):
        with self.store.connection() as db:
            users = self.store.users(db)
            account = next(((auth, user) for auth, user in users.items()
                            if user['username'] == self.settings.get('probe_username')), None)
            row = db.execute('SELECT * FROM fleet_managed WHERE id=?', (job,)).fetchone()
        if not account or not self.store.allowed(account[1]):
            raise ProvisionError('Активная учётная запись клиентской проверки не настроена')
        if row is None:
            raise ProvisionError('Регистрация новой ноды отсутствует')
        auth, user = account
        node = job if row['native_id'] is None else 'xray:' + str(row['native_id'])
        address = data.get('address') or data['host']
        if getattr(self,'transfer',None) and row['active']:
            profile=self.transfer.recovery.load(node)
            if profile.get('vpn'):
                with self.store.connection() as db:source=self.transfer.snapshot(node,db)
                targets=self.transfer_targets(source,profile,{**data,'address':address})
                return {**targets[0],'variants':[target['config'] for target in targets]}
        ca_file = self.settings.get('panel_ca_file')
        if data['protocol'] == 'hysteria2':
            tls = {'sni': data['domain']}
            if ca_file:
                tls['ca'] = ca_file
            config = {'_kind': 'hy2', '_hostname': data['domain'],
                      'server': address + ':' + str(data['vpn_port']), 'auth': auth, 'tls': tls}
        else:
            template = self.settings['vless_template']
            inbound = self.xray.config.get_inbound(template['inbound_tag'])
            stream = inbound['streamSettings']
            tls = {'serverName': data['domain'], 'allowInsecure': False}
            if stream.get('tlsSettings',{}).get('alpn'):
                tls['alpn']=copy.deepcopy(stream['tlsSettings']['alpn'])
            if ca_file:
                tls['certificates'] = [{'certificateFile': ca_file, 'usage': 'verify'}]
            config = {'_hostname': data['domain'],
                      'inbounds': [{'listen': '127.0.0.1', 'port': 0, 'protocol': 'socks',
                                    'settings': {'auth': 'noauth', 'udp': False}}],
                      'outbounds': [{'protocol': 'vless',
                                     'settings': {'vnext': [{'address': address, 'port': data['vpn_port'],
                                                            'users': [{'id': auth, 'encryption': 'none'}]}]},
                                     'streamSettings': {'network': 'grpc', 'security': 'tls',
                                                        'tlsSettings': tls,
                                                        'grpcSettings': copy.deepcopy(stream.get('grpcSettings', {}))}}]}
        return {'node': node, 'expected_ip': address, 'config': config}

    def active_target(self, job, data):
        target = self.target(job, data)
        from .relay_routes import current as relays
        address=relays.direct_target(target['node']) if relays else None
        if address:
            return {**target,'expected_ip':address,'resolved_ip':address}
        configs = [target['config'], *target.get('variants', [])]
        hostnames = {config['_hostname'] for config in configs}
        common_addresses = None
        for hostname in sorted(hostnames):
            try:
                records = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            except OSError:
                raise ProvisionError('Не удалось определить текущий IPv4 адреса ноды') from None
            addresses = {record[4][0] for record in records}
            if not addresses:
                raise ProvisionError('У адреса ноды отсутствует IPv4')
            if not self.settings.get('lab_network') and any(
                not ipaddress.ip_address(address).is_global for address in addresses
            ):
                raise ProvisionError('Адрес клиентской проверки должен указывать на публичный IPv4')
            common_addresses = addresses if common_addresses is None else common_addresses & addresses
        if not common_addresses:
            raise ProvisionError('Адреса одной ноды разрешаются в разные IPv4. Сверьте DNS')
        address = sorted(common_addresses)[0]
        return {**target, 'expected_ip': address, 'resolved_ip': address}

    def run(self, job, data, attempts=3, follow_dns=False):
        target = self.active_target(job, data) if follow_dns else self.target(job, data)
        settings = {'direct_targets': [target['expected_ip']],
                    'xray_binary': xray_probe_binary(self.settings),
                    'hysteria_binary': self.settings.get('hysteria_binary', '')}
        with self.lock:
            result = None
            for attempt in range(attempts):
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    port = listener.getsockname()[1]
                result = probe(target, settings, port)
                self.reachability.ingest_local(target['node'], result,
                                               self.settings.get('probe_origin', 'Сервер панели'),job=job)
                if result['passed']:
                    return result
                if attempt + 1 < attempts:
                    time.sleep(1)
        raise ProvisionError('VPN-трафик с сервера панели не прошёл; этап ' + result['stage'])

    def run_active(self):
        with self.store.connection() as db:
            rows = db.execute('''SELECT m.*,n.address AS native_address,i.address AS managed_address
                                 FROM fleet_managed m LEFT JOIN nodes n ON n.id=m.native_id
                                 LEFT JOIN fleet_inventory i ON i.id=m.id WHERE m.active=1''').fetchall()
        for row in rows:
            with self.store.connection() as db:
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_node_transfers'").fetchone() and db.execute("SELECT 1 FROM fleet_node_transfers WHERE node=? AND state='switched'",('xray:'+str(row['native_id']) if row['native_id'] is not None else row['id'],)).fetchone():continue
            data = {'protocol': row['protocol'], 'domain': row['domain'], 'vpn_port': row['port'],
                    'host': row['native_address'] or row['managed_address']}
            try:
                self.run(row['id'], data, attempts=1, follow_dns=True)
            except Exception as error:
                logging.getLogger('fleet').warning('Managed-node payload check %s failed (%s)', row['id'], type(error).__name__)
