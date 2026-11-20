"""Authenticated forward proxies installed by direct, temporary SSH sessions."""
import base64
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time

import bcrypt
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field, StrictInt, model_validator
from urllib.parse import quote

from . import bootstrap
from .provision import ProvisionError
from .proxy_probe import probe
from .proxy_secrets import ProxySecrets, ProxySecretError


class ProxyRequest(BaseModel):
    node: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')
    host: str = Field(min_length=1, max_length=253)
    address: str | None = Field(default=None, max_length=45)
    ssh_port: StrictInt = Field(default=22, ge=1, le=65535)
    username: str = Field(default='root', min_length=1, max_length=64)
    private_key: str = Field(default='', max_length=16384)
    key_passphrase: str = Field(default='', max_length=1024)
    password: str = Field(default='', max_length=1024)
    fingerprint: str = Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')
    domain: str = Field(default='', max_length=253)
    http_port: StrictInt | None = Field(default=3128, ge=1, le=65535)
    https_port: StrictInt | None = Field(default=8443, ge=1, le=65535)
    proxy_username: str = Field(default='', max_length=64, pattern=r'^(?:[A-Za-z0-9][A-Za-z0-9_.-]*)?$')
    proxy_password: str = Field(default='', max_length=72)
    replace_legacy_squid: bool = False
    replace_service: str | None = Field(default=None, pattern=r'^[a-f0-9]{32}$')
    certificate: str = Field(default='', max_length=32768)
    certificate_key: str = Field(default='', max_length=16384)
    cleanup_job: str | None = Field(default=None, pattern=r'^[a-f0-9]{32}$')

    @model_validator(mode='after')
    def modes_and_password(self):
        if self.replace_legacy_squid and self.replace_service:
            raise ValueError('Выберите один вид замены прокси')
        if self.replace_legacy_squid and not self.proxy_password:
            raise ValueError('Введите действующий пароль Squid')
        if not self.replace_legacy_squid and not self.replace_service and (not self.proxy_username or len(self.proxy_password) < 12):
            raise ValueError('Укажите логин и пароль нового прокси от 12 символов')
        if self.replace_service and self.proxy_password and len(self.proxy_password) < 12:
            raise ValueError('Новый пароль прокси должен содержать от 12 символов')
        if self.http_port is None and self.https_port is None:
            raise ValueError('Выберите HTTP или HTTPS-прокси')
        if self.http_port is not None and self.http_port == self.https_port:
            raise ValueError('Для HTTP и HTTPS нужны разные порты')
        if len(self.proxy_password.encode('utf-8')) > 72 or any(ord(char) < 32 or ord(char) == 127 for char in self.proxy_password):
            raise ValueError('Пароль прокси должен содержать до 72 байт без управляющих символов')
        if not self.private_key.strip() and not self.password:
            raise ValueError('Укажите SSH-ключ или пароль')
        return self


class ProxyDeploy(BaseModel):
    plan_id: str = Field(pattern=r'^[a-f0-9]{32}$')


class ProxyCheck(BaseModel):
    proxy_password: str = Field(default='', max_length=72)
    remember: bool = False

    @model_validator(mode='after')
    def password_bytes(self):
        if len(self.proxy_password.encode('utf-8')) > 72 or any(ord(char) < 32 or ord(char) == 127 for char in self.proxy_password):
            raise ValueError('Проверьте длину и символы пароля прокси')
        return self


class ProxyReconcile(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    address: str | None = Field(default=None, max_length=45)
    ssh_port: StrictInt = Field(default=22, ge=1, le=65535)
    username: str = Field(default='root', min_length=1, max_length=64)
    private_key: str = Field(default='', max_length=16384)
    key_passphrase: str = Field(default='', max_length=1024)
    password: str = Field(default='', max_length=1024)
    fingerprint: str = Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')
    proxy_password: str = Field(default='', max_length=72)

    @model_validator(mode='after')
    def credentials(self):
        if not self.password and not self.private_key.strip():
            raise ValueError('Укажите SSH-ключ или пароль для сверки')
        if len(self.proxy_password.encode('utf-8')) > 72 or any(ord(value) < 32 or ord(value) == 127 for value in self.proxy_password):
            raise ValueError('Проверьте длину и символы пароля прокси')
        return self


PUBLIC_CONTEXT = ('node', 'host', 'address', 'ssh_port', 'username', 'domain', 'http_port', 'https_port', 'proxy_username', 'replace_legacy_squid', 'replace_service')


def squid_configuration(data, settings):
    lines = ['visible_hostname rime-proxy', 'pid_filename /run/squid/squid.pid',
             'cache_effective_user nobody', 'cache_effective_group nogroup',
             'cache_log /dev/stderr', 'access_log none', 'cache_store_log none',
             'logfile_rotate 0', 'cache_mem 8 MB', 'maximum_object_size 0 KB', 'cache deny all',
             'forwarded_for delete', 'via off', 'shutdown_lifetime 2 seconds',
             'connect_timeout 10 seconds', 'request_timeout 30 seconds', 'read_timeout 5 minutes',
             'auth_param basic program /usr/lib/squid/basic_ncsa_auth /state/passwd',
             'auth_param basic children 5 startup=1 idle=1', 'auth_param basic realm Rime proxy',
             'auth_param basic credentialsttl 1 minute', 'auth_param basic casesensitive on',
             'acl authenticated proxy_auth REQUIRED', 'acl Safe_ports port 80 443',
             'acl SSL_ports port 443', 'acl CONNECT method CONNECT', 'acl manager proto cache_object',
             'acl private_dst dst 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 ::/128 ::1/128 fc00::/7 fe80::/10 ff00::/8']
    allowed = [str(ipaddress.ip_network(value, strict=False)) for value in settings.get('lab_destinations', [])]
    if allowed:
        lines.append('acl lab_destinations dst ' + ' '.join(allowed))
    lines += ['http_access deny manager', 'http_access deny !Safe_ports', 'http_access deny CONNECT !SSL_ports',
              'http_access deny !authenticated']
    if allowed:
        lines.append('http_access allow authenticated lab_destinations')
    lines += ['http_access deny private_dst', 'http_access allow authenticated', 'http_access deny all']
    if data.get('http_port') is not None:
        lines.append('http_port 3128')
    if data.get('https_port') is not None:
        lines.append('https_port 8443 tls-cert=/state/cert.pem tls-key=/state/key.pem')
    return '\n'.join(lines) + '\n'


class ProxyService:
    def __init__(self, store, provision):
        self.store = store
        self.provision = provision
        self.settings = provision.settings.get('proxy', {})
        self.secrets = ProxySecrets(self.settings.get('secrets_key_file', Path(store.path).parent / 'proxy-secrets.key'))
        self.plans = {}
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_proxy_jobs(
                id TEXT PRIMARY KEY,node TEXT NOT NULL,state TEXT NOT NULL,message TEXT NOT NULL,
                steps TEXT NOT NULL,context TEXT NOT NULL,created_at REAL NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_proxy_services(
                id TEXT PRIMARY KEY,node TEXT NOT NULL,host TEXT NOT NULL,address TEXT NOT NULL,
                domain TEXT NOT NULL,http_port INTEGER,https_port INTEGER,username TEXT NOT NULL,
                password_hash TEXT NOT NULL,created_at REAL NOT NULL,checked_at REAL NOT NULL,
                result TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1)''')
            if 'node_generation' not in {row['name'] for row in db.execute('PRAGMA table_info(fleet_proxy_services)')}:
                db.execute("ALTER TABLE fleet_proxy_services ADD COLUMN node_generation TEXT NOT NULL DEFAULT ''")
            columns = {row['name'] for row in db.execute('PRAGMA table_info(fleet_proxy_services)')}
            if 'password_secret' not in columns:
                db.execute("ALTER TABLE fleet_proxy_services ADD COLUMN password_secret TEXT NOT NULL DEFAULT ''")
            if 'legacy_squid' not in columns:
                db.execute('ALTER TABLE fleet_proxy_services ADD COLUMN legacy_squid INTEGER NOT NULL DEFAULT 0')
            if 'runtime_id' not in columns:
                db.execute("ALTER TABLE fleet_proxy_services ADD COLUMN runtime_id TEXT NOT NULL DEFAULT ''")
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_proxy_node_generations(
                node TEXT PRIMARY KEY,source_stamp TEXT NOT NULL,generation TEXT NOT NULL)''')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='nodes'").fetchone():
                db.execute('''CREATE TRIGGER IF NOT EXISTS fleet_proxy_native_delete AFTER DELETE ON nodes
                              BEGIN DELETE FROM fleet_proxy_node_generations WHERE node='xray:'||OLD.id; END''')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_inventory'").fetchone():
                db.execute('''CREATE TRIGGER IF NOT EXISTS fleet_proxy_inventory_delete AFTER DELETE ON fleet_inventory
                              BEGIN DELETE FROM fleet_proxy_node_generations WHERE node=OLD.id; END''')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_proxy_jobs_time ON fleet_proxy_jobs(created_at)')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_proxy_node ON fleet_proxy_services(node,active)')
            db.execute("UPDATE fleet_proxy_jobs SET state='failed',message='Панель перезапущена. Повторите проверку и сверку установки' WHERE state='running'")
        from .recovery import Recovery
        self.recovery=Recovery(store,self.secrets)
        provision.recovery=self.recovery
        provision.proxies=self

    def options(self):
        path = self.settings.get('image_bundle', '')
        return {'enabled': bool(re.fullmatch(r'sha256:[a-f0-9]{64}', self.settings.get('image', ''))
                                and path and Path(path).is_file()
                                and re.fullmatch(r'[a-f0-9]{64}', self.settings.get('image_bundle_sha256', ''))),
                'automatic_tls': all(Path(self.provision.settings.get(key, '/nonexistent')).is_file()
                                     for key in ['certificate_file', 'certificate_key_file'])}

    @staticmethod
    def node_reference(db, node):
        if node == 'xray:local':
            raise ProvisionError('Для прокси выберите удалённую ноду')
        native = node.startswith('xray:') and node[5:].isdigit()
        if native:
            row = db.execute('SELECT * FROM nodes WHERE id=?', (int(node[5:]),)).fetchone()
        else:
            row = db.execute('SELECT * FROM fleet_inventory WHERE id=?', (node,)).fetchone()
        if not row or not row['address']:
            raise ProvisionError('Нода не найдена или её SSH-адрес отсутствует')
        values = dict(row)
        managed = None
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_managed'").fetchone():
            if native:
                managed = db.execute('SELECT id FROM fleet_managed WHERE native_id=?', (int(node[5:]),)).fetchone()
            else:
                managed = db.execute('SELECT id FROM fleet_managed WHERE id=?', (node,)).fetchone()
        stamp = {'created_at': values.get('created_at'), 'managed': managed['id'] if managed else None}
        if not stamp['created_at'] and not stamp['managed']:
            stamp['address'] = values['address']
        return values['address'], json.dumps(stamp, sort_keys=True, default=str)

    def node_host(self, node):
        with self.store.connection() as db:
            return self.node_reference(db, node)[0]

    def node_identity(self, node, db=None):
        if db is None:
            with self.store.connection(write=True) as connection:return self.node_identity(node,connection)
        host, stamp = self.node_reference(db, node)
        row = db.execute('SELECT source_stamp,generation FROM fleet_proxy_node_generations WHERE node=?', (node,)).fetchone()
        if row and row['source_stamp'] == stamp:
            return host, row['generation']
        generation = secrets.token_hex(16)
        db.execute('''INSERT INTO fleet_proxy_node_generations VALUES(?,?,?) ON CONFLICT(node)
                      DO UPDATE SET source_stamp=excluded.source_stamp,generation=excluded.generation''', (node, stamp, generation))
        return host, generation

    def current_generation(self, db, node):
        try:
            _, stamp = self.node_reference(db, node)
        except ProvisionError:
            return None
        row = db.execute('SELECT source_stamp,generation FROM fleet_proxy_node_generations WHERE node=?', (node,)).fetchone()
        return row['generation'] if row and row['source_stamp'] == stamp else None

    def access_metadata(self, node):
        with self.store.connection() as database:
            host=self.node_reference(database,node)[0]
            managed=database.execute("SELECT id FROM fleet_managed WHERE id=? OR 'xray:'||native_id=?",(node,node)).fetchone()
            job=database.execute("SELECT context FROM fleet_jobs WHERE state='succeeded' AND json_extract(context,'$.move_node')=? ORDER BY created_at DESC LIMIT 1",(node,)).fetchone()
            if job is None and managed:job=database.execute('SELECT context FROM fleet_jobs WHERE id=?',(managed['id'],)).fetchone()
            context=json.loads(job['context']) if job else {}
        value={'host':host,'ssh_port':context.get('ssh_port',22),'username':context.get('username','root'),'fingerprint':context.get('fingerprint')}
        if getattr(self,'relays',None):
            value['host']=self.relays.direct_target(node) or host
            if self.relays.has_origin_route(node):value.update(self.relays.origin_access(node))
        return value

    def validate_access(self, node, data):
        host,_=self.node_identity(node)
        current=self.provision.resolve(data['host'],data['ssh_port'])
        address=data.get('address') or current[0]
        if address not in current:raise ProvisionError('Повторите проверку текущего SSH-адреса')
        relays=getattr(self,'relays',None)
        if relays:host=relays.direct_target(node) or host
        routed=relays.origin_access(node) if relays and relays.has_origin_route(node) else None
        selected=bool(routed and routed['host']==address and routed['ssh_port']==data['ssh_port'])
        if not selected and address not in self.provision.resolve(host,data['ssh_port']):
            raise ProvisionError('SSH-адрес отличается от адреса выбранной ноды')
        data['address']=address
        data['_origin_address']=relays.direct_target(node) if selected else address
        data['_relay_access']=selected
        return address

    def connect(self, data, node=None):
        node=node or data.get('node')
        if data.get('_relay_access') and getattr(self,'relays',None):return self.relays.connect_origin(node,data)
        return self.provision.connect(data)

    def encrypted_password(self, identity, password):
        with self.store.connection() as db:
            existing = db.execute("SELECT id,password_secret FROM fleet_proxy_services WHERE password_secret<>'' LIMIT 1").fetchone()
        try:
            if existing:
                self.secrets.decrypt(existing['id'], existing['password_secret'])
            return self.secrets.encrypt(identity, password, create=existing is None)
        except (ProxySecretError, OSError) as error:
            raise ProvisionError(str(error) if isinstance(error, ProxySecretError) else 'Ключ хранилища прокси не создан. Проверьте постоянный каталог данных') from None

    def clear_password(self, record):
        if not record['password_secret']:
            raise ProvisionError('Сначала проверьте действующий пароль с сохранением, затем изменяйте прокси')
        try:
            return self.secrets.decrypt(record['id'], record['password_secret'])
        except ProxySecretError as error:
            raise ProvisionError(str(error)) from None

    def replacement(self, data):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND active=1', (data['replace_service'],)).fetchone()
        if not row or row['node'] != data['node'] or self.job(row['id'])['state'] != 'succeeded':
            raise ProvisionError('Исходная установка прокси требует сверки или больше не активна')
        old = dict(row)
        _, generation = self.node_identity(old['node'])
        if not old['node_generation'] or old['node_generation'] != generation:
            raise ProvisionError('Экземпляр ноды изменился. Сначала сверьте исходный прокси')
        if data.get('domain') and data['domain'] != old['domain']:
            raise ProvisionError('Домен существующего прокси менять нельзя. Его сертификат и продление привязаны к текущему имени')
        data['domain'] = old['domain']
        old_password = self.clear_password(old)
        data['_rollback_password'] = old_password
        if not data.get('proxy_password'):
            data['proxy_password'] = old_password
            data['_password_hash'] = old['password_hash']
        if not data.get('proxy_username'):
            data['proxy_username'] = old['username']
        data['_replace'] = old
        return old

    def connection_info(self, identity):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND active=1', (identity,)).fetchone()
        if row is None:
            raise ProvisionError('Прокси не найден')
        record = dict(row)
        self.require_stable_node(record['node'])
        _, generation = self.node_identity(record['node'])
        if not record['node_generation'] or record['node_generation'] != generation:
            raise ProvisionError('Экземпляр ноды изменился. Сначала сверьте привязку прокси по SSH')
        state = self.job(identity)['state']
        password = self.clear_password(record) if record['password_secret'] and state == 'succeeded' else None
        urls = {}
        for mode, field in [('http', 'http_port'), ('https', 'https_port')]:
            endpoint = self.relays.proxy_endpoint(identity,mode,record[field]) if getattr(self,'relays',None) and record[field] else None
            host = endpoint['domain'] if endpoint else record['domain']
            port = endpoint['public_port'] if endpoint else record[field]
            urls[mode] = (mode + '://' + quote(record['username'], safe='') + ':' + quote(password, safe='') + '@' +
                          host + ':' + str(port)) if password is not None and port is not None else None
        return {'id': identity, 'node': record['node'], 'host': record['domain'], 'domain': record['domain'],
                'username': record['username'], 'password': password, 'http_port': record['http_port'],
                'https_port': record['https_port'], 'urls': urls, 'credentials_available': password is not None,
                'needs_password': not bool(record['password_secret']), 'deployment_state': state, 'locked_domain': True}

    def reconcile(self, identity, access):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND active=1', (identity,)).fetchone()
        if row is None or self.job(identity)['state'] == 'succeeded':
            raise ProvisionError('Нет незавершённой установки для сверки. Для рабочего прокси используйте проверку или изменение')
        if getattr(self,'relays',None):self.relays.changes.recover()
        record = dict(row)
        host, generation = self.node_identity(record['node'])
        if record['node_generation'] != generation:
            raise ProvisionError('Экземпляр ноды изменился. Сверка прежнего сервера запрещена')
        address=self.validate_access(record['node'],access)
        with self.provision.lock:
            if address in self.provision.running or len(self.provision.running) >= self.provision.settings.get('max_concurrent_installs', 2):
                raise ProvisionError('На сервере выполняется другая операция. Повторите сверку после её завершения')
            self.provision.running.add(address)
        access['address'] = address
        try:
            self.update(identity, record['node'], 'running', 'Сверка владельца контейнера и восстановления после прерывания')
            threading.Thread(target=self.reconcile_worker, args=(record, access), daemon=True).start()
        except Exception:
            with self.provision.lock:self.provision.running.discard(address)
            self.update(identity, record['node'], 'failed', 'Поток сверки не запущен. Повторите запрос, исходные ресурсы сохранены')
            access.clear()
            raise
        return {'id': identity}

    def reconcile_worker(self, record, access):
        identity, node = record['id'], record['node']
        relays=getattr(self,'relays',None)
        relay_prepared=False
        outcome=None
        try:
            context = self.job(identity)['context']
            password = self.clear_password(record) if record['password_secret'] else access.get('proxy_password')
            if not password:
                raise ProvisionError('Введите текущий пароль для подтверждения незавершённой установки')
            addresses = {value[4][0] for value in socket.getaddrinfo(record['domain'], None, socket.AF_INET, socket.SOCK_STREAM)}
            origin=access.get('_origin_address',access['address'])
            if addresses not in [{origin},{access['address']}]:
                raise ProvisionError('DNS-имя прокси отличается от проверяемого сервера')
            data = {**record, 'address':origin,'_origin_address':origin,'proxy_username':record['username'],'proxy_password':password,
                    'replace_service':context.get('replace_service')}
            if context.get('replace_service'):
                with self.store.connection() as database:
                    old=database.execute('SELECT * FROM fleet_proxy_services WHERE id=?',(context['replace_service'],)).fetchone()
                data['_replace']=dict(old) if old else {}
            with self.connect(access,node) as client:
                state = self.remote(client, {'id': identity, 'action': 'reconcile-state', 'legacy_managed': bool(record['legacy_squid'])})
                ready = False
                if state.get('candidate') and not state.get('restored'):
                    snapshot = state['candidate']
                    if snapshot['username'] == record['username'] and snapshot['password_hash'] == record['password_hash']:
                        if not snapshot['running']:
                            self.remote(client, {'id': identity, 'action': 'managed-start'})
                        if relays:
                            data['certificate']=snapshot.get('certificate','')
                            after=relays.changes.prepare_proxy(data,identity)
                            relay_prepared=relays.changes.pending(identity) is not None
                            if after:
                                relays.changes.apply(identity,after)
                                data['_relay_job']=identity
                        ready = self.check(data)['passed']
                if ready:
                    if context.get('replace_legacy_squid'):
                        if not state['committed']:
                            self.remote(client, {'id': identity, 'action': 'legacy-commit'})
                    elif context.get('replace_service'):
                        if not state['committed']:
                            self.remote(client, {'id': identity, 'action': 'managed-commit', 'http_port': record['http_port'], 'https_port': record['https_port']})
                    else:
                        raise ProvisionError('Контекст установки не содержит подтверждённого источника замены')
                    envelope = self.encrypted_password(identity, password) if not record['password_secret'] else record['password_secret']
                    with self.store.connection(write=True) as db:
                        if self.current_generation(db, node) != record['node_generation']:
                            raise ProvisionError('Регистрация ноды изменилась во время сверки')
                        db.execute('UPDATE fleet_proxy_services SET password_secret=? WHERE id=?', (envelope, identity))
                        if relay_prepared and relays.changes.read(identity)['after']:relays.changes.publish(identity,database=db)
                    outcome=('succeeded','Установка сверена по SSH. Владелец контейнера, доступы и трафик подтверждены')
                    return
                old_id = context.get('replace_service')
                if context.get('replace_legacy_squid'):
                    self.remote(client, {'id': identity, 'action': 'legacy-restore', 'force': True})
                    rollback_data = data
                elif old_id:
                    with self.store.connection() as db:
                        old_row = db.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND node=?', (old_id, node)).fetchone()
                    if old_row is None:
                        raise ProvisionError('Исходная запись прокси отсутствует')
                    old = dict(old_row)
                    self.remote(client, {'id': identity, 'action': 'managed-restore', 'force': True,
                                         'replace_service': old_id, 'legacy_managed': bool(old['legacy_squid'])})
                    rollback_data = {**data, 'domain': old['domain'], 'http_port': old['http_port'], 'https_port': old['https_port'],
                                     'proxy_username': old['username'], 'proxy_password': self.clear_password(old)}
                else:
                    raise ProvisionError('Нет подтверждённого источника для восстановления')
                if relay_prepared:relays.changes.rollback(identity)
                if not self.check(rollback_data)['passed']:
                    raise ProvisionError('Источник восстановлен, но клиентский трафик не подтверждён')
                with self.store.connection(write=True) as db:
                    if self.current_generation(db, node) != record['node_generation']:
                        raise ProvisionError('Регистрация ноды изменилась во время восстановления')
                    db.execute('UPDATE fleet_proxy_services SET active=0 WHERE id=?', (identity,))
                    if old_id:db.execute('UPDATE fleet_proxy_services SET active=1 WHERE id=?', (old_id,))
                outcome=('rolled_back','Исходный прокси восстановлен и проверен. Незавершённая замена отозвана')
        except Exception as error:
            outcome=('failed',str(error) if isinstance(error,ProvisionError) else 'Сверка не завершена. Исходные ресурсы сохранены для повторной проверки')
        finally:
            if relay_prepared:
                try:relays.changes.finish(identity,bool(outcome and outcome[0]=='succeeded'))
                except Exception:outcome=('failed','Маршрут прокси требует повторной сверки')
            with self.provision.lock:self.provision.running.discard(access.get('address'))
            access.clear()
            if outcome:self.update(identity,node,*outcome)

    def tls(self, data):
        if data.get('https_port') is None:
            return
        if not data.get('domain') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', data['domain']):
            raise ProvisionError('Для HTTPS-прокси укажите имя или IPv4 из сертификата сервера')
        if not data.get('certificate') and not data.get('certificate_key'):
            try:
                data['certificate'] = Path(self.provision.settings['certificate_file']).read_text()
                data['certificate_key'] = Path(self.provision.settings['certificate_key_file']).read_text()
            except (KeyError, OSError):
                raise ProvisionError('Автоматический TLS не настроен на панели') from None
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        try:
            cert = x509.load_pem_x509_certificate(data['certificate'].encode())
            key = serialization.load_pem_private_key(data['certificate_key'].encode(), password=None)
            encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            if cert.public_key().public_bytes(encoding, form) != key.public_key().public_bytes(encoding, form):
                raise ValueError()
            now = datetime.now(timezone.utc)
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                raise ValueError()
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = san.get_values_for_type(x509.DNSName)+[str(value) for value in san.get_values_for_type(x509.IPAddress)]
            domain = data['domain'].lower()
            if not any(domain == name.lower() or (name.startswith('*.') and domain.count('.') == name.count('.') and domain.endswith(name[1:].lower())) for name in names):
                raise ValueError()
        except Exception:
            raise ProvisionError('Проверьте TLS-сертификат, его ключ, срок действия и домен') from None

    def validate(self, data):
        with self.store.connection() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_node_transfers'").fetchone() and db.execute("SELECT 1 FROM fleet_node_transfers WHERE node=? AND state='switched'",(data['node'],)).fetchone():
                raise ProvisionError('Дождитесь завершения переноса ноды перед настройкой прокси')
        if not self.options()['enabled']:
            raise ProvisionError('Образ HTTP/HTTPS-прокси не подготовлен на панели')
        expected_host, generation = self.node_identity(data['node'])
        if data.get('_node_generation') and data['_node_generation'] != generation:
            raise ProvisionError('Экземпляр ноды изменился. Повторите настройку прокси для текущей ноды')
        data['_node_generation'] = generation
        address=self.validate_access(data['node'],data)
        if data.get('domain'):
            try:
                addresses = {row[4][0] for row in socket.getaddrinfo(data['domain'], None, socket.AF_INET, socket.SOCK_STREAM)}
                allowed=[{data['_origin_address']}]
                if getattr(self,'relays',None) and self.relays.direct_target(data['node']):
                    with self.store.connection() as database:
                        entry=database.execute("SELECT e.address,t.flags FROM fleet_tunnels t JOIN fleet_relay_entries e ON e.id=t.entry WHERE t.node=? AND t.state='active'",(data['node'],)).fetchone()
                    if entry and json.loads(entry['flags']).get('include_proxies') is not False:allowed.append({entry['address']})
                if addresses not in allowed:
                    raise ValueError()
            except (OSError, ValueError):
                raise ProvisionError('DNS-имя прокси должно указывать на выбранный сервер') from None
        elif data.get('https_port') is None:
            data['domain'] = data['_origin_address']
        self.tls(data)

    def remote(self, client, config):
        config=dict(config)
        with self.store.connection() as db:
            for field in ['replace_service','qualify_service']:
                if config.get(field):
                    row=db.execute('SELECT runtime_id FROM fleet_proxy_services WHERE id=?',(config[field],)).fetchone()
                    if row and row['runtime_id']:config[field]=row['runtime_id']
            if config.get('action')=='managed-start':
                row=db.execute('SELECT runtime_id FROM fleet_proxy_services WHERE id=?',(config['id'],)).fetchone()
                if row and row['runtime_id']:config['id']=row['runtime_id']
        if config.get('image') == self.settings.get('image'):
            from .provision import archive_image_candidates
            config = {**config, 'image_candidates': archive_image_candidates(
                self.settings['image_bundle'], self.settings['image_bundle_sha256'], self.settings['image'])}
        code = base64.b64encode(Path(__file__).with_name('port_check.py').read_bytes() + b'\n' + Path(__file__).with_name('proxy_install.py').read_bytes()).decode()
        if config.get('action') in ['legacy-stop', 'managed-stop']:
            config = {**config, 'recovery_code': code}
        incoming, output, errors = client.exec_command('python3 -c "import base64;exec(base64.b64decode(\'' + code + '\'))"', timeout=220)
        incoming.write(json.dumps(config))
        incoming.flush()
        incoming.channel.shutdown_write()
        raw = output.read(1024 * 1024)
        errors.read()
        if output.channel.recv_exit_status() != 0:
            try:
                failure = json.loads(raw)
                failure_code = failure.get('code') if isinstance(failure, dict) else None
            except (ValueError, UnicodeError):
                failure_code = None
            messages = {
                'image_unavailable': 'Образ прокси отсутствует на сервере. Повторите проверку и передачу сборки',
                'image_identity_unresolved': 'Docker загрузил архив, но ожидаемый образ прокси не найден. Требуется проверка совместимости сборки',
                'legacy_password_rejected': 'Действующий пароль Squid отклонён. Введите текущий пароль без его смены',
                'legacy_changed': 'Существующий Squid изменился после проверки. Повторите предварительную проверку',
                'legacy_adapter_unavailable': 'Адаптер продления сертификата существующего Squid не подготовлен',
                'legacy_hash_incompatible': 'Сохранённые доступы не прошли проверку в новом образе. Действующий Squid оставлен в работе',
                'managed_changed': 'Исходный контейнер, его файлы или TLS изменились. Повторите предварительную проверку',
                'port_conflict': 'TCP-порт прокси уже занят. Выберите другой порт и повторите проверку. Действующая VPN-служба сохранена',
            }
            if failure_code in messages:
                raise ProvisionError(messages[failure_code])
            raise ProvisionError('Операция с контейнером прокси не завершена. Проверьте журнал установки на сервере')
        return json.loads(raw)

    def previous(self, data):
        record = self.job(data['cleanup_job'])
        if record['state'] != 'failed' or not record['context']:
            raise ProvisionError('Предыдущая попытка не требует очистки')
        if any(record['context'].get(key) != data.get(key) for key in ['node', 'host', 'ssh_port', 'username']):
            raise ProvisionError('Для очистки выберите прежнюю ноду и SSH-пользователя')
        if record['context'].get('node_generation') != data.get('_node_generation'):
            raise ProvisionError('Предыдущая попытка относится к другому экземпляру ноды')
        with self.store.connection() as db:
            if db.execute('SELECT 1 FROM fleet_proxy_services WHERE id=? AND active=1', (data['cleanup_job'],)).fetchone():
                raise ProvisionError('Этот прокси уже установлен. Откройте его в списке')
        return record

    def preflight(self, data):
        if data.get('replace_legacy_squid'):
            data.update(http_port=3128)
        if data.get('replace_service'):
            self.replacement(data)
        self.validate(data)
        if data.get('cleanup_job'):
            self.previous(data)
        job = secrets.token_hex(16)
        ports = [value for value in [data.get('http_port'), data.get('https_port')] if value is not None]
        with self.connect(data) as client:
            runtime = bootstrap.inspect(client, [(port, 'tcp') for port in ports])
            if runtime['python_available']:
                result = self.remote(client, {'id': job, 'action': 'preflight', 'ports': ports,
                                             'cleanup_job': data.get('cleanup_job'), 'allow_bootstrap': True,
                                             'replace_legacy_squid': data.get('replace_legacy_squid', False),
                                             'replace_service': data.get('replace_service'),
                                             'legacy_managed': bool(data.get('_replace', {}).get('legacy_squid')),
                                             'legacy_password': data['proxy_password'] if data.get('replace_legacy_squid') else None})
            else:
                if data.get('replace_legacy_squid') or data.get('replace_service'):
                    raise ProvisionError('Для безопасной замены действующего Squid нужен Python 3 на сервере')
                result = runtime
        if data.get('replace_legacy_squid'):
            legacy = result['legacy']
            data.update(http_port=legacy.get('http_port',3128),https_port=legacy.get('https_port',443),
                        proxy_username=legacy['username'], certificate=legacy['certificate'],
                        certificate_key=legacy['certificate_key'], _legacy=legacy)
            self.tls(data)
        if data.get('replace_service'):
            managed = result['managed']
            old = data['_replace']
            if managed['username'] != old['username'] or managed['password_hash'] != old['password_hash']:
                raise ProvisionError('Учётная запись исходного контейнера отличается от панели. Нужна сверка')
            data['_managed_guard'] = managed['fingerprint']
            if managed.get('files'):
                data['_managed_files']=managed['files']
                accounts=dict(line.split(':',1) for line in managed['files']['passwd'].splitlines() if line)
                if data['proxy_username']!=old['username'] and data['proxy_username'] in accounts:
                    raise ProvisionError('Новый логин уже принадлежит другой сохранённой записи прокси')
            data['_managed_policy'] = {key: managed[key] for key in ['Safe_ports', 'SSL_ports']}
            if managed['certificate'] and managed['certificate_key']:
                data.update(certificate=managed['certificate'], certificate_key=managed['certificate_key'])
            self.tls(data)
        result['bootstrap_required'] = runtime['bootstrap_required']
        plan = {'id': job, 'ready': all(check['passed'] for check in result['checks']), 'checks': result['checks'],
                'expires_at': time.time() + 600,
                'summary': {'Сервер': data['host'], 'Адрес': data['address'], 'Логин прокси': data['proxy_username'],
                            'Режимы': ', '.join(mode for mode, port in [('HTTP', data.get('http_port')), ('HTTPS', data.get('https_port'))] if port is not None),
                            'Проверка': 'Авторизация и настоящий HTTPS-трафик с сервера панели',
                            'Учёт': 'Прокси использует отдельную авторизацию. Квоты VPN-подписок к нему не применяются. Сетевые метрики ОС включают общий трафик сервера',
                            'Откат': 'Удаляется контейнер этой установки. Файлы и пакеты ОС сохраняются'}}
        if getattr(self,'relays',None):
            preview=self.relays.changes.preview_proxy(data,job)
            data['_relay_preview']=self.relays.changes.proxy_ports(preview,job)
            if preview:
                entry=self.relays.entry(preview['tunnel']['entry'])
                plan['summary']['Вход']=entry['name']
                plan['summary']['Публичные порты прокси']=' · '.join(str(value)+'/TCP' for value in data['_relay_preview'].values())
            if data.get('_relay_access'):plan['summary']['SSH-маршрут']='Через выбранный входной сервер'
        if data.get('replace_legacy_squid'):
            plan['summary'].update({'Замена': 'squid.service. Действующие логин, пароль, TLS и порты сохраняются',
                                    'Восстановление': 'Старый Squid восстанавливается при ошибке. Локальная страховка действует 180 секунд'})
        if data.get('replace_service'):
            plan['summary'].update({'Замена': 'Управляемый прокси. Старый контейнер сохраняется до проверки нового',
                                    'Домен': 'Сертификат и имя подключения сохраняются',
                                    'Восстановление': 'Исходный контейнер возвращается при ошибке, локальная страховка действует 180 секунд'})
        record = {'plan': plan, 'data': dict(data), 'remote': result}
        with self.provision.lock:
            if len(self.plans) >= 20:
                raise ProvisionError('Слишком много незавершённых планов прокси')
            self.plans[job] = record
        def expire():
            with self.provision.lock:
                expired = self.plans.pop(job, None)
                if expired:
                    expired['data'].clear()
        timer = threading.Timer(600, expire)
        timer.daemon = True
        timer.start()
        return plan

    @staticmethod
    def write_job(db, job, node, state, message, context=None):
        old = db.execute('SELECT steps,context FROM fleet_proxy_jobs WHERE id=?', (job,)).fetchone()
        steps = json.loads(old['steps']) if old else []
        steps.append({'at': time.time(), 'message': message})
        public = json.dumps(context) if context is not None else old['context'] if old else '{}'
        db.execute('''INSERT INTO fleet_proxy_jobs VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE
                      SET state=excluded.state,message=excluded.message,steps=excluded.steps,context=excluded.context''',
                   (job, node, state, message, json.dumps(steps, ensure_ascii=False), public, time.time()))

    def update(self, job, node, state, message, context=None):
        with self.store.connection(write=True) as db:
            self.write_job(db, job, node, state, message, context)

    def job(self, job):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM fleet_proxy_jobs WHERE id=?', (job,)).fetchone()
        if row is None:
            raise ProvisionError('Задание прокси не найдено')
        return {**dict(row), 'steps': json.loads(row['steps']), 'context': json.loads(row['context'])}

    def deploy(self, job):
        with self.provision.lock:
            record = self.plans.get(job)
            if not record or record['plan']['expires_at'] <= time.time():
                if record:
                    record['data'].clear()
                    self.plans.pop(job)
                raise ProvisionError('План прокси истёк. Повторите проверку')
            if not record['plan']['ready']:
                raise ProvisionError('Проверка сервера не пройдена')
            address = record['data']['address']
            if address in self.provision.running:
                raise ProvisionError('На этом сервере уже выполняется установка')
            if len(self.provision.running) >= self.provision.settings.get('max_concurrent_installs', 2):
                raise ProvisionError('Выполняется предельное число установок. Дождитесь завершения и повторите запуск')
            try:
                from update_runtime.leases import acquire
                record['_operation_lease'] = acquire(Path(self.store.path).parent / '.updates')
            except BlockingIOError:
                raise ProvisionError('Панель обновляется. Повторите операцию после завершения обновления') from None
            self.provision.running.add(address)
            self.plans.pop(job)
        data = record['data']
        try:
            context = {key: data.get(key) for key in PUBLIC_CONTEXT}
            context['node_generation'] = data['_node_generation']
            self.update(job, data['node'], 'running', 'Проверка доступа к серверу', context)
            threading.Thread(target=self.worker, args=(record,), daemon=True).start()
        except Exception:
            with self.provision.lock:
                self.provision.running.discard(address)
                self.plans[job] = record
            lease = record.pop('_operation_lease', None)
            if lease is not None:os.close(lease)
            raise
        return {'id': job}

    def upload_image(self, client, record, config):
        if self.remote(client, {'id': config['id'], 'action': 'image-present', 'image': config['image']})['present']:
            return
        with client.open_sftp() as sftp:
            directory = record['remote']['home']
            for part in ['.local', 'share', 'fleet-proxies']:
                directory += '/' + part
                try:
                    sftp.mkdir(directory, mode=0o700)
                except OSError:
                    sftp.stat(directory)
            path = directory + '/' + config['id'] + '.image.tar.gz'
            sftp.put(self.settings['image_bundle'], path)
            sftp.chmod(path, 0o600)
        config.update(image_bundle=path, image_bundle_sha256=self.settings['image_bundle_sha256'])

    def configuration(self, job, data):
        from .recovery import proxy_runtime_config
        legacy = data.get('_legacy')
        password_hash = legacy['password_hash'] if legacy else data.get('_password_hash') or bcrypt.hashpw(data['proxy_password'].encode(), bcrypt.gensalt()).decode()
        files = {'squid.conf': squid_configuration(data, self.settings),
                 'passwd': legacy['passwd'] if legacy else data['proxy_username'] + ':' + password_hash + '\n'}
        if data.get('_managed_files'):
            original=data['_managed_files']
            old_username=data['_replace']['username']
            accounts=[line.split(':',1) for line in original['passwd'].splitlines() if line]
            files.update(original)
            files['passwd']='\n'.join((data['proxy_username']+':'+password_hash) if name==old_username else name+':'+hashed for name,hashed in accounts)+'\n'
            rows=[]
            for line in original['squid.conf'].splitlines():
                if re.match(r'^\s*https?_port\s',line):continue
                if data['proxy_username']!=old_username and re.match(r'^\s*acl\s+\S+\s+proxy_auth\s',line):
                    line=re.sub(r'(?<!\S)'+re.escape(old_username)+r'(?!\S)',lambda _:data['proxy_username'],line)
                rows.append(line)
            for key,inside in [('http_port',3128),('https_port',8443)]:
                if data.get(key) is not None:
                    rows.append(('http_port 3128' if key=='http_port' else 'https_port 8443 tls-cert=/state/cert.pem tls-key=/state/key.pem'))
            files['squid.conf']='\n'.join(rows)+'\n'
        if legacy:
            for acl in ['Safe_ports', 'SSL_ports']:
                files['squid.conf'] = re.sub(r'^acl ' + acl + r' port .*$', 'acl ' + acl + ' port ' + legacy[acl], files['squid.conf'], flags=re.MULTILINE)
        if data.get('_managed_policy'):
            for acl, ports in data['_managed_policy'].items():
                files['squid.conf'] = re.sub(r'^acl ' + acl + r' port .*$', 'acl ' + acl + ' port ' + ports, files['squid.conf'], flags=re.MULTILINE)
        if data.get('https_port') is not None or (data.get('replace_service') and data.get('certificate') and data.get('certificate_key')):
            files.update({'cert.pem': data['certificate'], 'key.pem': data['certificate_key']})
        ports = [(data[key], inside) for key, inside in [('http_port', 3128), ('https_port', 8443)] if data.get(key) is not None]
        files['squid.conf']=proxy_runtime_config(files['squid.conf'])
        return {'id': job, 'node': data['node'], 'action': 'install', 'image': self.settings['image'], 'publish': ports, 'files': files}, password_hash

    def check(self, data):
        settings = {**self.settings, 'panel_ca_file': self.provision.settings.get('panel_ca_file')}
        checks = []
        for key, tls in [('http_port', False), ('https_port', True)]:
            if data.get(key) is None:
                continue
            value = None
            for attempt in range(3):
                relays=getattr(self,'relays',None)
                endpoint=relays.changes.pending_proxy_endpoint(data['_relay_job'],data[key]) if relays and data.get('_relay_job') else None
                if endpoint is None and relays and data.get('replace_service'):
                    endpoint=relays.proxy_endpoint(data['replace_service'],'https' if tls else 'http',data[key])
                address=endpoint['address'] if endpoint else data.get('_origin_address',data['address'])
                domain=endpoint['domain'] if endpoint else data['domain']
                port=endpoint['public_port'] if endpoint else data[key]
                expected={**settings,'expected_egress_ip':data.get('_origin_address',data['address'])}
                value = probe(address,domain,port,tls,data['proxy_username'],data['proxy_password'],expected)
                if value['passed']:
                    break
                if attempt < 2:
                    time.sleep(1)
            checks.append(value)
        return {'passed': bool(checks) and all(value['passed'] for value in checks), 'checks': checks,
                'origin': self.settings.get('probe_origin', self.provision.settings.get('probe_origin', 'Сервер панели'))}

    def worker(self, record):
        data, job = record['data'], record['plan']['id']
        relays=getattr(self,'relays',None)
        relay_prepared=False
        completed=False
        success_message=None
        touched = False
        replacing = False
        replacing_managed = False
        registered = False
        try:
            if data.get('replace_service'):
                self.replacement(data)
            self.validate(data)
            if relays:
                after=relays.changes.prepare_proxy(data,job)
                relay_prepared=relays.changes.pending(job) is not None
                data['_relay_after']=after
                data['_relay_job']=job
            config, password_hash = self.configuration(job, data)
            password_secret = self.encrypted_password(job, data['proxy_password'])
            with self.connect(data) as client:
                if record['remote']['bootstrap_required']:
                    self.update(job, data['node'], 'running', 'Подготовка Python 3 и Docker')
                    bootstrap.install(client, job)
                if data.get('cleanup_job'):
                    previous = self.previous(data)
                    self.update(job, data['node'], 'running', 'Очистка незавершённой предыдущей установки прокси')
                    if previous['context'].get('replace_legacy_squid'):
                        self.remote(client, {'id': data['cleanup_job'], 'action': 'legacy-restore', 'force': True})
                    elif previous['context'].get('replace_service'):
                        self.remote(client, {'id': data['cleanup_job'], 'action': 'managed-restore', 'force': True,
                                             'replace_service': previous['context']['replace_service'],
                                             'legacy_managed': bool(data.get('_replace', {}).get('legacy_squid'))})
                    self.remote(client, {'id': data['cleanup_job'], 'action': 'rollback'})
                    self.update(data['cleanup_job'], data['node'], 'rolled_back', 'Контейнер предыдущей установки удалён')
                checked = self.remote(client, {'id': job, 'action': 'preflight', 'ports': [value for value in [data.get('http_port'), data.get('https_port')] if value is not None],
                                              'replace_legacy_squid': data.get('replace_legacy_squid', False),
                                              'replace_service': data.get('replace_service'),
                                              'legacy_managed': bool(data.get('_replace', {}).get('legacy_squid'))})
                if not all(value['passed'] for value in checked['checks']):
                    raise ProvisionError('Повторная проверка сервера прокси не пройдена')
                self.update(job, data['node'], 'running', 'Передача проверенного образа прокси')
                touched = True
                self.upload_image(client, record, config)
                if data.get('replace_legacy_squid'):
                    self.update(job, data['node'], 'running', 'Подготовка образа до остановки действующего Squid')
                    self.remote(client, {**config, 'action': 'image-prepare',
                                         'legacy_fingerprint': data['_legacy']['fingerprint'], 'legacy_password': data['proxy_password']})
                    self.update(job, data['node'], 'running', 'Резервная копия и короткое переключение Squid')
                    replacing = True
                    self.remote(client, {'id': job, 'action': 'legacy-stop', 'legacy_fingerprint': data['_legacy']['fingerprint']})
                if data.get('replace_service'):
                    self.update(job, data['node'], 'running', 'Подготовка образа до переключения управляемого прокси')
                    preparation = {**config, 'action': 'image-prepare'}
                    if data.get('_password_hash'):
                        preparation.update(qualify_service=data['replace_service'], managed_fingerprint=data['_managed_guard'],
                                           legacy_managed=bool(data['_replace']['legacy_squid']), qualify_password=data['proxy_password'])
                    self.remote(client, preparation)
                    self.update(job, data['node'], 'running', 'Резервирование и короткое переключение управляемого прокси')
                    replacing_managed = True
                    self.remote(client, {'id': job, 'action': 'managed-stop', 'replace_service': data['replace_service'],
                                         'legacy_managed': bool(data['_replace']['legacy_squid']), 'managed_fingerprint': data['_managed_guard']})
                self.update(job, data['node'], 'running', 'Запуск отдельного контейнера Squid')
                self.remote(client, config)
                if relay_prepared and data['_relay_after']:
                    self.update(job,data['node'],'running','Обновление правил прокси на входном сервере')
                    relays.changes.apply(job,data['_relay_after'])
                self.update(job, data['node'], 'running', 'Проверка авторизации и реального HTTPS-трафика')
                result = self.check(data)
                if not result['passed']:
                    raise ProvisionError('Проверка прокси не пройдена. Проверьте доступность порта, TLS и авторизацию')
                with self.store.connection(write=True) as db:
                    if self.current_generation(db, data['node']) != data['_node_generation']:
                        raise ProvisionError('Экземпляр ноды изменился во время установки')
                    db.execute('''UPDATE fleet_proxy_services SET active=0 WHERE node=? AND active=1
                                  AND ((http_port IS NOT NULL AND http_port IN (?,?))
                                       OR (https_port IS NOT NULL AND https_port IN (?,?)))''',
                               (data['node'], data.get('http_port'), data.get('https_port'), data.get('http_port'), data.get('https_port')))
                    db.execute('''INSERT INTO fleet_proxy_services(id,node,host,address,domain,http_port,https_port,
                                  username,password_hash,created_at,checked_at,result,active,node_generation,password_secret,legacy_squid)
                                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)''',
                               (job, data['node'], data['host'], data.get('_origin_address',data['address']), data['domain'], data.get('http_port'), data.get('https_port'),
                                data['proxy_username'], password_hash, time.time(), time.time(), json.dumps(result), data['_node_generation'],
                                password_secret, int(bool(data.get('replace_legacy_squid') or data.get('_replace', {}).get('legacy_squid')))))
                    if data.get('replace_service'):
                        db.execute('UPDATE fleet_proxy_services SET active=0 WHERE id=?', (data['replace_service'],))
                    self.recovery.remember_proxy(data['node'],job,config,data['domain'],db,password=data['proxy_password'])
                    if relay_prepared and data['_relay_after']:relays.changes.publish(job,database=db)
                    if not data.get('replace_legacy_squid') and not data.get('replace_service'):
                        success_message='Прокси установлен. Авторизация и передача HTTPS-трафика проверены'
                registered = True
                if data.get('replace_legacy_squid'):
                    self.remote(client, {'id': job, 'action': 'legacy-commit'})
                    success_message='Прокси заменён. Доступы и порты сохранены.'+(' Продление TLS подключено к управляемому контейнеру.' if data.get('https_port') is not None else '')
                if data.get('replace_service'):
                    self.remote(client, {'id': job, 'action': 'managed-commit', 'http_port': data.get('http_port'), 'https_port': data.get('https_port')})
                    success_message='Прокси обновлён. Новые параметры и передача трафика проверены'
                    try:
                        self.remote(client, {'id': job, 'action': 'managed-retire', 'replace_service': data['replace_service']})
                    except Exception:
                        success_message='Новый прокси работает. Старый остановленный контейнер сохранён для сверки очистки'
            completed=True
        except Exception as error:
            if relay_prepared:
                try:relays.changes.rollback(job)
                except Exception:pass
            rollback = not touched
            if touched and not replacing and not replacing_managed:
                try:
                    with self.connect(data) as client:
                        self.remote(client, {'id': job, 'action': 'rollback'})
                    rollback = True
                except Exception:
                    rollback = False
            if replacing:
                try:
                    with self.connect(data) as client:
                        self.remote(client, {'id': job, 'action': 'legacy-restore', 'force': True})
                    if not self.check(data)['passed']:
                        raise ProvisionError('Восстановленный Squid не прошёл клиентскую проверку')
                    rollback = True
                except Exception:
                    rollback = False
            if replacing_managed:
                try:
                    with self.connect(data) as client:
                        self.remote(client, {'id': job, 'action': 'managed-restore', 'force': True, 'replace_service': data['replace_service'],
                                             'legacy_managed': bool(data['_replace']['legacy_squid'])})
                    old = data['_replace']
                    rollback_data = {**data, 'domain': old['domain'], 'http_port': old['http_port'], 'https_port': old['https_port'],
                                     'proxy_username': old['username'], 'proxy_password': data['_rollback_password']}
                    if not self.check(rollback_data)['passed']:
                        raise ProvisionError('Исходный прокси не прошёл проверку после восстановления')
                    rollback = True
                except Exception:
                    rollback = False
            if registered and rollback:
                with self.store.connection(write=True) as db:
                    db.execute('UPDATE fleet_proxy_services SET active=0 WHERE id=?', (job,))
                    if data.get('replace_service'):
                        db.execute('UPDATE fleet_proxy_services SET active=1 WHERE id=?', (data['replace_service'],))
            message = str(error) if isinstance(error, (ProvisionError, ValueError)) else 'Операция установки прокси завершилась ошибкой'
            self.update(job, data['node'], 'rolled_back' if rollback else 'failed',
                        message + ('. Откат этой попытки завершён' if touched and rollback else ''))
        finally:
            if relay_prepared:
                try:relays.changes.finish(job,completed)
                except Exception:
                    completed=False
                    self.update(job,data['node'],'failed','Установка прокси сохранена. Маршрут входного сервера требует сверки')
            node=data['node']
            with self.provision.lock:
                self.provision.running.discard(data.get('address'))
            data.clear()
            lease = record.pop('_operation_lease', None)
            if lease is not None:os.close(lease)
            if completed:self.update(job,node,'succeeded',success_message)

    def list(self, node):
        try:
            _, generation = self.node_identity(node)
        except ProvisionError:
            generation = None
        with self.store.connection() as db:
            rows = db.execute('''SELECT s.*,j.state AS deployment_state,j.message AS deployment_error
                                 FROM fleet_proxy_services s LEFT JOIN fleet_proxy_jobs j ON j.id=s.id
                                 WHERE s.node=? AND s.active=1 ORDER BY s.created_at DESC''', (node,)).fetchall()
        result = [{key: row[key] for key in ['id', 'node', 'address', 'domain', 'http_port', 'https_port', 'username', 'created_at', 'checked_at']}
                | {'result': json.loads(row['result']), 'stale': not row['node_generation'] or row['node_generation'] != generation,
                   'deployment_state': row['deployment_state'] or 'needs_reconciliation',
                   'deployment_error': row['deployment_error'], 'credentials_available': bool(row['password_secret']),
                   'credentials_saved': bool(row['password_secret']),
                   'edit_allowed': bool(row['password_secret']) and row['deployment_state'] == 'succeeded' and row['node_generation'] == generation,
                   'reconcile_allowed': row['deployment_state'] != 'succeeded' and bool(row['node_generation']) and row['node_generation'] == generation,
                   'locked_domain': True} for row in rows]
        for item in result:
            item['endpoints']={}
            if getattr(self,'relays',None):
                for mode in ['http','https']:
                    port=item[mode+'_port']
                    endpoint=self.relays.proxy_endpoint(item['id'],mode,port) if port else None
                    if endpoint:item['endpoints'][mode]={'host':endpoint['domain'],'port':endpoint['public_port'],'entry':endpoint['entry_name']}
        return result

    def recheck(self, service, password, remember=False):
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM fleet_proxy_services WHERE id=? AND active=1', (service,)).fetchone()
        if row is None:
            raise ProvisionError('Прокси не найден')
        self.require_stable_node(row['node'])
        if self.job(service)['state'] != 'succeeded':
            raise ProvisionError('Установка требует сверки контейнера по SSH. Одна клиентская проба не подтверждает завершение замены')
        data = dict(row)
        if not password:
            password = self.clear_password(data)
        host, generation = self.node_identity(row['node'])
        if not row['node_generation'] or row['node_generation'] != generation:
            raise ProvisionError('Прокси относится к прежнему экземпляру ноды. Проверьте сервер перед новой установкой')
        endpoints = {mode:self.relays.proxy_endpoint(service,mode,row[mode+'_port'])
                     for mode in ['http','https'] if row[mode+'_port']} if getattr(self,'relays',None) else {}
        if endpoints and all(endpoints.values()):
            checks=[]
            for mode,endpoint in endpoints.items():
                checks.append(probe(endpoint['address'],endpoint['domain'],endpoint['public_port'],mode=='https',row['username'],password,
                    {**self.settings,'panel_ca_file':self.provision.settings.get('panel_ca_file'),'expected_egress_ip':row['address']}))
            result={'passed':all(value['passed'] for value in checks),'checks':checks,'origin':'Сервер панели → выбранный вход'}
            envelope=self.encrypted_password(service,password) if result['passed'] and remember else None
            with self.store.connection(write=True) as database:
                if self.current_generation(database,row['node']) != generation:
                    raise ProvisionError('Экземпляр ноды изменился во время проверки')
                current=database.execute('SELECT runtime_id,address,active FROM fleet_proxy_services WHERE id=?',(service,)).fetchone()
                if not current or not current['active'] or current['runtime_id']!=row['runtime_id'] or current['address']!=row['address']:
                    raise ProvisionError('Прокси изменился во время проверки. Повторите проверку текущего сервера')
                database.execute('UPDATE fleet_proxy_services SET checked_at=?,result=?,password_secret=COALESCE(?,password_secret) WHERE id=? AND active=1',
                    (time.time(),json.dumps(result),envelope,service))
            return result
        if getattr(self,'relays',None):host=self.relays.direct_target(row['node']) or host
        addresses = self.provision.resolve(host, 22)
        domain_addresses = {value[4][0] for value in socket.getaddrinfo(row['domain'], None, socket.AF_INET, socket.SOCK_STREAM)}
        if len(domain_addresses) != 1 or not domain_addresses <= set(addresses):
            raise ProvisionError('DNS-адрес прокси отличается от текущего адреса ноды')
        data['address'] = next(iter(domain_addresses))
        data['proxy_username'], data['proxy_password'] = row['username'], password
        result = self.check(data)
        envelope = self.encrypted_password(service, password) if result['passed'] and remember else None
        with self.store.connection(write=True) as db:
            if self.current_generation(db, row['node']) != generation:
                raise ProvisionError('Экземпляр ноды изменился во время проверки')
            current=db.execute('SELECT address,runtime_id FROM fleet_proxy_services WHERE id=?',(service,)).fetchone()
            if not current or current['address']!=row['address'] or current['runtime_id']!=row['runtime_id']:
                raise ProvisionError('Прокси перенесён во время проверки. Повторите пробу текущего сервера')
            db.execute('''UPDATE fleet_proxy_services SET checked_at=?,result=?,
                          address=CASE WHEN ? THEN ? ELSE address END,password_secret=COALESCE(?,password_secret)
                          WHERE id=? AND active=1''',
                       (time.time(), json.dumps(result), result['passed'], data['address'], envelope, service))
        return result

    def require_stable_node(self,node):
        with self.store.connection() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_node_transfers'").fetchone() and db.execute("SELECT 1 FROM fleet_node_transfers WHERE node=? AND state='switched'",(node,)).fetchone():
                raise ProvisionError('Дождитесь завершения переноса ноды')

    def prune(self):
        with self.store.connection(write=True) as db:
            db.execute('''DELETE FROM fleet_proxy_jobs WHERE ((state='succeeded' AND created_at<?)
                          OR (state='rolled_back' AND created_at<?))
                          AND id NOT IN (SELECT id FROM fleet_proxy_services WHERE active=1)''',
                       (time.time() - 30 * 86400, time.time() - 90 * 86400))
            db.execute('DELETE FROM fleet_proxy_services WHERE active=0 AND created_at<?', (time.time() - 90 * 86400,))


def install(app, store, provision):
    from app.models.admin import Admin
    service = ProxyService(store, provision)
    app.state.fleet_proxy = service
    def call(function, *args):
        try:
            return function(*args)
        except ProvisionError as error:
            raise HTTPException(409, str(error)) from None
        except Exception:
            raise HTTPException(503, 'Операция прокси недоступна. Повторите проверку') from None

    @app.get('/api/fleet/proxy/options', tags=['Fleet'])
    def options(admin=Depends(Admin.check_sudo_admin)):
        return service.options()

    @app.get('/api/fleet/nodes/{node}/proxies', tags=['Fleet'])
    def proxies(node: str, admin=Depends(Admin.check_sudo_admin)):
        return service.list(node)

    @app.get('/api/fleet/nodes/{node}/proxy-access',tags=['Fleet'])
    def proxy_access(node:str,admin=Depends(Admin.check_sudo_admin)):
        return call(service.access_metadata,node)

    @app.post('/api/fleet/proxy/preflight', tags=['Fleet'])
    def preflight(data: ProxyRequest, admin=Depends(Admin.check_sudo_admin)):
        return call(service.preflight, data.model_dump())

    @app.post('/api/fleet/proxy/deploy', tags=['Fleet'])
    def deploy(data: ProxyDeploy, admin=Depends(Admin.check_sudo_admin)):
        return call(service.deploy, data.plan_id)

    @app.get('/api/fleet/proxy/jobs/{job}', tags=['Fleet'])
    def job(job: str, admin=Depends(Admin.check_sudo_admin)):
        try:
            return service.job(job)
        except ProvisionError as error:
            raise HTTPException(404, str(error)) from None

    @app.post('/api/fleet/proxy/{proxy}/check', tags=['Fleet'])
    def check(proxy: str, data: ProxyCheck, admin=Depends(Admin.check_sudo_admin)):
        return call(service.recheck, proxy, data.proxy_password, data.remember)

    @app.get('/api/fleet/proxy/{proxy}/connection', tags=['Fleet'])
    def connection(proxy: str, admin=Depends(Admin.check_sudo_admin)):
        from fastapi.responses import JSONResponse
        return JSONResponse(call(service.connection_info, proxy), headers={'Cache-Control': 'no-store'})

    @app.post('/api/fleet/proxy/{proxy}/reconcile', tags=['Fleet'])
    def reconcile(proxy: str, data: ProxyReconcile, admin=Depends(Admin.check_sudo_admin)):
        return call(service.reconcile, proxy, data.model_dump())

    from app import scheduler
    scheduler.add_job(service.prune, 'interval', hours=1, id='rime_proxy_retention', replace_existing=True, max_instances=1)
    from .proxy_delete import install as install_deletion
    service.deletion = install_deletion(app, service)
    return service
