"""Encrypted node recovery profiles and bounded, data-only legacy archive import."""
from copy import deepcopy
import hashlib
import gzip
import io
import json
from pathlib import PurePosixPath
import posixpath
import re
import shlex
import tarfile
import time
import yaml

from .provision import ProvisionError
from .proxy_secrets import ProxySecretError


MAX_PROFILE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024


class ArchiveBudget:
    def __init__(self,source,budget=None):
        self.source=source
        self.budget=budget or self
        if budget is None:
            self.remaining=MAX_EXPANDED_BYTES
            self.members=4000

    def read(self,size=-1):
        maximum=self.budget.remaining+1
        value=self.source.read(maximum if size<0 else min(size,maximum))
        self.budget.remaining-=len(value)
        if self.budget.remaining<0:raise ProvisionError('Распакованный архив превышает 128 MiB. Выберите конфигурационный комплект')
        return value


class Recovery:
    def __init__(self, store, secrets):
        self.store = store
        self.secrets = secrets
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_recovery_profiles(
                node TEXT PRIMARY KEY,generation TEXT NOT NULL,envelope TEXT NOT NULL,
                digest TEXT NOT NULL,updated_at REAL NOT NULL)''')

    @staticmethod
    def generation(db, node):
        if node.startswith('xray:') and node[5:].isdigit():
            row = db.execute('SELECT created_at FROM nodes WHERE id=?', (int(node[5:]),)).fetchone()
        else:
            row = db.execute('SELECT created_at FROM fleet_inventory WHERE id=?', (node,)).fetchone()
        if not row:
            raise ProvisionError('Нода комплекта восстановления отсутствует')
        return str(row['created_at'])

    def load(self, node, db=None):
        if db is None:
            with self.store.connection() as connection:
                return self.load(node, connection)
        row = db.execute('SELECT * FROM fleet_recovery_profiles WHERE node=?', (node,)).fetchone()
        if not row or row['generation'] != self.generation(db, node):
            return {'version': 1, 'vpn': None, 'proxies': {}, 'originals': {}}
        try:
            raw = self.secrets.decrypt('node-recovery/' + node + '/' + row['generation'], row['envelope'])
            if hashlib.sha256(raw.encode()).hexdigest() != row['digest']:
                raise ValueError()
            profile = json.loads(raw)
            if profile['version'] != 1 or not isinstance(profile['proxies'], dict):
                raise ValueError()
            return profile
        except (ProxySecretError, ValueError, KeyError):
            raise ProvisionError('Комплект восстановления не расшифрован. Восстановите ключ хранилища из резерва панели') from None

    def save(self, node, profile, db=None):
        if db is None:
            with self.store.connection(write=True) as connection:
                return self.save(node, profile, connection)
        raw = json.dumps(profile, sort_keys=True, ensure_ascii=False)
        if len(raw.encode()) > MAX_PROFILE_BYTES or profile.get('version') != 1:
            raise ProvisionError('Некорректный размер или версия комплекта восстановления')
        generation = self.generation(db, node)
        digest=hashlib.sha256(raw.encode()).hexdigest()
        current=db.execute('SELECT generation,digest FROM fleet_recovery_profiles WHERE node=?',(node,)).fetchone()
        if current and current['generation']==generation and current['digest']==digest:
            self.load(node,db)
            return
        existing = db.execute('SELECT 1 FROM fleet_recovery_profiles LIMIT 1').fetchone()
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_proxy_services'").fetchone():
            existing = existing or db.execute("SELECT 1 FROM fleet_proxy_services WHERE password_secret<>'' LIMIT 1").fetchone()
        try:
            envelope = self.secrets.encrypt('node-recovery/' + node + '/' + generation, raw, create=not existing)
        except ProxySecretError:
            raise ProvisionError('Ключ комплекта восстановления недоступен. Восстановите его из резерва панели') from None
        db.execute('INSERT OR REPLACE INTO fleet_recovery_profiles VALUES(?,?,?,?,?)',
                   (node, generation, envelope, digest, time.time()))

    def remember_vpn(self, node, vpn, db=None):
        if db is None:
            with self.store.connection(write=True) as connection:
                return self.remember_vpn(node, vpn, connection)
        profile = self.load(node, db)
        profile['vpn'] = deepcopy(vpn)
        self.save(node, profile, db)

    def remember_proxy(self, node, identity, config, domain, db, password=None):
        profile = self.load(node, db)
        profile['proxies'][identity] = {'files': deepcopy(config['files']),
                                        'publish': deepcopy(config['publish']), 'domain': domain}
        if password is not None:profile['proxies'][identity]['known_password']=password
        self.save(node, profile, db)

    def summary(self, node):
        profile = self.load(node)
        with self.store.connection() as db:
            row = db.execute('SELECT updated_at FROM fleet_recovery_profiles WHERE node=?', (node,)).fetchone()
        vpn = profile.get('vpn') or {}
        missing=[]
        missing_proxies=[]
        with self.store.connection() as db:
            tables={row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if node.startswith('xray:') and {'hosts','fleet_host_nodes'}<=tables:
                wanted={row['inbound_tag'] for row in db.execute('SELECT h.inbound_tag FROM hosts h JOIN fleet_host_nodes f ON f.host_id=h.id WHERE f.node=?',(node,))}
                missing=sorted(wanted-{value['tag'] for value in vpn.get('config',{}).get('inbounds',[])})
            if 'fleet_proxy_services' in tables and 'active' in {row['name'] for row in db.execute('PRAGMA table_info(fleet_proxy_services)')}:
                active={row['id'] for row in db.execute('SELECT id FROM fleet_proxy_services WHERE node=? AND active=1',(node,))}
                missing_proxies=sorted(active-profile['proxies'].keys())
        return {'available': bool(vpn) and not missing and not missing_proxies, 'protocol': vpn.get('protocol'), 'proxies': len(profile['proxies']),
                'updated_at': row['updated_at'] if row else None,
                'original_files': len(profile.get('originals', {})), 'missing_inbounds':missing, 'missing_proxies':missing_proxies}

    def import_archive(self, node, data, domain):
        files = archive_files(data)
        return self.import_files(node,files,domain)

    def import_files(self,node,files,domain):
        if sum(len(value.encode()) for value in files.values())>MAX_PROFILE_BYTES:
            raise ProvisionError('Комплект конфигурации слишком большой')
        profile = self.load(node)
        expected='vless' if node.startswith('xray:') else 'hysteria2'
        vpn = None
        for name, raw in files.items():
            if not name.endswith(('.json', '.yaml', '.yml')):
                continue
            try:
                if name.endswith('.json'):
                    value = json.loads(raw)
                else:
                    value = yaml.safe_load(raw)
            except (ValueError, TypeError, yaml.YAMLError, RecursionError):
                continue
            if not isinstance(value, dict):
                continue
            if expected=='vless' and isinstance(value.get('inbounds'), list) and any(i.get('protocol') == 'vless' for i in value['inbounds']):
                bounded_config(value)
                value=deepcopy(value)
                value['inbounds']=[entry for entry in value['inbounds'] if entry.get('tag')!='API_INBOUND']
                value.pop('api',None)
                for entry in value['inbounds']:entry.get('settings',{}).pop('clients',None)
                candidate = {'protocol': 'vless', 'config': inline_certificates(value, files)}
                if vpn and vpn != candidate:
                    raise ProvisionError('В архиве несколько разных Xray-конфигураций. Выберите конфигурационный комплект нужной версии')
                vpn = candidate
            elif expected=='hysteria2' and 'listen' in value and isinstance(value.get('tls'), dict) and 'auth' in value:
                bounded_config(value)
                candidate = {'protocol': 'hysteria2', 'config': deepcopy(value)}
                tls = candidate['config']['tls']
                parent=str(PurePosixPath(name).parent)
                candidate['certificate'] = files.get(parent+'/'+PurePosixPath(tls['cert']).name) or find_file(files, tls['cert'])
                candidate['certificate_key'] = files.get(parent+'/'+PurePosixPath(tls['key']).name) or find_file(files, tls['key'])
                if vpn and vpn != candidate:
                    raise ProvisionError('В архиве несколько разных VPN-конфигураций. Выберите комплект нужной ноды')
                vpn = candidate
        if vpn:
            if vpn['protocol']=='vless':
                previous=(profile.get('vpn') or {}).get('management_tls')
                if previous:vpn['management_tls']=deepcopy(previous)
                for certificate,key in [('node-cert.pem','node-key.pem'),('ssl_cert.pem','ssl_key.pem')]:
                    certs=[name for name in files if PurePosixPath(name).name==certificate]
                    for name in certs:
                        peer=str(PurePosixPath(name).with_name(key))
                        if peer in files:vpn['management_tls']={'certificate':files[name],'key':files[peer]}
                if 'recovery-active-management-cert.pem' in files and 'recovery-active-management-key.pem' in files:
                    vpn['management_tls']={'certificate':files['recovery-active-management-cert.pem'],'key':files['recovery-active-management-key.pem']}
            profile['vpn'] = vpn
        managed = [name for name in files if re.search(r'/fleet-proxies/[a-f0-9]{32}/squid\.conf$', '/' + name)]
        proxy_paths = managed or [name for name in files if name.endswith('/squid.conf')]
        for name in proxy_paths:
            match = re.search(r'/fleet-proxies/([a-f0-9]{32})/', '/' + name)
            identity = match.group(1) if match else hashlib.sha256((node + '/' + name).encode()).hexdigest()[:32]
            with self.store.connection() as db:
                row=db.execute('SELECT * FROM fleet_proxy_services WHERE node=? AND (runtime_id=? OR id=?)',(node,identity,identity)).fetchone()
            if row:identity=row['id']
            proxy=proxy_profile(name, files, row['domain'] if row and 'domain' in row.keys() else domain)
            if row and 'http_port' in row.keys():
                proxy['publish']=[[row[field],inside] for field,inside in [('http_port',3128),('https_port',8443)] if row[field] is not None]
            if row and row['password_secret'] and row['username']==proxy['username'] and row['password_hash']==proxy['password_hash']:
                proxy['known_password']=self.secrets.decrypt(row['id'],row['password_secret'])
            for old_identity,old in list(profile['proxies'].items()):
                if old['domain']==proxy['domain'] and old['publish']==proxy['publish']:
                    if old.get('known_password') and old['files']['passwd'].splitlines()[0]==proxy['files']['passwd'].splitlines()[0]:
                        proxy['known_password']=old['known_password']
                    if old_identity!=identity:profile['proxies'].pop(old_identity)
            profile['proxies'][identity] = proxy
        groups={re.match(r'(.*/fleet-(?:nodes|proxies))/[a-f0-9]{32}/',name).group(1) for name in files if re.match(r'(.*/fleet-(?:nodes|proxies))/[a-f0-9]{32}/',name)}
        profile['originals']={name:value for name,value in profile['originals'].items()
                              if not any(name.startswith(group+'/') for group in groups)}
        profile['originals'].update(files)
        if not profile['vpn'] and not profile['proxies']:
            raise ProvisionError('В архиве не найдены конфигурации VPN или HTTP/HTTPS-прокси')
        self.save(node, profile)
        return self.summary(node)


def archive_files(data, depth=0, budget=None):
    if len(data) > MAX_ARCHIVE_BYTES or depth > 2:
        raise ProvisionError('Архив конфигурации слишком большой или содержит лишние вложения')
    files = {}
    links = {}
    total = 0
    try:
        raw=io.BytesIO(data)
        source=gzip.GzipFile(fileobj=raw) if data.startswith(b'\x1f\x8b') else raw
        stream=ArchiveBudget(source,budget)
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for index, member in enumerate(archive):
                parts = PurePosixPath(member.name).parts
                stream.budget.members-=1
                if stream.budget.members<0 or member.name.startswith('/') or '..' in parts or '\\' in member.name:
                    raise ProvisionError('Небезопасный путь или слишком много файлов в архиве')
                name = '/'.join(part for part in parts if part != '.')
                if member.issym() or member.islnk():
                    target = member.linkname.lstrip('/') if member.linkname.startswith('/') else posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                    if target.startswith('../') or target == '..':
                        raise ProvisionError('Ссылка архива выходит за пределы комплекта')
                    links[name] = target
                    continue
                if not member.isfile() or member.size > MAX_PROFILE_BYTES:
                    continue
                if name.endswith(('.tar.gz', '.tgz')) and ('recovery' in name or 'config' in name):
                    nested = archive_files(archive.extractfile(member).read(), depth + 1,stream.budget)
                    files.update(nested)
                    if sum(len(value.encode()) for value in files.values())>MAX_PROFILE_BYTES:
                        raise ProvisionError('Распакованный комплект конфигурации слишком большой')
                elif name.endswith(('.json', '.yaml', '.yml', '.conf', '.cnf', '.pem', '.key', '.crt', '.cer', '.passwd', '.htpasswd', '.txt', '.lst')) or PurePosixPath(name).name in ('passwd', 'passwords', 'squid_passwd', '.htpasswd'):
                    if member.size > 1024 * 1024:
                        raise ProvisionError('Файл конфигурации слишком большой')
                    raw = archive.extractfile(member).read()
                    total += len(raw)
                    if total > MAX_PROFILE_BYTES:
                        raise ProvisionError('Распакованный комплект конфигурации слишком большой')
                    files[name] = raw.decode('utf-8')
        for _ in range(8):
            for name, target in links.items():
                if target in files:
                    files[name] = files[target]
        if sum(len(value.encode()) for value in files.values()) > MAX_PROFILE_BYTES:
            raise ProvisionError('Распакованный комплект конфигурации слишком большой')
        return files
    except (tarfile.TarError, UnicodeError, OSError):
        raise ProvisionError('Архив конфигурации повреждён или содержит двоичные данные вместо настроек') from None


def find_file(files, path):
    name = str(path).lstrip('/')
    if name in files:
        return files[name]
    matches = [value for key, value in files.items() if PurePosixPath(key).name == PurePosixPath(name).name]
    if len(matches) != 1:
        raise ProvisionError('В комплекте отсутствует однозначный файл ' + PurePosixPath(name).name)
    return matches[0]


def inline_certificates(config, files):
    result = deepcopy(config)
    for inbound in result.get('inbounds', []):
        stream = inbound.get('streamSettings', {})
        for certificate in stream.get('tlsSettings', {}).get('certificates', []):
            for external, inline in [('certificateFile', 'certificate'), ('keyFile', 'key')]:
                if certificate.get(external):
                    certificate[inline] = find_file(files, certificate.pop(external)).splitlines()
    return result


def proxy_runtime_config(text):
    lines=[line for line in text.splitlines() if not re.match(r'^\s*pid_filename\s',line)]
    return '\n'.join(lines).rstrip('\n')+'\npid_filename /run/squid/squid.pid\n'


def proxy_profile(name, files, domain):
    text = expand_includes(name, files)
    directory = str(PurePosixPath(name).parent)
    rows = [shlex.split(line, comments=True) for line in text.splitlines()]
    auth = [row for row in rows if row[:3] == ['auth_param', 'basic', 'program']]
    if len(auth) != 1 or len(auth[0]) != 5 or 'ncsa' not in auth[0][3]:
        raise ProvisionError('Для восстановления прокси требуется его NCSA-файл пользователей')
    def local_file(path):
        relative = directory + '/' + PurePosixPath(path).name
        return files[relative] if relative in files else find_file(files, path)
    passwd = local_file(auth[0][4])
    accounts = [line.split(':', 1) for line in passwd.splitlines() if line]
    if not accounts or any(len(line) != 2 or not line[0] or not line[1] for line in accounts):
        raise ProvisionError('Файл пользователей прокси повреждён')
    output = {'passwd': passwd}
    publish = []
    normalized = []
    for line,row in zip(text.splitlines(),rows):
        if not row:
            normalized.append(line)
            continue
        replacement=None
        if row[0] in ('http_port', 'https_port'):
            port = int(row[1].rsplit(':', 1)[-1])
            if not 1 <= port <= 65535:
                raise ProvisionError('Некорректный порт прокси в архиве')
            inside = 3128 if row[0] == 'http_port' else 8443
            publish.append([port, inside])
            if row[0] == 'https_port':
                options = dict(item.split('=', 1) for item in row[2:] if '=' in item)
                output['cert.pem'] = local_file(options.get('tls-cert') or options.get('cert', 'cert.pem'))
                output['key.pem'] = local_file(options.get('tls-key') or options.get('key', 'key.pem'))
                extra=[item for item in row[2:] if not item.startswith(('tls-cert=','tls-key=','cert=','key='))]
                replacement=' '.join(['https_port','8443','tls-cert=/state/cert.pem','tls-key=/state/key.pem',*extra])
            else:
                row[1] = '3128'
                replacement=' '.join(row)
        elif row[:3] == ['auth_param', 'basic', 'program']:
            replacement='auth_param basic program /usr/lib/squid/basic_ncsa_auth /state/passwd'
        elif row[0] in ('access_log', 'cache_log', 'cache_store_log', 'pid_filename'):
            continue
        for item in row[1:]:
            path=item.split('=',1)[-1]
            if not path.startswith('/') or path in [auth[0][3],auth[0][4]] or row[0] in ['http_port','https_port']:
                continue
            candidate=path.lstrip('/')
            relative=directory+'/'+PurePosixPath(path).name
            if relative in files:candidate=relative
            if candidate in files:
                filename='extra-'+hashlib.sha256(candidate.encode()).hexdigest()[:16]+'.txt'
                output[filename]=files[candidate]
                line=line.replace(path,'/state/'+filename)
            elif row[0]=='acl':
                raise ProvisionError('В комплекте отсутствует файл ACL прокси '+PurePosixPath(path).name)
        normalized.append(replacement if replacement is not None else line)
    if not publish or len(publish) > 2:
        raise ProvisionError('Не найдены однозначные HTTP/HTTPS-порты прокси')
    output['squid.conf'] = proxy_runtime_config('\n'.join(normalized) + '\naccess_log none\ncache_log /dev/null\ncache_store_log none\n')
    return {'files': output, 'publish': publish, 'domain': domain,
            'username': accounts[0][0], 'password_hash': accounts[0][1]}


def bounded_config(value):
    stack=[(value,0)]
    seen=set()
    count=0
    while stack:
        item,depth=stack.pop();count+=1
        if count>50000 or depth>32:raise ProvisionError('Конфигурация слишком глубоко вложена')
        if isinstance(item,(dict,list)):
            if id(item) in seen:raise ProvisionError('Повторные YAML-ссылки нужно раскрыть в конфигурации')
            seen.add(id(item))
            stack.extend((child,depth+1) for child in (item.values() if isinstance(item,dict) else item))


def expand_includes(name, files, visited=()):
    import fnmatch
    if name in visited or len(visited) >= 8:
        raise ProvisionError('Циклические include в конфигурации прокси')
    result = []
    for line in files[name].splitlines():
        row = shlex.split(line, comments=True)
        if row and row[0] == 'include':
            if len(row) != 2:
                raise ProvisionError('Некорректный include прокси')
            pattern = row[1].lstrip('/')
            matches = sorted(key for key in files if fnmatch.fnmatchcase(key, pattern))
            if not matches:
                raise ProvisionError('В резерве отсутствуют файлы include прокси')
            result.extend(expand_includes(key, files, (*visited, name)) for key in matches)
        else:
            result.append(line)
    return '\n'.join(result)


def vless_profile(config, hosts, certificates=None, include_all=False, published=None):
    files = dict(certificates or {})
    tags = {host['inbound_tag'] for host in hosts}
    config = deepcopy(config)
    inbounds = [value for value in config.get('inbounds', []) if value.get('tag') in tags or (include_all and value.get('protocol')=='vless')]
    if not tags<={value.get('tag') for value in inbounds}:
        raise ProvisionError('В резерве отсутствует часть исходных VLESS-входов')
    ports = {}
    for inbound in inbounds:
        if inbound.get('protocol') != 'vless' or type(inbound.get('port')) != int:
            raise ProvisionError('Некорректный VLESS-вход в комплекте восстановления')
        for certificate in inbound.get('streamSettings', {}).get('tlsSettings', {}).get('certificates', []):
            for key in ['certificateFile', 'keyFile']:
                path = certificate.get(key)
                if path and path not in files and path.lstrip('/') not in files:
                    from pathlib import Path
                    try:
                        if Path(path).stat().st_size > 131072:
                            raise OSError()
                        files[path.lstrip('/')] = Path(path).read_text()
                    except OSError:
                        raise ProvisionError('В резерве отсутствует TLS-файл входа ' + inbound['tag']) from None
        for host in hosts:
            if host['inbound_tag'] != inbound['tag']:
                continue
            outside = host['port'] or inbound['port']
            protocol = 'udp' if inbound.get('streamSettings', {}).get('network') in ['kcp', 'quic'] else 'tcp'
            pair = (outside, protocol)
            if pair in ports and ports[pair] != inbound['port']:
                raise ProvisionError('Адреса разных входов используют один внешний порт')
            ports[pair] = inbound['port']
        if inbound['tag'] not in tags:
            protocol='udp' if inbound.get('streamSettings',{}).get('network') in ['kcp','quic'] else 'tcp'
            outside_ports=[outside for outside,inside,transport in published or [] if inside==inbound['port'] and transport==protocol] or [inbound['port']]
            for outside in outside_ports:
                pair=(outside,protocol)
                if pair in ports and ports[pair]!=inbound['port']:raise ProvisionError('Сохранённые входы используют один внешний порт')
                ports[pair]=inbound['port']
        inbound.setdefault('settings', {}).pop('clients', None)
    config['inbounds'] = inbounds
    config.pop('api', None)
    config = inline_certificates(config, files)
    return {'protocol': 'vless', 'config': config,
            'publish': [[outside, inside, protocol] for (outside, protocol), inside in ports.items()]}
