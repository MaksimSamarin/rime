"""Pinned SSH provisioning with expiring in-memory credentials and audited jobs."""
import base64
from datetime import datetime,timezone
import hashlib
import io
import json
import logging
from pathlib import Path
import re
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit


class ProvisionError(ValueError):pass


class Provisioner:
    def __init__(self,store,settings,register,unregister,ready):
        self.store=store;self.settings=settings
        self.register=register;self.unregister=unregister;self.ready=ready
        self.plans={};self.lock=threading.Lock()
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_jobs(id TEXT PRIMARY KEY,state TEXT NOT NULL,
                message TEXT NOT NULL,steps TEXT NOT NULL,created_at REAL NOT NULL)''')
            db.execute("UPDATE fleet_jobs SET state='failed',message='Панель перезапущена; требуется сверка контейнера и регистрации' WHERE state='running'")

    def target(self,host,port):
        if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}',host):raise ProvisionError('Некорректный адрес')
        if type(port)!=int or not 1<=port<=65535:raise ProvisionError('Некорректный SSH-порт')
        allowed=self.settings.get('allowed_hosts',[])
        if host not in allowed:raise ProvisionError('Сервер не входит в список разрешённых для установки')
        return host,port

    @staticmethod
    def fingerprint(key):return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')

    def scan(self,host,port):
        import paramiko
        self.target(host,port)
        with socket.create_connection((host,port),timeout=8) as sock:
            with paramiko.Transport(sock) as transport:
                transport.start_client(timeout=8)
                return {'fingerprint':self.fingerprint(transport.get_remote_server_key())}

    def connect(self,data):
        import paramiko
        self.target(data['host'],data['ssh_port'])
        expected=data['fingerprint'];fingerprint=self.fingerprint
        class Pin(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self,client,hostname,key):
                if fingerprint(key)!=expected:raise ProvisionError('SSH-ключ сервера изменился')
        client=paramiko.SSHClient();client.set_missing_host_key_policy(Pin())
        key=None
        if data.get('private_key','').strip():
            for cls in (paramiko.Ed25519Key,paramiko.ECDSAKey,paramiko.RSAKey):
                try:key=cls.from_private_key(io.StringIO(data['private_key']),password=data.get('key_passphrase') or None);break
                except (paramiko.SSHException,ValueError):continue
            if key is None:raise ProvisionError('Не удалось прочитать SSH-ключ')
        try:
            client.connect(data['host'],port=data['ssh_port'],username=data['username'],pkey=key,
                password=data.get('password') if key is None else None,timeout=8,auth_timeout=8,banner_timeout=8,
                allow_agent=False,look_for_keys=False)
            return client
        except Exception:
            client.close();raise ProvisionError('SSH-подключение не выполнено; проверьте доступ и отпечаток') from None

    def remote(self,client,cfg):
        code=base64.b64encode(Path(__file__).with_name('remote_install.py').read_bytes()).decode()
        command="python3 -c \"import base64;exec(base64.b64decode('"+code+"'))\""
        inp,out,err=client.exec_command(command,timeout=200)
        inp.write(json.dumps(cfg));inp.flush();inp.channel.shutdown_write()
        raw=out.read(1024*1024);status=out.channel.recv_exit_status()
        if status:raise ProvisionError('Проверка или установка на сервере не выполнена')
        return json.loads(raw)

    def validate(self,d):
        self.target(d['host'],d['ssh_port'])
        if d['protocol'] not in ('hysteria2','vless'):raise ProvisionError('Неизвестный протокол')
        if type(d['vpn_port'])!=int or not 1<=d['vpn_port']<=65535:raise ProvisionError('Некорректный VPN-порт')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',d['domain']):raise ProvisionError('Некорректный TLS-домен')
        if not self.settings.get('lab_network'):
            try:
                destination={x[4][0] for x in socket.getaddrinfo(d['host'],None)}
                domain={x[4][0] for x in socket.getaddrinfo(d['domain'],None)}
                if not destination.intersection(domain):raise ValueError()
            except Exception:raise ProvisionError('DNS имени подключения не указывает на выбранный сервер') from None
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        try:
            cert=x509.load_pem_x509_certificate(d['certificate'].encode())
            key=serialization.load_pem_private_key(d['certificate_key'].encode(),password=None)
            encoding=serialization.Encoding.DER;fmt=serialization.PublicFormat.SubjectPublicKeyInfo
            if cert.public_key().public_bytes(encoding,fmt)!=key.public_key().public_bytes(encoding,fmt):raise ValueError()
            now=datetime.now(timezone.utc)
            if not cert.not_valid_before_utc<=now<cert.not_valid_after_utc:raise ValueError()
            names=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            domain=d['domain'].lower()
            if not any(domain==n.lower() or (n.startswith('*.') and domain.count('.')==n.count('.') and domain.endswith(n[1:].lower())) for n in names):raise ValueError()
        except Exception:raise ProvisionError('Сертификат, ключ, срок действия или SAN домена не совпадают') from None
        if d['protocol']=='hysteria2':
            url=urlsplit(self.settings.get('panel_url',''))
            if url.scheme!='https' and not (self.settings.get('lab_network') and url.hostname in ('127.0.0.1','localhost')):
                raise ProvisionError('Для ноды требуется HTTPS-адрес панели')
            if not Path(self.settings.get('hy2_bundle','')).is_file():raise ProvisionError('Сборка ядра и агента не настроена')
        elif not self.settings.get('vless_template'):raise ProvisionError('Шаблон VLESS не настроен администратором')

    def preflight(self,d):
        self.validate(d);job=secrets.token_hex(16)
        ports=[(d['vpn_port'],'udp' if d['protocol']=='hysteria2' else 'tcp')]
        if d['protocol']=='vless':ports += [(self.settings['vless_template']['service_port'],'tcp'),(self.settings['vless_template']['api_port'],'tcp')]
        with self.connect(d) as client:result=self.remote(client,{'id':job,'action':'preflight','ports':ports})
        ready=all(x['passed'] for x in result['checks'])
        plan={'id':job,'ready':ready,'checks':result['checks'],
              'summary':{'Нода':d['name'],'Сервер':d['host'],'Протокол':d['protocol'],'Порт':d['vpn_port'],
                         'Размещение':result['home']+'/.local/share/fleet-nodes/'+job,
                         'Откат':'Удаляется только новый контейнер; данные сохраняются'},
              'expires_at':time.time()+600}
        with self.lock:
            self.plans={k:v for k,v in self.plans.items() if v['plan']['expires_at']>time.time()}
            if len(self.plans)>=20:raise ProvisionError('Слишком много незавершённых планов')
            self.plans[job]={'plan':plan,'data':dict(d),'remote':result}
        def expire():
            with self.lock:
                expired=self.plans.pop(job,None)
                if expired:expired['data'].clear()
        timer=threading.Timer(600,expire);timer.daemon=True;timer.start()
        return plan

    def job(self,job):
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM fleet_jobs WHERE id=?',(job,)).fetchone()
        if row is None:raise ProvisionError('Задание не найдено')
        value=dict(row);value['steps']=json.loads(value['steps']);return value

    def update(self,job,state,message):
        with self.store.connection(write=True) as db:
            old=db.execute('SELECT steps FROM fleet_jobs WHERE id=?',(job,)).fetchone()
            steps=json.loads(old['steps']) if old else []
            steps.append({'message':message,'at':time.time()})
            db.execute('INSERT INTO fleet_jobs VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,message=excluded.message,steps=excluded.steps',
                       (job,state,message,json.dumps(steps,ensure_ascii=False),time.time()))

    def deploy(self,job):
        with self.lock:
            record=self.plans.pop(job,None)
        if not record or record['plan']['expires_at']<time.time():raise ProvisionError('План истёк; повторите проверку')
        if not record['plan']['ready']:raise ProvisionError('Проверка сервера не пройдена')
        self.update(job,'running','Проверка доступа перед установкой')
        threading.Thread(target=self.worker,args=(record,),daemon=True).start()
        return {'id':job}

    def worker(self,record):
        d=record['data'];job=record['plan']['id'];registered=False;installed=False
        try:
            self.validate(d)
            token=secrets.token_urlsafe(48)
            cfg=self.configuration(job,d,token)
            with self.connect(d) as client:
                if d['protocol']=='hysteria2':
                    with client.open_sftp() as sftp:
                        base=record['remote']['home']+'/.local/share/fleet-nodes'
                        # Fixed path derived from authenticated home, never UI input.
                        current=record['remote']['home']
                        for part in ('.local','share','fleet-nodes'):
                            current+='/'+part
                            try:sftp.mkdir(current,mode=0o700)
                            except OSError:sftp.stat(current)
                        cfg['bundle']=base+'/'+job+'.tar.gz'
                        sftp.put(self.settings['hy2_bundle'],cfg['bundle']);sftp.chmod(cfg['bundle'],0o600)
                self.update(job,'running','Запуск отдельного контейнера')
                installed=True
                result=self.remote(client,cfg)
                if not result['running']:raise ProvisionError('Контейнер завершился')
                if cfg.get('lab_network')=='bridge' and d['protocol']=='vless':d['_registration_address']=result['ip']
                self.register(job,d,token);registered=True
                self.update(job,'running','Ожидание связи с панелью')
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    if self.ready(job,d):break
                    time.sleep(1)
                else:raise ProvisionError('Нода не подтвердила готовность')
                self.update(job,'succeeded','Нода подключена к панели')
        except Exception as exc:
            logging.getLogger('fleet').error('Provision job %s failed (%s): %s',job,type(exc).__name__,str(exc) if isinstance(exc,ProvisionError) else 'details withheld')
            rollback=True
            if installed:
                try:self.unregister(job,d)
                except Exception:rollback=False
            if installed:
                try:
                    with self.connect(d) as client:self.remote(client,{'action':'rollback','id':job})
                except Exception:rollback=False
            self.update(job,'rolled_back' if installed and rollback else 'failed',
                        'Установка не завершена; новая регистрация и контейнер отозваны, данные сохранены' if installed and rollback else
                        'Установка не завершена; требуется проверить сервер и регистрацию ноды')
        finally:
            d.clear()

    def configuration(self,job,d,token):
        files={'cert.pem':d['certificate'],'key.pem':d['certificate_key']}
        cfg={'action':'install','id':job,'protocol':d['protocol'],'files':files,
             'lab_network':self.settings.get('lab_network_by_protocol',{}).get(d['protocol'],self.settings.get('lab_network')),'ports':[]}
        if d['protocol']=='hysteria2':
            cfg['image']=self.settings['python_image'];cfg['publish']=[(d['vpn_port'],24443,'udp')]
            agent={'panel_url':self.settings['panel_url'].rstrip('/')+'/api/hy2/nodes/'+job,
                'node_token':token,'stats_url':'http://127.0.0.1:19999','stats_secret':secrets.token_urlsafe(48),
                'auth_port':18888,'spool':'/state/spool.db','pid_file':'/state/hysteria.pid',
                'interval':1,'policy_ttl':5,'durable':True,'traffic_wal':'/state/traffic.wal','core_version':'2.12.3-fleet.1'}
            files['agent.json']=json.dumps(agent)
            files['hysteria.json']=json.dumps({'listen':':24443','tls':{'cert':'/state/cert.pem','key':'/state/key.pem'},
                'auth':{'type':'http','http':{'url':'http://127.0.0.1:18888/auth'}},
                'trafficStats':{'listen':'127.0.0.1:19999','secret':agent['stats_secret']}})
        else:
            t=self.settings['vless_template'];cfg['image']=t['image']
            cfg['publish']=[(d['vpn_port'],t['inbound_port'],'tcp'),(t['service_port'],62050,'tcp'),(t['api_port'],62051,'tcp')]
            files['client.pem']=t['client_certificate']
            cfg['env']={'SSL_CLIENT_CERT_FILE':'/state/client.pem','SSL_CERT_FILE':'/state/node-cert.pem',
                        'SSL_KEY_FILE':'/state/node-key.pem','INBOUNDS':t['inbound_tag']}
            cfg['mounts']=[('cert.pem',t['certificate_path']),('key.pem',t['key_path'])]
        return cfg
