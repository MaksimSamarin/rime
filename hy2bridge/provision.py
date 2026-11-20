"""Pinned SSH provisioning with expiring in-memory credentials and audited jobs."""
import base64
from datetime import datetime,timezone
import hashlib
import io
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time
import tarfile
from urllib.parse import urlsplit


class ProvisionError(ValueError):pass


def archive_image_candidates(path, checksum, expected):
    """Resolve verified OCI platform manifests for classic config-digest pins."""
    wanted=expected.rsplit('@',1)[-1]
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',wanted):
        raise ProvisionError('Образ установки должен быть закреплён контрольной суммой')
    with Path(path).open('rb') as stream:
        digest=hashlib.sha256()
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    if digest.hexdigest()!=checksum:
        raise ProvisionError('Контрольная сумма архива образа не совпадает. Требуется проверка сборки на панели')
    with tarfile.open(path) as archive:
        def metadata(name):
            member=archive.getmember(name)
            if not member.isfile() or member.size>1024*1024:raise ValueError('Invalid image metadata')
            return archive.extractfile(member).read()
        manifest=json.loads(metadata('manifest.json'))
        configs=[metadata(entry['Config']) for entry in manifest]
        if not any('sha256:'+hashlib.sha256(raw).hexdigest()==wanted
                   and json.loads(raw).get('architecture')=='amd64'
                   and json.loads(raw).get('os')=='linux' for raw in configs):
            raise ProvisionError('Архив не содержит ожидаемый образ Linux amd64. Требуется проверка сборки на панели')
        if 'index.json' not in archive.getnames():return []
        candidates=[];seen={}
        def visit(descriptor):
            platform=descriptor.get('platform')
            if platform and (platform.get('architecture')!='amd64' or platform.get('os')!='linux'):return False
            reference=descriptor['digest']
            if not re.fullmatch(r'sha256:[0-9a-f]{64}',reference):raise ValueError('Invalid image digest')
            if reference in seen:return seen[reference]
            if len(seen)>=32:raise ValueError('Image metadata graph is too large')
            seen[reference]=False
            raw=metadata('blobs/sha256/'+reference.split(':')[1])
            if 'sha256:'+hashlib.sha256(raw).hexdigest()!=reference:raise ValueError('Image metadata checksum mismatch')
            value=json.loads(raw)
            if value.get('config') and value['config'].get('digest')!=wanted:
                raise ProvisionError('OCI-архив содержит другой образ для выбранной платформы. Требуется проверка сборки на панели')
            matches=value.get('config',{}).get('digest')==wanted
            for child in value.get('manifests',[]):matches=visit(child) or matches
            seen[reference]=matches
            if matches:candidates.append(reference)
            return matches
        for descriptor in json.loads(metadata('index.json')).get('manifests',[]):visit(descriptor)
    return candidates


class Provisioner:
    def __init__(self,store,settings,register,unregister,ready,activate=None,verify=None):
        self.store=store;self.settings=settings
        self.register=register;self.unregister=unregister;self.ready=ready
        self.activate=activate;self.verify=verify
        self.plans={};self.lock=threading.Lock()
        self.running=set()
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_jobs(id TEXT PRIMARY KEY,state TEXT NOT NULL,
                message TEXT NOT NULL,steps TEXT NOT NULL,created_at REAL NOT NULL)''')
            if 'context' not in {row['name'] for row in db.execute('PRAGMA table_info(fleet_jobs)')}:
                db.execute("ALTER TABLE fleet_jobs ADD COLUMN context TEXT NOT NULL DEFAULT '{}'")
            tables={row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if {'fleet_managed','fleet_client_probes'}<=tables:
                pending=db.execute("SELECT j.id,m.native_id FROM fleet_jobs j JOIN fleet_managed m ON m.id=j.id WHERE j.state='running' AND m.active=1").fetchall()
                for row in pending:
                    node='xray:'+str(row['native_id']) if row['native_id'] is not None else row['id']
                    observed=db.execute("SELECT data FROM fleet_client_probes WHERE node=? AND probe='panel-managed'",(node,)).fetchone()
                    if observed and json.loads(observed['data']).get('passed') is True:
                        db.execute("UPDATE fleet_jobs SET state='succeeded',message='Нода опубликована до перезапуска. Текущее состояние доступно в её карточке' WHERE id=?",(row['id'],))
            db.execute("UPDATE fleet_jobs SET state='failed',message='Панель перезапущена; требуется сверка контейнера и регистрации' WHERE state='running'")

    def target(self,host,port):
        if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}',host):raise ProvisionError('Некорректный адрес')
        if type(port)!=int or not 1<=port<=65535:raise ProvisionError('Некорректный SSH-порт')
        allowed=self.settings.get('allowed_hosts',[])
        if host not in allowed and not self.settings.get('allow_public_hosts'):
            raise ProvisionError('Сервер не входит в список разрешённых для установки')
        if host in self.settings.get('protected_hosts',[]):
            raise ProvisionError('Этот сервер защищён от установки новых нод')
        return host,port

    def resolve(self,host,port):
        self.target(host,port)
        try:
            addresses=sorted({row[4][0] for row in socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM)})
        except OSError:
            raise ProvisionError('Не удалось определить IPv4 сервера') from None
        if not addresses:
            raise ProvisionError('У сервера отсутствует IPv4-адрес')
        allowed=host in self.settings.get('allowed_hosts',[])
        protected=set(self.settings.get('protected_hosts',[]))
        if any(address in protected or ipaddress.ip_address(address).is_multicast
               or (not allowed and not ipaddress.ip_address(address).is_global) for address in addresses):
            raise ProvisionError('Для установки требуется публичный IPv4 нового сервера')
        return addresses

    @staticmethod
    def fingerprint(key):return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')

    def options(self):
        automatic_tls=all(Path(self.settings.get(key,'/nonexistent')).is_file()
                          for key in ['certificate_file','certificate_key_file'])
        return {'enabled':bool(self.settings.get('allow_public_hosts') or self.settings.get('allowed_hosts')),
                'automatic_tls':automatic_tls,
                'protocols':{'vless':bool(self.settings.get('vless_template')),
                             'hysteria2':Path(self.settings.get('hy2_bundle','/nonexistent')).is_file()},
                'payload_check':bool(self.verify)}

    def scan(self,host,port):
        import paramiko
        address=self.resolve(host,port)[0]
        try:
            with socket.create_connection((address,port),timeout=8) as sock:
                with paramiko.Transport(sock) as transport:
                    transport.start_client(timeout=8)
                    return {'fingerprint':self.fingerprint(transport.get_remote_server_key()),'address':address}
        except (OSError,paramiko.SSHException):
            raise ProvisionError('SSH не отвечает с сервера панели. Проверьте прямой доступ и SSH-порт') from None

    def connect(self,data):
        import paramiko
        addresses=self.resolve(data['host'],data['ssh_port'])
        address=data.get('address') or addresses[0]
        if address not in addresses:
            raise ProvisionError('Адрес сервера изменился; повторите проверку SSH-ключа')
        data['address']=address
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
            client.connect(address,port=data['ssh_port'],username=data['username'],pkey=key,
                password=data.get('password') if key is None else None,timeout=8,auth_timeout=8,banner_timeout=8,
                allow_agent=False,look_for_keys=False)
            client.get_transport().set_keepalive(10)
            return client
        except ProvisionError:
            client.close();raise
        except paramiko.AuthenticationException:
            client.close();raise ProvisionError('SSH-аутентификация отклонена. Проверьте пользователя, пароль или ключ') from None
        except Exception:
            client.close();raise ProvisionError('SSH-подключение не выполнено; проверьте доступ и отпечаток') from None

    def remote(self,client,cfg):
        cfg=dict(cfg)
        if cfg.get('image') and self.settings.get('base_image_bundle'):
            cfg['image_candidates']=archive_image_candidates(self.settings['base_image_bundle'],
                self.settings['base_image_bundle_sha256'],cfg['image'])
        worker=Path(__file__).with_name('control_firewall.py').read_text()
        code=base64.b64encode(Path(__file__).with_name('port_check.py').read_bytes()+b'\n'+('CONTROL_FIREWALL_WORKER='+repr(worker)+'\n').encode()+Path(__file__).with_name('remote_install.py').read_bytes()).decode()
        command="python3 -c \"import base64;exec(base64.b64decode('"+code+"'))\""
        inp,out,err=client.exec_command(command,timeout=200)
        inp.write(json.dumps(cfg));inp.flush();inp.channel.shutdown_write()
        raw=out.read(1024*1024);status=out.channel.recv_exit_status()
        if status:
            try:
                failure=json.loads(raw)
                code=failure.get('code') if isinstance(failure,dict) else None
            except (ValueError,TypeError):code=None
            messages={'image_unavailable':'Docker не нашёл проверенный образ после загрузки. Требуется проверка сборки на панели',
                      'port_conflict':'Порт ноды уже занят другой службой. Выберите свободный порт и повторите проверку',
                      'container_start_failed':'Контейнер ноды не запустился. Подробности сохранены в install-error.log на сервере'}
            raise ProvisionError(messages.get(code,'Проверка или установка на сервере не выполнена. Диагностика сохранена в каталоге этой попытки на сервере'))
        return json.loads(raw)

    def upload(self,client,local,job,suffix,home):
        with client.open_sftp() as sftp:
            current=home
            for part in ('.local','share','fleet-nodes'):
                current+='/'+part
                try:sftp.mkdir(current,mode=0o700)
                except OSError:sftp.stat(current)
            path=current+'/'+job+suffix
            sftp.put(local,path)
            sftp.chmod(path,0o600)
            return path

    def validate(self,d):
        self.target(d['host'],d['ssh_port'])
        if not d['name'].strip():raise ProvisionError('Укажите название ноды')
        if d['protocol'] not in ('hysteria2','vless'):raise ProvisionError('Неизвестный протокол')
        if type(d['vpn_port'])!=int or not 1<=d['vpn_port']<=65535:raise ProvisionError('Некорректный VPN-порт')
        self.validate_connection(d)
        url=urlsplit(self.settings.get('panel_url',''))
        if url.scheme!='https' and not (self.settings.get('lab_network') and url.hostname in ('127.0.0.1','localhost')):
            raise ProvisionError('Для связи ноды и мониторинга требуется HTTPS-адрес панели')
        if d['protocol']=='hysteria2':
            if not Path(self.settings.get('hy2_bundle','')).is_file():raise ProvisionError('Сборка ядра и агента не настроена')
        elif not self.settings.get('vless_template'):raise ProvisionError('Шаблон VLESS не настроен администратором')

    def validate_connection(self,d):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',d['domain']):raise ProvisionError('Некорректный TLS-домен')
        if not self.settings.get('lab_network'):
            try:
                destination=self.resolve(d['host'],d['ssh_port'])
                address=d.get('address') or destination[0]
                if address not in destination:raise ValueError()
                domain=socket.getaddrinfo(d['domain'],None,socket.AF_UNSPEC,socket.SOCK_STREAM)
                if any(row[0]==socket.AF_INET6 for row in domain):
                    raise ProvisionError('Мастер поддерживает IPv4. Удалите AAAA-запись имени подключения перед установкой')
                if {row[4][0] for row in domain if row[0]==socket.AF_INET}!={address}:raise ValueError()
                d['address']=address
            except ProvisionError:raise
            except Exception:raise ProvisionError('DNS имени подключения должен указывать только на выбранный IPv4 сервера') from None
        d.setdefault('_custom_tls',bool(d.get('certificate') or d.get('certificate_key')))
        if not d.get('certificate') and not d.get('certificate_key'):
            try:
                d['certificate']=Path(self.settings['certificate_file']).read_text()
                d['certificate_key']=Path(self.settings['certificate_key_file']).read_text()
            except (KeyError,OSError):
                raise ProvisionError('Автоматический TLS не настроен; обратитесь к администратору панели') from None
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

    def preflight(self,d):
        self.validate(d);job=secrets.token_hex(16)
        cleanup=self.cleanup_context(d) if d.get('cleanup_job') else None
        ports=self.required_ports(d)
        from .bootstrap import inspect
        with self.connect(d) as client:
            runtime=inspect(client,ports)
            if runtime['python_available']:
                result=self.remote(client,{'id':job,'action':'preflight','ports':ports,'allow_bootstrap':True,
                                           'cleanup_job':d.get('cleanup_job')})
                result.update({key:runtime[key] for key in ['bootstrap_required','python_available','docker_installed']})
            else:
                result=runtime
            if d['protocol']=='vless' and self.settings.get('control_source'):
                result['checks'].append({'passed':result['uid']==0,'message':'Root-доступ для защиты управляющих портов'})
        ready=all(x['passed'] for x in result['checks'])
        plan={'id':job,'ready':ready,'checks':result['checks'],
              'summary':{'Нода':d['name'],'Сервер':d['host'],'Протокол':d['protocol'],'Порт':d['vpn_port'],
                         'Размещение':result['home']+'/.local/share/fleet-nodes/'+job,
                         'Откат':'Удаляются новые контейнеры и регистрация. Данные и пакеты ОС сохраняются'},
              'expires_at':time.time()+600}
        if cleanup:plan['summary']['Предыдущая попытка']='Остатки установки '+d['cleanup_job']+' будут удалены перед повтором'
        with self.lock:
            for key in list(self.plans):
                if self.plans[key]['plan']['expires_at']<=time.time():
                    self.plans.pop(key)['data'].clear()
            if len(self.plans)>=20:raise ProvisionError('Слишком много незавершённых планов')
            self.plans[job]={'plan':plan,'data':dict(d),'remote':result}
        def expire():
            with self.lock:
                expired=self.plans.pop(job,None)
                if expired:expired['data'].clear()
        timer=threading.Timer(600,expire);timer.daemon=True;timer.start()
        return plan

    def required_ports(self,data):
        ports=[(data['vpn_port'],'udp' if data['protocol']=='hysteria2' else 'tcp')]
        if data['protocol']=='vless':
            ports += [(self.settings['vless_template']['service_port'],'tcp'),(self.settings['vless_template']['api_port'],'tcp')]
        return ports

    def job(self,job):
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM fleet_jobs WHERE id=?',(job,)).fetchone()
        if row is None:raise ProvisionError('Задание не найдено')
        value=dict(row);value['steps']=json.loads(value['steps']);value['context']=json.loads(value['context']);return value

    def cleanup_context(self,data):
        previous=self.job(data['cleanup_job'])
        context=previous['context']
        if previous['state']!='failed' or not context:
            raise ProvisionError('Предыдущая попытка не требует очистки')
        if any(context.get(key)!=data.get(key) for key in ['host','ssh_port','username']):
            raise ProvisionError('Для очистки укажите прежний SSH-сервер и пользователя')
        with self.store.connection() as db:
            published=db.execute('SELECT active FROM fleet_managed WHERE id=?',(data['cleanup_job'],)).fetchone()
        if published and published['active']:
            raise ProvisionError('Нода уже опубликована; откройте её карточку перед повторной установкой')
        return context

    def update(self,job,state,message,context=None):
        with self.store.connection(write=True) as db:
            old=db.execute('SELECT steps FROM fleet_jobs WHERE id=?',(job,)).fetchone()
            steps=json.loads(old['steps']) if old else []
            steps.append({'message':message,'at':time.time()})
            db.execute('''INSERT INTO fleet_jobs(id,state,message,steps,created_at,context) VALUES(?,?,?,?,?,?)
                          ON CONFLICT(id) DO UPDATE SET state=excluded.state,message=excluded.message,steps=excluded.steps,
                          context=CASE WHEN excluded.context='{}' THEN fleet_jobs.context ELSE excluded.context END''',
                       (job,state,message,json.dumps(steps,ensure_ascii=False),time.time(),json.dumps(context or {},ensure_ascii=False)))

    def deploy(self,job):
        with self.lock:
            record=self.plans.get(job)
            if not record or record['plan']['expires_at']<time.time():
                if record:record['data'].clear();self.plans.pop(job)
                raise ProvisionError('План истёк; повторите проверку')
            if not record['plan']['ready']:raise ProvisionError('Проверка сервера не пройдена')
            target=record['data'].get('address') or record['data']['host']
            if target in self.running:
                raise ProvisionError('На этом сервере уже выполняется установка; дождитесь её завершения')
            if len(self.running)>=self.settings.get('max_concurrent_installs',2):
                raise ProvisionError('Выполняется предельное число установок. Дождитесь завершения и повторите запуск')
            try:
                from update_runtime.leases import acquire
                record['_operation_lease'] = acquire(Path(self.store.path).parent / '.updates')
            except BlockingIOError:
                raise ProvisionError('Панель обновляется. Повторите установку после завершения обновления') from None
            self.plans.pop(job)
            self.running.add(target)
        context={key:record['data'].get(key) for key in ['host','address','ssh_port','username','fingerprint','name','protocol','domain','vpn_port','move_node']}
        try:
            self.update(job,'running','Проверка доступа перед установкой',context)
            threading.Thread(target=self.worker,args=(record,),daemon=True).start()
        except Exception:
            with self.lock:
                self.running.discard(target)
                self.plans[job]=record
            lease = record.pop('_operation_lease', None)
            if lease is not None:os.close(lease)
            raise
        return {'id':job}

    def worker(self,record):
        d=record['data'];job=record['plan']['id'];registered=False;installed=False;transferred=False
        try:
            self.validate(d)
            d['_expected_memory']=record.get('remote',{}).get('mem_total_bytes')
            token=secrets.token_urlsafe(48)
            cfg=self.configuration(job,d,token)
            with self.connect(d) as client:
                if record.get('remote',{}).get('bootstrap_required'):
                    from .bootstrap import install
                    self.update(job,'running','Установка Python 3 и Docker на новом сервере')
                    try:install(client,job)
                    except ValueError as error:raise ProvisionError(str(error)) from None
                    ports=self.required_ports(d)
                    checked=self.remote(client,{'id':job,'action':'preflight','ports':ports})
                    if not all(check['passed'] for check in checked['checks']):
                        raise ProvisionError('После подготовки сервера предварительная проверка не пройдена')
                if d.get('cleanup_job'):
                    previous=self.cleanup_context(d)
                    self.update(job,'running','Очистка незавершённой предыдущей попытки')
                    self.remote(client,{'id':d['cleanup_job'],'action':'rollback'})
                    self.unregister(d['cleanup_job'],previous)
                    self.update(d['cleanup_job'],'rolled_back','Очистка предыдущей установки завершена')
                    checked=self.remote(client,{'id':job,'action':'preflight','ports':self.required_ports(d)})
                    if not all(check['passed'] for check in checked['checks']):
                        raise ProvisionError('После очистки сервер не прошёл повторную проверку')
                if d['protocol']=='hysteria2':
                    transferred=True
                    cfg['bundle']=self.upload(client,self.settings['hy2_bundle'],job,'.tar.gz',record['remote']['home'])
                if self.settings.get('base_image_bundle'):
                    present=self.remote(client,{'id':job,'action':'image-present','image':cfg['image']})
                    if not present['present']:
                        self.update(job,'running','Передача проверенного образа ноды')
                        transferred=True
                        cfg['image_bundle']=self.upload(client,self.settings['base_image_bundle'],job,'.image.tar.gz',record['remote']['home'])
                        cfg['image_bundle_sha256']=self.settings['base_image_bundle_sha256']
                self.update(job,'running','Запуск отдельного контейнера')
                installed=True
                result=self.remote(client,cfg)
                if not result['running']:raise ProvisionError('Контейнер завершился')
                if cfg.get('lab_network')=='bridge' and d['protocol']=='vless':d['_registration_address']=result['ip']
                if result.get('management_tls'):
                    d['_management_server_certificate']=result['management_tls']['certificate']
                    if d.get('_profile'):
                        from copy import deepcopy
                        d['_profile']['vpn']['management_tls']=deepcopy(result['management_tls'])
                if result.get('management_auth') and d.get('_profile'):
                    d['_profile']['vpn']['management_auth']=result['management_auth']
                registration=self.register(job,d,token);registered=True
                if result.get('management_tls'):registration['management_tls']=result['management_tls']
                if result.get('management_auth'):registration['management_auth']=result['management_auth']
                if d['protocol']=='vless':
                    self.update(job,'running','Настройка отдельного сборщика ресурсов')
                    self.remote(client,self.observer_configuration(job,d,token,registration))
                self.update(job,'running','Ожидание первых свежих CPU, RAM, диска и сетевых метрик')
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    if self.ready(job,d):break
                    time.sleep(1)
                else:raise ProvisionError('Нода не подтвердила готовность или не передала полные свежие метрики')
                if self.verify:
                    self.update(job,'running','Проверка настоящего VPN-трафика с сервера панели')
                    self.verify(job,d)
                if self.activate:self.activate(job,d)
                if getattr(self,'capture',None):self.capture(job,d,cfg,registration)
                self.update(job,'succeeded','Нода подключена; метрики и VPN-трафик проверены' if self.verify else 'Нода подключена; свежие метрики ресурсов получены и проверены')
        except Exception as exc:
            logging.getLogger('fleet').error('Provision job %s failed (%s): %s',job,type(exc).__name__,str(exc) if isinstance(exc,ProvisionError) else 'details withheld')
            if d.get('_transfer_accepted'):
                logging.getLogger('fleet').error('Accepted transfer %s retained for job reconciliation',job)
                try:self.update(job,'succeeded','Перенос завершён; подтверждение задачи восстановлено')
                except Exception:logging.getLogger('fleet').error('Transfer %s job confirmation remains pending',job)
                return
            rollback=True
            if installed:
                try:self.unregister(job,d)
                except Exception:rollback=False
            if (installed or transferred) and (rollback or not d.get('move_node')):
                try:
                    with self.connect(d) as client:self.remote(client,{'action':'rollback','id':job})
                except Exception:rollback=False
            reason=str(exc) if isinstance(exc,ProvisionError) else 'Внутренняя ошибка установки'
            cleaned=(installed or transferred) and rollback
            self.update(job,'rolled_back' if cleaned else 'failed',
                        'Установка не завершена; ресурсы этой попытки отозваны, данные сохранены' if cleaned else
                        'Установка не завершена; требуется проверить сервер и регистрацию ноды')
            self.update(job,'rolled_back' if cleaned else 'failed',reason)
        finally:
            with self.lock:self.running.discard(d.get('address') or d.get('host'))
            d.clear()
            lease = record.pop('_operation_lease', None)
            if lease is not None:os.close(lease)

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
            if self.settings.get('panel_ca_file'):
                files['panel-ca.pem']=Path(self.settings['panel_ca_file']).read_text()
                agent['panel_ca']='/state/panel-ca.pem';files['agent.json']=json.dumps(agent)
            files['hysteria.json']=json.dumps({'listen':':24443','tls':{'cert':'/state/cert.pem','key':'/state/key.pem'},
                'auth':{'type':'http','http':{'url':'http://127.0.0.1:18888/auth'}},
                'trafficStats':{'listen':'127.0.0.1:19999','secret':agent['stats_secret']}})
        else:
            t=self.settings['vless_template'];cfg['image']=t['image']
            cfg['publish']=[(d['vpn_port'],t['inbound_port'],'tcp'),(t['service_port'],62050,'tcp'),(t['api_port'],62051,'tcp')]
            files['client.pem']=t['client_certificate']
            cfg['env']={'SSL_CLIENT_CERT_FILE':'/state/client.pem','SSL_CERT_FILE':'/state/node-cert.pem',
                        'SSL_KEY_FILE':'/state/node-key.pem','INBOUNDS':t['inbound_tag'],'RIME_NODE_LISTEN':'0.0.0.0',
                        'RIME_NODE_RECOVERY_FILE':'/state/recovery-config.json'}
            cfg['export_identity']=True
            cfg['mounts']=[('cert.pem',t['certificate_path']),('key.pem',t['key_path'])]
            if t.get('runtime_dir'):
                for name in ['rest_service.py','node_autonomy.py']:
                    files[name]=Path(t['runtime_dir'],name).read_text()
                    cfg['mounts'].append((name,'/code/'+name))
            if d.get('_custom_tls') and t.get('runtime_dir'):
                cfg['env'].update(RIME_NODE_CERTIFICATE='/state/cert.pem',RIME_NODE_CERTIFICATE_KEY='/state/key.pem')
            if self.settings.get('control_source'):
                cfg['control_source']=self.settings['control_source']
        return cfg

    def observer_configuration(self,job,d,token,registration):
        from urllib.parse import quote
        node=registration['node'];template=self.settings['vless_template']
        cfg={'url':self.settings['panel_url'].rstrip('/')+'/api/fleet/telemetry/'+quote(node,safe=''),
             'token':token,'protocol':'xray','vpn_port':template['inbound_port'],'process_names':['xray'],
             'disk_path':'/observer','interval':5,
             'management_policy_dir':'/control-policy',
             'allow_loopback_http':bool(self.settings.get('lab_network'))}
        files={name:Path(__file__).with_name(name).read_text() for name in ('observer.py','connections.py','meter.py','spool.py')}
        if self.settings.get('panel_ca_file'):
            files['panel-ca.pem']=Path(self.settings['panel_ca_file']).read_text();cfg['ca_file']='/observer/panel-ca.pem'
        files['config.json']=json.dumps(cfg)
        return {'action':'observer','id':job,'image':template['image'],'files':files}
