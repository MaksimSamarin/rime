"""Exercise the UI update API, Docker replacement and rollback in an isolated lab."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


SERVER = r'''
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import hashlib,json,urllib.parse
root=Path('/fixtures');selected='0.9.1'
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  global selected
  path=urllib.parse.urlsplit(self.path).path
  if path.startswith('/select/'):
   selected=path.rsplit('/',1)[-1];body=b'{}';kind='application/json'
  elif path.startswith('/download/'):
   parts=path.split('/');version=parts[2].removeprefix('v');name=parts[3]
   file=root/version/name
   if not file.is_file():self.send_error(404);return
   self.send_response(200);self.send_header('Content-Length',str(file.stat().st_size));self.end_headers()
   with file.open('rb') as source:
    while data:=source.read(1024*1024):self.wfile.write(data)
   return
  else:
   version=path.rsplit('/',1)[-1].removeprefix('v') if '/tags/' in path else selected
   metadata=json.loads((root/version/'metadata.json').read_text())
   body=json.dumps([metadata] if '/tags/' not in path else metadata).encode();kind='application/json'
  self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
ThreadingHTTPServer(('127.0.0.1',18088),Handler).serve_forever()
'''

PANEL = r'''
import os,sqlite3,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/code')
if Path('/code/update-lab-failure').exists():
 with sqlite3.connect('/var/lib/marzban/db.sqlite3') as db:db.execute("UPDATE users SET note='candidate changed data'")
 time.sleep(300)
 raise SystemExit(1)
root=Path('/var/lib/marzban');root.mkdir(exist_ok=True)
config=root/'xray.json'
if not config.exists():config.write_text('{"inbounds":[{"tag":"LAB_VLESS","listen":"127.0.0.1","port":24443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none"}}],"outbounds":[{"protocol":"freedom","tag":"DIRECT"}]}')
subprocess.run([sys.executable,'-m','alembic','upgrade','head'],check=True)
from main import app
from app.routers.updates import service
from update_runtime.releases import ReleaseCatalog
import json
service.catalog=ReleaseCatalog('http://127.0.0.1:18088',allow_local=True,public_keys=json.loads(Path('/fixtures/release-public-keys.json').read_text()))
import uvicorn
uvicorn.run(app,host='0.0.0.0',port=8000,log_level='warning')
'''


def docker(*args, timeout=180):
    process = subprocess.run(['docker', *args], capture_output=True, text=True, encoding='utf-8', timeout=timeout)
    if process.returncode:
        raise RuntimeError('Docker lab command failed: ' + ' '.join(args[:3]) + '\n' + process.stderr[-2000:])
    return process.stdout.strip()


def install_default_worker(controller,panel,work,configuration,historical=None):
    """Run the real installer; adapt only host discovery/systemd in the fixture.

    The discovery adapter returns the actual Docker container's full ID, as
    `docker compose ps -q` does. Inspect/exec use the real Docker daemon. Volume
    host paths are translated to this closed controller's equivalent mounts.
    """
    shim=r'''#!/usr/bin/env python3
import http.client,json,socket,struct,sys,urllib.parse
from pathlib import Path
settings=json.loads(Path('/fixtures/installer-settings.json').read_text())
class Connection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.connect('/var/run/docker.sock')
def call(method,path,value=None,raw=False):
 c=Connection('localhost');c.request(method,path,body=json.dumps(value).encode() if value is not None else b'',headers={'Content-Type':'application/json'})
 response=c.getresponse();body=response.read();assert response.status<300,(path,response.status);c.close()
 return body if raw else json.loads(body or b'null')
args=sys.argv[1:]
if args[:4]==['compose','ps','-q','rime']:
 print(call('GET','/containers/'+settings['panel']+'/json')['Id'])
elif args[0]=='inspect':
 value=call('GET','/containers/'+urllib.parse.quote(args[1],safe='')+'/json')
 for mount in value['Mounts']:
  if mount['Destination']=='/var/lib/marzban':mount['Source']='/lab/data'
 print(json.dumps([value]))
elif args[0]=='exec':
 ident=call('POST','/containers/'+args[1]+'/exec',{'AttachStdout':True,'AttachStderr':True,'Cmd':args[2:]})['Id']
 body=call('POST','/exec/'+ident+'/start',{'Detach':False,'Tty':False},raw=True)
 while body:
  size=struct.unpack('>I',body[4:8])[0];sys.stdout.buffer.write(body[8:8+size]);body=body[8+size:]
 state=call('GET','/exec/'+ident+'/json');sys.exit(state['ExitCode'])
else:raise SystemExit('Unexpected fixture Docker command')
'''
    (work/'docker-installer-adapter.py').write_bytes(shim.encode())
    (work/'installer-settings.json').write_text(json.dumps({'panel':panel}))
    if historical:shutil.copy2(historical,work/'historical-installer.py')
    prepare=r'''
from pathlib import Path
import shutil
bin=Path('/tmp/installer-bin');bin.mkdir(exist_ok=True)
shutil.copy2('/fixtures/docker-installer-adapter.py',bin/'docker');(bin/'docker').chmod(0o755)
(bin/'systemctl').write_text('#!/bin/sh\nexit 0\n');(bin/'systemctl').chmod(0o755)
if Path('/fixtures/historical-installer.py').exists():
 root=Path('/tmp/installer-tree');(root/'scripts').mkdir(parents=True,exist_ok=True)
 shutil.copy2('/fixtures/historical-installer.py',root/'scripts/install_updater.py')
 shutil.copytree('/code/update_runtime',root/'update_runtime',dirs_exist_ok=True)
'''
    docker('exec',controller,'python','-c',prepare)
    source='/tmp/installer-tree/scripts/install_updater.py' if historical else '/code/scripts/install_updater.py'
    docker('exec','-e','PATH=/tmp/installer-bin:/usr/local/bin:/usr/bin:/bin',controller,
        'python',source,'--install-directory','/lab/installed','--state-directory','/lab/state')
    # Only the synthetic release origin/key and tight test timeout differ from
    # the actual installer's result. Its saved container identity is untouched.
    changes={key:value for key,value in configuration.items() if key not in
             {'container','data_directory','database','state_directory','panel_uid','panel_gid','current_version'}}
    script="from pathlib import Path;import json;p=Path('/lab/installed/config.json');c=json.loads(p.read_text());c.update("+repr(changes)+");p.write_text(json.dumps(c))"
    docker('exec',controller,'python','-c',script)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--keep', action='store_true')
    parser.add_argument('--installer-source',help='An optional historical installer for the closed regression replay')
    args = parser.parse_args()
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    nonce = uuid.uuid4().hex[:10]
    prefix = 'rime-update-lab-' + nonce
    label = 'rime.update.lab=' + nonce
    controller = prefix + '-controller'
    panel = prefix + '-panel'
    network = prefix + '-network'
    volumes = [prefix + '-data', prefix + '-state']
    images = []
    results = []
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    base = 'http://127.0.0.1:' + str(port)

    def check(name, condition):
        results.append({'name': name, 'passed': bool(condition)})
        print(('PASS ' if condition else 'FAIL ') + name, flush=True)
        if not condition:
            raise AssertionError(name)

    def request(path, payload=None, token=None,method=None):
        program = r'''
import base64,json,urllib.request,urllib.parse,urllib.error
headers={};body=None
if PAYLOAD is not None:
 if PATH=='/api/admin/token':body=urllib.parse.urlencode(PAYLOAD).encode();headers['Content-Type']='application/x-www-form-urlencoded'
 else:body=json.dumps(PAYLOAD).encode();headers['Content-Type']='application/json'
if TOKEN:headers['Authorization']='Bearer '+TOKEN
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:response=opener.open(urllib.request.Request('http://127.0.0.1:8000'+PATH,data=body,headers=headers,method=METHOD),timeout=10)
except urllib.error.HTTPError as error:response=error
with response:
 print(json.dumps({'status':response.status,'content_type':response.headers.get('Content-Type',''),'body':base64.b64encode(response.read()).decode()}))
'''
        source = 'PATH=' + repr(path) + '\nPAYLOAD=' + repr(payload) + '\nTOKEN=' + repr(token) + '\nMETHOD='+repr(method)+'\n' + program
        process = subprocess.run(['docker', 'exec', '-i', controller, 'python', '-'], input=source,
                                 capture_output=True, text=True, encoding='utf-8', timeout=20)
        if process.returncode:
            raise OSError('The isolated API is unavailable')
        import base64
        value = json.loads(process.stdout)
        raw = base64.b64decode(value['body'])
        if value['status'] >= 400:
            raise urllib.error.HTTPError(base + path, value['status'], 'Lab API response', None, None)
        return json.loads(raw) if 'application/json' in value['content_type'] else raw

    def login():
        return request('/api/admin/token', {'username': 'fixture_admin', 'password': 'Synthetic-Update-Password-031'})['access_token']

    def wait_for_login():
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                return login()
            except (OSError, ValueError):
                time.sleep(.5)
        raise RuntimeError('The isolated panel did not start')

    def select(version):
        script = "import urllib.request;urllib.request.urlopen('http://127.0.0.1:18088/select/" + version + "').read()"
        docker('exec', controller, 'python', '-c', script)

    try:
        (work / 'server.py').write_text(SERVER)
        (work / 'start_panel.py').write_text(PANEL)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        import base64
        fixture_key=Ed25519PrivateKey.generate()
        public=fixture_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        public_id=hashlib.sha256(public).hexdigest()[:16]
        public_keys={public_id:base64.b64encode(public).decode()}
        (work/'release-public-keys.json').write_text(json.dumps(public_keys))
        for version in ['0.9.0', '0.9.1', '0.9.2', '0.9.3']:
            directory = work / version
            directory.mkdir(exist_ok=True)
            replace = "from pathlib import Path;p=Path('/code/app/__init__.py');s=p.read_text();import re;p.write_text(re.sub(r'__version__ = .*', '__version__ = '+repr(" + repr(version) + "),s,count=1))"
            recipe = 'FROM ' + args.image + '\nRUN ' + json.dumps(['python', '-c', replace]) + '\n'
            recipe += 'LABEL org.opencontainers.image.source="https://github.com/MaksimSamarin/rime"\n'
            recipe += 'LABEL org.opencontainers.image.version="' + version + '"\n'
            recipe += 'LABEL org.opencontainers.image.revision="' + 'a' * 40 + '"\n'
            recipe += 'CMD ["python","/fixtures/start_panel.py"]\n'
            if version == '0.9.3':
                recipe += 'RUN ' + json.dumps(['python', '-c', "from pathlib import Path;Path('/code/update-lab-failure').touch()"]) + '\n'
            (directory / 'Dockerfile').write_text(recipe)
            image = prefix + ':' + version
            docker('build', '--network', 'none', '-t', image, str(directory))
            images.append(image)
            identity = json.loads(docker('image', 'inspect', image))[0]['Id']
            if version != '0.9.0':
                archive = directory / 'rime-linux-amd64.tar.gz'
                saved = subprocess.Popen(['docker', 'image', 'save', image], stdout=subprocess.PIPE)
                import gzip
                with gzip.open(archive, 'wb', compresslevel=1) as target:
                    shutil.copyfileobj(saved.stdout, target)
                saved.stdout.close()
                if saved.wait() != 0:
                    raise RuntimeError('Image export failed')
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                with tarfile.open(archive) as package:
                    saved_metadata = json.load(package.extractfile('manifest.json'))
                    saved_config = package.extractfile(saved_metadata[0]['Config']).read()
                    portable_identity = 'sha256:' + hashlib.sha256(saved_config).hexdigest()
                manifest = {'schema': 1, 'repository': 'MaksimSamarin/rime', 'version': version, 'revision': 'a' * 40,
                            'artifacts': {'linux/amd64': {'name': archive.name, 'size': archive.stat().st_size,
                                                        'sha256': digest, 'image_id': portable_identity}}}
                raw = json.dumps(manifest).encode()
                (directory / 'rime-release.json').write_bytes(raw)
                signature={'schema':1,'algorithm':'Ed25519','key_id':public_id,'signature':base64.b64encode(fixture_key.sign(raw)).decode()}
                (directory/'rime-release.sig').write_text(json.dumps(signature))
                origin = 'http://127.0.0.1:18088/download/v' + version + '/'
                metadata = {'id': int(version.rsplit('.', 1)[1]), 'tag_name': 'v' + version, 'body': 'Synthetic release',
                            'assets': [{'name': 'rime-release.json', 'browser_download_url': origin + 'rime-release.json',
                                        'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()},
                                       {'name':'rime-release.sig','browser_download_url':origin+'rime-release.sig'},
                                       {'name': archive.name, 'size': archive.stat().st_size, 'browser_download_url': origin + archive.name}]}
                (directory / 'metadata.json').write_text(json.dumps(metadata))
        config = {'container': panel, 'data_directory': '/lab/data', 'database': '/lab/data/db.sqlite3',
                  'state_directory': '/lab/state', 'current_version': '0.9.0', 'api_root': 'http://127.0.0.1:18088',
                  'lab': True, 'lab_release_public_keys':public_keys,'minimum_free_bytes':64*1024**2,'minimum_free_percent':0,'lab_image_prefix': prefix, 'health_timeout': 8, 'panel_uid': 0, 'panel_gid': 0, 'image_alias': prefix + ':current'}
        (work / 'config.json').write_text(json.dumps(config))
        docker('network', 'create', '--internal', '--label', label, network)
        for volume in volumes:
            docker('volume', 'create', '--label', label, volume)
        (work/'qualification-image.json').write_text(json.dumps({'reference':args.image,'image_id':json.loads(docker('image','inspect',args.image))[0]['Id'],'closed_network':True,'compose_discovery':'fixture adapter returns actual Docker ID','systemd':'unit files installed, systemctl activation adapted in disposable controller','docker_replacement':'real'},indent=2))
        fixture_mount = 'type=bind,src=' + str(work) + ',dst=/fixtures,readonly'
        docker('run', '-d', '--name', controller, '--label', label, '--network', network,
               '--mount', 'type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
               '--mount', 'type=volume,src=' + volumes[0] + ',dst=/lab/data',
               '--mount', 'type=volume,src=' + volumes[1] + ',dst=/lab/state',
               '--mount', fixture_mount, images[0], 'python', '/fixtures/server.py')
        docker('run', '-d', '--name', panel, '--label', label, '--network', 'container:' + controller,
               '--mount', 'type=volume,src=' + volumes[0] + ',dst=/var/lib/marzban', '--mount', fixture_mount,
               '-e', 'SQLALCHEMY_DATABASE_URL=sqlite:////var/lib/marzban/db.sqlite3',
               '-e', 'XRAY_JSON=/var/lib/marzban/xray.json', '-e', 'UVICORN_PORT=8000',
               '-e', 'SUDO_USERNAME=fixture_admin', '-e', 'SUDO_PASSWORD=Synthetic-Update-Password-031',
               images[0])
        token = wait_for_login()
        install_default_worker(controller,panel,work,config,args.installer_source)
        check('default installer persists canonical panel name rather than compose ID',json.loads(docker('exec',controller,'cat','/lab/installed/config.json'))['container']==panel)
        try:
            request('/api/system/updates')
            denied = False
        except urllib.error.HTTPError as error:
            denied = error.code == 401
        check('unauthenticated update access is rejected', denied)
        user = request('/api/user', {'username': 'demo_existing', 'proxies': {'vless': {}},
                                    'inbounds': {'vless': ['LAB_VLESS']}, 'note': 'Preserved fixture'}, token)
        original = {key: user[key] for key in ['username', 'proxies', 'subscription_url', 'note']}
        status = request('/api/system/updates/check', {}, token)
        check('published update is offered through the normal API', status['available'] and status['latest']['version'] == '0.9.1')
        original_admin_token = token
        request('/api/system/updates', {'version': '0.9.1'}, token)
        try:
            request('/api/system/updates', {'version': '0.9.1'}, token)
            denied = False
        except urllib.error.HTTPError as error:
            denied = error.code == 409
        check('concurrent update requests are rejected', denied)
        docker('exec', '--workdir', '/lab/installed', controller, 'python', '-m', 'update_runtime.worker', '--config', '/lab/installed/config.json', timeout=300)
        token = wait_for_login()
        check('administrator session survived the panel update', request('/api/system/updates', token=original_admin_token)['current_version'] == '0.9.1')
        status = request('/api/system/updates', token=token)
        (work / 'success-status.json').write_text(json.dumps(status, indent=2))
        check('real container update completed', status['current_version'] == '0.9.1' and status['job']['phase'] == 'succeeded')
        after = request('/api/user/demo_existing', token=token)
        fields = ['username', 'proxies', 'note']
        check('UUID and account settings survived update', {key: after[key] for key in fields} == {key: original[key] for key in fields})
        path = urllib.parse.urlsplit(original['subscription_url']).path
        check('old signed subscription still responds', bool(request(path)))
        select('0.9.2')
        request('/api/system/updates/check',{},token)
        request('/api/system/updates',{'version':'0.9.2'},token)
        docker('exec','--workdir','/lab/installed',controller,'python','-m','update_runtime.worker','--config','/lab/installed/config.json',timeout=300)
        token=wait_for_login()
        status=request('/api/system/updates',token=token)
        check('second consecutive update through the default installer succeeds',status['current_version']=='0.9.2' and status['job']['phase']=='succeeded')
        manual_parent=status['job']['id']
        preserved_note='Created after the second successful update'
        request('/api/user/demo_existing',{'note':preserved_note},token,method='PUT')
        original['note']=preserved_note
        select('0.9.3')
        request('/api/system/updates/check', {}, token)
        request('/api/system/updates', {'version': '0.9.3'}, token)
        docker('exec', '--workdir', '/lab/installed', controller, 'python', '-m', 'update_runtime.worker', '--config', '/lab/installed/config.json', timeout=300)
        token = wait_for_login()
        status = request('/api/system/updates', token=token)
        (work / 'rollback-status.json').write_text(json.dumps(status, indent=2))
        check('failed candidate rolled back to the previous image', status['current_version'] == '0.9.2' and status['job']['phase'] == 'rolled_back')
        restored = request('/api/user/demo_existing', token=token)
        check('rollback restored data changed by the failed candidate', {key: restored[key] for key in fields} == {key: original[key] for key in fields})
        check('old signed subscription responds after rollback', bool(request(path)))
        docker('exec','--workdir','/lab/installed',controller,'python','-m','update_runtime.worker','--config','/lab/installed/config.json',
               '--rollback',manual_parent,'--confirm','rollback',timeout=300)
        token=wait_for_login();status=request('/api/system/updates',token=token)
        check('explicit rollback after succeeded installs the previous version',status['current_version']=='0.9.1' and status['job']['phase']=='succeeded')
        restored=request('/api/user/demo_existing',token=token)
        check('manual rollback preserves data created after the successful update',{key:restored[key] for key in fields}=={key:original[key] for key in fields})
        check('old signed subscription responds after manual rollback',bool(request(path)))
        check('lab has no external route', json.loads(docker('network', 'inspect', network))[0]['Internal'])
        (work / 'result.json').write_text(json.dumps({'passed': True, 'checks': results}, indent=2))
    finally:
        log_directory = work / 'logs'
        log_directory.mkdir(exist_ok=True)
        for identity in docker('ps', '-aq', '--filter', 'label=' + label).splitlines():
            log = subprocess.run(['docker', 'logs', '--tail', '200', identity], capture_output=True, text=True, encoding='utf-8')
            (log_directory / (identity[:12] + '.log')).write_text(log.stdout + log.stderr, encoding='utf-8')
        if not args.keep:
            containers = docker('ps', '-aq', '--filter', 'label=' + label).splitlines()
            if containers:
                docker('rm', '-f', *containers)
            for volume in volumes:
                subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
            subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
        (work / 'checks.json').write_text(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
