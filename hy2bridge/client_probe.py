"""Client-side payload checks from a named vantage, independent of node agents."""
import argparse
import concurrent.futures
import copy
import json
import logging
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

LOG=logging.getLogger('rime.client_probe')


def xray_probe_binary(settings):
    """Use explicit probe settings, then the packaged compatibility client."""
    for key in ('client_probe_xray_binary', 'xray_binary'):
        if settings.get(key):
            return settings[key]
    packaged = '/opt/rime-probe/xray'
    return packaged if os.access(packaged, os.X_OK) else '/usr/local/bin/xray'


def exact(sock, size):
    result=b''
    while len(result)<size:
        part=sock.recv(size-len(result))
        if not part:raise OSError('Incomplete proxy response')
        result+=part
    return result


def probe(target, settings, port):
    if target.get('variants'):
        started=time.monotonic()
        for config in target['variants']:
            result=probe({**target,'config':config,'variants':[]},settings,port)
            if not result['passed']:return result
        result['latency_ms']=round((time.monotonic()-started)*1000,2)
        return result
    started=time.monotonic();stage='configuration';address=target.get('expected_ip','127.0.0.1')
    result={'checked_at':time.time(),'passed':False,'target_ip':address,'stage':stage}
    try:
        cfg=copy.deepcopy(target['config']);kind=cfg.pop('_kind','vless');hostname=cfg.pop('_hostname')
        address=target.get('resolved_ip') or socket.getaddrinfo(hostname,None,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
        result['target_ip']=address
        stage='route'
        if address not in settings['direct_targets']:raise ValueError('Target is not verified for direct routing')
        # Pin this resolution for the whole check, retaining the original TLS SNI.
        if kind=='hy2':
            cfg['server']=address+':'+cfg['server'].rsplit(':',1)[1]
            cfg['socks5']={'listen':'127.0.0.1:'+str(port)}
        else:
            cfg['outbounds'][0]['settings']['vnext'][0]['address']=address
            cfg['inbounds'][0]['port']=port
        binary=settings['hysteria_binary'] if kind=='hy2' else xray_probe_binary(settings)
        if not os.access(binary,os.X_OK):
            stage='configuration';raise ValueError('Client binary is unavailable')
        with tempfile.TemporaryDirectory(prefix='rime-probe-') as folder:
            path=Path(folder)/'config.json';path.write_text(json.dumps(cfg));path.chmod(0o600)
            with (Path(folder)/'client.log').open('w') as log:
                env=dict(os.environ)
                for name in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']:env.pop(name,None)
                env.update(NO_PROXY='*',no_proxy='*')
                proc=subprocess.Popen([binary,'client' if kind=='hy2' else 'run','-c',str(path)],stdout=log,stderr=log,env=env)
                try:
                    stage='client'
                    for _ in range(50):
                        if proc.poll() is not None:raise OSError('Client initialization failed')
                        try:
                            with socket.create_connection(('127.0.0.1',port),timeout=.2):pass
                            break
                        except OSError:time.sleep(.2)
                    else:raise TimeoutError('Proxy listener did not become ready')
                    stage='connect'
                    with socket.create_connection(('127.0.0.1',port),timeout=5) as sock:
                        sock.settimeout(8);sock.sendall(b'\x05\x01\x00')
                        if exact(sock,2)!=b'\x05\x00':raise OSError('SOCKS negotiation failed')
                        host=settings.get('probe_host','api.ipify.org').encode('ascii')
                        destination_port=settings.get('probe_port',443)
                        path=settings.get('probe_path','/?format=json')
                        if not 1<=len(host)<=253 or '\r' in path or '\n' in path or not path.startswith('/'):
                            raise ValueError('Invalid payload probe endpoint')
                        sock.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+destination_port.to_bytes(2,'big'))
                        reply=exact(sock,4)
                        if reply[1]!=0:raise OSError('VPN connection failed')
                        size={1:4,4:16}.get(reply[3]);size=exact(sock,1)[0] if size is None else size;exact(sock,size+2)
                        stage='payload'
                        context=ssl.create_default_context(cafile=settings.get('probe_ca_file'))
                        with context.wrap_socket(sock,server_hostname=host.decode()) as tls:
                            tls.sendall(('GET '+path+' HTTP/1.0\r\nHost: '+host.decode()+'\r\nConnection: close\r\n\r\n').encode());raw=b''
                            while part:=tls.recv(4096):
                                raw+=part
                                if len(raw)>65536:raise OSError('Probe response is too large')
                        headers,body=raw.split(b'\r\n\r\n',1)
                        expected_egress = target.get('expected_egress_ip', address)
                        if b' 200 ' not in headers.split(b'\r\n',1)[0] or json.loads(body).get('ip')!=expected_egress:
                            raise OSError('Unexpected VPN egress response')
                        result['passed']=True
                finally:
                    if proc.poll() is None:proc.terminate()
                    try:proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
    except Exception as error:
        # Client logs and credentials never leave this host.
        result['error']=type(error).__name__
    result.update(stage=stage,latency_ms=round((time.monotonic()-started)*1000,2),checked_at=time.time())
    return result


def publish(settings, target, result):
    parsed=urllib.parse.urlsplit(settings['panel_url'])
    if parsed.scheme!='https' or parsed.username or parsed.password:raise ValueError('Verified HTTPS is required')
    addresses={r[4][0] for r in socket.getaddrinfo(parsed.hostname,None,socket.AF_INET,socket.SOCK_STREAM)}
    if not addresses or not addresses<=set(settings['direct_targets']):raise ValueError('Panel route is not verified as direct')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    url=settings['panel_url'].rstrip('/')+'/api/fleet/client-probes/'+urllib.parse.quote(settings['id'],safe='')+'/'+urllib.parse.quote(target['node'],safe='')
    req=urllib.request.Request(url,data=json.dumps(result).encode(),headers={'Authorization':'Bearer '+settings['token'],'Content-Type':'application/json'})
    with opener.open(req,timeout=5) as response:
        if json.loads(response.read(4096)).get('received') is not True:raise ValueError('Probe was not acknowledged')


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--once',action='store_true');p.add_argument('--check-only',action='store_true');args=p.parse_args()
    os.umask(0o077);settings=json.loads(Path(args.config).read_text());stop=threading.Event();previous={}
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
    def run(pair):
        i,target=pair;value=probe(target,settings,21000+i)
        try:
            if not args.check_only:publish(settings,target,value)
            state='available' if value['passed'] else value['stage']
        except Exception as error:state='delivery_'+type(error).__name__
        if previous.get(target['node'])!=state:LOG.info('%s: %s',target['node'],state)
        previous[target['node']]=state
        return {'node':target['node'],**value,'delivery':None if args.check_only else not state.startswith('delivery_')}
    while not stop.is_set():
        started=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:values=list(pool.map(run,enumerate(settings['targets'])))
        if args.once:
            print(json.dumps(values));return 0 if all(v['passed'] and (args.check_only or v['delivery']) for v in values) else 1
        stop.wait(max(1,settings.get('interval',60)-(time.monotonic()-started)))
    return 0


if __name__=='__main__':
    logging.basicConfig(level=logging.INFO);raise SystemExit(main())
