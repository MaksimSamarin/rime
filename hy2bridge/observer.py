"""Read-only Linux resource observer. Standard library, no VPN configuration access."""
import argparse
import json
import logging
import os
from pathlib import Path
import signal
import ssl
import threading
import time
import urllib.parse
import urllib.request

LOG=logging.getLogger('rime.observer')
try:from .connections import tcp_summary,hy2_summary
except ImportError:from connections import tcp_summary,hy2_summary


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


class Resources:
    def __init__(self, config, proc='/proc'):
        self.config=config;self.proc=Path(proc);self.previous=None
        self.detail_key=(config.get('token') or os.urandom(32).hex()).encode()
        self.stats=None
        if config.get('stats_url'):
            url=urllib.parse.urlsplit(config['stats_url'])
            if url.scheme not in ('http','https') or url.hostname not in ('127.0.0.1','localhost','::1') or url.username or url.password or url.path not in ('','/') or url.query or url.fragment:
                raise ValueError('Hysteria statistics must use a loopback endpoint')
            if len(config.get('stats_secret',''))<16:raise ValueError('A statistics API secret is required')
            self.stats=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def connections(self):
        if self.stats is None:return {'online_users':None,'online_connections':None,'connection_metric_state':'not_configured'}
        try:
            request=urllib.request.Request(self.config['stats_url'].rstrip('/')+'/online',headers={'Authorization':self.config['stats_secret']})
            with self.stats.open(request,timeout=2) as response:
                raw=response.read(1024*1024+1)
                if len(raw)>1024*1024:raise ValueError('Statistics response is too large')
                data=json.loads(raw)
            if not isinstance(data,dict) or not all(type(v) is int and v>=0 for v in data.values()):raise ValueError('Invalid connection statistics')
            return {'online_users':sum(v>0 for v in data.values()),'online_connections':sum(data.values()),'connection_metric_state':'available','connection_details':hy2_summary(data,self.detail_key)}
        except Exception:
            return {'online_users':None,'online_connections':None,'connection_metric_state':'unavailable'}

    def sample(self):
        values=[int(x) for x in (self.proc/'stat').read_text().splitlines()[0].split()[1:]]
        total=sum(values[:8]);idle=values[3]+values[4];cpu=None
        if self.previous:
            delta=total-self.previous[0]
            if delta>0:cpu=max(0,min(100,round(100*(1-(idle-self.previous[1])/delta),2)))
        self.previous=(total,idle)
        memory={line.split(':')[0]:int(line.split()[1])*1024 for line in (self.proc/'meminfo').read_text().splitlines()}
        fs=os.statvfs(self.config.get('disk_path','/'))
        port=int(self.config['vpn_port']);protocol=self.config['protocol']
        listening=False;connections=0;socket_rows=[]
        for filename in (('tcp','tcp6') if protocol=='xray' else ('udp','udp6')):
            path=self.proc/'net'/filename
            if not path.exists():continue
            for line in path.read_text().splitlines()[1:]:
                fields=line.split()
                if int(fields[1].rsplit(':',1)[1],16)!=port:continue
                if fields[3]==('0A' if protocol=='xray' else '07'):listening=True
                if protocol=='xray' and fields[3]=='01':connections+=1;socket_rows.append((6 if filename.endswith('6') else 4,fields))
        running=False;processes=[]
        for path in self.proc.iterdir():
            if not path.name.isdigit():continue
            try:
                name=(path/'comm').read_text().strip()
                state=(path/'stat').read_text().rsplit(')',1)[1].split()[0]
                if state!='Z' and any(name.startswith(n) for n in self.config['process_names']):running=True;processes.append(path)
            except (OSError,IndexError):continue
        network=self.proc/'net/dev';rx=tx=None
        if network.exists():
            values=[line.split(':',1)[1].split() for line in network.read_text().splitlines()[2:] if ':' in line]
            rx=sum(int(row[0]) for row in values);tx=sum(int(row[8]) for row in values)
        result={'cpu_percent':cpu,'cpu_load1':os.getloadavg()[0],
            'core_version':self.config.get('core_version','unknown'),
            'mem_total_bytes':memory['MemTotal'],'mem_available_bytes':memory.get('MemAvailable',memory.get('MemFree',0)),
            'swap_total_bytes':memory.get('SwapTotal',0),'swap_free_bytes':memory.get('SwapFree',0),
            'disk_total_bytes':fs.f_blocks*fs.f_frsize,'disk_free_bytes':fs.f_bavail*fs.f_frsize,
            'uptime_seconds':int(float((self.proc/'uptime').read_text().split()[0])),
            'net_rx_bytes':rx,'net_tx_bytes':tx,
            'online_connections':connections if protocol=='xray' else None,
            'service_healthy':bool(running and listening)}
        if protocol=='hysteria2':result.update(self.connections())
        else:
            result['connection_details']=tcp_summary(socket_rows,processes,self.detail_key,port)
            result['online_connections']=result['connection_details']['total']
            result['connection_metric_state']='available'
        return result


class Sender:
    def __init__(self,config):
        self.url=config['url'];self.token=config['token']
        parsed=urllib.parse.urlsplit(self.url)
        local_test=bool(config.get('allow_loopback_http') and parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost','::1'))
        if (parsed.scheme!='https' and not local_test) or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Observer requires a verified HTTPS telemetry endpoint')
        if not parsed.path.startswith('/api/fleet/telemetry/') or len(self.token)<32:
            raise ValueError('Invalid telemetry endpoint or token')
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=config.get('ca_file'))))

    def send(self,data):
        request=urllib.request.Request(self.url,data=json.dumps(data).encode(),
            headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        with self.opener.open(request,timeout=5) as response:
            result=json.loads(response.read(4096))
        if result.get('received') is not True:raise ValueError('Telemetry was not acknowledged')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--once',action='store_true')
    args=parser.parse_args();config=json.loads(Path(args.config).read_text())
    logging.basicConfig(level=logging.INFO,format='%(levelname)s %(message)s')
    sampler=Resources(config);sender=Sender(config);stop=threading.Event();failed=False;meter=None;meter_failed=False
    if config.get('meter'):
        try:from .meter import MeterAgent
        except ImportError:from meter import MeterAgent
        meter=MeterAgent(config)
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
    while not stop.is_set():
        try:
            sender.send(sampler.sample())
            if failed:LOG.info('Resource telemetry recovered')
            failed=False
        except Exception as error:
            if not failed:LOG.warning('Resource telemetry unavailable (%s)',type(error).__name__)
            failed=True
            if args.once:raise SystemExit(1)
        if meter:
            try:
                meter.cycle()
                if meter_failed:LOG.info('VPN metering delivery recovered')
                meter_failed=False
            except Exception as error:
                if not meter_failed:LOG.warning('VPN metering delivery unavailable (%s)',type(error).__name__)
                meter_failed=True
        if args.once:
            if meter_failed:raise SystemExit(1)
            break
        stop.wait(max(5,min(20,int(config.get('interval',10)))))


if __name__=='__main__':main()
