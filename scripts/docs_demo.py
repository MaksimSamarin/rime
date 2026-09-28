"""Loopback-only, read-only API fixtures for screenshots of the real Rime UI.

Uses no database, environment credentials, VPN processes or outbound requests.
All names, addresses, counters and event histories below are synthetic.
"""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import mimetypes
from pathlib import Path
import time
from urllib.parse import parse_qs, unquote, urlsplit

WEB = Path(__file__).resolve().parents[1] / 'hy2bridge' / 'web'
GIB = 1024 ** 3
NAMES = ['demo_alex', 'demo_anna', 'demo_daria', 'demo_ivan', 'demo_kate', 'demo_leo', 'demo_maria', 'demo_max']
SERVERS = [('eu-west', 'Amsterdam', 'xray'), ('eu-north', 'Helsinki', 'hysteria2'), ('eu-central', 'Frankfurt', 'hysteria2')]


def users(now):
    return [{'username':name,'status':'disabled' if i==6 else 'limited' if i==7 else 'active',
             'tags':[['team'],['family'],['trial']][i%3], 'nodes':None if i%3 else ['eu-west','eu-north'],
             'used_traffic':(12+i*6.25)*GIB,'data_limit':(12+i*6.25)*GIB if i==7 else (60+i*20)*GIB,
             'expire':now+(i+7)*86400,'note':'Демонстрационная учётная запись',
             'subscription_url':'https://subscriptions.example.invalid/demo/'+name}
            for i,name in enumerate(NAMES)]


def events(now):
    return [{'id':str(i+1),'node':node,'code':code,'message':message,'severity':'warning',
             'first_at':now-age,'last_at':now-10,'occurrences':count,'resolved_at':None if i<2 else now-600,
             'action':{'acknowledged':True,'actor':'demo','updated_at':now-180,'note':'Проверяется расчётный период.'} if i==0 else None}
            for i,(node,code,message,age,count) in enumerate([
                ('eu-central','node_quota_80','Использовано более 80% квоты ноды',3600,4),
                ('eu-north','traffic_failed','Контрольная передача данных требует проверки',900,2),
                ('eu-west','heartbeat_stale','Связь с нодой восстановлена',7200,1)])]


def quota(node,now,percent):
    return {'node':node,'enabled':True,'limit_bytes':2*10**12,'used_bytes':int(percent/100*2*10**12),
            'remaining_bytes':int((100-percent)/100*2*10**12),'percent':percent,'stage':'warning' if percent>=80 else 'normal',
            'blocked':False,'transition_pending':False,'direction':'total','period':'monthly',
            'action':'warn','period_start':now-20*86400,'next_reset':now+10*86400}


def nodes(now):
    result=[]
    for i,(node,name,protocol) in enumerate(SERVERS):
        metrics={'cpu_percent':[18,31,46][i],'cpu_load1':[.38,.64,1.1][i],
                 'mem_total_bytes':4*GIB,'mem_available_bytes':[2.65,2.1,1.75][i]*GIB,
                 'disk_total_bytes':80*GIB,'disk_free_bytes':[52,41,23][i]*GIB,
                 'online_connections':[28,17,12][i],'online_users':[None,12,9][i],
                 'service_healthy':True,'traffic_healthy':i!=1,'traffic_checked_at':now-90,
                 'core_version':'demo','accounting_durable':protocol=='hysteria2','net_rx_bytes':28*GIB,'net_tx_bytes':110*GIB}
        result.append({'id':node,'name':name,'address':node+'.example.invalid','protocol':protocol,
                       'state':'degraded' if i==1 else 'healthy','seen_at':now-4-i,'age_seconds':4+i,
                       'enabled':True,'metrics':metrics,'quota':quota(node,now,[34,52,83][i]),'status_source':'demo'})
    result.append({'id':'xray:local','name':'Сервер панели','address':'panel.example.invalid','role':'panel','protocol':'xray',
                   'state':'healthy','seen_at':now-2,'age_seconds':2,'enabled':True,'status_source':'demo',
                   'metrics':{'cpu_percent':7,'cpu_load1':.14,'mem_total_bytes':4*GIB,'mem_available_bytes':3.1*GIB,
                              'disk_total_bytes':60*GIB,'disk_free_bytes':44*GIB,'service_healthy':True,'core_version':'demo'},
                   'panel':{'version':'0.2.0-rc6','uptime_seconds':172800,'host_uptime_seconds':864000,
                            'process_memory_bytes':140*1024**2,'hostname':'demo-panel'},'quota':{'enabled':False}})
    return result


def traffic(now,query):
    members=users(now)
    if query.get('tag'):members=[u for u in members if query['tag'][0] in u['tags']]
    if query.get('username'):members=[u for u in members if u['username']==query['username'][0]]
    rows=[];start_hour=int(now)//86400*24-6*24;end_hour=int(now)//3600
    lower=datetime.fromisoformat(query['start'][0].replace('Z','+00:00')).timestamp() if query.get('start') else 0
    upper=datetime.fromisoformat(query['end'][0].replace('Z','+00:00')).timestamp() if query.get('end') else now+3600
    for h in range(end_hour-start_hour+1):
        at=(start_hour+h)*3600
        if not lower<=at<upper:continue
        stamp=datetime.fromtimestamp(at,timezone.utc).strftime('%Y-%m-%d %H:00:00')
        for i,u in enumerate(members):
            for j,(node,_,protocol) in enumerate(SERVERS):
                protocol='xray' if protocol=='xray' else 'hysteria2'
                if query.get('node') and node!=query['node'][0]:continue
                if query.get('protocol') and protocol!=query['protocol'][0]:continue
                value=int((18+7*(1+math.sin(h*.23+i))+(h%24)/2+i*2+j*3)*1024**2)
                rows.append({'hour':stamp,'node':node,'username':u['username'],'protocol':protocol,
                             'tx':int(value*.18) if protocol=='hysteria2' else None,
                             'rx':value-int(value*.18) if protocol=='hysteria2' else None,'total':value})
    series={};totals={'hysteria2':0,'xray':0};by_user={}
    for row in rows:
        series.setdefault(row['hour'],{'hour':row['hour'],'hysteria2':0,'xray':0})[row['protocol']]+=row['total']
        totals[row['protocol']]+=row['total']
        by_user.setdefault(row['username'],{'username':row['username'],'hysteria2':0,'xray':0})[row['protocol']]+=row['total']
    return {'total':sum(totals.values()),'totals':totals,'series':list(series.values()),'rows':rows,
            'users':sorted(by_user.values(),key=lambda u:-u['hysteria2']-u['xray']),
            'hy2_first_sample_hour':next(iter(series),None),'hy2_upload_bytes':sum(r['tx'] or 0 for r in rows),
            'hy2_download_bytes':sum(r['rx'] or 0 for r in rows),'gaps':[]}


def history(now,selected):
    rows=[];minute=int(now)//60*60
    for n in selected:
        for i in range(1440):
            at=minute-(1439-i)*60;m=dict(n['metrics'])
            m.update(cpu_load1=round(.35+.12*math.sin(i*.027),2),cpu_percent=round(20+12*math.sin(i*.035),1),
                     mem_available_bytes=int((2.3+.15*math.cos(i*.03))*GIB),online_connections=round(18+7*math.sin(i*.024)))
            rows.append({'node':n['id'],'minute':at,'state':'degraded' if n['id']=='eu-north' and i>1425 else 'healthy','metrics':m})
    return rows


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass

    def send(self,value,status=200,mime='application/json'):
        body=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False).encode()
        self.send_response(status);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)

    def do_POST(self):
        length=int(self.headers.get('Content-Length',0))
        if length>4096:return self.send({'detail':'Request too large'},413)
        self.rfile.read(length)
        if self.path=='/api/admin/token':return self.send({'access_token':'synthetic-demo-token','token_type':'bearer'})
        self.send({'detail':'Демо доступно только для просмотра'},405)

    def do_PUT(self):self.send({'detail':'Демо доступно только для просмотра'},405)
    do_DELETE=do_PUT

    def do_GET(self):
        url=urlsplit(self.path);path=unquote(url.path);query=parse_qs(url.query);now=time.time()
        if path in ('/','/fleet','/fleet/'):
            html=(WEB/'index.html').read_text(encoding='utf-8').replace('<body>','<body><div class="demo-label">DEMO · Вымышленные пользователи, ноды и метрики</div>')
            return self.send(html.encode(),mime='text/html; charset=utf-8')
        if path.startswith('/fleet/assets/'):
            target=(WEB/path.removeprefix('/fleet/assets/')).resolve()
            if WEB.resolve() not in target.parents or not target.is_file():return self.send({},404)
            return self.send(target.read_bytes(),mime=mimetypes.guess_type(target.name)[0] or 'application/octet-stream')
        if path=='/api/fleet/overview':
            values=nodes(now);return self.send({'nodes':values,'summary':{s:sum(n['state']==s for n in values) for s in ['healthy','offline','degraded','unknown']},'events':events(now)})
        if path=='/api/fleet/events':return self.send(events(now))
        if path=='/api/fleet/tags':return self.send([{'tag':t,'users':sum(t in u['tags'] for u in users(now))} for t in ['family','team','trial']])
        if path=='/api/fleet/users':
            values=[u for u in users(now) if query.get('q',[''])[0] in u['username'] and (not query.get('tag') or query['tag'][0] in u['tags'])]
            offset=int(query.get('offset',[0])[0]);limit=int(query.get('limit',[30])[0]);return self.send({'total':len(values),'users':values[offset:offset+limit]})
        if path.startswith('/api/fleet/users/'):
            return self.send(next((u for u in users(now) if u['username']==path.rsplit('/',1)[-1]),{}))
        if path=='/api/fleet/traffic':return self.send(traffic(now,query))
        if path=='/api/fleet/monitoring':
            selected=[n for n in nodes(now) if not query.get('node') or n['id']==query['node'][0]]
            return self.send({'nodes':selected,'history':history(now,selected),'generated_at':now,'retention_days':7,'sample_seconds':60})
        if path.startswith('/api/fleet/nodes/'):
            parts=path.removeprefix('/api/fleet/nodes/').split('/')
            node=next((n for n in nodes(now) if n['id']==parts[0]),None)
            if node is None:return self.send({},404)
            if parts[1:]==['connections']:
                total=node['metrics'].get('online_connections',0);native=node['protocol']=='xray'
                count=2 if native else node['metrics']['online_users']
                details={'kind':'tcp_established' if native else 'hy2_client_instances','observed_at':now-4,'total':total,
                         'local_port':443 if native else None,'unique_source_ips':count if native else None,
                         'authenticated_users':None if native else count,'confirmed_core_sockets':total if native else None,
                         'unverified_owner_sockets':0 if native else None,'other_connections':0,
                         'groups':[{'key':f'{i+1:012x}','family':'ipv4' if native else 'account','count':total//count+int(i<total%count)} for i in range(count)]}
                return self.send({'node':node['id'],'name':node['name'],'protocol':node['protocol'],'received_at':now-4,'state':'available','count':total,'details':details})
            failed=node['id']=='eu-north'
            node.update(settings={'domain':node['address'],'vpn_port':443,'port':62050,'api_port':62051,'usage_coefficient':1,'active':True},hosts=[],
                        events=[e for e in events(now) if e['node']==node['id']],checks=[{'id':'demo','state':'failed' if failed else 'passed','completed_at':now-90,'result':{'stage':'payload','bytes':0 if failed else 2048,'latency_ms':None if failed else 42,'error':'Нет ответа контрольного клиента' if failed else None}}],
                        traffic=traffic(now,{'node':[node['id']]}))
            return self.send(node)
        self.send({'detail':'Demo fixture not found'},404)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=18808);args=parser.parse_args()
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'Synthetic Rime UI demo: http://127.0.0.1:{server.server_port}/fleet',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
