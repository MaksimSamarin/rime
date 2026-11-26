"""Loopback-only API fixtures and in-memory UI demonstrations.

Uses no database, environment credentials, VPN processes or outbound requests.
All names, addresses, counters and event histories below are synthetic.
"""
import argparse
import base64
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import mimetypes
from pathlib import Path
import secrets
import time
from urllib.parse import parse_qs, unquote, urlsplit

WEB = Path(__file__).resolve().parents[1] / 'hy2bridge' / 'web'
GIB = 1024 ** 3
NAMES = ['demo_alex', 'demo_anna', 'demo_daria', 'demo_ivan', 'demo_kate', 'demo_leo', 'demo_maria', 'demo_max']
SERVERS = [('eu-west', 'Amsterdam', 'xray'), ('eu-north', 'Helsinki', 'hysteria2'), ('eu-central', 'Frankfurt', 'hysteria2')]


def update_demo(server, now):
    """Synthetic update job: two seconds per phase, with stop and rollback paths."""
    started = getattr(server, 'update_started', None)
    rollback = getattr(server, 'rollback_started', None)
    cancelled = getattr(server, 'update_cancelled', None)
    latest = {'id': 'synthetic-release', 'tag': 'v0.9.1', 'version': '0.9.1', 'published_at': '2026-11-14T10:00:00Z',
              'notes': 'Более быстрые отчёты по трафику.\nПроверка VPN по текущему DNS.\nУлучшенная навигация на телефоне.'}
    current, job, offer = '0.9.0', {}, None
    if rollback:
        phases = ['backup', 'installing', 'verifying', 'succeeded']
        phase = phases[min(3, int((now - rollback) / 2))]
        job = {'id': 'synthetic-rollback', 'version': '0.9.0', 'phase': phase, 'operation': 'rollback'}
        current = '0.9.0' if phase == 'succeeded' else '0.9.1'
        offer = {'version': '0.9.1'} if phase == 'succeeded' else None
    elif cancelled:
        job = {'id': 'synthetic-update', 'version': '0.9.1', 'phase': 'failed', 'error': 'update_cancelled'}
    elif started:
        phases = ['checking', 'downloading', 'downloading', 'backup', 'installing', 'verifying', 'succeeded']
        phase = phases[min(6, int((now - started) / 2))]
        job = {'id': 'synthetic-update', 'version': '0.9.1', 'phase': phase, 'progress': 64, 'retries': 1}
        current = '0.9.1' if phase == 'succeeded' else '0.9.0'
        offer = {'version': '0.9.0'} if phase == 'succeeded' else None
    checked = getattr(server, 'update_checked', False)
    return {'demo': True, 'current_version': current, 'enabled': True,
            'checked_at': now if checked else None, 'latest': latest if checked else None,
            'available': checked and current == '0.9.0' and not rollback, 'job': job,
            'cancellable': job.get('phase') in ('queued', 'checking', 'downloading'), 'cancel_requested': False,
            'rollback': offer}


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
                       'enabled':True,'metrics':metrics,'quota':quota(node,now,[34,52,83][i]),'status_source':'demo',
                       'client_access':{'state':'unavailable' if i==1 else 'available','checked_at':now-8,
                                        'origin':'Демонстрационная проверка','target_ip':'192.0.2.'+str(10+i)}})
    result.append({'id':'xray:local','name':'Сервер панели','address':'panel.example.invalid','role':'panel','protocol':'xray',
                   'state':'healthy','seen_at':now-2,'age_seconds':2,'enabled':True,'status_source':'demo',
                   'metrics':{'cpu_percent':7,'cpu_load1':.14,'mem_total_bytes':4*GIB,'mem_available_bytes':3.1*GIB,
                              'disk_total_bytes':60*GIB,'disk_free_bytes':44*GIB,'service_healthy':True,'core_version':'demo'},
                   'panel':{'version':'0.9.0','uptime_seconds':172800,'host_uptime_seconds':864000,
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
    report = {'total':sum(totals.values()),'totals':totals,'series':list(series.values()),'rows':rows,
            'users':sorted(by_user.values(),key=lambda u:-u['hysteria2']-u['xray']),
            'hy2_first_sample_hour':next(iter(series),None),'hy2_upload_bytes':sum(r['tx'] or 0 for r in rows),
            'hy2_download_bytes':sum(r['rx'] or 0 for r in rows),'gaps':[]}
    grouping = query.get('group_by',['protocol'])[0]
    if grouping in ['node','tag','user']:
        tags = {user['username']:user['tags'][0] for user in members}
        names = {node:name for node,name,_ in SERVERS}
        identities = [(row['node'] if grouping=='node' else tags[row['username']] if grouping=='tag' else row['username']) for row in rows]
        ranked = {}
        for identity,row in zip(identities,rows):
            ranked[identity] = ranked.get(identity,0)+row['total']
        leaders = sorted(ranked,key=lambda key:(-ranked[key],key))
        leaders = leaders[:5] if len(leaders)>6 else leaders
        mapping = {identity:'g'+str(index) for index,identity in enumerate(leaders)}
        groups = [{'key':mapping[identity],'label':names.get(identity,identity),'total':ranked[identity]} for identity in leaders]
        if len(ranked)>6:
            groups.append({'key':'other','label':'Остальные','total':sum(value for key,value in ranked.items() if key not in mapping)})
        grouped = {hour:{'hour':hour,**{group['key']:None for group in groups}} for hour in series}
        for identity,row in zip(identities,rows):
            key = mapping.get(identity,'other')
            grouped[row['hour']][key] = (grouped[row['hour']][key] or 0)+row['total']
        report.update(chart_groups=groups,chart_series=list(grouped.values()),chart_group_count=len(ranked),
            chart_has_other=len(ranked)>6,chart_note='Демонстрационные группы и вымышленный расход.')
    return report


def history(now,selected):
    rows=[];minute=int(now)//60*60
    for n in selected:
        for i in range(1440):
            at=minute-(1439-i)*60;m=dict(n['metrics'])
            m.update(cpu_load1=round(.35+.12*math.sin(i*.027),2),cpu_percent=round(20+12*math.sin(i*.035),1),
                     mem_available_bytes=int((2.3+.15*math.cos(i*.03))*GIB),online_connections=round(18+7*math.sin(i*.024)))
            rows.append({'node':n['id'],'minute':at,'state':'degraded' if n['id']=='eu-north' and i>1425 else 'healthy','metrics':m})
    return rows


def relay_demo(server,now):
    entry={'id':'a'*32,'name':'Zurich entry','host':'entry.example.com','address':'203.0.113.10','domain':'entry.example.com',
        'control_port':62080,'metrics_port':62081,'ssh_port':22,'username':'root','state':'active','created_at':now-86400,
        'seen_at':now-6,'fresh':True,'health':{'cpu_percent':12,'mem_available_bytes':3*GIB,'disk_free_bytes':24*GIB}}
    if not hasattr(server,'demo_entries'):
        second={**entry,'id':'9'*32,'name':'Helsinki entry','host':'entry-north.example.com',
                'address':'203.0.113.11','domain':'entry-north.example.com'}
        server.demo_entries=[entry,second]
    for value in server.demo_entries:
        available=value['state']=='active'
        value.update(seen_at=now-6 if available else now-3600,fresh=available)
    if not hasattr(server,'demo_routes'):
        server.demo_routes=[{'id':'b'*32,'node':'eu-west','entry':'a'*32,'entry_name':entry['name'],'entry_domain':entry['domain'],
            'origin':'203.0.113.20','state':'active','created_at':now-3600,'checked_at':now-12,'result':{'passed':True},
            'services':[{'id':'e'*32,'kind':'vpn','proxy':None,'protocol':'tcp','origin_port':443,'public_port':10443,'state':'active','traffic':{'rx':31*GIB,'tx':4*GIB}},
                {'id':'f'*32,'kind':'proxy','mode':'http','proxy':'c'*32,'protocol':'tcp','origin_port':3128,'public_port':13128,'state':'active','traffic':{'rx':2*GIB,'tx':GIB//3}},
                {'id':'8'*32,'kind':'proxy','mode':'https','proxy':'c'*32,'protocol':'tcp','origin_port':8443,'public_port':18443,'state':'active','traffic':{'rx':GIB,'tx':GIB//8}}]}]
    for route in server.demo_routes:route['checked_at']=now-12
    for route in server.demo_routes:
        route['result'].update(vpn_passed=True,proxies_passed=True,ssh_passed=True,
            services=[{'kind':service['kind'],'origin_port':service['origin_port'],'passed':True,'stage':'payload'} for service in route['services']])
    return {'enabled':True,'runtime_available':True,'entries':server.demo_entries,'tunnels':server.demo_routes}


def console_nodes(server,now):
    values=nodes(now)
    for node in values:
        route=next((route for route in relay_demo(server,now)['tunnels'] if route['node']==node['id']),None)
        if route:node['tunnel_access']={'active':True,'fresh':True,'passed':True,'vpn_passed':True,'proxies_passed':True,
            'entry_name':route['entry_name'],'domain':route['entry_domain'],'origin':route['origin'],'checked_at':now-12,
            'management':any(service['kind']=='management' for service in route['services'])}
        node['subscription_hidden']=node['id'] in getattr(server,'hidden_nodes',set())
    return values


def demo_hosts(node):
    if node['protocol']!='xray' or node['id']=='xray:local':return []
    domain=node['address']
    return [{'id':101,'remark':node['name'],'address':domain,'port':443,'inbound_tag':'VLESS_REALITY','is_disabled':0,'node':node['id']},
            {'id':102,'remark':node['name'],'address':domain,'port':2053,'inbound_tag':'VLESS_XHTTP','is_disabled':1,'node':node['id']}]


def proxy_demo(server,node):
    if node!='eu-west' or getattr(server,'proxy_deleted',False):return []
    route=next((route for route in relay_demo(server,time.time())['tunnels'] if route['node']==node),None)
    endpoints={service['mode']:{'host':route['entry_domain'],'port':service['public_port'],'entry':route['entry_name']}
               for service in route['services'] if service['kind']=='proxy' and service.get('mode')} if route else {}
    return [{'id':'c'*32,'node':node,'address':'203.0.113.20','domain':'node.example.com','http_port':3128,'https_port':8443,
        'username':'demo_proxy','created_at':time.time()-86400,'checked_at':time.time()-30,'result':{'passed':True},
        'stale':False,'deployment_state':'succeeded','credentials_available':True,'edit_allowed':True,'locked_domain':True,
        'endpoints':endpoints}]


def operation_demo(server,identity,now):
    job=getattr(server,'demo_jobs',{}).get(identity)
    if not job:return {'detail':'Demo job not found'}
    labels=['Проверка доступа к серверу','Сохранение конфигурации','Применение изменений','Проверка реального трафика','Результат сохранён']
    if job['kind']=='route-switch':
        labels=['Проверка нового входа','Сохранение текущего маршрута','Создание правил нового входа',
                'Проверка VPN и прокси','Публикация нового входа','Очистка прежних правил','Смена входа завершена']
    index=min(len(labels)-1,int((now-job['started'])/1.5))
    state='succeeded' if index==len(labels)-1 else 'running'
    if state=='succeeded' and job['kind']=='route-switch' and not job.get('applied'):
        job['applied']=True
        catalog=relay_demo(server,now)
        selected=next(entry for entry in catalog['entries'] if entry['id']==job['plan']['entry'])
        route=next(route for route in server.demo_routes if route['id']==job['plan']['route_id'])
        route.update(entry=selected['id'],entry_name=selected['name'],entry_domain=selected['domain'],
                     old_cleanup_pending=job['plan'].get('old_offline',False))
        if route['old_cleanup_pending']:
            route['pending_cleanup_count']=1
            previous=next(entry for entry in catalog['entries'] if entry['id']!=selected['id'])
            previous['pending_cleanup_count']=1
    if state=='succeeded' and job['kind']=='proxy-delete':
        server.proxy_deleted=True
        for route in relay_demo(server,now)['tunnels']:route['services']=[value for value in route['services'] if value['kind']!='proxy']
    if state=='succeeded' and job['kind']=='route-delete':
        server.demo_routes=[route for route in relay_demo(server,now)['tunnels'] if route['id']!=job['target']]
    if state=='succeeded' and job['kind']=='route-add' and not job.get('applied'):
        job['applied']=True
        selected=next(entry for entry in relay_demo(server,now)['entries'] if entry['id']==job['plan']['entry'])
        server.demo_routes.append({'id':identity,'node':job['node'],'entry':selected['id'],'entry_name':selected['name'],'entry_domain':selected['domain'],
            'origin':'203.0.113.30','state':'active','checked_at':now,'result':{'passed':True},'services':[
                {'id':'d'*32,'kind':'vpn','proxy':None,'protocol':'udp','origin_port':443,'public_port':443,'state':'active','traffic':{'rx':0,'tx':0}}]})
    if state=='succeeded' and job['kind']=='entry-add' and not job.get('applied'):
        job['applied']=True
        entry=dict(relay_demo(server,now)['entries'][0]) if server.demo_entries else {'health':{},'state':'active','fresh':True}
        entry.update(id=identity,name=job['plan']['name'],host=job['plan']['host'],domain=job['plan']['domain'],address='203.0.113.20',ssh_port=22,username='root',seen_at=now-6)
        server.demo_entries.append(entry)
    if state=='succeeded' and job['kind']=='entry-remove':
        relay_demo(server,now)
        server.demo_entries=[entry for entry in server.demo_entries if entry['id']!=job['plan']['target']]
    context={'operation':job['kind']}
    if job['kind']=='route-switch':
        context.update(progress={'completed':len(labels) if state=='succeeded' else index,
                                 'total':len(labels),'phase':'complete' if state=='succeeded' else str(index),'label':labels[index]},
                       old_cleanup_pending=state=='succeeded' and job['plan'].get('old_offline',False))
    return {'id':identity,'state':state,'message':labels[index],
            'steps':[{'message':label} for label in labels[:index+1]],'context':context}


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass

    def send(self,value,status=200,mime='application/json'):
        body=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False).encode()
        self.send_response(status);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)

    def do_POST(self):
        length=int(self.headers.get('Content-Length',0))
        if length>4096:return self.send({'detail':'Request too large'},413)
        raw=self.rfile.read(length)
        try:data=json.loads(raw)
        except ValueError:data={}
        if self.path=='/api/admin/token':
            payload=base64.urlsafe_b64encode(json.dumps({'sub':'demo','exp':time.time()+3600}).encode()).decode().rstrip('=')
            return self.send({'access_token':'demo.'+payload+'.synthetic','token_type':'bearer'})
        if self.path=='/api/system/updates/check':
            self.server.update_checked=True
            return self.send(update_demo(self.server,time.time()))
        if self.path=='/api/system/updates':
            self.server.update_started=time.time();self.server.update_cancelled=None;self.server.rollback_started=None
            return self.send(update_demo(self.server,time.time()))
        if self.path=='/api/system/updates/cancel':
            self.server.update_cancelled=time.time()
            return self.send(update_demo(self.server,time.time()))
        if self.path=='/api/system/updates/rollback':
            if data.get('confirmation')!='rollback':return self.send({'detail':'rollback_confirmation_required'},409)
            self.server.rollback_started=time.time()
            return self.send(update_demo(self.server,time.time()))
        if self.path=='/api/fleet/provision/host-key':return self.send({'address':'203.0.113.20','fingerprint':'SHA256:'+'a'*43})
        if self.path.endswith('/delete/plan'):
            return self.send({'id':'d'*32,'ready':True,'summary':{'HTTP':3128,'HTTPS':8443,'Туннельных правил':1}})
        if self.path in ['/api/fleet/proxy/delete/deploy','/api/fleet/relays/deploy']:
            if not hasattr(self.server,'demo_jobs'):self.server.demo_jobs={}
            identity=data['plan_id'];plan=getattr(self.server,'demo_plans',{}).get(identity,{})
            kind='proxy-delete' if '/proxy/' in self.path else plan.get('kind','route-add')
            self.server.demo_jobs[identity]={'kind':kind,'plan':plan,'started':time.time(),'node':plan.get('node','eu-north')}
            return self.send({'id':identity})
        if self.path.startswith('/api/fleet/relays/routes/') and self.path.endswith('/switch/plan'):
            catalog=relay_demo(self.server,time.time())
            route=next((route for route in catalog['tunnels'] if route['id']==self.path.split('/')[-3]),None)
            selected=next((entry for entry in catalog['entries'] if entry['id']==data.get('entry') and entry['state']=='active'),None)
            if not route or not selected or selected['id']==route['entry']:
                return self.send({'detail':'Выберите другой готовый входной сервер'},409)
            if not hasattr(self.server,'demo_plans'):self.server.demo_plans={}
            identity=secrets.token_hex(16)
            previous=next(entry for entry in catalog['entries'] if entry['id']==route['entry'])
            self.server.demo_plans[identity]={'kind':'route-switch','route_id':route['id'],
                'node':route['node'],'entry':selected['id'],'old_offline':previous['state']!='active'}
            entry_fields=['id','name','domain']
            return self.send({'id':identity,'kind':'route-switch','route_id':route['id'],'node':route['node'],
                'name':next((name for key,name,protocol in SERVERS if key==route['node']),route['node']),
                'from_entry':{key:previous[key] for key in entry_fields},
                'to_entry':{key:selected[key] for key in entry_fields},'entry_name':selected['name'],
                'domain':selected['domain'],'origin':route['origin'],'ready':True,
                'message':'Новый вход будет проверен перед переключением. Обновите прежнюю подписку в клиенте.',
                'services':route['services']})
        if self.path=='/api/fleet/relays/route/plan':
            if not hasattr(self.server,'demo_plans'):self.server.demo_plans={}
            identity=secrets.token_hex(16)
            self.server.demo_plans[identity]={'kind':'route-add','node':data['node'],'entry':data['entry']}
            return self.send({'id':identity,'kind':'route','node':data['node'],'name':next((name for key,name,protocol in SERVERS if key==data['node']),data['node']),'entry_name':next(entry['name'] for entry in relay_demo(self.server,time.time())['entries'] if entry['id']==data['entry']),
                'origin':'203.0.113.30','ready':True,'message':'Ключи и URL подписок сохранятся. Обновите подписку для получения входного адреса.',
                'services':[{'kind':'VPN','origin_port':443,'public_port':443,'protocol':'udp'}]})
        if self.path=='/api/fleet/relays/entry/plan':
            if not hasattr(self.server,'demo_plans'):self.server.demo_plans={}
            identity=secrets.token_hex(16)
            self.server.demo_plans[identity]={'kind':'entry-add',**{key:data[key] for key in ['name','domain','host']}}
            return self.send({'id':identity,'kind':'entry','name':data['name'],'domain':data['domain'],'address':'203.0.113.20','ready':True,'message':'Будет установлен отдельный входной сервер.'})
        if self.path.startswith('/api/fleet/relays/entry/') and self.path.endswith('/remove/plan'):
            if not hasattr(self.server,'demo_plans'):self.server.demo_plans={}
            target=self.path.split('/')[-3];identity=secrets.token_hex(16)
            entry=next(entry for entry in relay_demo(self.server,time.time())['entries'] if entry['id']==target)
            self.server.demo_plans[identity]={'kind':'entry-remove','target':target}
            return self.send({'id':identity,'kind':'entry-remove','ready':True,'domain':entry['domain'],'address':entry['address'],
                'message':'Будут удалены служба туннеля и сборщик выбранного входа.'})
        if self.path.startswith('/api/fleet/relays/entry/') and self.path.endswith('/check'):
            if not hasattr(self.server,'demo_jobs'):self.server.demo_jobs={}
            identity=secrets.token_hex(16);self.server.demo_jobs[identity]={'kind':'entry-check','started':time.time()}
            return self.send({'id':identity})
        if self.path.startswith('/api/fleet/relays/routes/') and self.path.endswith('/check'):
            if not hasattr(self.server,'demo_jobs'):self.server.demo_jobs={}
            identity=secrets.token_hex(16);self.server.demo_jobs[identity]={'kind':'route-check','started':time.time()}
            return self.send({'id':identity})
        self.send({'detail':'Демо доступно только для просмотра'},405)

    def do_PUT(self):
        parts=self.path.split('?',1)[0].removeprefix('/api/fleet/nodes/').split('/')
        if self.path.startswith('/api/fleet/nodes/') and parts[1:]==['subscription']:
            length=int(self.headers.get('Content-Length',0))
            try:visible=bool(json.loads(self.rfile.read(min(length,4096))).get('visible'))
            except ValueError:return self.send({'detail':'Invalid request'},422)
            hidden=getattr(self.server,'hidden_nodes',set())
            (hidden.discard if visible else hidden.add)(parts[0]);self.server.hidden_nodes=hidden
            return self.send({'node':parts[0],'subscription_visible':visible})
        self.send({'detail':'Демо доступно только для просмотра'},405)
    def do_DELETE(self):
        if self.path.startswith('/api/fleet/relays/routes/'):
            if not hasattr(self.server,'demo_jobs'):self.server.demo_jobs={}
            identity='7'*32
            self.server.demo_jobs[identity]={'kind':'route-delete','target':self.path.rsplit('/',1)[-1],'started':time.time()}
            return self.send({'id':identity})
        self.send({'detail':'Демо доступно только для просмотра'},405)

    def do_GET(self):
        url=urlsplit(self.path);path=unquote(url.path);query=parse_qs(url.query);now=time.time()
        if path=='/api/system/updates':return self.send(update_demo(self.server,now))
        if path=='/api/fleet/relays':return self.send(relay_demo(self.server,now))
        if path.startswith('/api/fleet/relays/jobs/') or path.startswith('/api/fleet/proxy/jobs/'):
            return self.send(operation_demo(self.server,path.rsplit('/',1)[-1],now))
        if path.endswith('/delete/options'):
            return self.send({'node':'eu-west','host':'node.example.com','ssh_port':22,'username':'root','fingerprint':'SHA256:'+'a'*43,'http_port':3128,'https_port':8443})
        if path=='/api/fleet/proxy/options':return self.send({'enabled':True,'automatic_tls':True})
        if path.endswith('/connection') and '/proxy/' in path:
            services=proxy_demo(self.server,'eu-west')
            endpoints=services[0]['endpoints'] if services else {}
            urls={mode:mode+'://demo_proxy:synthetic-demo-only@'+value['host']+':'+str(value['port'])
                  for mode,value in endpoints.items()}
            return self.send({'id':'c'*32,'node':'eu-west','deployment_state':'succeeded','credentials_available':True,'needs_password':False,
                'urls':urls})
        if path in ('/','/fleet','/fleet/'):
            html=(WEB/'index.html').read_text(encoding='utf-8').replace('<body>','<body><div class="demo-label">DEMO · Вымышленные пользователи, ноды и метрики</div>')
            return self.send(html.encode(),mime='text/html; charset=utf-8')
        if path.startswith('/fleet/assets/'):
            target=(WEB/path.removeprefix('/fleet/assets/')).resolve()
            if WEB.resolve() not in target.parents or not target.is_file():return self.send({},404)
            return self.send(target.read_bytes(),mime=mimetypes.guess_type(target.name)[0] or 'application/octet-stream')
        if path=='/api/fleet/overview':
            values=console_nodes(self.server,now);return self.send({'nodes':values,'summary':{s:sum(n['state']==s for n in values) for s in ['healthy','offline','degraded','unknown']},'events':events(now)})
        if path=='/api/fleet/events':return self.send(events(now))
        if path=='/api/fleet/tags':return self.send([{'tag':t,'users':sum(t in u['tags'] for u in users(now))} for t in ['family','team','trial']])
        if path=='/api/fleet/users':
            values=[u for u in users(now) if query.get('q',[''])[0] in u['username'] and (not query.get('tag') or query['tag'][0] in u['tags'])]
            offset=int(query.get('offset',[0])[0]);limit=int(query.get('limit',[30])[0]);return self.send({'total':len(values),'users':values[offset:offset+limit]})
        if path.startswith('/api/fleet/users/'):
            return self.send(next((u for u in users(now) if u['username']==path.rsplit('/',1)[-1]),{}))
        if path=='/api/fleet/traffic':return self.send(traffic(now,query))
        if path=='/api/fleet/monitoring':
            selected=[n for n in console_nodes(self.server,now) if not query.get('node') or n['id']==query['node'][0]]
            return self.send({'nodes':selected,'history':history(now,selected),'generated_at':now,'retention_days':7,'sample_seconds':60})
        if path.startswith('/api/fleet/nodes/'):
            parts=path.removeprefix('/api/fleet/nodes/').split('/')
            node=next((n for n in console_nodes(self.server,now) if n['id']==parts[0]),None)
            if node is None:return self.send({},404)
            if parts[1:]==['proxies']:return self.send(proxy_demo(self.server,node['id']))
            if parts[1:]==['proxy-access']:return self.send({'host':node['address'],'ssh_port':22,'username':'root','fingerprint':'SHA256:'+'a'*43})
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
            node.update(settings={'domain':node['address'],'vpn_port':443,'port':62050,'api_port':62051,'usage_coefficient':1,'active':True},hosts=demo_hosts(node),
                        subscription_visible=node['id'] not in getattr(self.server,'hidden_nodes',set()),
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
