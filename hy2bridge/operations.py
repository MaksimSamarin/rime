"""Operational inventory, health events and reports. No secrets in report tables."""
from datetime import datetime, timedelta, timezone
import json
import time
import uuid


MESSAGES={
    'accounting_failed':'Не удалось передать расход в панель',
    'stats_unavailable':'API статистики недоступен',
    'ledger_failed':'Ошибка долговечного журнала',
    'control_expired':'Истёк срок действия управляющей политики',
    'counter_reset':'Счётчик изменился без смены журнала',
    'healthy':'Связь и учёт восстановлены',
    'native_unavailable':'Нет связи с ядром Xray',
    'heartbeat_stale':'Связь с нодой прерывалась более чем на 30 секунд',
    'traffic_failed':'Контрольный трафик через VPN не прошёл',
    'service_unavailable':'Процесс или порт VPN-службы недоступен на сервере',
    'meter_unavailable':'Не поступает учёт VPN-трафика',
    'node_quota_80':'Израсходовано 80% лимита ноды',
    'node_quota_95':'Израсходовано 95% лимита ноды',
    'node_quota_exceeded':'Лимит трафика ноды исчерпан',
}


class Operations:
    def __init__(self,store):
        self.store=store
        self.native_probe=lambda node_id:None
        self.local_probe=None
        self.quotas=None
        self.meters=None
        with store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_inventory(
                id TEXT PRIMARY KEY,name TEXT NOT NULL,protocol TEXT NOT NULL,address TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,enabled INTEGER NOT NULL DEFAULT 1)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_health(
                node TEXT PRIMARY KEY,seen_at REAL NOT NULL,data TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,node TEXT NOT NULL,code TEXT NOT NULL,
                severity TEXT NOT NULL,first_at REAL NOT NULL,last_at REAL NOT NULL,
                occurrences INTEGER NOT NULL DEFAULT 1,resolved_at REAL)''')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_events_time ON fleet_events(last_at)')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_checks(
                id TEXT PRIMARY KEY,node TEXT NOT NULL,state TEXT NOT NULL,requested_at REAL NOT NULL,
                started_at REAL,completed_at REAL,result TEXT NOT NULL DEFAULT '{}')''')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_checks_node_time ON fleet_checks(node,requested_at DESC)')
            # SQLite triggers keep native reporting history in the *same*
            # transaction as each native counter write, including across resets.
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_xray_hourly(
                node TEXT NOT NULL,user_id INTEGER NOT NULL,user_created TEXT NOT NULL,username TEXT,
                hour TEXT NOT NULL,total INTEGER NOT NULL,
                PRIMARY KEY(node,user_id,user_created,hour))''')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='node_user_usages'").fetchone():
                db.execute('''INSERT OR IGNORE INTO fleet_xray_hourly
                    SELECT COALESCE('xray:'||n.node_id,'xray:local'),n.user_id,COALESCE(u.created_at,''),u.username,
                           n.created_at,n.used_traffic FROM node_user_usages n LEFT JOIN users u ON u.id=n.user_id''')
                for action,delta in [('INSERT','NEW.used_traffic'),('UPDATE','MAX(0,NEW.used_traffic-OLD.used_traffic)')]:
                    db.execute(f'''CREATE TRIGGER IF NOT EXISTS fleet_native_{action.lower()}
                        AFTER {action} ON node_user_usages BEGIN
                        INSERT INTO fleet_xray_hourly(node,user_id,user_created,username,hour,total)
                        VALUES(COALESCE('xray:'||NEW.node_id,'xray:local'),NEW.user_id,
                               COALESCE((SELECT created_at FROM users WHERE id=NEW.user_id),''),
                               (SELECT username FROM users WHERE id=NEW.user_id),NEW.created_at,{delta})
                        ON CONFLICT(node,user_id,user_created,hour) DO UPDATE SET total=total+excluded.total;
                        END''')
                db.execute('CREATE INDEX IF NOT EXISTS fleet_xray_time ON fleet_xray_hourly(hour,node,username)')

    def ensure_node(self,node,name=None,protocol='hysteria2',address=''):
        with self.store.connection(write=True) as db:
            db.execute('INSERT OR IGNORE INTO fleet_inventory(id,name,protocol,address,created_at) VALUES(?,?,?,?,?)',
                       (node,name or node,protocol,address,time.time()))

    def heartbeat(self,node,health):
        now=time.time()
        with self.store.connection(write=True) as db:
            if health.get('resource_observer') and not db.execute('SELECT 1 FROM fleet_observers WHERE node=?',(node,)).fetchone():
                raise ValueError('Observer registration was removed')
            if getattr(self,'require_registered_nodes',False) and not health.get('resource_observer') and not db.execute('SELECT 1 FROM fleet_inventory WHERE id=? UNION SELECT 1 FROM fleet_managed WHERE id=?',(node,node)).fetchone():
                raise ValueError('Node registration was removed')
            if health.get('resource_observer'):
                incident=db.execute("SELECT id FROM fleet_events WHERE node=? AND code='service_unavailable' AND resolved_at IS NULL",(node,)).fetchone()
                if health.get('service_healthy') is False:
                    if incident:db.execute('UPDATE fleet_events SET last_at=?,occurrences=occurrences+1 WHERE id=?',(now,incident['id']))
                    else:db.execute("INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,'service_unavailable','error',?,?)",(node,now,now))
                elif health.get('service_healthy') is True and incident:
                    db.execute('UPDATE fleet_events SET resolved_at=?,last_at=? WHERE id=?',(now,now,incident['id']))
            previous=db.execute('SELECT seen_at FROM fleet_health WHERE node=?',(node,)).fetchone()
            if previous and now-previous['seen_at']>30:
                incident=db.execute('INSERT INTO fleet_events(node,code,severity,first_at,last_at,resolved_at) VALUES(?,?,?,?,?,?)',
                    (node,'heartbeat_stale','error',previous['seen_at']+30,now,now))
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_event_actions'").fetchone():
                    db.execute('''INSERT OR IGNORE INTO fleet_event_actions SELECT ?,acknowledged,note,actor,updated_at
                        FROM fleet_event_actions WHERE event_key=?''',
                        (str(incident.lastrowid),'offline:'+node+':'+str(previous['seen_at'])))
            check=health.pop('check',None)
            if check and isinstance(check,dict):
                row=db.execute("SELECT state FROM fleet_checks WHERE id=? AND node=?",(check.get('id'),node)).fetchone()
                if row and row['state'] in ('requested','running'):
                    passed=check.get('passed') is True
                    result={k:v for k,v in check.items() if k!='id'}
                    db.execute('UPDATE fleet_checks SET state=?,completed_at=?,result=? WHERE id=?',
                        ('passed' if passed else 'failed',now,json.dumps(result),check['id']))
                    open_event=db.execute("SELECT id FROM fleet_events WHERE node=? AND code='traffic_failed' AND resolved_at IS NULL",(node,)).fetchone()
                    if passed and open_event:
                        db.execute('UPDATE fleet_events SET resolved_at=?,last_at=? WHERE id=?',(now,now,open_event['id']))
                    elif not passed:
                        if open_event:db.execute('UPDATE fleet_events SET last_at=?,occurrences=occurrences+1 WHERE id=?',(now,open_event['id']))
                        else:db.execute("INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,'traffic_failed','error',?,?)",(node,now,now))
                    health['traffic_healthy']=passed
                    health['traffic_checked_at']=now
                    health['traffic_latency_ms']=result.get('latency_ms')
                    health['traffic_error']=result.get('error')
            db.execute('''INSERT INTO fleet_health VALUES(?,?,?) ON CONFLICT(node)
                          DO UPDATE SET seen_at=excluded.seen_at,data=excluded.data''',(node,now,json.dumps(health)))
            code=health.get('error')
            if code:
                row=db.execute('SELECT id FROM fleet_events WHERE node=? AND code=? AND resolved_at IS NULL',(node,code)).fetchone()
                if row:
                    db.execute('UPDATE fleet_events SET last_at=?,occurrences=occurrences+1 WHERE id=?',(now,row['id']))
                else:
                    db.execute('INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,?,?,?,?)',
                               (node,code,'error',now,now))
            else:
                codes=('accounting_failed','stats_unavailable','ledger_failed','control_expired','counter_reset')
                db.execute('UPDATE fleet_events SET resolved_at=? WHERE node=? AND resolved_at IS NULL AND code IN (?,?,?,?,?)',(now,node,*codes))
        return {'received':True}

    def request_check(self,node):
        now=time.time()
        with self.store.connection(write=True) as db:
            inventory=db.execute('SELECT 1 FROM fleet_inventory WHERE id=? AND enabled=1',(node,)).fetchone()
            health=db.execute('SELECT seen_at FROM fleet_health WHERE node=?',(node,)).fetchone()
            if not inventory:raise ValueError('Для этой ноды агент проверки трафика не подключён')
            if not health or now-health['seen_at']>30:raise ValueError('Нода не на связи; сначала восстановите агент мониторинга')
            active=db.execute("SELECT * FROM fleet_checks WHERE node=? AND state IN ('requested','running') ORDER BY requested_at DESC LIMIT 1",(node,)).fetchone()
            if active and now-active['requested_at']<30:return self._check(active)
            if active:db.execute("UPDATE fleet_checks SET state='failed',completed_at=?,result=? WHERE id=?",(now,json.dumps({'error':'Истекло время ожидания агента'}),active['id']))
            check_id=uuid.uuid4().hex
            db.execute("INSERT INTO fleet_checks(id,node,state,requested_at) VALUES(?,?,'requested',?)",(check_id,node,now))
            return {'id':check_id,'node':node,'state':'requested','requested_at':now,'result':{}}

    def claim_check(self,node):
        now=time.time()
        with self.store.connection(write=True) as db:
            row=db.execute("SELECT * FROM fleet_checks WHERE node=? AND state='requested' ORDER BY requested_at LIMIT 1",(node,)).fetchone()
            if not row:return None
            db.execute("UPDATE fleet_checks SET state='running',started_at=? WHERE id=?",(now,row['id']))
            return {'id':row['id'],'requested_at':row['requested_at']}

    @staticmethod
    def _check(row):
        value=dict(row);value['result']=json.loads(value.get('result') or '{}');return value

    def checks(self,node,limit=20):
        with self.store.connection() as db:
            return [self._check(r) for r in db.execute('SELECT * FROM fleet_checks WHERE node=? ORDER BY requested_at DESC LIMIT ?',(node,limit))]

    def nodes(self):
        now=time.time()
        with self.store.connection() as db:
            observers={r['node']:dict(r) for r in db.execute('SELECT node,kind,domain,port FROM fleet_observers').fetchall()} if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_observers'").fetchone() else {}
            rows=db.execute('''SELECT i.*,h.seen_at,h.data FROM fleet_inventory i
                               LEFT JOIN fleet_health h ON h.node=i.id ORDER BY i.name''').fetchall()
            result=[]
            for row in rows:
                item=dict(row);data=json.loads(item.pop('data') or '{}')
                age=now-item['seen_at'] if item['seen_at'] is not None else None
                state='unknown' if age is None else ('offline' if age>30 else ('degraded' if data.get('error') or data.get('traffic_healthy') is False or data.get('service_healthy') is False else 'healthy'))
                external=observers.get(item['id'],{}).get('kind')=='legacy_hy2'
                result.append({**item,'state':state,'age_seconds':round(age,1) if age is not None else None,'metrics':data,
                    'monitoring_only':external,'status_source':'observer' if external else 'agent'})
            # Native node status is a real Marzban fact, not a fabricated heartbeat.
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='nodes'").fetchone()
            if exists:
                # Finish the SQLite cursor before any remote RPC. In rollback
                # journal mode an open cursor can block accounting commits for
                # the entire network round trip (including remote timeouts).
                native_rows=db.execute('SELECT id,name,address,status,message,xray_version,last_status_change FROM nodes ORDER BY name').fetchall()
                native_health={r['node']:dict(r) for r in db.execute("SELECT * FROM fleet_health WHERE node LIKE 'xray:%'").fetchall()}
                for row in native_rows:
                    live=self.native_probe(row['id'])
                    node='xray:'+str(row['id']);health=native_health.get(node)
                    data=json.loads(health['data']) if health else {}
                    data.update(core_version=row['xray_version'],service_healthy=live)
                    seen=health['seen_at'] if health else None
                    managed=None
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_managed'").fetchone():
                        managed=db.execute('SELECT name FROM fleet_managed WHERE native_id=?',(row['id'],)).fetchone()
                    result.append({'id':'xray:'+str(row['id']),'name':managed['name'] if managed else row['name'],'protocol':'xray',
                        'address':row['address'],'state':'unknown' if live is None else ('healthy' if live else 'offline'),
                        'seen_at':seen,'age_seconds':round(now-seen,1) if seen is not None else None,'metrics':data,
                        'status_source':'marzban','native_status':row['status'],'outage_since':row['last_status_change']})
            if self.local_probe:
                result.append(self.local_probe())
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_node_labels'").fetchone():
                labels={r['node']:r['name'] for r in db.execute('SELECT * FROM fleet_node_labels')}
                for item in result:item['name']=labels.get(item['id'],item['name'])
            if self.quotas:
                for item in result:item['quota']=self.quotas.state(item['id'],db)
            if self.meters:
                for item in result:
                    item['meter']=self.meters.status(item['id'],db)
                    if item['meter'] and item['meter']['state']=='stale' and item['state']=='healthy':item['state']='degraded'
            return result

    def events(self,limit=100):
        with self.store.connection() as db:
            result=[{**dict(r),'message':MESSAGES.get(r['code'],'Сбой управляющего контура')}
                for r in db.execute('SELECT * FROM fleet_events ORDER BY last_at DESC LIMIT ?',(limit,))]
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_jobs'").fetchone():
                for job in db.execute("SELECT * FROM fleet_jobs WHERE state IN ('failed','rolled_back') ORDER BY created_at DESC LIMIT ?",(limit,)):
                    result.append({'id':'job:'+job['id'],'node':'Установка '+job['id'][:8],
                        'code':'provision_'+job['state'],'severity':'error','first_at':job['created_at'],
                        'last_at':job['created_at'],'occurrences':1,'message':job['message'],
                        'resolved_at':job['created_at'] if job['state']=='rolled_back' else None})
                result.sort(key=lambda r:r['last_at'] or 0,reverse=True)
        # A disconnected node cannot report its own outage. Expose derived stale
        # telemetry explicitly rather than leaving the dashboard deceptively green.
        for node in self.nodes():
            if node['state']=='offline' and not any(e['node']==node['id'] and not e['resolved_at'] and e['code']=='native_unavailable' for e in result):
                result.insert(0,{'id':'offline:'+node['id']+':'+str(node.get('seen_at') or node.get('outage_since') or 0),'node':node['id'],'code':'heartbeat_stale',
                    'severity':'error','first_at':node.get('seen_at'),'last_at':node.get('seen_at'),
                    'occurrences':1,'resolved_at':None,'message':'Нет актуальной связи с нодой','derived':True})
        with self.store.connection() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_event_actions'").fetchone():
                actions={r['event_key']:dict(r) for r in db.execute('SELECT * FROM fleet_event_actions')}
                for event in result:event['action']=actions.get(str(event['id']))
        return result[:limit]

    def traffic(self,start,end,protocol=None,node=None,username=None,tag=None):
        if end<=start or end-start>timedelta(days=366):raise ValueError('Период должен быть от 1 часа до 366 дней')
        begin=start.replace(tzinfo=None).isoformat(' ');finish=end.replace(tzinfo=None).isoformat(' ')
        records=[];sample_hours=set();meter_status=[];gaps=[]
        with self.store.connection() as db:
            if protocol in (None,'hysteria2'):
                sql='SELECT node,username,hour,SUM(tx) tx,SUM(rx) rx FROM hy2_hourly WHERE hour>=? AND hour<?'
                params=[begin,finish]
                if node:sql+=' AND node=?';params.append(node)
                if username:sql+=' AND username=?';params.append(username)
                if tag:
                    sql+=''' AND EXISTS(SELECT 1 FROM fleet_user_meta m JOIN users u ON u.id=m.user_id
                        AND u.created_at=m.user_created JOIN proxies p ON p.user_id=u.id,json_each(m.tags) t
                        WHERE u.id=hy2_hourly.user_id AND json_extract(p.settings,'$.id')=hy2_hourly.auth AND t.value=?)''';params.append(tag)
                sql+=' GROUP BY node,username,hour ORDER BY hour LIMIT 50001'
                for row in db.execute(sql,params):
                    r=dict(row);r.update(protocol='hysteria2',total=r['tx']+r['rx']);records.append(r)
            if protocol in (None,'xray'):
                sql='''SELECT node,username,hour,SUM(total) total FROM fleet_xray_hourly
                       WHERE hour>=? AND hour<?'''
                params=[begin,finish]
                if node:sql+=' AND node=?';params.append(node)
                if username:sql+=' AND username=?';params.append(username)
                if tag:
                    sql+=''' AND EXISTS(SELECT 1 FROM fleet_user_meta m JOIN users u ON u.id=m.user_id
                        AND u.created_at=m.user_created,json_each(m.tags) t WHERE u.id=fleet_xray_hourly.user_id
                        AND m.user_created=fleet_xray_hourly.user_created AND t.value=?)''';params.append(tag)
                sql+=' GROUP BY node,username,hour ORDER BY hour LIMIT 50001'
                records += [{**dict(r),'protocol':'xray','tx':None,'rx':None} for r in db.execute(sql,params)]
            if protocol in (None,'hysteria2'):
                sql='SELECT DISTINCT hour FROM hy2_samples WHERE hour>=? AND hour<?';params=[begin,finish]
                if node:sql+=' AND node=?';params.append(node)
                sample_hours={r['hour'][:13]+':00:00' for r in db.execute(sql,params).fetchall()}
                if self.meters:
                    ids=[r['node'] for r in db.execute('SELECT node FROM fleet_meters').fetchall() if not node or r['node']==node]
                    meter_status=[{'node':ident,**self.meters.status(ident,db)} for ident in ids]
                    sql='SELECT node,start_at,end_at,reason,loss_possible FROM fleet_meter_gaps WHERE start_at<? AND end_at>=?';params=[end.timestamp(),start.timestamp()]
                    if node:sql+=' AND node=?';params.append(node)
                    gaps=[dict(r) for r in db.execute(sql,params).fetchall()]
        if len(records)>50000:raise ValueError('Слишком большой отчёт: сузьте период или выберите ноду / пользователя')
        series={};users={};totals={'hysteria2':0,'xray':0};upload=download=0
        for r in records:
            totals[r['protocol']]+=r['total']
            hour=r['hour'][:13]+':00:00'
            series.setdefault(hour,{'hour':hour,'hysteria2':0,'xray':0})[r['protocol']]+=r['total']
            key=r['username'] or '(удалён)'
            users.setdefault(key,{'username':key,'hysteria2':0,'xray':0})[r['protocol']]+=r['total']
            if r['protocol']=='hysteria2':upload+=r['tx'];download+=r['rx']
        for hour in sample_hours:
            series.setdefault(hour,{'hour':hour,'hysteria2':0,'xray':0})
        known_hy2=sample_hours|{r['hour'][:13]+':00:00' for r in records if r['protocol']=='hysteria2'}
        known_xray={r['hour'][:13]+':00:00' for r in records if r['protocol']=='xray'}
        for hour,value in series.items():
            if hour not in known_hy2 or protocol=='xray':value['hysteria2']=None
            if hour not in known_xray or protocol=='hysteria2':value['xray']=None
        return {'from':start.isoformat(),'to':end.isoformat(),'totals':totals,'total':sum(totals.values()),
                'series':sorted(series.values(),key=lambda x:x['hour']),
                'users':sorted(users.values(),key=lambda x:-(x['hysteria2']+x['xray'])),
                'rows':records,'time_basis':'posting_hour','native_direction_available':False,
                'hy2_upload_bytes':upload,'hy2_download_bytes':download,'meters':meter_status,'gaps':gaps,
                'hy2_first_sample_hour':min(known_hy2) if known_hy2 else None}
