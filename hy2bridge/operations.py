"""Operational inventory, health events and reports. No secrets in report tables."""
from datetime import datetime, timedelta, timezone
import json
import time
import uuid

CHECK_TIMEOUT_SECONDS=30
HEALTH_RETENTION_ROWS=250000
METER_RETENTION_ROWS=250000
GAP_RETENTION_DAYS=90
GAP_RETENTION_ROWS=10000
COMPLETED_JOB_ROWS=5000


MESSAGES={
    'accounting_failed':'Не удалось передать расход в панель',
    'stats_unavailable':'API статистики недоступен',
    'ledger_failed':'Ошибка долговечного журнала',
    'control_expired':'Истёк срок действия управляющей политики',
    'counter_reset':'Счётчик изменился без смены журнала',
    'healthy':'Связь и учёт восстановлены',
    'native_unavailable':'Нет связи с ядром Xray',
    'native_tls_unverified':'Сертификат управления нодой не подтверждён',
    'native_tls_identity_changed':'Сертификат управления нодой изменился: подключение отклонено',
    'heartbeat_stale':'Связь с нодой прерывалась более чем на 30 секунд',
    'traffic_failed':'Контрольный трафик через VPN не прошёл',
    'service_unavailable':'Процесс или порт VPN-службы недоступен на сервере',
    'meter_unavailable':'Не поступает учёт VPN-трафика',
    'client_unreachable':'Клиентская проба VPN-трафика не прошла',
    'relay_client_unreachable':'Трафик через выбранный вход не прошёл',
    'relay_proxy_unreachable':'Прокси через выбранный вход не передал трафик',
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
        self.reachability=None
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
            db.execute('CREATE INDEX IF NOT EXISTS fleet_events_open ON fleet_events(node,code,resolved_at,last_at)')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_checks(
                id TEXT PRIMARY KEY,node TEXT NOT NULL,state TEXT NOT NULL,requested_at REAL NOT NULL,
                started_at REAL,completed_at REAL,result TEXT NOT NULL DEFAULT '{}')''')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_checks_node_time ON fleet_checks(node,requested_at DESC)')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_checks_expiry ON fleet_checks(state,requested_at)')
            db.execute('CREATE INDEX IF NOT EXISTS fleet_checks_retention ON fleet_checks(state,completed_at)')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_retention_state(
                table_name TEXT PRIMARY KEY,trimmed_before REAL NOT NULL)''')
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
                prior=db.execute("SELECT id FROM fleet_events WHERE node=? AND code='heartbeat_stale' AND last_at>? ORDER BY last_at DESC LIMIT 1",(node,now-86400)).fetchone()
                if prior:
                    db.execute('UPDATE fleet_events SET last_at=?,resolved_at=?,occurrences=occurrences+1 WHERE id=?',(now,now,prior['id']))
                    incident_id=prior['id']
                else:
                    incident_id=db.execute('INSERT INTO fleet_events(node,code,severity,first_at,last_at,resolved_at) VALUES(?,?,?,?,?,?)',
                        (node,'heartbeat_stale','error',previous['seen_at']+30,now,now)).lastrowid
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_event_actions'").fetchone():
                    db.execute('''INSERT OR IGNORE INTO fleet_event_actions SELECT ?,acknowledged,note,actor,updated_at
                        FROM fleet_event_actions WHERE event_key=?''',
                        (str(incident_id),'offline:'+node+':'+str(previous['seen_at'])))
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
                    resource_fresh=bool(health and now-health['seen_at']<=30)
                    data.update(core_version=row['xray_version'],control_healthy=live)
                    if not resource_fresh:data['service_healthy']=None
                    service=data.get('service_healthy')
                    state='offline' if service is False else 'healthy' if live is True else 'degraded' if service is True else 'unknown'
                    seen=health['seen_at'] if health else None
                    managed=None
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_managed'").fetchone():
                        managed=db.execute('SELECT name FROM fleet_managed WHERE native_id=?',(row['id'],)).fetchone()
                    result.append({'id':'xray:'+str(row['id']),'name':managed['name'] if managed else row['name'],'protocol':'xray',
                        'address':row['address'],'state':state,
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
            hidden={r[0] for r in db.execute('SELECT node FROM fleet_subscription_hidden')} \
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_subscription_hidden'").fetchone() else set()
            for item in result:
                item['subscription_hidden']=item['id'] in hidden
                item['client_access']=self.reachability.summary(db,item['id']) if self.reachability else {'state':'unknown','origin':None,'checked_at':None,'fresh':False}
                if getattr(self,'relays',None):item['tunnel_access']=self.relays.summary(db,item['id'])
                tunnel=item.get('tunnel_access') or {}
                selected_available=tunnel.get('active') and tunnel.get('fresh') and tunnel.get('vpn_passed',tunnel.get('passed')) is True
                # Behind an entry server the route check through the entry is what clients get.
                selected_failed=tunnel.get('active') and tunnel.get('fresh') and tunnel.get('vpn_passed',tunnel.get('passed')) is False
                if item['state']=='healthy' and (selected_failed or (item['client_access']['state']=='unavailable' and not selected_available)):item['state']='degraded'
            return result

    def expire_checks(self,now=None):
        now=time.time() if now is None else now
        with self.store.connection() as db:
            stale=db.execute("SELECT 1 FROM fleet_checks WHERE state IN ('requested','running') AND requested_at<? LIMIT 1",
                             (now-CHECK_TIMEOUT_SECONDS,)).fetchone()
        if not stale:return 0
        with self.store.connection(write=True) as db:
            result=db.execute("""UPDATE fleet_checks SET state='failed',completed_at=requested_at+?,result=?
                                 WHERE state IN ('requested','running') AND requested_at<?""",
                              (CHECK_TIMEOUT_SECONDS,json.dumps({'error':'Истекло время ожидания агента'}),now-CHECK_TIMEOUT_SECONDS))
            return result.rowcount

    @staticmethod
    def _prune_samples(db,table,column,before,row_limit):
        # Table and column names are fixed internal callers, never API input.
        floor=db.execute(f'SELECT MAX({column}) FROM {table} WHERE {column}<?',(before,)).fetchone()[0]
        db.execute(f'DELETE FROM {table} WHERE {column}<?',(before,))
        if db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]>row_limit:
            overflow=db.execute(f'SELECT {column} FROM {table} ORDER BY {column} DESC,rowid DESC LIMIT 1 OFFSET ?',
                                (row_limit,)).fetchone()[0]
            floor=max(floor,overflow) if floor is not None else overflow
            db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY {column} DESC,rowid DESC LIMIT -1 OFFSET ?)',
                       (row_limit,))
        if floor is not None:
            db.execute('''INSERT INTO fleet_retention_state VALUES(?,?) ON CONFLICT(table_name)
                          DO UPDATE SET trimmed_before=MAX(trimmed_before,excluded.trimmed_before)''',(table,floor))

    def prune(self, now=None):
        """Bound diagnostic history only; never delete usage, policies or open incidents."""
        now=time.time() if now is None else now
        self.expire_checks(now)
        active_keys=['offline:'+n['id']+':'+str(n.get('seen_at') or n.get('outage_since') or 0) for n in self.nodes() if n['state']=='offline']
        with self.store.connection(write=True) as db:
            db.execute('DELETE FROM fleet_events WHERE resolved_at IS NOT NULL AND (last_at<? OR id IN (SELECT id FROM fleet_events WHERE resolved_at IS NOT NULL ORDER BY last_at DESC,id DESC LIMIT -1 OFFSET 5000))',(now-30*86400,))
            db.execute("DELETE FROM fleet_checks WHERE state IN ('passed','failed') AND completed_at<?",(now-7*86400,))
            tables={row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table,column,days,limit in [('fleet_health_history','minute',7,HEALTH_RETENTION_ROWS),
                                             ('fleet_meter_samples','at',7,METER_RETENTION_ROWS),
                                             ('fleet_meter_gaps','end_at',GAP_RETENTION_DAYS,GAP_RETENTION_ROWS)]:
                if table not in tables:continue
                if table=='fleet_meter_gaps':
                    db.execute('CREATE INDEX IF NOT EXISTS fleet_meter_gaps_retention ON fleet_meter_gaps(end_at)')
                self._prune_samples(db,table,column,now-days*86400,limit)
            if 'fleet_jobs' in tables:
                db.execute('CREATE INDEX IF NOT EXISTS fleet_jobs_retention ON fleet_jobs(state,created_at)')
                unreferenced='NOT EXISTS(SELECT 1 FROM fleet_managed m WHERE m.id=fleet_jobs.id)' if 'fleet_managed' in tables else '1'
                if 'fleet_node_transfers' in tables:
                    db.execute('CREATE INDEX IF NOT EXISTS fleet_node_transfers_retention ON fleet_node_transfers(node,state,created_at)')
                    unreferenced+=''' AND NOT EXISTS(
                        SELECT 1 FROM fleet_node_transfers t WHERE t.id=fleet_jobs.id AND t.state='succeeded'
                        AND NOT EXISTS(SELECT 1 FROM fleet_node_transfers newer
                            WHERE newer.node=t.node AND newer.state='succeeded'
                            AND (newer.created_at>t.created_at OR (newer.created_at=t.created_at AND newer.id>t.id))))'''
                db.execute("DELETE FROM fleet_jobs WHERE "+unreferenced+" AND ((state='succeeded' AND created_at<?) OR (state='rolled_back' AND created_at<?))",
                           (now-30*86400,now-90*86400))
                db.execute("DELETE FROM fleet_jobs WHERE id IN (SELECT id FROM fleet_jobs WHERE "+unreferenced+
                           " AND state IN ('succeeded','rolled_back') ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET ?)",(COMPLETED_JOB_ROWS,))
                if 'fleet_node_transfers' in tables:
                    db.execute("DELETE FROM fleet_node_transfers WHERE state IN ('succeeded','rolled_back') AND NOT EXISTS(SELECT 1 FROM fleet_jobs j WHERE j.id=fleet_node_transfers.id)")
                if 'fleet_transfer_components' in tables:
                    db.execute('DELETE FROM fleet_transfer_components WHERE NOT EXISTS(SELECT 1 FROM fleet_jobs j WHERE j.id=fleet_transfer_components.transfer_id)')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_event_actions'").fetchone():
                db.execute("DELETE FROM fleet_event_actions WHERE updated_at<? AND (event_key NOT GLOB '*[^0-9]*' AND NOT EXISTS(SELECT 1 FROM fleet_events e WHERE CAST(e.id AS TEXT)=event_key))",(now-30*86400,))
                db.execute("DELETE FROM fleet_event_actions WHERE updated_at<? AND event_key LIKE 'offline:%' AND event_key NOT IN ("+','.join('?' for _ in active_keys)+')',[now-30*86400,*active_keys])

    def events(self,limit=100,nodes=None):
        with self.store.connection() as db:
            result=[{**dict(r),'message':MESSAGES.get(r['code'],'Сбой управляющего контура')}
                for r in db.execute('SELECT * FROM fleet_events ORDER BY resolved_at IS NULL DESC,last_at DESC LIMIT ?',(limit,))]
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_jobs'").fetchone():
                for job in db.execute("SELECT * FROM fleet_jobs WHERE state IN ('failed','rolled_back') ORDER BY created_at DESC LIMIT ?",(limit,)):
                    result.append({'id':'job:'+job['id'],'node':'Установка '+job['id'][:8],
                        'code':'provision_'+job['state'],'severity':'error','first_at':job['created_at'],
                        'last_at':job['created_at'],'occurrences':1,'message':job['message'],
                        'resolved_at':job['created_at'] if job['state']=='rolled_back' else None})
                result.sort(key=lambda r:r['last_at'] or 0,reverse=True)
        # A disconnected node cannot report its own outage. Expose derived stale
        # telemetry explicitly rather than leaving the dashboard deceptively green.
        observed=self.nodes() if nodes is None else nodes
        by_id={node['id']:node for node in observed}
        for event in result:
            tunnel=by_id.get(event['node'],{}).get('tunnel_access') or {}
            if event['code']=='client_unreachable' and tunnel.get('active'):
                if tunnel.get('fresh') and tunnel.get('vpn_passed',tunnel.get('passed')):
                    event['message']='Прямой адрес ноды недоступен. Клиенты подключаются через вход, маршрут работает'
                    event['severity']='warning'
                else:
                    event['message']='Прямой адрес ноды недоступен, маршрут через вход тоже требует проверки'
        for node in observed:
            if node['state']=='offline' and not any(e['node']==node['id'] and not e['resolved_at'] and e['code']=='native_unavailable' for e in result):
                result.insert(0,{'id':'offline:'+node['id']+':'+str(node.get('seen_at') or node.get('outage_since') or 0),'node':node['id'],'code':'heartbeat_stale',
                    'severity':'error','first_at':node.get('seen_at'),'last_at':node.get('seen_at'),
                    'occurrences':1,'resolved_at':None,'message':'Нет актуальной связи с нодой','derived':True})
        with self.store.connection() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_event_actions'").fetchone():
                keys=[str(e['id']) for e in result]
                actions={r['event_key']:dict(r) for r in db.execute('SELECT * FROM fleet_event_actions WHERE event_key IN ('+','.join('?' for _ in keys)+')',keys)} if keys else {}
                for event in result:event['action']=actions.get(str(event['id']))
        return result[:limit]

    @staticmethod
    def _traffic_source(begin,finish,protocol,node,username,tag):
        sources=[]
        parameters=[]
        for kind,table in [('hysteria2','hy2_hourly'),('xray','fleet_xray_hourly')]:
            if protocol not in (None,kind):continue
            columns='tx+rx AS total,tx,rx' if kind=='hysteria2' else 'total,NULL AS tx,NULL AS rx'
            identity="user_id,NULL AS user_created,auth" if kind=='hysteria2' else "user_id,user_created,NULL AS auth"
            sql=f"SELECT '{kind}' AS protocol,node,username,{identity},hour AS raw_hour,substr(hour,1,13)||':00:00' AS hour,{columns} FROM {table} WHERE hour>=? AND hour<?"
            values=[begin,finish]
            if node:sql+=' AND node=?';values.append(node)
            if username:sql+=' AND username=?';values.append(username)
            if tag:
                if kind=='hysteria2':
                    sql+=''' AND EXISTS(SELECT 1 FROM fleet_user_meta m JOIN users u ON u.id=m.user_id
                            AND u.created_at=m.user_created JOIN proxies p ON p.user_id=u.id,json_each(m.tags) t
                            WHERE u.id=hy2_hourly.user_id AND json_extract(p.settings,'$.id')=hy2_hourly.auth AND t.value=?)'''
                else:
                    sql+=''' AND EXISTS(SELECT 1 FROM fleet_user_meta m JOIN users u ON u.id=m.user_id
                            AND u.created_at=m.user_created,json_each(m.tags) t WHERE u.id=fleet_xray_hourly.user_id
                            AND m.user_created=fleet_xray_hourly.user_created AND t.value=?)'''
                values.append(tag)
            sources.append(sql)
            parameters.extend(values)
        if not sources:
            return "SELECT '' AS protocol,'' AS node,NULL AS username,'' AS raw_hour,'' AS hour,0 AS total,NULL AS tx,NULL AS rx WHERE 0",[]
        return ' UNION ALL '.join(sources),parameters

    def traffic(self,start,end,protocol=None,node=None,username=None,tag=None,detail=True,group_by='protocol'):
        if group_by not in ('protocol','node','tag','user'):raise ValueError('Неизвестная группировка графика')
        if end<=start or end-start>timedelta(days=366):
            raise ValueError('Период должен быть положительным и не больше 366 дней')
        begin=start.replace(tzinfo=None).isoformat(' ')
        finish=end.replace(tzinfo=None).isoformat(' ')
        source,parameters=self._traffic_source(begin,finish,protocol,node,username,tag)
        records=[]
        sample_hours=set()
        meter_status=[]
        gaps=[]
        chart_data={}
        with self.store.connection() as db:
            db.execute('BEGIN')
            grouped='SELECT protocol,node,username,raw_hour,SUM(total) AS total,SUM(tx) AS tx,SUM(rx) AS rx FROM ('+source+') GROUP BY protocol,node,username,raw_hour'
            if detail:
                records=[dict(row) for row in db.execute('SELECT protocol,node,username,raw_hour AS hour,total,tx,rx FROM ('+grouped+') ORDER BY protocol,raw_hour,node,username LIMIT 50001',parameters).fetchall()]
                if len(records)>50000:
                    raise ValueError('Слишком большой отчёт: сузьте период или выберите ноду / пользователя')
                row_count=len(records)
            else:
                # Summaries do not materialize the user×node×hour detail in Python.
                row_count=db.execute('SELECT COUNT(*) FROM ('+grouped+')',parameters).fetchone()[0]
            hours=[dict(row) for row in db.execute('SELECT protocol,hour,SUM(total) AS total,SUM(tx) AS tx,SUM(rx) AS rx FROM ('+source+') GROUP BY protocol,hour ORDER BY hour,protocol',parameters).fetchall()]
            per_user=[dict(row) for row in db.execute("SELECT protocol,COALESCE(NULLIF(username,''),'(удалён)') AS username,SUM(total) AS total FROM ("+source+") GROUP BY protocol,COALESCE(NULLIF(username,''),'(удалён)')",parameters).fetchall()]
            per_node=[dict(row) for row in db.execute('SELECT node,SUM(total) AS total FROM ('+source+') GROUP BY node ORDER BY total DESC,node',parameters).fetchall()]
            if protocol in (None,'hysteria2'):
                sql='SELECT DISTINCT hour FROM hy2_samples WHERE hour>=? AND hour<?'
                values=[begin,finish]
                if node:sql+=' AND node=?';values.append(node)
                sample_hours={row['hour'][:13]+':00:00' for row in db.execute(sql,values).fetchall()}
                if self.meters:
                    ids=[row['node'] for row in db.execute('SELECT node FROM fleet_meters').fetchall() if not node or row['node']==node]
                    for ident in ids:
                        status=self.meters.status(ident,db)
                        if status:meter_status.append({'node':ident,**status})
                    sql='SELECT node,start_at,end_at,reason,loss_possible FROM fleet_meter_gaps WHERE start_at<? AND end_at>=?'
                    values=[end.timestamp(),start.timestamp()]
                    if node:sql+=' AND node=?';values.append(node)
                    gaps=[dict(row) for row in db.execute(sql,values).fetchall()]
            floor=db.execute("SELECT trimmed_before FROM fleet_retention_state WHERE table_name='fleet_meter_gaps'").fetchone()
            if group_by!='protocol':
                from .traffic_groups import grouped_chart
                chart_data=grouped_chart(db,source,parameters,group_by,sample_hours|{row['hour'] for row in hours})
        series={}
        users={}
        totals={'hysteria2':0,'xray':0}
        upload=download=0
        known={'hysteria2':set(sample_hours),'xray':set()}
        for row in hours:
            kind=row['protocol']
            totals[kind]+=row['total']
            known[kind].add(row['hour'])
            series.setdefault(row['hour'],{'hour':row['hour'],'hysteria2':0,'xray':0})[kind]+=row['total']
            if kind=='hysteria2':upload+=row['tx'];download+=row['rx']
        for row in per_user:
            users.setdefault(row['username'],{'username':row['username'],'hysteria2':0,'xray':0})[row['protocol']]+=row['total']
        for hour in sample_hours:
            series.setdefault(hour,{'hour':hour,'hysteria2':0,'xray':0})
        for hour,value in series.items():
            if hour not in known['hysteria2'] or protocol=='xray':value['hysteria2']=None
            if hour not in known['xray'] or protocol=='hysteria2':value['xray']=None
        gap_complete=not known['hysteria2'] or (start.timestamp()>=time.time()-GAP_RETENTION_DAYS*86400 and (not floor or start.timestamp()>floor['trimmed_before']))
        return {'from':start.isoformat(),'to':end.isoformat(),'totals':totals,'total':sum(totals.values()),'group_by':group_by,**chart_data,
                'series':sorted(series.values(),key=lambda row:row['hour']),
                'users':sorted(users.values(),key=lambda row:(-(row['hysteria2']+row['xray']),row['username'])),
                'rows':records,'row_count':row_count,'nodes':per_node,
                'time_basis':'posting_hour','native_direction_available':False,
                'hy2_upload_bytes':upload,'hy2_download_bytes':download,'meters':meter_status,'gaps':gaps,
                'hy2_first_sample_hour':min(known['hysteria2']) if known['hysteria2'] else None,
                'gap_retention_days':GAP_RETENTION_DAYS,'gap_history_complete':gap_complete}
