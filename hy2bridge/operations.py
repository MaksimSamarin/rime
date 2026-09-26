"""Operational inventory, health events and reports. No secrets in report tables."""
from datetime import datetime, timedelta, timezone
import json
import time


MESSAGES={
    'accounting_failed':'Не удалось передать расход в панель',
    'stats_unavailable':'API статистики недоступен',
    'ledger_failed':'Ошибка долговечного журнала',
    'control_expired':'Истёк срок действия управляющей политики',
    'counter_reset':'Счётчик изменился без смены журнала',
    'healthy':'Связь и учёт восстановлены',
    'heartbeat_stale':'Связь с нодой прерывалась более чем на 30 секунд',
}


class Operations:
    def __init__(self,store):
        self.store=store
        self.native_probe=lambda node_id:None
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
            previous=db.execute('SELECT seen_at FROM fleet_health WHERE node=?',(node,)).fetchone()
            if previous and now-previous['seen_at']>30:
                db.execute('INSERT INTO fleet_events(node,code,severity,first_at,last_at,resolved_at) VALUES(?,?,?,?,?,?)',
                    (node,'heartbeat_stale','error',previous['seen_at']+30,now,now))
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
                db.execute('UPDATE fleet_events SET resolved_at=? WHERE node=? AND resolved_at IS NULL',(now,node))
        return {'received':True}

    def nodes(self):
        now=time.time()
        with self.store.connection() as db:
            rows=db.execute('''SELECT i.*,h.seen_at,h.data FROM fleet_inventory i
                               LEFT JOIN fleet_health h ON h.node=i.id ORDER BY i.name''').fetchall()
            result=[]
            for row in rows:
                item=dict(row);data=json.loads(item.pop('data') or '{}')
                age=now-item['seen_at'] if item['seen_at'] is not None else None
                state='unknown' if age is None else ('offline' if age>30 else ('degraded' if data.get('error') else 'healthy'))
                result.append({**item,'state':state,'age_seconds':round(age,1) if age is not None else None,'metrics':data})
            # Native node status is a real Marzban fact, not a fabricated heartbeat.
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='nodes'").fetchone()
            if exists:
                for row in db.execute('SELECT id,name,address,status,message,xray_version,last_status_change FROM nodes ORDER BY name'):
                    live=self.native_probe(row['id'])
                    managed=None
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_managed'").fetchone():
                        managed=db.execute('SELECT name FROM fleet_managed WHERE native_id=?',(row['id'],)).fetchone()
                    result.append({'id':'xray:'+str(row['id']),'name':managed['name'] if managed else row['name'],'protocol':'xray',
                        'address':row['address'],'state':'unknown' if live is None else ('healthy' if live else 'offline'),
                        'seen_at':None,'age_seconds':None,'metrics':{'core_version':row['xray_version']},
                        'status_source':'marzban','native_status':row['status']})
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
            if node['state']=='offline':
                result.insert(0,{'id':'offline:'+node['id'],'node':node['id'],'code':'heartbeat_stale',
                    'severity':'error','first_at':node.get('seen_at'),'last_at':node.get('seen_at'),
                    'occurrences':1,'resolved_at':None,'message':'Нет актуальной связи с нодой','derived':True})
        return result[:limit]

    def traffic(self,start,end,protocol=None,node=None,username=None):
        if end<=start or end-start>timedelta(days=366):raise ValueError('Период должен быть от 1 часа до 366 дней')
        begin=start.replace(tzinfo=None).isoformat(' ');finish=end.replace(tzinfo=None).isoformat(' ')
        records=[]
        with self.store.connection() as db:
            if protocol in (None,'hysteria2'):
                sql='SELECT node,username,hour,SUM(tx) tx,SUM(rx) rx FROM hy2_hourly WHERE hour>=? AND hour<?'
                params=[begin,finish]
                if node:sql+=' AND node=?';params.append(node)
                if username:sql+=' AND username=?';params.append(username)
                sql+=' GROUP BY node,username,hour ORDER BY hour LIMIT 50001'
                for row in db.execute(sql,params):
                    r=dict(row);r.update(protocol='hysteria2',total=r['tx']+r['rx']);records.append(r)
            if protocol in (None,'xray'):
                sql='''SELECT node,username,hour,SUM(total) total FROM fleet_xray_hourly
                       WHERE hour>=? AND hour<?'''
                params=[begin,finish]
                if node:sql+=' AND node=?';params.append(node)
                if username:sql+=' AND username=?';params.append(username)
                sql+=' GROUP BY node,username,hour ORDER BY hour LIMIT 50001'
                records += [{**dict(r),'protocol':'xray','tx':None,'rx':None} for r in db.execute(sql,params)]
        if len(records)>50000:raise ValueError('Слишком большой отчёт: сузьте период или выберите ноду / пользователя')
        series={};users={};totals={'hysteria2':0,'xray':0}
        for r in records:
            totals[r['protocol']]+=r['total']
            hour=r['hour'][:13]+':00:00'
            series.setdefault(hour,{'hour':hour,'hysteria2':0,'xray':0})[r['protocol']]+=r['total']
            key=r['username'] or '(удалён)'
            users.setdefault(key,{'username':key,'hysteria2':0,'xray':0})[r['protocol']]+=r['total']
        return {'from':start.isoformat(),'to':end.isoformat(),'totals':totals,'total':sum(totals.values()),
                'series':sorted(series.values(),key=lambda x:x['hour']),
                'users':sorted(users.values(),key=lambda x:-(x['hysteria2']+x['xray'])),
                'rows':records,'time_basis':'posting_hour','native_direction_available':False}
