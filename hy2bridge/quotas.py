"""Per-node VPN quotas. User quotas and issued subscriptions are independent."""
import calendar
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import logging
import threading
import time

current = None
UTC = timezone.utc


def next_boundary(value, period, anchor_day):
    date = datetime.fromtimestamp(value, UTC)
    if period in ('daily', 'weekly'):
        return (date + timedelta(days=1 if period == 'daily' else 7)).timestamp()
    year, month = date.year + (date.month == 12), date.month % 12 + 1
    return date.replace(year=year, month=month, day=min(anchor_day, calendar.monthrange(year, month)[1])).timestamp()


class NodeQuotas:
    def __init__(self, store):
        self.store = store
        self.enforced = {}
        self.configured = {}
        self.lock = threading.Lock()
        with store.connection(write=True) as db:
            first_install=not db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_node_traffic'").fetchone()
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_node_traffic(
                node TEXT NOT NULL,hour INTEGER NOT NULL,incoming INTEGER NOT NULL,outgoing INTEGER NOT NULL,
                PRIMARY KEY(node,hour))''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_node_quotas(
                node TEXT PRIMARY KEY,limit_bytes INTEGER NOT NULL,direction TEXT NOT NULL,period TEXT NOT NULL,
                action TEXT NOT NULL,period_start REAL NOT NULL,next_reset REAL,anchor_day INTEGER NOT NULL,
                base_in INTEGER NOT NULL,base_out INTEGER NOT NULL,generation INTEGER NOT NULL DEFAULT 1,
                updated_at REAL NOT NULL,actor TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_quota_audit(
                id INTEGER PRIMARY KEY AUTOINCREMENT,node TEXT NOT NULL,action TEXT NOT NULL,
                at REAL NOT NULL,actor TEXT NOT NULL)''')
            if first_install:
                db.execute('''INSERT OR IGNORE INTO fleet_node_traffic
                    SELECT node,CAST(strftime('%s',hour) AS INTEGER),SUM(tx),SUM(rx)
                    FROM hy2_hourly GROUP BY node,hour''')
            self._triggers(db, 'hy2_totals', 'NEW.node', 'NEW.tx', 'NEW.rx', 'OLD.tx', 'OLD.rx')
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='node_usages'").fetchone():
                if first_install:
                    db.execute('''INSERT OR IGNORE INTO fleet_node_traffic
                        SELECT COALESCE('xray:'||node_id,'xray:local'),CAST(strftime('%s',created_at) AS INTEGER),
                        SUM(uplink),SUM(downlink) FROM node_usages GROUP BY node_id,created_at''')
                self._triggers(db, 'node_usages', "COALESCE('xray:'||NEW.node_id,'xray:local')",
                               'NEW.uplink','NEW.downlink','OLD.uplink','OLD.downlink')
            # Reusing a deleted node ID must not inherit another server's quota.
            for table, ident in [('nodes', "'xray:'||OLD.id"), ('fleet_inventory', 'OLD.id')]:
                if db.execute('SELECT 1 FROM sqlite_master WHERE name=?',(table,)).fetchone():
                    db.execute(f'''CREATE TRIGGER IF NOT EXISTS fleet_quota_delete_{table}
                        AFTER DELETE ON {table} BEGIN
                        DELETE FROM fleet_node_quotas WHERE node={ident};
                        DELETE FROM fleet_node_traffic WHERE node={ident}; END''')
        # Startup configurations use the persisted desired state. Remember it so
        # an immediate reset after panel restart also restores native listeners.
        with store.connection() as db:
            self.enforced={r['node']:self.state(r['node'],db)['blocked'] for r in db.execute('SELECT node FROM fleet_node_quotas')}
            self.configured=dict(self.enforced)

    @staticmethod
    def _triggers(db, table, node, new_in, new_out, old_in, old_out):
        for operation, incoming, outgoing in [('INSERT',new_in,new_out),
                ('UPDATE',f'MAX(0,{new_in}-{old_in})',f'MAX(0,{new_out}-{old_out})')]:
            db.execute(f'''CREATE TRIGGER IF NOT EXISTS fleet_quota_{table}_{operation.lower()}
                AFTER {operation} ON {table} BEGIN
                INSERT INTO fleet_node_traffic VALUES({node},CAST(strftime('%s','now') AS INTEGER)/3600*3600,{incoming},{outgoing})
                ON CONFLICT(node,hour) DO UPDATE SET incoming=incoming+excluded.incoming,outgoing=outgoing+excluded.outgoing;
                END''')

    @staticmethod
    def totals(db, node, start=None):
        clause = ' AND hour>=?' if start is not None else ''
        row=db.execute('SELECT COALESCE(SUM(incoming),0),COALESCE(SUM(outgoing),0) FROM fleet_node_traffic WHERE node=?'+clause,
                       (node,start) if start is not None else (node,)).fetchone()
        return row[0],row[1]

    def state(self, node, db=None, now=None):
        if db is None:
            with self.store.connection() as connection:return self.state(node,connection,now)
        now=time.time() if now is None else now
        row=db.execute('SELECT * FROM fleet_node_quotas WHERE node=?',(node,)).fetchone()
        if row is None:return {'enabled':False,'limit_bytes':0,'used_bytes':0,'remaining_bytes':None,'blocked':False,'stage':'disabled'}
        result=dict(row);incoming,outgoing=self.totals(db,node)
        reset=result['next_reset'];start=result['period_start'];rolled=False
        while reset is not None and reset<=now:
            start=reset;reset=next_boundary(reset,result['period'],result['anchor_day']);rolled=True
        if rolled:
            used_in,used_out=self.totals(db,node,start)
            result.update(base_in=incoming-used_in,base_out=outgoing-used_out,period_start=start,next_reset=reset)
        else:used_in=max(0,incoming-result['base_in']);used_out=max(0,outgoing-result['base_out'])
        used=used_out if result['direction']=='outgoing' else used_in+used_out
        limit=result['limit_bytes'];ratio=used/limit if limit else 0
        stage='exceeded' if ratio>=1 else 'warning95' if ratio>=.95 else 'warning80' if ratio>=.8 else 'normal'
        result.update(enabled=limit>0,used_bytes=used,remaining_bytes=max(0,limit-used) if limit else None,
                      percent=round(ratio*100,2),blocked=bool(limit and used>=limit and result['action']=='stop'),
                      stage=stage if limit else 'disabled',rolled=rolled,
                      accounting_basis='VPN payload; outgoing to clients; posting hour UTC')
        if node.startswith('xray:'):
            result['enforced_blocked']=self.enforced.get(node,False)
            result['transition_pending']=result['blocked']!=result['enforced_blocked']
        return result

    def save(self,node,data,actor,now=None):
        now=time.time() if now is None else now
        if data['period'] not in ('none','daily','weekly','monthly') or data['direction'] not in ('outgoing','total') or data['action'] not in ('warn','stop'):
            raise ValueError('Некорректные параметры лимита')
        reset=data.get('reset_at')
        if data['period']=='none':reset=None
        elif reset is None or reset<=now or datetime.fromtimestamp(reset,UTC).time().isoformat()!='00:00:00':
            raise ValueError('Укажите будущую дату сброса, 00:00 UTC')
        with self.store.connection(write=True) as db:
            old=self.state(node,db,now);incoming,outgoing=self.totals(db,node)
            if not data['limit_bytes'] and 'node' not in old:return old
            base_in=old.get('base_in',incoming);base_out=old.get('base_out',outgoing)
            anchor=old['anchor_day'] if old.get('next_reset')==reset and old.get('period')==data['period'] else datetime.fromtimestamp(reset,UTC).day if reset else 1
            db.execute('''INSERT INTO fleet_node_quotas VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(node) DO UPDATE SET limit_bytes=excluded.limit_bytes,direction=excluded.direction,
                period=excluded.period,action=excluded.action,period_start=excluded.period_start,next_reset=excluded.next_reset,
                anchor_day=excluded.anchor_day,base_in=excluded.base_in,base_out=excluded.base_out,
                updated_at=excluded.updated_at,actor=excluded.actor''',
                (node,data['limit_bytes'],data['direction'],data['period'],data['action'],old.get('period_start',now),
                 reset,anchor,base_in,base_out,old.get('generation',1),now,actor))
            db.execute('INSERT INTO fleet_quota_audit(node,action,at,actor) VALUES(?,?,?,?)',(node,'settings',now,actor))
        return self.state(node,now=now)

    def reset(self,node,actor,now=None):
        now=time.time() if now is None else now
        with self.store.connection(write=True) as db:
            state=self.state(node,db,now)
            if 'node' not in state:raise ValueError('Сначала настройте лимит ноды')
            incoming,outgoing=self.totals(db,node)
            db.execute('''UPDATE fleet_node_quotas SET base_in=?,base_out=?,period_start=?,next_reset=?,
                generation=generation+1,updated_at=?,actor=? WHERE node=?''',
                (incoming,outgoing,now,state['next_reset'],now,actor,node))
            db.execute('INSERT INTO fleet_quota_audit(node,action,at,actor) VALUES(?,?,?,?)',(node,'manual_reset',now,actor))
        return self.state(node,now=now)

    def blocked(self,node,db=None):
        return self.state(node,db)['blocked']

    def sync(self):
        """Persist automatic boundaries and reconcile threshold incidents."""
        states=[];now=time.time()
        with self.store.connection(write=True) as db:
            for row in db.execute('SELECT node FROM fleet_node_quotas').fetchall():
                node=row['node'];s=self.state(node,db,now);states.append(s)
                if s['rolled']:
                    db.execute('UPDATE fleet_node_quotas SET base_in=?,base_out=?,period_start=?,next_reset=?,generation=generation+1 WHERE node=?',
                        (s['base_in'],s['base_out'],s['period_start'],s['next_reset'],node))
                    db.execute('INSERT INTO fleet_quota_audit(node,action,at,actor) VALUES(?,?,?,?)',(node,'scheduled_reset',now,'scheduler'))
                code={'warning80':'node_quota_80','warning95':'node_quota_95','exceeded':'node_quota_exceeded'}.get(s['stage'])
                db.execute("UPDATE fleet_events SET resolved_at=? WHERE node=? AND code IN ('node_quota_80','node_quota_95','node_quota_exceeded') AND resolved_at IS NULL AND code<>?",(now,node,code or ''))
                if code and not db.execute('SELECT id FROM fleet_events WHERE node=? AND code=? AND resolved_at IS NULL',(node,code)).fetchone():
                    db.execute('INSERT INTO fleet_events(node,code,severity,first_at,last_at) VALUES(?,?,?,?,?)',(node,code,'warning' if s['stage']!='exceeded' else 'error',now,now))
        return states

    def install(self,app):
        from app import scheduler,xray
        def reconcile():
            if not self.lock.acquire(blocking=False):return
            try:
                for s in self.sync():
                    node=s['node'];desired=s['blocked']
                    if not node.startswith('xray:'):continue # Hy2 consumes policy and kicks existing sessions.
                    previous=self.enforced.get(node,False)
                    if desired==previous:continue
                    try:
                        target=xray.core if node=='xray:local' else xray.nodes.get(int(node[5:]))
                        if target is None or (node!='xray:local' and not target.connected):continue
                        if self.configured.get(node,False)!=desired:
                            # Capture native volatile usage before closing old sessions.
                            for name in ('record_user_usages','record_node_usages'):
                                jobs=[j for j in scheduler.get_jobs() if j.func.__name__==name]
                                if len(jobs)==1:jobs[0].func()
                            config=xray.config.include_db_users()
                            target.restart(enforcement_config(config,node))
                            self.configured[node]=desired
                        # The data listener may open before gRPC has reconnected.
                        # Report completion only once later user edits can reach it.
                        import grpc
                        api=xray.api if node=='xray:local' else target.api
                        deadline=time.monotonic()+12
                        while True:
                            try:
                                grpc.channel_ready_future(api._channel).result(timeout=2)
                                api.get_sys_stats(timeout=2)
                                break
                            except Exception:
                                if time.monotonic()>=deadline:raise
                                time.sleep(.2)
                        self.enforced[node]=desired
                    except Exception as exc:
                        logging.getLogger('fleet').warning('Node quota enforcement deferred for %s (%s)',node,type(exc).__name__)
            finally:self.lock.release()
        self.reconcile=reconcile
        scheduler.add_job(reconcile,'interval',seconds=2,id='fleet_node_quotas',replace_existing=True,max_instances=1)


def blocked(node,db=None):
    return current is not None and current.blocked(node,db)


def enforcement_config(config,node):
    # Remote core restart bypasses XRayCore.start: explicitly retain per-user ACL.
    from .access import filter_config as scoped_config
    return scoped_config(config,node)


def filter_config(config,node):
    if not blocked(node):return config
    value=deepcopy(config)
    # Preserve only Xray's administrative API listener. Restart closes old VPN sessions.
    api_tag=value.get('api',{}).get('tag')
    api_inbounds=set()
    for rule in value.get('routing',{}).get('rules',[]):
        if api_tag and rule.get('outboundTag')==api_tag:api_inbounds.update(rule.get('inboundTag',[]))
    value['inbounds']=[inbound for inbound in value.get('inbounds',[]) if inbound.get('tag') in api_inbounds]
    return value
