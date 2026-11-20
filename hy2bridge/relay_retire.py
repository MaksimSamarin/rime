"""Withdraw a dead entry's publication before deferred, ownership-checked cleanup."""
import json
import os
from pathlib import Path
import secrets
import time

from .provision import ProvisionError


class RelayRetirements:
    def __init__(self, relays):
        self.relays=relays
        self.store=relays.store
        with self.store.connection(write=True) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS fleet_relay_retirements(
                id TEXT PRIMARY KEY,tunnel TEXT NOT NULL,node TEXT NOT NULL,entry TEXT NOT NULL,
                services TEXT NOT NULL,phase TEXT NOT NULL,retry_at REAL NOT NULL,updated_at REAL NOT NULL)''')

    def pending_entry(self, entry):
        with self.store.connection() as db:
            return db.execute("SELECT count(*) FROM fleet_relay_retirements WHERE entry=? AND phase='cleanup_pending'",(entry,)).fetchone()[0]

    def prune(self):
        with self.store.connection(write=True) as db:
            db.execute("DELETE FROM fleet_relay_retirements WHERE phase IN ('complete','abandoned') AND updated_at<?",(time.time()-90*86400,))

    def entries_for_node(self, node, database=None):
        if database is None:
            with self.store.connection() as db:return self.entries_for_node(node,db)
        entries={row[0] for row in database.execute("SELECT entry FROM fleet_tunnels WHERE node=? AND state<>'deleted'",(node,))}
        entries.update(row[0] for row in database.execute("SELECT entry FROM fleet_relay_changes WHERE node=? AND phase NOT IN ('committed','rolled_back','abandoned')",(node,)))
        for row in database.execute("SELECT old_entry,new_entry FROM fleet_relay_switches WHERE node=? AND phase NOT IN ('complete','rolled_back','abandoned')",(node,)):
            entries.update(row)
        return entries

    def require_quiet(self, node, entries, job, database):
        owners=getattr(self.relays.worker_state,'owners',set()) if getattr(self.relays.worker_state,'identity',None)==job else set()
        if (entries & self.relays.busy)-owners:
            raise ProvisionError('Дождитесь завершения выполняющейся операции входа')
        # Durable running rows may be orphaned after a controller crash. Only
        # RAM ownership of this single locked controller proves a live worker.
        running=getattr(self.relays.provision,'running',set())
        addresses={row[0] for row in database.execute("SELECT origin FROM fleet_tunnels WHERE node=? AND state<>'deleted'",(node,))}
        for entry in entries:
            row=database.execute('SELECT address FROM fleet_relay_entries WHERE id=?',(entry,)).fetchone()
            if row:addresses.add(row[0])
        tables={row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ('fleet_jobs','fleet_proxy_jobs'):
            if table not in tables:continue
            columns={row['name'] for row in database.execute('PRAGMA table_info('+table+')')}
            if 'context' not in columns:continue
            for row in database.execute('SELECT * FROM '+table+" WHERE state='running'"):
                context=json.loads(row['context'])
                related=(context.get('node')==node or context.get('move_node')==node or ('node' in columns and row['node']==node))
                if related:addresses.update(value for value in (context.get('address'),context.get('host')) if value)
        if addresses & running:
            raise ProvisionError('На выходной ноде выполняется операция. Повторите возврат после её завершения')

    def abandon_stale(self, node, database):
        from .relay_control import canonical_service
        services=[dict(row) for row in database.execute("SELECT s.* FROM fleet_tunnel_services s JOIN fleet_tunnels t ON t.id=s.tunnel WHERE t.node=? AND s.state<>'deleted'",(node,))]
        changes=[dict(row) for row in database.execute("SELECT * FROM fleet_relay_changes WHERE node=? AND phase NOT IN ('committed','rolled_back','abandoned')",(node,))]
        switches=[dict(row) for row in database.execute("SELECT * FROM fleet_relay_switches WHERE node=? AND phase NOT IN ('complete','rolled_back','abandoned')",(node,))]
        for row in [*changes,*switches]:
            for field in ('before','after'):
                if row.get(field):services.extend(json.loads(row[field]).get('services',[]))
        tables={row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for row in [*changes,*switches]:
            for table in ('fleet_jobs','fleet_proxy_jobs','fleet_relay_jobs'):
                if table not in tables:continue
                columns={col['name'] for col in database.execute('PRAGMA table_info('+table+')')}
                message=",message='Незавершённое изменение маршрута отменено оператором'" if 'message' in columns else ''
                database.execute('UPDATE '+table+" SET state='failed'"+message+" WHERE id=? AND state='running'",(row['id'],))
            if 'fleet_relay_edits' in tables:
                database.execute("UPDATE fleet_relay_edits SET state='abandoned' WHERE id=? AND state<>'succeeded'",(row['id'],))
        database.execute("UPDATE fleet_relay_changes SET phase='abandoned',updated_at=? WHERE node=? AND phase NOT IN ('committed','rolled_back','abandoned')",(time.time(),node))
        database.execute("UPDATE fleet_relay_switches SET phase='abandoned',retry_at=0,updated_at=? WHERE node=? AND phase NOT IN ('complete','rolled_back','abandoned')",(time.time(),node))
        unique={}
        for service in services:
            key=(service['entry'],json.dumps(canonical_service(json.loads(service['config'])),sort_keys=True))
            unique[key]=service
        return list(unique.values())

    def detach(self, job, route):
        with self.relays.lock,self.store.connection(write=True) as db:
            if not self.relays.route_matches(db,route):
                raise ProvisionError('Маршрут изменился. Повторите подтверждение прямого подключения')
            entries=self.entries_for_node(route['node'],db)
            self.require_quiet(route['node'],entries,job,db)
            rows=self.abandon_stale(route['node'],db)
            grouped={}
            for service in rows:grouped.setdefault(service['entry'],[]).append(service)
            ledgers=[]
            for entry,owned in grouped.items():
                identity=job if entry==route['entry'] else secrets.token_hex(16)
                ledgers.append(identity)
                db.execute('INSERT INTO fleet_relay_retirements VALUES(?,?,?,?,?,?,?,?)',
                           (identity,route['id'],route['node'],entry,json.dumps(owned),'cleanup_pending',0,time.time()))
            db.execute("UPDATE fleet_tunnels SET state='deleted' WHERE node=? AND state<>'deleted'",(route['node'],))
            for service in rows:db.execute("UPDATE fleet_tunnel_services SET state='retired' WHERE id=? AND state<>'deleted'",(service['id'],))
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='fleet_events'").fetchone():
                db.execute("UPDATE fleet_events SET resolved_at=?,last_at=? WHERE node=? AND code IN ('relay_client_unreachable','relay_proxy_unreachable') AND resolved_at IS NULL",(time.time(),time.time(),route['node']))
        self.relays.changes.suspended_management.discard(route['node'])
        try:self.relays.reconnect(route['node'])
        except Exception:pass
        from .native_management import refresh_management_sources
        refresh_management_sources(self.relays,route['node'])
        cleaned=all([self.cleanup(identity) for identity in ledgers])
        self.relays.update(job,'succeeded','Подписка возвращена на прямые адреса'+('' if cleaned else '. Очистка правил входа отложена'),
                           {'operation':'route-detach','route_id':route['id'],'cleanup_pending':not cleaned})

    def cleanup(self, identity):
        with self.store.connection() as db:
            row=db.execute('SELECT * FROM fleet_relay_retirements WHERE id=?',(identity,)).fetchone()
        if row is None or row['phase']!='cleanup_pending':return True
        try:self.relays.switches.remove_owned(row['entry'],json.loads(row['services']))
        except Exception:
            with self.store.connection(write=True) as db:
                db.execute('UPDATE fleet_relay_retirements SET retry_at=?,updated_at=? WHERE id=?',(time.time()+60,time.time(),identity))
            return False
        with self.store.connection(write=True) as db:
            for service in json.loads(row['services']):
                db.execute("UPDATE fleet_tunnel_services SET state='deleted' WHERE id=? AND entry=? AND state='retired'",(service['id'],row['entry']))
            db.execute("UPDATE fleet_relay_retirements SET phase='complete',retry_at=0,updated_at=? WHERE id=?",(time.time(),identity))
        return True

    def recover(self):
        with self.store.connection() as db:
            rows=[dict(row) for row in db.execute("SELECT * FROM fleet_relay_retirements WHERE phase='cleanup_pending' AND retry_at<=? ORDER BY updated_at LIMIT 4",(time.time(),))]
        from update_runtime.leases import acquire
        for row in rows:
            with self.relays.lock:
                if row['entry'] in self.relays.busy:continue
                try:lease=acquire(Path(self.store.path).parent/'.updates')
                except BlockingIOError:continue
                self.relays.busy.add(row['entry'])
            try:self.cleanup(row['id'])
            finally:
                with self.relays.lock:self.relays.busy.discard(row['entry'])
                os.close(lease)
